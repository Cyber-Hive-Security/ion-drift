# Security review — advisory engine (Phases 3–4) and confusable-domain detector

**Reviewed:** 2026-08-05, commits `f7dec75..05aa229` on `development`.
**Fixes:** `cc317c1..` (this branch), same day.

## Scope

The advisory auth-failure accumulator (Phase 3), cross-cycle sustained counting
(Phase 4), and the confusable-domain detector — `dns.db`, the DNS cache poller,
the UTS #39 skeleton matcher, and the watchlist catalog loader.

## What was already sound

- **No new HTTP surface.** The engines are internal pollers; zero routes were
  added, so no new authentication, authorisation, or CSRF exposure.
- **Injection is structurally impossible.** Every SQL statement in the storage
  crate is a static string with bound parameters. No statement is built by
  string formatting. This was true before the review and needed no change.
- **No panics on untrusted input** in any production path of the new code.
- **Rendering is escaped.** Findings render through React's escaping, and the
  three `innerHTML` tooltip sites all pass through `escHtml`.

## What was fixed

| # | Finding | Fix |
|---|---|---|
| F1 | `dns_observation` grew without bound — distinct names are attacker-controlled and free to mint, so time-based pruning alone could not bound the table | 50k row ceiling, evicted oldest-first, eviction logged at `warn` |
| F2 | One registered lookalike plus unlimited unique subdomains minted unlimited High findings; findings are auto-resolved but never deleted | Findings keyed on the matched suffix, not the observed name; subdomains merge into one finding with capped `observed_names` evidence |
| F3 | `normalize_domain` discarded the IDNA result and stripped no control/format characters, so bidi overrides and zero-width characters reached finding titles, database rows and log lines | Display-hostile characters scrubbed before IDNA decoding; a lossy decode is logged at `debug` |
| F4 | A single database error aborted the remainder of a poll cycle, skipping later names, the match pass, and the prune | Per-item failures log and continue; batch-level failures still abort the cycle |
| F5 | Cross-cycle counting counted rows, and `tokio::time::interval` defaults to firing missed ticks back-to-back — a stalled host could manufacture the cycle spread the sustained rule requires | Distinct `observed_at` stamps are counted; both pollers use `MissedTickBehavior::Skip` |

## The staging layer

Validation was previously uneven: the advisory catalog allow-listed its control
fields, but several values reached SQLite verbatim — `dns_observation.addresses`
(cloned from the router response), `confusable_watchlist.brand` (catalog text
that reaches finding titles), and the `service` half of every `surface_key`
(defined by the log parser as whatever followed `" via "`).

`ion_drift_web::staging` is now the single boundary. Two rules govern it:

1. **Bound, don't drop.** Over-length values are truncated, not discarded —
   evidence an operator needs must survive a length limit.
2. **Unknown is not invalid.** An unrecognised RouterOS service is tagged and
   still counted. A wording change in a future release must degrade to "flagged
   unknown", never to silence.

`dns.db` schema v2 adds `CHECK` constraints as the backstop beneath it. The
staging functions are where a bad value is meant to be caught; the constraints
are what catches a writer that forgets to call them. The v1→v2 migration
**repairs** rows (truncates over-long values, clamps out-of-range numbers)
rather than dropping them: a migration step is a static SQL string and cannot
log a dropped-row count, and silent loss of investigation evidence is worse
than an over-long string.

## Known limitations, accepted

- **Surface-key delimiter (F6).** `"{device_id}:svc:{service}"` is parsed back
  with `rsplit_once(":svc:")` and neither half is escaped. Both inputs are
  trusted-ish today and staging bounds the service length, which shrinks the
  window without closing it. Revisit if surface keys ever take untrusted input.
- **Catalog overlay trust boundary.** Anyone who can write to
  `<data_dir>/advisories/` or `<data_dir>/confusable/` can add entries — or set
  `"allow": true` — and blind a detector. Neither catalog is signature-verified.
  The overlay directory must be protected to the same standard as the binary.
- **Single-source slow runs** remain invisible to the sustained rule: the
  accumulator retains no user identities, so one host pacing failures is
  indistinguishable from an integration retrying a stale credential. Closing
  this needs a schema change, not a threshold change.

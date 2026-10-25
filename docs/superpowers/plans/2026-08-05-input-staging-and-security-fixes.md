# Input Staging Layer + Security Review Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give every write path in the advisory/confusable engines a real staging layer (bounds + charset + classification at the boundary, `CHECK` constraints as backstop), then fix the findings from the 2026-08-05 security review of `f7dec75..05aa229`.

**Authorization:** Scott approved this work on 2026-08-05, scheduled to begin ~06:25 UTC the same day. Review findings and the staging design were presented and accepted before scheduling.

**Architecture:** Validation today is uneven — the advisory catalog allow-lists its control fields (`requires_surface_class`, `severity`, `confidence`, `signal_id`), but free-text and data fields reach SQLite verbatim. SQL injection is already structurally impossible (every statement is static with bound `params![]`); this plan is about garbage-in containment and storage bounds, not injection. Boundary validation goes in code where it can log and truncate gracefully; `CHECK` constraints go in the schema as the backstop that catches a future writer bypassing the staging functions — the same belt-and-braces the existing `advisory_signal.confidence` CHECK already demonstrates.

**Tech Stack:** Rust workspace `<repo>`, branch `development`. Head at time of writing: `05aa229`.

## Global Constraints

- Branch `development`; Conventional Commits; TDD — prove RED before GREEN, capture the failing output.
- Windowed counting + prune, NO EWMA (ADR PATTERNS).
- `dns.db` gains schema **v2** via `apply_versioned` + `MIGRATION_STEPS` (currently v1 with an empty step list). SQLite cannot add a CHECK to an existing table with `ALTER TABLE` — the v2 step must create the new table, copy rows, drop, rename. Bump `DnsStore::SCHEMA_VERSION` to 2 in the same commit. Migration steps use plain `CREATE TABLE` (no `IF NOT EXISTS`) so a wrongly re-run step fails loudly.
- `advisory.db` is at v2 and its accumulator tables are recent; adding CHECKs there needs a **v3** step following the same rebuild pattern. If that proves invasive, ship the code-level staging for advisory and note the CHECK backstop as deferred — do NOT skip it silently.
- Do NOT weaken any existing guardrail to make a test pass.
- Verify with `cargo test --workspace` AND `cargo-deny >= 0.20 check` (0.18.x chokes on CVSS 4.0 in the RustSec DB). Show real output before claiming done.
- **Host caveat (this box):** `openssl-sys` needs the scratchpad prefix workaround:
  ```bash
  cd <scratchpad> && apt-get download libssl-dev && dpkg-deb -x libssl-dev_*.deb prefix
  cp prefix/usr/include/x86_64-linux-gnu/openssl/* prefix/usr/include/openssl/
  export OPENSSL_STATIC=1 \
    OPENSSL_LIB_DIR=$PWD/prefix/usr/lib/x86_64-linux-gnu \
    OPENSSL_INCLUDE_DIR=$PWD/prefix/usr/include
  ```
  The `opensslconf.h` copy is the non-obvious step. `cargo-deny` is not installed; use the prebuilt musl binary from GitHub releases.
- **Gotcha:** `ion-drift-web` has parallel module trees in BOTH `src/lib.rs` and `src/main.rs`. A new top-level module must be registered in both or the lib/test target fails E0433 while the bin target compiles.
- Push to `origin development` (the Gitea remote) when green.

## File Structure

| File | Responsibility |
|---|---|
| `crates/ion-drift-web/src/staging.rs` (create) | Boundary validators: bounds, charset, classification. Pure, heavily tested. Register in `lib.rs` AND `main.rs`. |
| `crates/ion-drift-storage/src/dns.rs` (modify) | v2 migration adding CHECK constraints + length bounds |
| `crates/ion-drift-web/src/tasks/dns_cache.rs` (modify) | Apply staging; per-item error isolation (F4) |
| `crates/ion-drift-web/src/confusable/skeleton.rs` (modify) | Strip Cc/Cf, honour IDNA result (F3) |
| `crates/ion-drift-web/src/confusable/catalog.rs` (modify) | Stage `brand`; bound lengths |
| `crates/ion-drift-web/src/confusable/detector.rs` (modify) | Finding id keyed on matched suffix (F2) |
| `crates/ion-drift-web/src/advisory/sustained.rs` (modify) | Per-item error isolation (F4); distinct-bucket cycle count (F5) |
| `crates/ion-drift-web/src/tasks/advisory.rs` (modify) | `MissedTickBehavior::Skip` (F5) |

---

### Task 1: The staging module (pure, testable)

**Produces** (later tasks consume these exact signatures):
- `pub(crate) const MAX_DNS_NAME: usize = 253;` / `MAX_SERVICE: usize = 32;` / `MAX_ADDRESS: usize = 45;` / `MAX_BRAND: usize = 128;` / `MAX_LIST_ITEMS: usize = 16;`
- `pub(crate) fn stage_dns_name(raw: &str) -> Option<String>` — normalize, strip `Cc`/`Cf`, reject empty / >MAX_DNS_NAME / no dot
- `pub(crate) fn stage_service(raw: &str) -> String` — trim, strip control chars, truncate to MAX_SERVICE; unknown-but-legal values preserved (do NOT drop — see rationale below)
- `pub(crate) fn stage_addresses(raw: &[String]) -> Vec<String>` — trim, strip control chars, truncate each to MAX_ADDRESS, cap list at MAX_LIST_ITEMS, dedup, sort
- `pub(crate) fn stage_text(raw: &str, max: usize) -> String` — generic: strip control chars, collapse whitespace, truncate
- `pub(crate) fn is_known_service(s: &str) -> bool` — allow-list: api, api-ssl, ssh, telnet, winbox, ftp, www, www-ssl, console

**Design rationale to preserve in comments:** unknown services are *tagged, not dropped*. Dropping an unrecognised service would blind the detector to a RouterOS service Drift has not met yet, and the log parser takes `service` as "everything after ` via `" — a wording change in a future RouterOS release must degrade to "still counted, flagged as unknown", never to silence. Same reasoning the existing parser uses for keeping unparseable `src_ip` verbatim.

Tests (prove RED first): truncation at each bound; `U+202E`/zero-width stripped from names; empty-after-strip rejected; single-label rejected; address list capped and deduped; `is_known_service` positive and negative; a 10 KB blob truncated rather than stored.

Commit: `feat(staging): boundary validators for router and catalog input`

---

### Task 2: `dns.db` v2 — CHECK constraints as backstop

Add to `DnsStore`: `SCHEMA_VERSION = 2` and a `MIGRATION_STEPS` entry rebuilding both tables with:
- `dns_observation`: `CHECK (length(name) BETWEEN 1 AND 253)`, `CHECK (length(skeleton) <= 253)`, `CHECK (first_seen > 0)`, `CHECK (last_seen >= first_seen)`
- `confusable_watchlist`: `CHECK (length(domain) BETWEEN 3 AND 253)`, `CHECK (length(brand) <= 128)`, `CHECK (allow IN (0,1))`, `CHECK (catalog_version >= 0)`

Rebuild pattern per table: `CREATE TABLE <t>_new (...CHECKs...)` → `INSERT INTO <t>_new SELECT ... FROM <t> WHERE <rows that satisfy the constraints>` → `DROP TABLE <t>` → `ALTER TABLE <t>_new RENAME TO <t>` → recreate indexes. Rows that would violate a constraint are dropped by the WHERE, and the count must be logged (`tracing::warn!`) — silent data loss during migration is not acceptable.

Tests: a v1 fixture DB (baseline DDL copied verbatim, `PRAGMA user_version = 1`, one good row + one oversized row) migrates to v2, keeps the good row, drops and reports the bad one; reopening at v2 is a no-op; a fresh DB lands on v2; an oversized insert is rejected by the CHECK with a loud error. Mirror the existing `create_v1_database` fixture style in `advisory.rs`.

Commit: `feat(storage): dns.db v2 adds CHECK constraints on staged fields`

---

### Task 3: F2 — finding id keyed on the matched suffix

`finding_id` currently embeds the full observed name, so one registered lookalike plus unlimited unique subdomains mints unlimited High-severity findings, and findings are auto-resolved but never deleted.

Change `build_finding` to `format!("confusable:{}:{}", hit.watchlist_domain, hit.matched_suffix)` and carry the observed names as an evidence array (`observed_names`) so the operator still sees every subdomain under one finding. The poller must therefore aggregate hits by `matched_suffix` before building findings, merging their observed names and addresses.

Tests: two distinct subdomains of one lookalike produce ONE finding id; both observed names appear in evidence; the existing `finding_id_is_stable_per_pair` test updated to reflect suffix keying.

Commit: `fix(confusable): key findings on the matched suffix, not the observed name`

---

### Task 4: F3 + F1 — charset gate and storage bounds

- `normalize_domain`: strip `Cc`/`Cf` (bidi overrides, zero-width joiners), and stop discarding the IDNA `Result` — log it at `debug!`. Keep the "never panic on attacker input" property.
- `prune_observations` gains a companion cap: after the time-based prune, evict oldest-by-`last_seen` beyond `MAX_DNS_OBSERVATIONS` (start at 50_000, a const with a comment explaining the appliance-storage rationale). Log the evicted count — no silent truncation.

Tests: a name carrying `U+202E` is stored stripped; the cap evicts oldest first and reports the count; a name that is only control characters is rejected before insert.

Commit: `fix(confusable): strip control chars and bound dns_observation growth`

---

### Task 5: F4 + F5 — resilience and cycle-count integrity

- `poll_once` and `note_sustained`: replace `?` on per-item store calls with log-and-continue, so one transient DB error cannot skip the remaining names, the match pass, or the prune. Keep `?` on the batch-level fetch and the watchlist read, where failure genuinely means "no useful work this cycle".
- `sustained_hits`: count **distinct `observed_at` buckets** rather than rows, so a tokio missed-tick burst cannot inflate the cycle count toward `SUSTAINED_MIN_CYCLES`.
- `tasks/advisory.rs` and `tasks/dns_cache.rs`: set `MissedTickBehavior::Skip` on the intervals.

Tests: two accumulator rows sharing one `observed_at` count as one cycle; a hit still fires on genuinely distinct cycles (existing tests must stay green).

Commit: `fix(advisory): isolate per-item failures and harden the cycle count`

---

### Task 6: Apply staging at the call sites + full verification

Wire `staging::*` into `tasks/dns_cache.rs` (names, addresses), `confusable/catalog.rs` (`brand`, `domain`), and the advisory accumulator path (`service` → `surface_key`, `src_ips`). Then:

- `cargo test --workspace` — 0 failures, show the counts.
- `cargo-deny >= 0.20 check` — advisories/bans/licenses/sources ok.
- `cargo clippy -p ion-drift-web -p ion-drift-storage` — no NEW warnings from these files.
- Update `docs/security/` with a short note recording the staging layer and the review date.
- Commit, then `git push origin development`.
- `mem_checkpoint` (source=code) recording what shipped, what was deferred, and any finding NOT fixed with the reason.

---

## Findings NOT scheduled for fix (record the decision, do not silently skip)

- **F6 — surface-key delimiter has no escaping.** `"{device_id}:svc:{service}"` parsed back with `rsplit_once(":svc:")`. Both inputs are trusted-ish today; staging bounds the service length, which shrinks but does not close it. Fix properly only if surface keys ever take untrusted input.
- **Operator overlay trust boundary.** Anyone who can write `<data_dir>/confusable/` or `<data_dir>/advisories/` can add `"allow": true` entries and blind a detector. No signature verification on either catalog — identical to the pre-existing advisory model. Document it in `docs/security/`; do not build signing under this plan.

## Self-Review Notes

- The plan fixes F1, F2, F3, F4, F5 and adds the staging layer + CHECK backstop; F6 and the overlay trust boundary are explicitly deferred with reasons above.
- SQL injection needed no fix — it was already structurally impossible. Do not "harden" it and claim credit.

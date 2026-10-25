# Advisory Vulnerability Feed + Exposure Findings — Design

**Date:** 2026-09-24 (rev 2; rev 1 2026-09-23 superseded) · **Branch:** `development` @ `6a98ca1`
**Status:** approved in conversation, pending spec review

**Authorization (Scott):**
- 2026-09-23: "the finding not being displayed until it's being actively exploited is a big miss. The
  whole purpose is to say, 'your config enables this CVE.' We can still keep the alerts for if and when
  the CVE is being actively exploited, but this should be an early warning system."
- 2026-09-24: "I want this module to not require updates from CHS." → "because it's only me maintaining
  the tool, let's go with the automatic layer. That will pull in new CVEs, notify the user. We can save
  the curated for down the road."
- 2026-09-24: "On by default. Include a pop-up that cannot be disabled or cleared until the user confirms
  on by default or changes to off, which then comes with a warning."

## Problem

1. **Findings only on exploitation.** The advisory engine raises nothing until an attack is under way.
2. **Exposure is never observed.** No code reads `/ip/service`; a surface exists only once failed
   logins appear in the router log. `mikrotik.json`'s claim "Drift raises this advisory whenever api or
   api-ssl is observed exposed" has no implementation.
3. **The catalog is one hand-written entry with no refresh.** New CVEs reach operators only via a Drift
   release. Measured 2026-09-24: **CVE-2026-86060** (SSH login privilege escalation, CVSS 4.0 9.2) and
   **CVE-2026-67277** (btest pre-auth memory disclosure / DoS, 8.8) were published 2026-09-05 and added to
   CISA KEV on 2026-09-10. Drift has no knowledge of either.

## Goal

Every managed RouterOS device whose **version** is in a published vulnerable range produces a finding,
automatically, with no CHS involvement. Actively exploited (KEV) CVEs are Critical. Bundled advisories
additionally evaluate **service exposure**. Exploitation findings are unchanged and co-exist.

## Non-goals (this turn)

- CHS-curated / signed catalog feed (deferred; curation layer).
- Config and package surface classes (`/ip/dns allow-remote-requests`, installed packages, …) — they
  require curation to derive from prose. Fetched CVEs are version-only.
- Firewall-rule evaluation.

## Sources — verified 2026-09-24

| Source | Endpoint | Coverage |
|---|---|---|
| NVD API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*` | 83 RouterOS CVEs (2008–2026); all carry machine-readable configurations; 55 with version ranges, 27 with exact versions only |
| CISA KEV | `www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 4 MikroTik entries (CVE-2018-14847, CVE-2018-7445, CVE-2026-86060, CVE-2026-67277) |

Both hosts are **compile-time constants**, not configuration: no operator- or module-influenced
destination, so no SSRF surface.

## Design

### 1. Consent gate (on by default, must be answered)

Server-side state in `app_settings`, key `advisory_feed_consent`:

| Value | Meaning | Fetcher |
|---|---|---|
| absent | unanswered | **idle — no outbound request is made** |
| `on` | confirmed on (default choice) | runs |
| `off` | admin chose off after warning | idle |

Stored alongside: `advisory_feed_consent_by` (username) and `advisory_feed_consent_at` (unix ts).

**Modal** (mounted in `__root.tsx`, shown whenever the server reports `unanswered`):
- Visible to **admins**; blocks the app — no close button, no Escape, no backdrop dismissal, no
  client-side "seen" flag. The server is the only source of truth, so a reload or another browser
  shows it again until answered.
- Text names exactly what is contacted and what is sent: two hosts above, GET requests, no data about
  this installation, its network, or its devices.
- Primary action **Keep on (recommended)** — preselected default.
- Secondary **Turn off** → second confirmation with warning: Drift will not learn of new vulnerabilities;
  only advisories bundled in this release are evaluated; new actively exploited CVEs affecting your
  routers will not be reported. Confirm / Back.
- Non-admin users are not blocked; they see a read-only banner "Vulnerability feed awaiting
  administrator confirmation" until answered.

**Settings → Security** shows current state, who set it and when. Switching **on → off** shows the
same warning; **off → on** needs no warning. Mutating endpoint is admin-guarded like every mutating route.

**Assumption (flagged for review):** "on by default" means *preselected*, and fetching begins only once
an admin confirms. A disclosure made after traffic has already been sent is not consent, and the first
admin login happens during setup, so the practical delay is minutes.

Upgrading installs have no key → modal on next admin login.

### 2. Feed fetcher — `tasks/advisory_feed.rs`

- Runs only when consent = `on`. First run: full RouterOS CPE pull (1 request at current volume).
  Then **daily**, incremental via NVD `lastModStartDate`/`lastModEndDate`, plus KEV (single JSON).
  Well within NVD's unauthenticated limit (5 requests / 30 s). No API key.
- `reqwest` with rustls (existing), timeouts, response-size cap, HTTPS only.
- All fetched content is **untrusted input**: staged at the boundary (`stage_text`, length caps,
  control-character scrub), CVE IDs validated `^CVE-\d{4}-\d{4,}$`, malformed records skipped + counted.
- **Fail-soft, last-known-good:** a failed or malformed fetch never deletes stored data.
- Persisted in `advisory.db` **schema v3** via `apply_versioned` (append-only step, ADR PATTERNS):
  `feed_cve` (id, published, last_modified, description, cvss_version, cvss_score, cvss_vector, cwe,
  nvd_status), `feed_cve_range` (cve_id, start, start_incl, end, end_incl, exact), `feed_kev`
  (cve_id, date_added, due_date), `feed_state` (source, last_success_at, last_attempt_at, last_error).

**Third-party text.** NVD/CVE descriptions are displayed at runtime with attribution and an NVD link;
each install fetches them directly (client-fetch — the model adopted in checkpoint #27). They are never
copied into the bundled catalog, whose "original prose only" rule is unchanged.

### 3. RouterOS version matching — `advisory/version.rs`

- Device version from existing `/system/resource` `version` (e.g. `7.24.1 (stable)`) — strip channel
  suffix, parse numeric components; `rc`/`beta` pre-releases order **below** the release.
- A CVE applies if the version falls in **any** of its ranges (start/end, each inclusive or exclusive,
  either bound optional) or equals an exact version.
- Unparseable device version or range bound → **cannot evaluate**: no finding is raised or resolved on
  that basis; logged, and surfaced as a device-level "vulnerability status unknown" note.
- The same matcher evaluates `version_constraint` in the bundled catalog (rev 1's "reject at load" is
  withdrawn — the matcher now exists). A constraint in an unrecognised shape is rejected at load and
  degrades the catalog, per the existing contract.

### 4. Vulnerability findings (fetched + bundled, version-based)

| Field | Value |
|---|---|
| module | `advisory` |
| finding_id | `<device>:ver:<CVE-ID>` |
| category | `advisory_vulnerable` |
| severity | on KEV → **Critical**; else CVSS ≥ 7.0 → High; 4.0–6.9 → Medium; < 4.0 → Low; no score → Medium |
| title | `<CVE-ID> — RouterOS <version> is affected` (+ " — actively exploited" when on KEV) |
| narrative | NVD description (attributed) + **"Your RouterOS version is in the affected range. Drift has not checked whether the affected feature is enabled on this router."** |
| recommended_actions | "Upgrade to <first fixed version on this device's branch>" derived from the matching range's exclusive end; NVD link |
| evidence | device_id, device version, matched range, CVSS vector, KEV date_added |

Lifecycle: upsert each evaluation; **auto-resolve** ("no longer affected — RouterOS <new version>") when
a *successful* version read falls outside all ranges; reopen via existing `reopen_by_key` on regression.
A failed device read changes nothing.

Precedence: if the bundled catalog has an entry for the same CVE, the bundled entry's metadata wins
(curated beats fetched); version still decides applicability.

### 5. Service exposure findings (bundled entries with a service surface)

Unchanged from rev 1 for bundled advisories naming `requires_surface_names` (today: CVE-2026-16347):

- New `IpService` resource + `MikrotikClient::ip_services()` (`/ip/service`: name, port, disabled,
  address), staged at the call site.
- Enabled + `address` empty/`0.0.0.0/0`/`::/0` → **High**; enabled + scoped → **Low** with scope in
  evidence; disabled/absent on a successful read → resolve "exposure ceased"; failed read → no change.
- finding_id `<device>:svc:<service>:<advisory>:exposure`, category `advisory_exposure`.
- Acknowledged finding whose severity escalates (Low → High) **reopens** with a note — new store method
  `FindingsStore::reopen_acknowledged_by_key` (existing `reopen_by_key` only reopens `resolved`).
  Unchanged or improved config keeps an acknowledgment. No schema change to `findings.db`.

### 6. Staleness

If consent = `on` and a source's `last_success_at` is older than **3 days**, Findings shows a banner
"Vulnerability data stale since <date> — last error: <…>". If consent = `off`, a persistent banner states
only bundled advisories are evaluated. Neither state is ever presented as "no vulnerabilities".

### 7. Ownership

Fetcher is the sole writer of `feed_*` tables. The advisory evaluator (900 s) remains the sole writer of
advisory findings — vulnerability, exposure and exploitation (ADR sole-writer rule).

## Error handling

- Fetch failure (DNS, TLS, timeout, 4xx/5xx, rate-limit): record in `feed_state`, retry next day with
  jitter; never touch stored CVEs.
- Oversized / malformed response: rejected whole, counted, logged at `warn`.
- Per-record failures skip that record only (2026-08-05 review F4 pattern).
- Device `/system/resource` or `/ip/service` failure: skip that device this cycle; existing findings kept.

## Testing — RED first (each test proven failing before implementation, per ADR)

Version matcher
1. `7.24.1 (stable)` parses; channel suffix ignored.
2. `7.25rc1 < 7.25`; `7.24.1 < 7.24.2`; `6.49.21 < 7.0`.
3. CVE-2026-86060 ranges: 7.24.1 affected, 7.24.2 not, 7.23.4 not, 7.23.3 affected, 6.49.20 affected.
4. Unparseable version → cannot-evaluate, no finding.

Feed
5. Real NVD JSON fixture (CVE-2026-86060) → stored ranges match source.
6. Malformed record skipped, rest of page stored; oversized body rejected, prior data intact.
7. Failed fetch leaves last-known-good untouched.
8. Hostile description (bidi, zero-width, 100 KB) staged/truncated.

Consent
9. Unanswered → fetcher makes **zero** outbound requests (assert on a mock transport).
10. Consent API: non-admin → 403; `off` requires explicit value; state persists across restart.
11. Frontend: modal renders when server says unanswered, cannot be dismissed by Escape/backdrop; Turn off
    shows warning before submitting.

Findings
12. KEV-listed affected CVE → Critical; non-KEV CVSS 8.8 → High.
13. Upgrade past fixed version → finding resolves; failed version read → unchanged.
14. Exposure: unrestricted api-ssl → High; scoped → Low; disabled → resolves; failed read → unchanged.
15. Acknowledged Low exposure widened to unrestricted → reopens High; unchanged → stays acknowledged.
16. Exposure, vulnerability and exploitation findings coexist for one device.

Verify: `cargo test --workspace`, `cargo deny check` (≥ 0.20), `tsc --noEmit`, vitest; live on the dev box:
confirm modal → within one fetch + one evaluator cycle, Findings shows the two KEV CVEs for any router
below 7.24.2 / 7.23.4 / 6.49.21, and the CVE-2026-16347 exposure finding for enabled `api-ssl`.

## Limitations (declared)

- **Version-only for fetched CVEs.** A router below 7.24.2 with the btest server disabled is still
  flagged for CVE-2026-67277. The finding text says so explicitly; resolving it needs the curation layer.
- **NVD range imprecision.** Some older entries express branches as overlapping upper bounds
  (e.g. CVE-2018-1156: `<6.40.9` OR `<6.42.7`), which flags a patched long-term router. Reported as-is.
- **Upstream lag.** NVD analysis can trail disclosure; a CVE in "Deferred"/"Awaiting Analysis" status
  may carry no ranges — e.g. CVE-2026-16347 has none, which is why bundled entries remain the floor.
- "Scoped" exposure is binary (`10.0.0.0/8` rates Low).
- Up to one fetch cycle (24 h) + one evaluator cycle (15 min) between publication and finding.

## Decisions

| Decision | Chosen | Rejected |
|---|---|---|
| Catalog source | Automatic NVD + KEV, client-fetched; bundled floor | CHS-curated signed feed (deferred — single maintainer); CHS-hosted mirror |
| Remote fetch default | On, confirmed via mandatory modal; off requires warning | Silent on; off by default |
| Fetch before confirmation | None (assumption, flagged) | Fetch from boot, disclose after |
| Version constraints | Evaluated by new matcher | Rev 1 "reject at load" (withdrawn) |
| Severity | KEV → Critical, else CVSS bands | CVSS only (ignores exploitation-in-the-wild) |
| Acknowledged exposure + worse config | Reopen on escalation | Sticky ack; reopen on any change |
| Third-party CVE text | Runtime display with attribution, never bundled | Paraphrase into catalog (curation work) |

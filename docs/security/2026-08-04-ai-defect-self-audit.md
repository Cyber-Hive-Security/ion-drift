# Ion Drift — Self-Audit Against the Seven Recurring AI-Codebase Defects

**Date:** 2026-08-04
**Commit audited:** `d6b569c` on `development` (unreleased; `main` is v0.5.2b)
**Auditor:** internal (Claude Code, directed by the maintainer). **Not a third-party review.**
**Method:** static enumeration of the router, full git-history secret scanning, and a live
instance booted on loopback from a throwaway data directory and probed over HTTP.

## What this audit is and is not

This is an audit **against one specific checklist** — the seven defects reported as recurring in
AI-assisted codebases. Passing it means those seven classes were checked and what was found is
written down. It does **not** mean Ion Drift is secure, and it is **not** a penetration test, a
code-level review of all 178 Rust files, or an external assessment. Findings below are ranked by
exploitability against Ion Drift's real posture: a self-hosted appliance holding **credentialed
administrative access to network devices**. That credential is the highest-value asset in the
product, so blast radius is measured against it rather than against a generic CVSS profile.

---

## Verdicts at a glance

| # | Defect | Verdict | Evidence |
|---|---|---|---|
| 1 | Secrets committed / exposed in frontend | **Absent** | 547 commits scanned, 0 leaks, two rule sets |
| 2 | UI-only authorization | **Absent** | 183/183 `/api` routes returned 401 unauthenticated, live |
| 3 | IDOR / cross-account reads | **Not applicable** (single-tenant) — with a caveat | No per-user data partition exists to cross |
| 4 | Absent error handling / no observability | **Absent** | 33 panic-capable calls in production code, supervised tasks |
| 5 | Untested backups | **Absent as documented — but the archive is a credential bundle** | Restore performed end-to-end; see F1 |
| 6 | Payments trusting the client | **Not applicable** | No payment path exists; license is offline Ed25519 |
| 7 | Silent rewrites in unreviewed areas | **PRESENT** | Core detection engines carry zero tests; see F2, F3 |

Five of seven are clean. The one genuinely present defect is #7, which is the one no scanner
can catch — and it is present in exactly the place the product's value lives.

---

## Findings, ranked by exploitability

### F1 — The backup archive is a complete, self-contained credential bundle (MEDIUM-HIGH)

**Status: confirmed by performing the restore.**

`docs/backup-restore.md` Option A instructs the operator to `tar czf` the whole data volume. That
archive contains, together in one file:

- `secrets.db` — encrypted router credentials, OIDC secret, session secret, license key
- `kek.local` — the encrypted local copy of the key-encryption key
- `kek.salt` and `machine.key` — the material that unwraps it

I restored that archive onto a wiped data directory and started the server. It came up in normal
mode, the pre-backup admin account authenticated, and the secrets manager initialised with the
**same KEK fingerprint** (`c860…e11b`) — no external dependency, no password prompt, no Keycloak.

That is correct disaster-recovery behaviour and the documented procedure works. The problem is the
security property it implies: **on a local-auth install, possession of the backup tarball is
equivalent to possession of the router's administrative credentials.** An operator following the
docs will typically drop that file on a NAS, a cloud sync folder, or a cron-driven backup share —
none of which are treated as secret stores. `docs/backup-restore.md` never says the archive must be
protected at the same level as the appliance itself.

The doc *does* correctly note that mTLS/Keycloak installs need Keycloak reachable to decrypt. That
carve-out makes the local-auth case look equally protected when it is not.

**Remediation (before wider distribution):**
- Add an explicit warning to `docs/backup-restore.md`: the archive is credential-equivalent; store
  it encrypted (`age`/`gpg`) and restrict access.
- Document an option to exclude `kek.local`/`kek.salt`/`machine.key` and re-derive from the admin
  password on restore, trading convenience for a non-credential-bearing backup.
- Consider surfacing this in the UI wherever backups are mentioned.

### F2 — The core detection engines have zero test coverage (MEDIUM — this is Defect 7)

**Status: confirmed by counting.**

93% of history (534 of 574 commits) carries a Claude co-author trailer. This is an AI-authored
codebase built across many sessions, which is the exact precondition for silent drift. Coverage over
the behaviour that *is the product*:

| Module | Lines | Tests |
|---|---:|---:|
| `ion-drift-storage/src/behavior.rs` | 3,529 | **0** |
| `ion-drift-web/src/correlation_engine.rs` | 1,997 | **0** |
| `ion-drift-web/src/behavior_engine.rs` | 1,199 | **0** |
| `ion-drift-web/src/log_parser.rs` | 628 | **0** |
| `ion-drift-web/src/anomaly_correlator.rs` | 468 | **0** |
| `ion-drift-web/src/alerting.rs` | 3,719 | 39 |
| `ion-drift-web/src/advisory/exploitation.rs` | 869 | 8 |

Alerting and the advisory engine are genuinely well covered. Behaviour baselining, correlation, and
log parsing — the analytics a customer buys — have **no automated proof of correctness at all**. A
regression there would be silent: no test fails, and the output is statistical, so a human is
unlikely to notice a subtly wrong baseline.

This is not a vulnerability. It is the defect that produces vulnerabilities later, and it is the one
the brief correctly predicted would be present.

**Remediation (can follow distribution, but should start now):** characterization tests over
`log_parser.rs` first — it parses untrusted router output, it is pure input→output, and it is the
cheapest to pin. Then `behavior_engine` baseline maths against fixed fixtures.

### F3 — The authorization guard test covers 34% of the routes it exists to protect (MEDIUM — Defect 7)

**Status: confirmed by re-implementing the test's own parser.**

`crates/ion-drift-web/tests/authz_test.rs::all_mutating_api_handlers_require_admin_extractor` exists
to guarantee every mutating API route requires admin. Its parser only matches routes registered on a
**single source line** starting with `.route("/`. Measured against the real router:

- Mutating routes it checks: **20**
- Mutating routes that actually exist: **59**

The 39 it never sees include the most sensitive endpoints in the product:

```
PUT    /settings/secrets
POST   /settings/secrets/session/regenerate
DELETE /settings/sessions/{session_id}
POST   /devices        PUT /devices/{id}       DELETE /devices/{id}
POST   /alerts/rules   PUT /alerts/rules/{id}  DELETE /alerts/rules/{id}
… plus 30 more (network identities, port bindings, topology, backbone links)
```

**All 39 are in fact correctly `RequireAdmin`-guarded today** — I verified this independently by
resolving every route to its handler signature. There is no live exposure. The defect is that the
regression test protecting them is blind to them, so a future session could drop a guard and CI
would stay green.

Two secondary weaknesses in the same test:
- It resolves handlers by first match in a **concatenated blob of all route sources**. Five handler
  names are defined in more than one file (`status`, `history`, `list`, `vlan_detail`, `summary`),
  so it may validate a different function than the one actually routed.
- The **403 branch of `RequireAdmin` is never exercised** by any test, and cannot be exercised
  through local auth, because every local account is an admin by design. Only an OIDC deployment can
  produce a non-admin identity, and no test covers that path.

**Remediation (before wider distribution — this is cheap):** replace source-text parsing with a
runtime test that boots the router and asserts status codes per route. The unauthenticated half of
that test is what I ran by hand below and it is straightforward to automate.

### F4 — The shipped example config hard-fails startup (MEDIUM, availability)

**Status: reproduced. I hit this by copying the documented config.**

`config/server.example.toml:33` ships `ca_cert_path = ""` under the comment *"Leave empty for Let's
Encrypt or other publicly trusted certificates."* Starting the server with that value produces:

```
Error: TLS configuration error: failed to read CA cert : No such file or directory (os error 2)
```

Cause: `config.rs:606` maps the field with `.as_ref().map(PathBuf::from)`, so `Some("")` becomes
`Some(PathBuf::from(""))` rather than `None`; `mikrotik-core/src/client.rs:141` then treats the empty
string as a path and reads it. There is no empty-string normalization anywhere in the crate.

Compounding it: `tests/config_docs_test.rs` **requires** `router.ca_cert_path` to be present and
uncommented in the example config, so the test suite actively enforces shipping the value that
breaks a fresh boot.

Impact is first-run experience, not exploitability — but it lands on exactly the users a
distribution push would bring in.

**Remediation (before wider distribution):** treat empty/whitespace as `None` at config load, and
either comment out the key in the example or set a real path.

### F5 — Encryption status misreports key provenance (LOW)

`crates/ion-drift-web/src/routes/settings.rs:368` hardcodes `source: "keycloak_mtls"`. My local-auth
instance — whose KEK is argon2id-derived from the admin password — reported
`{"key_fingerprint":"c860…","source":"keycloak_mtls","all_secrets_current":false}`.

SECURITY.md documents three distinct KEK modes. The status endpoint that exists to tell an operator
which one is in force always answers with the same one. Not exploitable; it misinforms an operator
reasoning about key custody, which for a security product is a trust defect.

**Remediation:** derive `source` from the actual bootstrap path, or remove the field.

### F6 — Fixed-index unwraps on batched router responses (LOW, informational)

`correlation_engine.rs:135-139` and `alerting.rs:1102-1104` submit N requests to the router queue and
then `batch_iter.next().unwrap()` exactly N times. This is safe only while `submit()` guarantees
one result per request. If that contract ever changes, the task panics rather than degrading.

Contained by design: `task_supervisor.rs` restarts panicking tasks with exponential backoff (5s→60s,
reset after 5 min healthy), so the blast radius is a restarted detection loop, not a downed server.
Worth converting to a destructuring pattern or an explicit length check when next touched.

---

## What was verified clean (with evidence)

**Defect 1 — secrets.** `gitleaks` 8.30.1 over the full history (547 commits, 60 MB) with the repo's
`.gitleaks.toml` **and** again with default rules, ignoring the repo allowlist: **no leaks found**
in both runs. Targeted history greps for `password=`, `session_secret=`, `api_key=`, and
`PRIVATE KEY` in `*.toml`/`*.rs`/`*.ts`/`*.yaml` across all refs returned **0 hits**. The only
secret-shaped literals in `web/src` are two fixtures in a module test. `.env.example` contains only
commented placeholders. **No live credential was found, so there is no rotation item.**

**Defect 2 — server-side authorization.** Enforced in depth: a global `require_auth_layer` on the
entire `/api` scope, per-handler `RequireAuth`/`RequireAdmin` extractors (107 and 76 routes
respectively), and a `route_layer(admin_mw)` on the module subrouters. Runtime proof — every `/api`
route enumerated from the router source and probed **unauthenticated** against a live instance:

```
routes probed: 190
status distribution: {"401": 183, "404": 5, "405": 2}
routes returning data without authentication: NONE
```

The 7 non-401 responses are the deliberately public root-mounted routes (`/health`, `/auth/*`) that
my prefixing mislabelled as `/api` — they are unauthenticated by design and expose no data
(`/health` returns `{"status":"ok"}` only; the version string is behind auth at `/api/system/about`).

**Setup mode** was probed separately, since it handles credentials before any account exists. In
setup mode the API is not mounted at all (307 to `/setup`). Attempting to claim the instance with
**no token** and with a **wrong token** were both rejected, and no account was created; the token is
compared with `subtle::ConstantTimeEq`.

**Sessions.** SECURITY.md claims a stolen `sessions.db` cannot be replayed. Verified rather than
trusted: `GET /api/settings/sessions` exposes a 64-hex `session_id`; the browser cookie is a
129-char token; `sha256(cookie) == exposed value`, and replaying the exposed value as a cookie
returns **401**. The claim holds.

**Module HMAC path.** `modules_registry/hmac.rs` signs `HMAC-SHA256(secret, "<ts>.<body>")`,
verifies with `mac.verify_slice` (constant-time, length-checked), enforces a ±300s skew window, and
collapses all failure modes into opaque errors that are never echoed to the caller. The inbound
publish endpoint is mounted at the top level specifically so it cannot inherit session-cookie auth.

**Admin secret endpoints.** `GET /api/settings/secrets` returns only metadata — name, `updated_at`,
`stored`, `key_current` — and **no plaintext secret values**. Scanning admin read endpoints for
plaintext credentials or high-entropy strings found nothing outside the (non-replayable) session
hash. `POST /settings/secrets/session/regenerate` behaved correctly: it invalidated my live session.

**Defect 3 — IDOR.** Ion Drift is **single-tenant by architecture**: it monitors one network, and all
data is instance-global. There is no per-user or per-tenant partition, so there is no cross-account
read to attempt — the horizontal boundary IDOR describes does not exist. SECURITY.md already
documents the consequence ("every local account is an admin; no per-operator accountability").
The only privilege boundary is vertical (admin vs non-admin), which exists solely under OIDC.
**Honest limitation:** I could not exercise the non-admin→403 path live, because local auth cannot
produce a non-admin identity and no OIDC provider was available. That boundary is verified
structurally only — see F3.

**Defect 4 — error handling and observability.** Production code (with `#[cfg(test)]` modules
excluded) contains **13 `.unwrap()`, 20 `.expect()`, and zero `panic!`/`todo!`/`unimplemented!`**
across 178 Rust files — unusually disciplined. Failures are contained and visible:
`TaskSupervisor` restarts panicking background tasks with exponential backoff; `ion-drift-module-host`
wraps module calls in a `catch_unwind` panic guard that logs and isolates; 289 `tracing::warn!`/
`error!` sites carry structured context. The advisory catalog loader is the model: malformed input is
logged into a `CatalogLoadReport` and skipped, loads are upsert-only so a bad load degrades to
last-known-good, and no input path may panic.

**Defect 6 — payments.** No payment integration exists anywhere in the codebase — no Stripe, Paddle,
LemonSqueezy, checkout, or billing path (the single `stripe` match is a comment noting the HMAC
scheme is Stripe-style). Licensing is **offline Ed25519** `verify_strict` against a compiled-in
public key, with no license server. The entitlement tier is read from the **signed payload**, never
from client input, and key submission is `RequireAdmin`. The client-trust failure mode does not
exist here.

---

## Remediation punch list

**Before wider distribution (item 2e):**

1. **F4** — normalize empty `ca_cert_path` to `None`; fix the example config. *Small; blocks fresh
   installs that follow the docs.*
2. **F1** — add the credential-equivalence warning to `docs/backup-restore.md`. *Documentation only;
   highest real-world blast radius.*
3. **F3** — replace the static authz test with a runtime status-code test. *Half of it is already
   demonstrated above.*

**Can follow:**

4. **F2** — characterization tests for `log_parser.rs`, then the behaviour engine. *Largest effort,
   highest long-term value.*
5. **F5** — derive or drop the hardcoded `source` field.
6. **F6** — replace fixed-index batch unwraps when next touching those files.

**No action:** Defects 1 and 6 are clean; Defect 3 is not applicable to a single-tenant appliance.

## Coverage limitations of this audit

State these alongside any public claim:

- Non-admin (403) authorization was **not** exercised at runtime — no OIDC provider was available.
- The live instance ran with **no real router attached** (`router.host` pointed at loopback), so
  device-interaction paths — SNMP, RouterOS REST, provisioning — were not exercised end-to-end.
- The frontend was not reviewed for DOM-XSS; only server responses and secret-shaped literals were.
- Dependency vulnerabilities were covered only to the extent `cargo deny check` covers them
  (it passes: advisories, bans, licenses, sources all ok).
- No fuzzing, no timing analysis beyond confirming constant-time primitives are used, and no review
  of the 178-file Rust surface outside the paths named above.

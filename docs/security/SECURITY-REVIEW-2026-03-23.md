# Ion Drift Security Review — 2026-03-23

Reviewed 22 commits (excluding 3 DNS policy deviation commits).

---

## CRITICAL — Must fix before release

**(none found)**

---

## HIGH — Should fix before release

### H-1: KEK salt derived from filesystem path is fragile and non-random
- **File:** `/home/yodaadmin/ion-drift/crates/ion-drift-web/src/bootstrap.rs` lines 486-491
- **Commit:** 56846c9
- **Issue:** `derive_kek_from_password()` creates the argon2id salt by SHA-256 hashing `b"ion-drift-kek-salt:" + db_path`. The db_path is a predictable local path (e.g., `/app/data/secrets.db`). This means every Docker deployment using the default data directory has **the same salt**. The argon2id parameters (64 MiB, 3 iterations, parallelism 4) are reasonable, but identical salt + identical OIDC client secret across installations yields identical KEK.
- **Recommendation:** Incorporate a random 16-byte salt generated on first run and persisted alongside the cached KEK, rather than deriving salt solely from the db path. Alternatively, include additional installation-specific entropy (e.g., a UUID generated at first boot).

### H-2: SNMP v2c community string not wrapped in SecretString
- **File:** `/home/yodaadmin/ion-drift/crates/mikrotik-core/src/snmp_client.rs` line 143
- **Commit:** 0242679
- **Issue:** The SNMP v3 auth/priv passwords were correctly wrapped in `SecretString`, but `community: Option<String>` remains a plain `String`. The `Debug` impl already redacts it via `map(|_| "[REDACTED]")`, but the field is still `Serialize`-capable and could leak in API responses or logs via `{:?}` on parent structs. The v3 passwords got the `SecretString` treatment; community should too for consistency.
- **Recommendation:** Wrap `community` in `SecretString` to match the v3 credential handling.

---

## MEDIUM — Fix soon

### M-1: Empty router password accepted silently on subsequent runs
- **File:** `/home/yodaadmin/ion-drift/crates/ion-drift-web/src/config.rs` lines 370-374
- **Commit:** afba7e9
- **Issue:** `DRIFT_ROUTER_PASSWORD` uses `unwrap_or_default()` (empty string) in all auth modes. On subsequent runs, if the encrypted secrets DB fails to load or is corrupted, the app will silently proceed with an empty router password. The startup code in `main.rs` does attempt to load from the secrets DB, but the `if let Ok(Some(p))` pattern means a missing/failed decryption silently leaves the password empty.
- **Risk:** The router API connection will simply fail (no bypass risk), but this could cause confusing "authentication failed" errors with no indication that the env var was missing and the DB load failed.
- **Recommendation:** Add a warning log when the config ends up with an empty router password after all loading stages complete.

### M-2: Diagnostic report exposes data directory path
- **File:** `/home/yodaadmin/ion-drift/crates/ion-drift-web/src/routes/stats.rs` ~line 279+
- **Commit:** fd4969d / 18087e5
- **Issue:** `DiagnosticReport.environment.data_directory` includes the absolute filesystem path. While the endpoint is protected by `RequireAdmin`, this leaks internal path structure to any admin user. For a single-admin product this is low-risk, but if admin access is ever shared or the report is copy-pasted into a support ticket, it reveals deployment details.
- **Recommendation:** Consider omitting or hashing the data directory path, or replacing it with a relative/symbolic name.

### M-3: `get_profiles_bulk` builds dynamic SQL IN clause
- **File:** `/home/yodaadmin/ion-drift/crates/ion-drift-web/src/routes/` (behavior store)
- **Commit:** 7d39e38 (investigation enrichment uses `get_identity_by_mac` which is safe, but bulk queries exist)
- **Issue:** `get_profiles_bulk()` builds a dynamic `IN (?, ?, ...)` clause from the MAC array length. The placeholders are parameterized (not string-interpolated), so there is **no SQL injection** risk. However, the lack of an upper bound on the MAC array size could lead to excessively large queries.
- **Recommendation:** Add a `LIMIT` or cap on the number of MACs accepted in bulk queries, consistent with the 10,000-row limits added elsewhere.

---

## LOW / INFORMATIONAL — Noted, no action needed

### L-1: `as any` type assertions reverted in D3/Sankey (65a4383)
- **Issue:** TypeScript `as any` casts were reverted for build compatibility. These are frontend-only and pose no runtime security risk — D3 types are purely for developer ergonomics.

### L-2: Page view context sanitization uses unsalted SHA-256 for MAC hashing
- **File:** `/home/yodaadmin/ion-drift/crates/ion-drift-web/src/routes/stats.rs`
- **Issue:** MAC addresses in page view context are replaced with truncated SHA-256 hashes. Since MACs are a small keyspace (~280 trillion), an attacker with DB access could rainbow-table them. However, this is analytics data behind auth, not a public-facing API, and the threat model is low.

### L-3: Docker compose templates include resource limits (good practice)
- **Commit:** 0242679
- **Note:** `deploy.resources.limits` of 2 CPU / 2GB RAM added. This is a positive security control preventing resource exhaustion.

### L-4: Nmap dead code removal (20ffc26) reduces attack surface
- **Note:** Removing unused nmap scanning code eliminates a potential command injection vector that was never exposed but existed in the codebase.

---

## PASSED — Areas reviewed with no issues found

### Authentication & Authorization
- **Startup with unreachable router (cd62d78):** The web UI starts, but all API routes remain behind the global auth middleware layer (`RequireAuth` / `RequireAdmin`). No auth bypass is created — the router being offline only means data collection stops. Users must still authenticate to access any API endpoint. **PASS.**
- **OIDC KEK derivation flow (56846c9 + afba7e9):** On first run, `DRIFT_OIDC_SECRET` is required and bails if empty. On subsequent runs, the KEK is loaded from the local cache (encrypted). The OIDC client secret is only needed if no cached KEK exists. The `bail!` on empty secret is correctly placed in the `None` (first-run) branch. **PASS** (salt concern noted in H-1).
- **Stats endpoints auth:** `record_page_view` and `get_page_views` use `RequireAuth`; `diagnostic_report` uses `RequireAdmin`. All correctly gated. **PASS.**
- **Investigation enrichment (7d39e38):** The `/api/sankey/device/{mac}` endpoint was already auth-protected. New enrichment queries use parameterized SQL. **PASS.**

### Input Validation
- **Page view recording:** Validates page name against a whitelist (`KNOWN_PAGES`), limits context to 100 chars, sanitizes MAC addresses. Uses parameterized SQLite queries via `rusqlite`. **PASS.**
- **SNMP cycle rejection (f097cc0):** Rejects entire SNMP polling cycle on partial `ifName` walk failure — fail-closed behavior. **PASS.**
- **Query safety bounds (0242679):** `LIMIT 10000` added to `get_neighbors()` and `get_backbone_links()`. Prevents OOM on large networks. **PASS.**

### Secrets Handling
- **SNMP v3 credentials (0242679):** `v3_auth_password` and `v3_priv_password` wrapped in `SecretString`. `Debug` impl redacts all credentials. `expose_secret()` only called at point of use in the SNMP session. **PASS** (community string noted in H-2).
- **Session secret generation:** When `DRIFT_SESSION_SECRET` is not set, a random UUID is generated as fallback. This is acceptable for single-instance deployments. **PASS.**

### Error Handling
- **Task supervisor panic catch (9f7953b):** Uses `std::panic::catch_unwind` with `AssertUnwindSafe` around factory calls. Caught panics are logged and trigger backoff restart. Does not leak stack traces to API responses. **PASS.**
- **Serialization panic prevention (0242679):** Replaced `.unwrap()` with `.unwrap_or_default()` on `serde_json::to_value()` in 8 route handlers. **PASS.**
- **Inference route error logging (0242679):** Added `tracing::warn!` to 9 previously silent error paths. Error messages include the rusqlite error text but not stack traces. Acceptable for internal diagnostics. **PASS.**

### CSRF / CORS
- All new endpoints are nested under `/api` which has the global auth middleware layer. The `POST /api/stats/page-view` endpoint requires `RequireAuth` (session cookie). CORS and security headers (X-Frame-Options: DENY, X-Content-Type-Options: nosniff, CSP) are applied globally. **PASS.**

### Compression & Caching (910d9e5)
- HTTP compression (gzip + brotli) applied via `tower_http::CompressionLayer`. Static assets under `/assets/` get `cache-control: public, max-age=31536000, immutable` (appropriate for hashed filenames from Vite builds). No compression oracle risk since this is not a TLS-layer compression and the API doesn't reflect user secrets in responses. **PASS.**

### License changes (65615b7, ca830f6)
- Rename from `device_limit` to `router_limit` with `#[serde(alias = "device_limit")]` for backwards compatibility. Display-only change in the UI. No enforcement bypass. **PASS.**

### Documentation commits (a06ae5b, 6ab907a, 181587c, 1bd839a)
- Pure documentation changes (markdown files). No code impact. **PASS.**

---

## Summary

| Severity | Count | Action |
|----------|-------|--------|
| Critical | 0 | — |
| High | 2 | Fix before release |
| Medium | 3 | Fix soon |
| Low/Info | 4 | No action needed |
| Passed | 10 categories | Clean |

The two high-severity items (H-1: predictable KEK salt, H-2: community string not in SecretString) are the only items that warrant attention before pushing to main. Neither is exploitable remotely — H-1 requires knowing the OIDC client secret, and H-2 requires a code path that serializes the SnmpClient struct to an API response — but both weaken the defense-in-depth posture.

---

## Resolution — 2026-04-21

All findings closed.

| Finding | Status | Resolution |
|---------|--------|------------|
| H-1 KEK salt | **Fixed** | `bootstrap.rs::derive_kek_from_password` now generates a random 16-byte salt on first run and persists it at `data_dir/kek.salt` (0600 perms). |
| H-2 SNMP community | **Fixed** | `snmp_client.rs` — `community` field is now `Option<SecretString>`, matching v3 credential handling. |
| M-1 Empty router password | **Fixed** | `main.rs` emits `tracing::warn!` when the router password is missing/empty after all load stages. |
| M-2 Data directory path exposure | **Fixed (2026-04-21)** | `stats.rs::diagnostic_report` — `data_directory` field now contains `sha256:<8-byte hex>` of the path, not the path itself. |
| M-3 `get_profiles_bulk` unbounded | **Fixed (2026-04-21)** | `behavior.rs::get_profiles_bulk` enforces a 10,000-MAC cap and returns an error if exceeded. |

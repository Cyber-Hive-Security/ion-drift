# Ion Drift Authentication Architecture

This document covers the authentication and secrets architecture for contributors and advanced users.

## Authentication Modes

Ion Drift supports three authentication configurations:

1. **Local auth (default)** — Username and password authentication with argon2id password hashing. The setup wizard creates the initial admin account on first visit. No external dependencies required.

2. **OIDC** — Any OpenID Connect-compatible provider (Keycloak, Authentik, Authelia, etc.). Uses authorization code flow with PKCE. Provider discovery via `.well-known/openid-configuration`.

3. **Both simultaneously** — When an `[oidc]` section is present in the config, the login page shows both a username/password form and a "Sign in with SSO" button. Users can authenticate via either method. The `/auth/config` endpoint tells the frontend which modes are available.

---

## Session Lifecycle

### Session ID Generation

1. **Token creation:** 32 cryptographically random bytes generated via `rand::random()`, hex-encoded to a 64-character string.
2. **Signing:** The token is signed using HMAC-SHA256 with the session secret as the key. The final session ID is `{token}.{signature}` (hex-encoded).
3. **Validation:** On each request, the session ID is split at the `.`, the HMAC is recomputed over the token portion, and compared in constant-time against the provided signature.

### Storage

- **In-memory:** `DashMap<String, SessionEntry>` for fast concurrent access.
- **Persistent:** SQLite database (WAL mode) for survival across restarts. Active sessions are loaded from SQLite on startup.
- **Session data stored:** session ID, user ID, username, email, roles (JSON), creation timestamp, last-accessed timestamp, client IP, user agent.

### Expiry and Cleanup

- **Max age:** Configurable via `session.max_age_seconds` (default: 86400 = 24 hours). Sessions older than this are expired.
- **Cleanup task:** A background tokio task runs every 5 minutes (`300s` interval), removing expired sessions from both the DashMap and SQLite, and flushing dirty (modified) session entries to disk.
- **Pending auth cleanup:** OIDC pending auth entries older than 5 minutes (300 seconds) are also purged during cleanup.

### Rotation

- The admin can regenerate the session secret via the admin API (`rotate_signing_secret`).
- Rotating the secret calls `clear_all()`, which purges all sessions from both memory and SQLite and clears all pending OIDC auth entries. All users must re-authenticate.

---

## KEK Management

The Key Encryption Key (KEK) is used by the `SecretsManager` to encrypt sensitive values (router password, OIDC client secret, session secret, CertWarden API keys) at rest in SQLite using AES-256-GCM.

Three modes are available:

### 1. Local KDF (default)

Used when no `[oidc.bootstrap]` section is configured (the typical case for local auth or generic OIDC setups).

- **Derivation:** The KEK is derived from the admin password using argon2id KDF during the setup wizard.
- **Caching:** The derived KEK is encrypted with a `machine.key` (a random 32-byte AES-256-GCM key stored on disk at `data/machine.key`) and written to `data/kek.local`.
- **Startup:** On subsequent starts, `load_local_kek()` reads `machine.key`, decrypts `kek.local`, and recovers the KEK without needing the admin password.
- **Security trade-off:** The machine key provides convenience (no password on restart) at the cost of at-rest security — an attacker with filesystem access to both files can recover the KEK. This is acceptable for single-server homelab deployments.

### 2. Keycloak mTLS Bootstrap

Used when `[oidc.bootstrap]` is configured. Keycloak-specific.

- **Retrieval:** Ion Drift authenticates to Keycloak via mutual TLS (client certificate), obtains an access token, and reads/writes the KEK as a user attribute on the service account.
- **Generation:** If no KEK exists in Keycloak, a random 32-byte key is generated, stored in the configured Keycloak attribute (default: `ion_drift_kek`), and returned.
- **Retry:** Exponential backoff on Keycloak connection failures: 5s, 10s, 30s, 60s, 120s, 300s.
- **Local cache:** After successful retrieval, the KEK is cached locally (encrypted with a key derived from the client certificate) for resilience against Keycloak outages.
- **Fallback:** If all Keycloak retries fail, the local cache is loaded as a fallback.

### 3. OIDC without mTLS Bootstrap

Used when `[oidc]` is configured but `[oidc.bootstrap]` is not — i.e., OIDC with a non-Keycloak provider or without mTLS infrastructure.

- **Derivation:** The KEK is derived from the OIDC client secret using argon2id KDF on first startup.
- **Caching:** The derived KEK is cached locally using `machine.key` + `kek.local` (same mechanism as Local KDF).
- **Startup:** On subsequent starts, the KEK is loaded from the local cache. The client secret is not re-read.
- **Migration:** On first startup, router credentials and session secret are migrated from environment variables / config into the encrypted secrets DB. After migration, env vars are no longer read.
- **Recovery:** If the data volume is lost, the KEK can be re-derived from the original OIDC client secret. If the client secret has been rotated since initial setup, a fresh setup with re-entered credentials is required.
- This mode supports any OIDC provider (Authentik, Authelia, etc.) without requiring Keycloak-specific mTLS setup.

---

## Security Model Comparison

The three KEK modes provide different levels of protection depending on the threat scenario. The critical distinction is whether an attacker who gains access to the host filesystem can recover your encrypted secrets.

| Threat Scenario | Local Auth | OIDC without mTLS | OIDC with mTLS Bootstrap |
|----------------|------------|-------------------|--------------------------|
| **Network observer** (sees traffic) | Protected (TLS) | Protected (TLS) | Protected (TLS) |
| **Web UI brute force** | Protected (argon2id + rate limiting) | N/A (OIDC) | N/A (OIDC) |
| **Docker container escape** | **Secrets recoverable** | **Secrets recoverable** | Protected (KEK in Keycloak) |
| **Host filesystem read access** | **Secrets recoverable** | **Secrets recoverable** | Protected (KEK in Keycloak) |
| **Backup/snapshot leak** | **Secrets recoverable** | **Secrets recoverable** | Protected (KEK in Keycloak) |
| **Stolen/decommissioned disk** | **Secrets recoverable** | **Secrets recoverable** | Protected (KEK in Keycloak) |
| **Data volume loss** | Re-run setup wizard | Re-enter env vars | Auto-recovers from Keycloak |

### Why Local Auth and OIDC without mTLS are vulnerable to host compromise

Both modes store everything needed to decrypt secrets on the local filesystem:

1. `machine.key` — a random AES-256-GCM key stored in the data directory
2. `kek.local` — the KEK encrypted with `machine.key`

An attacker with read access to both files can decrypt `kek.local` to obtain the KEK, then decrypt all values in `secrets.db` (router password, OIDC client secret, session secret). No password, token, or external service is required.

This is a deliberate trade-off for convenience — Ion Drift restarts without human intervention (no passphrase prompt). For single-server homelab deployments where the host is physically secured, this is an acceptable risk. For environments where host compromise is a realistic threat, use mTLS bootstrap.

### Why mTLS Bootstrap is different

In mTLS bootstrap mode, the KEK is stored as a user attribute in Keycloak and retrieved via mutual TLS authentication. An attacker with filesystem access gets the local cache (encrypted with a key derived from the client certificate private key), but:

- The client certificate is issued by your CA and can be revoked
- Keycloak access requires valid mTLS credentials
- The KEK can be rotated in Keycloak independently of the host

A local cache exists for resilience against Keycloak outages, but it's encrypted with the client certificate key — compromising it requires both the cache file and the private key file.

### Recommendation

| Deployment | Recommended Mode |
|-----------|-----------------|
| Homelab, single server, physically secured | Local auth — simplest setup, acceptable risk |
| Homelab with existing OIDC provider | OIDC without mTLS — SSO convenience, same host-compromise risk as local auth |
| Production, multi-user, compliance requirements | OIDC with mTLS bootstrap — KEK not recoverable from host alone |

---

## Rate Limiting

### Local Login (`/auth/local-login`)

Per-username exponential backoff protects against brute-force attacks:

| Failed attempts | Cooldown |
|----------------|----------|
| 1 | 0s (no delay) |
| 2 | 1s |
| 3 | 2s |
| 4 | 4s |
| 5 | 8s |
| 6 | 16s |
| 7+ | 30s (cap) |

- **Tracking:** `DashMap<String, (attempt_count, last_attempt_timestamp)>` keyed by username.
- **TTL:** Stale entries (no activity for 5 minutes) are cleaned up by the session cleanup background task.
- **Success:** On successful login, the attempt counter for that username is cleared (`record_success`).
- **Error response:** Returns HTTP 429 Too Many Requests with the number of seconds until retry is allowed.

### OIDC Auth State

- **Guard:** `MAX_PENDING = 1000` — the `insert_pending()` method rejects new OIDC login flows if there are already 1000 pending auth entries in the DashMap. This prevents memory exhaustion from login endpoint flooding.
- **Expiry:** Pending auth entries older than 300 seconds (5 minutes) are rejected when consumed and cleaned up by the background task.

---

## Role Mapping

### OIDC Role Extraction

Roles are extracted from the JWT ID token payload (after signature verification by the OIDC library):

1. **Configured claim:** The `roles_claim` config value (dot-notation, e.g., `"realm_access.roles"`) is traversed through the JSON payload. Each dot-separated segment navigates into nested objects.
2. **Fallback chain:** If the configured claim path yields no results:
   - Try `"roles"` at the JSON root (if not already the configured claim)
   - Try `"groups"` at the JSON root (if not already the configured claim)
3. **Value extraction:** The target field must be a JSON array of strings. Each string becomes a role.

### Admin Determination

- The `admin_role` config value (default: `"ion-drift-admin"`) is compared against the extracted roles.
- If any role matches, the user is granted admin access.

### Local Auth Role Mapping

- Local users have a `role` field in the `local_users` SQLite table (set during account creation).
- The `"admin"` role is mapped to `"ion-drift-admin"` internally so that the same authorization checks apply regardless of auth method.

---

## OIDC-Only Mode

When no local users exist (typical for mTLS bootstrap deployments), Ion Drift operates in OIDC-only mode:

- The login page shows a "Sign in with SSO" button instead of a username/password form
- 401 responses redirect to the login page (not directly to the OIDC provider) to avoid redirect loops
- Logout redirects to the OIDC provider's end-session endpoint to kill both the Ion Drift session and the IdP SSO session
- The `/auth/config` endpoint reports `local_auth_enabled: false` and `oidc_enabled: true`

---

## Provider Compatibility Matrix

| Feature | Local | Keycloak | Authentik | Authelia |
|---------|-------|----------|-----------|---------|
| Login | password | OIDC | OIDC | OIDC |
| Roles source | DB `role` field | `realm_access.roles` | `groups` | `groups` |
| `roles_claim` | N/A | `realm_access.roles` (default) | `groups` | `groups` |
| `admin_role` | `admin` (mapped internally) | `ion-drift-admin` (default) | configurable group name | configurable group name |
| KEK mode | Local KDF | Local KDF or mTLS bootstrap | Local KDF (machine key) | Local KDF (machine key) |
| mTLS bootstrap | N/A | opt-in via `[oidc.bootstrap]` | N/A | N/A |
| Setup complexity | Low | Medium | Medium | Medium |
| External dependencies | None | Keycloak instance | Authentik instance | Authelia instance |

---

## Security Notes

- **Password hashing:** Local auth uses argon2id with default parameters (Argon2 crate defaults) and a random salt per password.
- **CSRF protection:** SameSite cookie attribute (default `lax`) plus Content-Type enforcement on mutation endpoints.
- **Session cookies:** `Secure` flag (default `true`), `HttpOnly`, configurable `SameSite`.
- **User enumeration prevention:** Failed local login returns the same error message ("invalid username or password") for both unknown usernames and wrong passwords.
- **OIDC PKCE:** Authorization code flow uses PKCE (Proof Key for Code Exchange) for all providers.
- **Constant-time comparison:** Session ID HMAC signatures are verified using constant-time comparison to prevent timing attacks.

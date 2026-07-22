# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| Latest on `main` | Yes |
| Older releases | No |

Only the latest release on the `main` branch receives security updates.

## Reporting a Vulnerability

**Do NOT open public issues for security vulnerabilities.**

To report a vulnerability, use one of the following channels:

- **GitHub Security Advisory:** Go to the repository's Security tab and select "Report a vulnerability"
- **Email:** [scott@mycyberhive.com](mailto:scott@mycyberhive.com)

### What to expect

- **Acknowledgment:** Within 72 hours of your report
- **Resolution:** Within 30 days for a fix or coordinated public disclosure
- **Credit:** We will credit reporters in the advisory unless you prefer to remain anonymous

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). Please do not disclose the vulnerability publicly until we have published a fix or agreed on a disclosure timeline.

## Security Model

- **Self-hosted only** -- no telemetry, no phone-home, no external data collection
- **Secrets encrypted at rest** using AES-256-GCM with a key encryption key (KEK); the KEK comes from an mTLS-bootstrapped Keycloak, a password-derived key (argon2id), or a local machine key depending on deployment mode
- **Authentication:** local accounts (argon2id password hashing, constant-time verification) or OIDC (any OpenID Connect provider); login is rate-limited per-username and per-IP
- **Sessions:** opaque, server-side, 256-bit CSPRNG identifiers, HMAC-SHA256 signed; HttpOnly + Secure (config) + SameSite cookies; absolute and optional idle timeouts; a fresh identifier is issued on every authentication (no fixation)
- **OIDC:** PKCE + nonce + id-token signature/issuer/audience/expiry validation; the in-progress flow is bound to the initiating browser (login-CSRF defense)
- **Outbound requests** whose destination is module/config-influenced pass a shared SSRF guard (blocks link-local/metadata/unspecified/broadcast incl. IPv6-embedded-IPv4 forms; no redirect following; re-validated before each connection)
- **License validation:** offline Ed25519 (`verify_strict`) signature verification (no license server)
- **Transport security headers:** HSTS, CSP (`script-src 'self'`, `frame-ancestors 'none'`), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy

## Scope

### In scope

- Authentication or authorization bypass
- Privilege escalation
- Injection (SQL, command, template, etc.)
- Server-side request forgery (SSRF)
- Secret or credential exposure
- Session hijacking or fixation
- Cross-site scripting (XSS) or cross-site request forgery (CSRF)

### Out of scope

- Social engineering or phishing attacks
- Physical access to the host
- Denial of service against single-user homelab instances
- Vulnerabilities in upstream dependencies with no demonstrated exploit path
- Issues requiring pre-existing root/admin access on the host

## Security-Related Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `session.secure` | `true` | Requires HTTPS for session cookies. A startup warning is emitted if disabled. |
| `session.same_site` | `"lax"` | SameSite cookie attribute for CSRF protection. `"none"` warns at startup. |
| `session.idle_timeout_seconds` | `0` (off) | Idle/inactivity session timeout (capped at `max_age_seconds`). Example configs set `43200` (12h). |
| `server.trust_proxy_headers` | `true` | Whether to trust `X-Forwarded-For`/`X-Real-IP` for client IP. **Set `false` if directly exposed** (no reverse proxy) so forwarding headers can't rotate the per-IP rate-limit bucket; the limiter then keys on the real socket peer address. |
| `router.tls` | `true` | Use HTTPS for the RouterOS REST API. A startup warning is emitted if disabled (plaintext credentials). |
| Rate limiting | Enabled | Login endpoints are rate-limited per-username and per-IP with automatic cleanup. |
| CSRF protection | Enabled | **Every** mutating API request (incl. no-body) must use `Content-Type: application/json`; combined with locked single-origin CORS and SameSite cookies. |
| Security headers | Enabled | HSTS, CSP (`script-src 'self'`, `frame-ancestors 'none'`), X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy. |
| Body size limit | 2 MiB (1 MiB module inbound) | Maximum request body size. Device and module *responses* are stream-capped (8/10 MiB) and rejected early on an oversized `Content-Length`. |
| Module proxy | API-only | Reverse-proxied module routes are restricted to the manifest's `exposed_routes` (method + path), and responses are forced inert (`application/json`, `nosniff`, `attachment`) so a module cannot serve active content on Ion Drift's origin. |
| Session tokens | Hashed at rest | The `sessions` store keys on `SHA-256(token)`; the bearer token exists only in the client cookie, so a stolen `sessions.db` can't be replayed. |

## Deployment Guidance

- **Terminate TLS** in front of Ion Drift (reverse proxy or `session.secure=true`) so HSTS and Secure cookies apply. Run the first-time **setup wizard over TLS or bound to loopback** — it handles credentials.
- The **syslog listener (UDP 5514) is unauthenticated** (source-IP filter only, which is spoofable on plaintext UDP). **Bind it to a trusted management segment** and do not expose it to untrusted networks. A LAN-adjacent attacker able to spoof the router's source IP can both **suppress genuine firewall events** (the rate cap is global, so forged packets crowd out real ones) and **inject false connection records** that consume retention storage. Enforce anti-spoofing (uRPF / port ACLs) on the segment. **If your router does not forward syslog, disable external ingest by setting `syslog.bind_address = "127.0.0.1"`.** Ingest is rate-capped as a DoS backstop, and syslog-sourced data is treated as lower-trust than polled data.
- **Module registration is admin-only.** Registering a module trusts that module's endpoint; register only modules you control or trust.
- If Ion Drift is **directly exposed** (no reverse proxy overwriting forwarding headers), set `server.trust_proxy_headers = false`.

## Known Limitations / Roadmap

These are known, deliberately-scoped gaps tracked for future releases; they are not considered release-blocking for a single-operator, network-isolated homelab deployment:

- **No multi-user / role separation for local auth.** Every local account is an admin; there is no per-operator accountability. Use OIDC for multiple identities and role mapping (the `ion-drift-admin` realm role gates admin routes).
- **No in-app password change / rotation for local accounts.** Because the local KEK is derived from the admin password, rotation currently requires re-running setup. A dedicated rotation flow is planned.
- **No multi-factor authentication for local accounts.** Deploy behind an OIDC provider that enforces MFA for a second factor today.
- **No per-user concurrent-session cap.** Admins can enumerate and revoke sessions from Settings; an automatic cap is planned.
- **SSRF guard re-validates the destination before each connection but does not yet pin the resolved IP at the socket layer.** No-redirect + pre-connect re-validation substantially shrink the DNS-rebinding window.
- **Module secret "fingerprint"** shown to admins is a truncated hash of the shared secret (so a module and Drift can be compared for drift without a shared key). This is a deliberate, low-risk trade-off; use high-entropy secrets (the provisioning tooling generates 288-bit secrets).
- **Legacy device protocols** (SwOS HTTP-Digest/MD5, SNMPv3 DES/MD5) are vendor-dictated and used only for device management, not for protecting Ion Drift's own data. Keep device management on an isolated VLAN.
- **Syslog ingest is a global-rate-capped, spoofable UDP listener.** The 500 events/s cap is a coarse DoS backstop, not per-source, and there is no storage-side backpressure on syslog-derived rows beyond time-based retention. An authenticated transport (syslog-over-TLS/RELP), an explicit opt-in enable flag, and per-source quotas with storage backpressure are on the roadmap; until then, rely on network isolation and anti-spoofing (see Deployment Guidance), or bind the listener to loopback if unused.

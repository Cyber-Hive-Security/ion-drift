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
- **Secrets encrypted at rest** using AES-256-GCM with a key encryption key (KEK)
- **Authentication:** local accounts (argon2id password hashing) or OIDC (any OpenID Connect provider)
- **Sessions:** HMAC-SHA256 signed, HttpOnly/Secure/SameSite=Lax cookies
- **License validation:** offline Ed25519 signature verification (no license server)

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
| `session.secure` | `true` | Requires HTTPS for session cookies |
| `session.same_site` | `"lax"` | SameSite cookie attribute for CSRF protection |
| Rate limiting | Enabled | Login endpoints are rate-limited with automatic cleanup |
| CSRF protection | Enabled | Mutating API requests must use `Content-Type: application/json` |
| Security headers | Enabled | X-Frame-Options DENY, X-Content-Type-Options nosniff, CSP, XSS protection |
| Body size limit | 2 MiB | Maximum request body size for all API endpoints |

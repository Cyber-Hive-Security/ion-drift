# Ion Drift Troubleshooting Guide

Common issues and their solutions, organized by symptom.

---

## Login Issues

### Login page flashes/reloads in a loop

**Cause:** A bug in versions prior to v0.2.5 where page view tracking fired before authentication, causing a redirect loop.

**Fix:** Upgrade to v0.2.5 or later.

### "Nothing happens" when clicking login with correct password

**Cause:** The session cookie has the `Secure` flag set, but you're accessing Ion Drift over plain HTTP. Browsers silently reject `Secure` cookies on non-HTTPS connections — login succeeds server-side but the cookie is never stored.

**Fix:** In your `server.toml`:

```toml
[session]
secure = false
```

Only set `secure = true` if Ion Drift is behind a reverse proxy that terminates HTTPS (Traefik, Nginx, Caddy, etc.).

### Wrong password gives error, correct password gives error too

**Cause:** The password stored in the encrypted secrets database doesn't match what you expect. This can happen if Docker Compose environment variable quoting included literal quote characters in the password during initial setup.

**Fix:** Delete the secrets database and re-run the setup wizard:

```bash
docker compose down
rm -f /path/to/your/data/ion-drift/secrets.db /path/to/your/data/ion-drift/machine.key /path/to/your/data/ion-drift/kek.local /path/to/your/data/ion-drift/kek.salt
docker compose up -d
```

Navigate to `http://your-host:port/setup` to create a new admin account.

> **Note:** This only removes authentication data. Your monitoring databases (connections, behavior, metrics) are preserved.

---

## Router Connection Issues

### "Authentication failed"

**Check the port.** Ion Drift uses the RouterOS **REST API** on port **443** (HTTPS). Ports 8728 and 8729 are the RouterOS proprietary API (used by Winbox and the API client library) — a completely different protocol. If you connect to 8728/8729, the "authentication failed" error is actually a protocol mismatch, not a password problem.

```toml
[router]
port = 443   # Correct — REST API
# port = 8728  # WRONG — proprietary API
# port = 8729  # WRONG — proprietary API-SSL
```

**Check the password.** Verify your credentials work by running from the Docker host:

```bash
curl -u ion-drift:yourpassword https://your-router/rest/system/identity
```

If curl works but Ion Drift doesn't, the password in the secrets database may be stale. Update it via Settings → Devices in the UI, or delete the secrets database and re-run setup (see above).

### "error sending request for url" on all REST API endpoints

**Check TLS certificate trust.** This usually means Ion Drift can't verify your router's TLS certificate.

**Let's Encrypt or public CA:** No `ca_cert_path` needed — remove it from your config if present. A stale `ca_cert_path` pointing to an old/wrong CA cert will cause Ion Drift to reject the valid public certificate.

**Private CA (Smallstep, EJBCA, self-signed):** Mount your CA's root certificate and set `ca_cert_path`:

```toml
[router]
ca_cert_path = "/app/certs/root_ca.crt"
```

**Hostname must match the certificate.** If your router's TLS certificate is issued for a hostname (e.g., `router.example.com`), you must connect using that hostname — not the IP address. Ion Drift (via rustls) enforces strict hostname verification. Set the router host in Settings → Devices to match the certificate's Subject Alternative Name (SAN).

**Diagnose with curl:**

```bash
curl -v https://your-router/rest/system/identity -u ion-drift:yourpassword 2>&1 | head -30
```

The `-v` output shows the TLS handshake. Look for:
- `SSL certificate verify ok` — TLS is fine, problem is elsewhere
- `SSL certificate problem: unable to get local issuer certificate` — you need `ca_cert_path`
- `SSL certificate problem: certificate has expired` — renew your router's cert

### "UnsupportedSignatureAlgorithmContext" TLS error

**Cause:** Your router's TLS certificate uses a signature algorithm not supported by Ion Drift's TLS library (rustls).

**Supported algorithms:**
- ECDSA with SHA-256 or SHA-384 (recommended: P-256/SHA-256 or P-384/SHA-384)
- RSA with SHA-256, SHA-384, or SHA-512
- Ed25519

**Not supported:** ECDSA-SHA512 (P-256 + SHA-512). This is a non-standard pairing — the P-256 curve provides 128-bit security, so SHA-512 adds no benefit over SHA-256.

**Fix:** Re-issue your router's certificate with a supported algorithm. If using a private CA, P-256/SHA-256 is the standard choice. For higher security, use P-384/SHA-384.

### Router shows "Offline" after successful setup

**Cause:** The router was unreachable during startup (wrong credentials, network issue, cert problem). Ion Drift starts the web UI anyway so you can fix it.

**Fix:** Go to Settings → Devices, verify the connection details, and update if needed. After correcting, restart the container for the connection to be retried.

---

## Docker Issues

### "DRIFT_ROUTER_PASSWORD env var is required"

**Cause:** You're running a version prior to v0.2.4 which required the router password as an environment variable. In v0.2.4+, credentials are managed through the setup wizard and stored encrypted.

**Fix:** Upgrade to v0.2.4 or later. If upgrading isn't possible, add the env var temporarily:

```yaml
environment:
  - DRIFT_ROUTER_PASSWORD=yourpassword
```

After upgrading, remove it — credentials are managed through the UI.

### Docker Compose environment variable quoting

In Docker Compose list-style `environment:`, **do not quote values:**

```yaml
# WRONG — the literal quotes become part of the value
- DRIFT_ROUTER_PASSWORD="mypassword"

# CORRECT — no quotes needed
- DRIFT_ROUTER_PASSWORD=mypassword
```

If your password contains special characters (`$`, `!`, `#`), use the mapping format:

```yaml
environment:
  DRIFT_ROUTER_PASSWORD: 'p@ss$word!'
```

### Container restarts in a loop

Check logs with `docker logs ion-drift --tail 50`. Common causes:

- **Missing config file:** If you bind-mount a `server.toml` that doesn't exist, the container fails immediately. Create the file first.
- **Corrupt secrets database:** Delete `secrets.db`, `machine.key`, `kek.local`, and `kek.salt` from the data directory and restart.

---

## World Map / GeoIP

### World map is empty

**Cause:** No GeoIP database is configured. Ion Drift requires MaxMind GeoLite2 databases for geographic enrichment. Without them, connections are tracked but not geolocated.

**Fix:**
1. Create a free MaxMind account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
2. Generate a license key in your MaxMind account dashboard
3. In Ion Drift, go to Settings → System → GeoIP and enter your credentials
4. Click "Download" to fetch the databases

Connection tracking and all other features work without GeoIP — only the world map visualization and country-level analytics require it.

### World map shows countries but no city dots

**Cause:** City-level geolocation (lat/lon coordinates) requires the MaxMind GeoLite2 City database. If only the Country database is loaded, country aggregation works but city dots are unavailable.

**Fix:** Ensure both GeoLite2-City and GeoLite2-ASN databases are downloaded via Settings → System → GeoIP.

---

## RouterOS User Setup

If you haven't created a dedicated API user on your router:

```routeros
/user group add name=ion-drift policy=api,read,!write,!ftp,!local,!telnet,!ssh,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api
/user add name=ion-drift group=ion-drift password=YourStrongPasswordHere
```

**Do not use the admin account.** If Ion Drift's credentials were compromised, an attacker with `admin` access would have full control of your router.

Ion Drift requires HTTPS on port 443. Enable the REST API on your router:

```routeros
/ip/service set www-ssl disabled=no port=443
```

Ensure your router has a TLS certificate installed. You can use Let's Encrypt (via RouterOS ACME), your internal CA, or a self-signed certificate.

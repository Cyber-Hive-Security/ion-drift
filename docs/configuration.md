# Ion Drift Configuration Guide

## Quick Start (Local Auth)

Ion Drift works out of the box with no external dependencies. On first launch, visit the web UI and the setup wizard will guide you through creating an admin account. No OIDC provider, no environment variables, no config file editing required to get started.

All configuration is optional for a basic setup — you only need to point Ion Drift at your Mikrotik router.

## Configuration File

Two example configs are provided:

| File | Purpose |
|------|---------|
| `config/server.example.toml` | Local development (`cargo run`). Uses host filesystem paths. |
| `config/production.example.toml` | Docker deployment. Uses container paths (`/app/...`). Includes OIDC, mTLS bootstrap, and CertWarden sections. |

**For Docker deployment:**
```bash
cp config/production.example.toml config/production.toml
# Edit production.toml with your environment-specific values
```

The `docker-compose.yml` bind-mounts `production.toml` into the container as `/app/config/server.toml`.

**For local development:**
```bash
cp config/server.example.toml config/server.toml
cargo run --bin ion-drift-web -- --config config/server.toml
```

The config file path is resolved in this order:
1. CLI argument (`--config <path>`)
2. `ION_DRIFT_CONFIG` environment variable
3. Default: `./server.toml`

Format: TOML.

> **Important:** Your production config (`production.toml`) is gitignored and not tracked in version control. **Back it up separately.** If the file is lost or emptied, Ion Drift will fail to start with `missing field 'server'`. Keep a copy outside the repository or in your secrets manager.

---

### `[server]`

General server settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | string | `"0.0.0.0"` | IP address to bind the HTTP server to. |
| `listen_port` | integer | `3000` | Port for the web server. |
| `home_lon` | float | *(none)* | Home location longitude for the world map (e.g., `142.20`). **Required for connection arc lines on the world map.** |
| `home_lat` | float | *(none)* | Home location latitude for the world map (e.g., `11.35`). **Required for connection arc lines on the world map.** |
| `home_country` | string | *(none)* | Home country ISO 3166-1 alpha-2 code (e.g., `"US"`). Highlighted green on the map. |
| `warning_countries` | array of strings | `[]` | Country codes flagged for security monitoring. Connections to these countries are highlighted on the map. Configure via Settings > Monitored Regions in the UI. |

```toml
[server]
listen_addr = "0.0.0.0"
listen_port = 3000
home_lon = 142.20
home_lat = 11.35
home_country = "US"
warning_countries = ["RU", "CN"]
```

---

### `[router]`

Connection settings for your Mikrotik RouterOS device.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | `"192.168.88.1"` | Router IP or hostname. **Required for production.** The default is the Mikrotik factory default and will emit a warning. |
| `port` | integer | `443` | RouterOS REST API port. **Must be 443.** Do not use 8728 or 8729 — those are the RouterOS proprietary API (Winbox/API), a completely different protocol. |
| `tls` | boolean | `true` | Whether to use TLS for the router connection. |
| `ca_cert_path` | string | *(none)* | Path to a PEM-encoded CA certificate if the router uses a private/internal CA. |
| `username` | string | `"admin"` | RouterOS API username. |
| `password` | *(managed)* | — | Configured through the setup wizard and stored encrypted. Only use `DRIFT_ROUTER_PASSWORD` env var if running OIDC without mTLS bootstrap (see [Environment Variables](#environment-variables-oidc-without-mtls-bootstrap)). |
| `wan_interface` | string | `"1-WAN"` | WAN interface name for traffic tracking. |
| `dns_server` | string | *(none)* | Internal DNS server IP for PTR lookups. If not set, PTR lookups are skipped. |

```toml
[router]
host = "192.168.88.1"
port = 443       # Must be 443 — do NOT use 8728/8729 (proprietary API)
tls = true
ca_cert_path = "/path/to/ca.crt"
username = "ion-drift"
wan_interface = "ether1"
dns_server = "192.168.88.1"
```

> **Common mistake:** MikroTik ports 8728 (API) and 8729 (API-SSL) are the *proprietary* API used by Winbox and the RouterOS API client library. Ion Drift uses the *REST API*, which runs over standard HTTPS on port 443. If you see `Authentication failed` with port 8728/8729, this is why — the protocols are incompatible.

#### RouterOS User Permissions

Ion Drift requires a dedicated RouterOS user with specific policies. **Do not use the default `admin` account.** If Ion Drift's credentials were ever compromised, an attacker with `admin` access would have full control of your router — routing tables, firewall rules, VPN configs, everything.

**Step 1: Create a read-only user group and user:**

```routeros
/user group add name=ion-drift policy=api,read,!write,!ftp,!local,!telnet,!ssh,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api
/user add name=ion-drift group=ion-drift password=YourStrongPasswordHere
```

This is sufficient for all monitoring functionality. Ion Drift will read system resources, interfaces, firewall rules, DHCP leases, ARP tables, connection tracking, and logs.

**Step 2 (optional): Temporarily enable write for auto-provisioning:**

If you want to use Ion Drift's auto-provisioning feature (Settings > Provision) to automatically create mangle flow accounting rules and syslog forwarding on the router, temporarily add `write` to the group:

```routeros
/user group set ion-drift policy=api,read,write,!ftp,!local,!telnet,!ssh,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api
```

Run the provisioning from the Ion Drift UI, then **immediately remove write access**:

```routeros
/user group set ion-drift policy=api,read,!write,!ftp,!local,!telnet,!ssh,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api
```

> **Security note:** The `write` policy should only be active during initial provisioning. Once your mangle and syslog rules are created, Ion Drift operates entirely in read-only mode. Leaving `write` enabled is unnecessary and increases your attack surface.

**Required policies:**

| Policy | Why | When |
|--------|-----|------|
| `api` | REST API access | Always |
| `read` | Read system resources, interfaces, firewall, DHCP, ARP, connections, logs | Always |
| `write` | Create mangle flow accounting rules and syslog forwarding config | Provisioning only — remove after |

**API endpoints used (read):**

- `/system/resource`, `/system/identity`, `/system/logging`, `/system/logging/action`
- `/interface`, `/interface/bridge/host`, `/interface/bridge/port`, `/interface/bridge/vlan`, `/interface/ethernet`, `/interface/vlan`
- `/ip/address`, `/ip/route`, `/ip/arp`, `/ip/dns`, `/ip/pool`
- `/ip/dhcp-server`, `/ip/dhcp-server/lease`, `/ip/dhcp-server/network`
- `/ip/firewall/filter`, `/ip/firewall/nat`, `/ip/firewall/mangle`, `/ip/firewall/connection`, `/ip/firewall/connection/tracking`, `/ip/firewall/address-list`
- `/ip/neighbor`
- `/log`

**API endpoints used (write — provisioning only):**

- `/ip/firewall/mangle` (PUT) — creates traffic accounting rules
- `/system/logging/action` (PUT) — configures syslog forwarding target
- `/system/logging` (PUT) — creates logging rules for firewall topics
- `/ip/firewall/filter` (PUT) — creates firewall log rules

#### TLS Requirements

Ion Drift requires HTTPS for router connections. HTTP is not supported — router credentials are transmitted via HTTP Basic Auth on every API request, and sending them over an unencrypted connection would expose them to any observer on the network path.

Configure your RouterOS with a TLS certificate (self-signed, Let's Encrypt, ACME, or your internal CA) and connect via HTTPS on port 443. If your CA is not publicly trusted, mount the CA certificate into the container and set `ca_cert_path` in the config.

**Supported TLS certificate signature algorithms** (via `rustls`):

- ECDSA with SHA-256 or SHA-384 (recommended: P-384/SHA-384 for higher security)
- RSA with SHA-256, SHA-384, or SHA-512 (PKCS#1 v1.5 and PSS)
- Ed25519

Other signature algorithms (e.g., ECDSA-SHA512) are not supported by `rustls` and will result in a connection error.

---

### `[oidc]` *(optional)*

OpenID Connect configuration. Omit this entire section to use local auth only. When present, both local auth and OIDC are available simultaneously — the login page shows a username/password form with a "Sign in with SSO" button.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer_url` | string | *(required)* | OIDC issuer URL (e.g., `https://idp.example.com/realms/MyRealm`). |
| `client_id` | string | *(required)* | OIDC client ID. |
| `client_secret` | *(env var)* | — | Set via `DRIFT_OIDC_SECRET` environment variable. |
| `redirect_uri` | string | *(required)* | Callback URL, typically `https://your-ion-drift.example.com/auth/callback`. |

> **Important:** The `redirect_uri` must be the externally-accessible URL that users use to reach Ion Drift — typically the reverse proxy hostname (e.g., `https://hiverouter.example.com/auth/callback`), not the internal container IP or Docker-mapped port.

| `ca_cert_path` | string | *(none)* | CA cert for verifying the OIDC provider's TLS certificate (optional). |
| `roles_claim` | string | `"realm_access.roles"` | Dot-notation path to the roles array in the ID token. Use `"groups"` for Authentik/Authelia. |
| `admin_role` | string | `"ion-drift-admin"` | Role or group name that grants admin access. |

```toml
[oidc]
issuer_url = "https://idp.example.com/realms/MyRealm"
client_id = "ion-drift"
redirect_uri = "https://ion-drift.example.com/auth/callback"
roles_claim = "realm_access.roles"
admin_role = "ion-drift-admin"
```

---

### `[session]`

Session cookie and expiry settings. All fields have sensible defaults.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cookie_name` | string | `"ion_drift_session"` | Name of the session cookie. |
| `max_age_seconds` | integer | `86400` (24 hours) | Session lifetime in seconds. |
| `secure` | boolean | `true` | Set the `Secure` flag on cookies (requires HTTPS). |
| `same_site` | string | `"lax"` | SameSite cookie attribute (`"lax"`, `"strict"`, or `"none"`). |
| `session_secret` | *(managed)* | — | Auto-generated by the setup wizard (recommended). Only set via `DRIFT_SESSION_SECRET` env var if running OIDC without mTLS bootstrap. If you do set it manually, use at least 32 bytes of entropy (e.g., `openssl rand -hex 32`). |

```toml
[session]
cookie_name = "ion_drift_session"
max_age_seconds = 86400
secure = true
same_site = "lax"
```

---

### `[oidc.bootstrap]` *(advanced, Keycloak-only)*

Enables mTLS-based KEK retrieval from Keycloak. When configured, the Key Encryption Key is fetched from a Keycloak user attribute via mutual TLS instead of being derived from the admin password. This is only needed for Keycloak deployments that want mTLS-based key management. Requires the `[tls]` section for client certificate paths.

> **Note:** Encrypted secrets at rest are available in *all* auth modes (local auth, OIDC with bootstrap, OIDC without bootstrap via first-run migration). This section only controls *how the KEK is obtained*, not whether secrets are encrypted.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `client_id` | string | *(required)* | Bootstrap client ID (e.g., `"ion-drift-bootstrap"`). |
| `token_url` | string | *(required)* | Full Keycloak token endpoint URL. |
| `admin_url` | string | *(required)* | Full Keycloak Admin API URL (e.g., `.../admin/realms/YourRealm`). |
| `kek_attribute` | string | `"ion_drift_kek"` | Keycloak user attribute name for storing the KEK. |

```toml
[oidc.bootstrap]
client_id = "ion-drift-bootstrap"
token_url = "https://keycloak.example.com/realms/MyRealm/protocol/openid-connect/token"
admin_url = "https://keycloak.example.com/admin/realms/MyRealm"
kek_attribute = "ion_drift_kek"
```

---

### `[tls]`

Client certificate paths for mTLS authentication (used by `[oidc.bootstrap]`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `client_cert` | string | `"/app/data/certs/client.crt"` | Path to PEM-encoded mTLS client certificate. |
| `client_key` | string | `"/app/data/certs/client.key"` | Path to PEM-encoded mTLS client private key. |

```toml
[tls]
client_cert = "/app/data/certs/client.crt"
client_key = "/app/data/certs/client.key"
```

---

### `[certwarden]`

Automatic TLS certificate renewal via CertWarden. Both `base_url` and `cert_name` must be set to enable this feature.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | string | *(none)* | CertWarden API base URL (e.g., `https://certwarden.example.com:4051/certwarden`). Include the `/certwarden` path prefix. |
| `cert_name` | string | *(none)* | Certificate name in CertWarden. |
| `renewal_threshold_days` | integer | `30` | Days before expiry to trigger renewal. |
| `check_interval_hours` | integer | `1` | Hours between certificate expiry checks. |

```toml
[certwarden]
base_url = "https://certwarden.example.com:4051/certwarden"
cert_name = "ion-drift"
renewal_threshold_days = 30
check_interval_hours = 1
```

---

### `[syslog]`

Syslog listener for receiving log messages from the router.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | integer | `5514` | UDP port to listen on for syslog messages. |
| `bind_address` | string | `"0.0.0.0"` | Bind address for the syslog listener. |
| `target_ip` | string | *(none)* | IP address of this server as seen by the router. If set, Ion Drift will configure RouterOS to forward syslog here automatically. If not set, router syslog setup is skipped. |

```toml
[syslog]
port = 5514
bind_address = "0.0.0.0"
target_ip = "192.168.1.100"
```

---

### `[data]`

Data directory settings. Currently a placeholder section with no configurable fields — the data directory defaults to `./data/` relative to the working directory.

---

## OIDC Setup by Provider

### Keycloak

1. In your Keycloak realm, go to **Clients** and create a new client:
   - **Client ID:** `ion-drift`
   - **Client Protocol:** OpenID Connect
   - **Access Type:** Confidential
   - **Valid Redirect URIs:** `https://your-ion-drift.example.com/auth/callback`
2. Copy the client secret from the **Credentials** tab.
3. Go to **Realm Roles** and create a role named `ion-drift-admin`.
4. Assign the `ion-drift-admin` role to users who should have admin access.

```toml
[oidc]
issuer_url = "https://keycloak.example.com/realms/YourRealm"
client_id = "ion-drift"
redirect_uri = "https://ion-drift.example.com/auth/callback"
roles_claim = "realm_access.roles"   # default, can be omitted
admin_role = "ion-drift-admin"        # default, can be omitted
```

Set the environment variable:
```bash
export DRIFT_OIDC_SECRET="your-client-secret-from-keycloak"
```

### Authentik

1. In Authentik, go to **Applications > Providers** and create a new **OAuth2/OpenID Provider**:
   - **Name:** Ion Drift
   - **Authorization flow:** default-provider-authorization-implicit-consent
   - **Redirect URIs:** `https://your-ion-drift.example.com/auth/callback`
2. Create an **Application** and link it to the provider.
3. Create a **Group** named `ion-drift-admins` and add admin users to it.

```toml
[oidc]
issuer_url = "https://authentik.example.com/application/o/ion-drift/"
client_id = "your-client-id"
redirect_uri = "https://ion-drift.example.com/auth/callback"
roles_claim = "groups"
admin_role = "ion-drift-admins"
```

Set the environment variable:
```bash
export DRIFT_OIDC_SECRET="your-client-secret-from-authentik"
```

### Authelia

1. Add an OIDC client to your Authelia `configuration.yml`:

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: ion-drift
        client_secret: 'your-hashed-secret'
        authorization_policy: two_factor
        redirect_uris:
          - https://ion-drift.example.com/auth/callback
        scopes:
          - openid
          - profile
          - email
          - groups
```

2. Create a group named `ion-drift-admin` in your Authelia user database and add admin users.

```toml
[oidc]
issuer_url = "https://authelia.example.com"
client_id = "ion-drift"
redirect_uri = "https://ion-drift.example.com/auth/callback"
roles_claim = "groups"
admin_role = "ion-drift-admin"
```

Set the environment variable:
```bash
export DRIFT_OIDC_SECRET="your-client-secret"
```

---

## How Credentials Are Managed

Ion Drift encrypts all secrets (router password, session secret, OIDC client secret) at rest in SQLite using AES-256-GCM. **You do not need to put passwords in config files or environment variables** in most setups.

| Auth Mode | How credentials are stored | Env vars needed? |
|-----------|--------------------------|------------------|
| **Local auth** (default) | Setup wizard → encrypted secrets DB | **No** |
| **OIDC with mTLS bootstrap** | Keycloak mTLS → encrypted secrets DB | **No** |
| **OIDC without mTLS bootstrap** | Environment variables (see below) | **Yes** |

For local auth and mTLS bootstrap modes, credentials are managed through the web UI (Settings → Devices). Environment variables like `DRIFT_ROUTER_PASSWORD` are only read on first startup for initial migration — after that, the encrypted secrets database is the source of truth and env vars are ignored.

### Environment Variables (OIDC without mTLS Bootstrap)

These are **only required** when using OIDC without the `[oidc.bootstrap]` section. For local auth or mTLS bootstrap, skip this section entirely.

| Variable | Required | Description |
|----------|----------|-------------|
| `DRIFT_ROUTER_PASSWORD` | Yes | RouterOS API password. |
| `DRIFT_OIDC_SECRET` | Yes | OIDC client secret. |
| `DRIFT_SESSION_SECRET` | No | HMAC signing key for session cookies. If set, use at least 32 bytes of entropy (`openssl rand -hex 32`). Auto-generated if not set. |
| `DRIFT_ROUTER_HOST` | No | Override `router.host` from config. |
| `DRIFT_ROUTER_USER` | No | Override `router.username` from config. |
| `DRIFT_ROUTER_CA_CERT` | No | Override `router.ca_cert_path` from config. |
| `DRIFT_ROUTER_DNS_SERVER` | No | Override `router.dns_server` from config. |

> **Docker Compose quoting:** In list-style `environment:`, do not quote values — `- DRIFT_ROUTER_PASSWORD=mypass` is correct, `- DRIFT_ROUTER_PASSWORD="mypass"` passes the literal quotes as part of the value. For passwords with special characters, use the mapping format: `DRIFT_ROUTER_PASSWORD: 'p@ss$word!'`.

---

## Syslog Setup

Ion Drift can receive syslog messages from your Mikrotik router for real-time log analysis.

### Automatic Setup

If `syslog.target_ip` is set in the config, Ion Drift will configure your RouterOS device to forward syslog messages automatically on startup.

### Manual RouterOS Configuration

If you prefer to configure syslog forwarding manually:

1. In RouterOS, go to **System > Logging > Actions** and create a new action:
   - **Name:** `ion-drift`
   - **Type:** Remote
   - **Remote Address:** IP of your Ion Drift server
   - **Remote Port:** `5514` (or whatever you set in `syslog.port`)
   - **Src. Address:** (leave empty or set to router's management IP)

2. Go to **System > Logging > Rules** and add a rule:
   - **Topics:** Select the log topics you want forwarded
   - **Action:** `ion-drift`
   - **Prefix:** `ION` (required — Ion Drift filters for this prefix)

The log prefix `ION` is required for Ion Drift to process incoming syslog messages.

```toml
[syslog]
port = 5514
bind_address = "0.0.0.0"
target_ip = "192.168.1.100"
```

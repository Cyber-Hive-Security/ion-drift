# Configuration Reference

Single source of truth for runtime configuration in `ion-drift-web` and `ion-drift-cli`.

## Web Server (`server.toml`)

| TOML Key | Type | Default | Env Override | Required | Description |
|---|---|---|---|---|---|
| `server.listen_addr` | string | `0.0.0.0` | - | No | Web server bind address. |
| `server.listen_port` | u16 | `3000` | - | No | Web server port. |
| `server.home_lon` | f64 | - | - | No | Optional map home longitude. |
| `server.home_lat` | f64 | - | - | No | Optional map home latitude. |
| `server.home_country` | string | - | - | No | Optional ISO country code for map home. |
| `router.host` | string | `192.168.88.1` | `HIVE_ROUTER_HOST` | No | Primary router host/IP. |
| `router.port` | u16 | `443` | - | No | RouterOS REST API port. |
| `router.tls` | bool | `true` | - | No | Use TLS for RouterOS client. |
| `router.ca_cert_path` | string | - | `HIVE_ROUTER_CA_CERT` | No | CA cert path for router TLS validation. |
| `router.username` | string | `admin` | `HIVE_ROUTER_USER` | No | Router username. |
| `router.password` | string | - | `HIVE_ROUTER_PASSWORD` | Yes\* | Router password secret. |
| `router.wan_interface` | string | `1-WAN` | - | No | WAN interface used by traffic tracker. |
| `router.dns_server` | string | - | `HIVE_ROUTER_DNS_SERVER` | No | Internal DNS server for PTR lookups. |
| `oidc.issuer_url` | string | - | - | Yes | OIDC issuer URL. |
| `oidc.client_id` | string | - | - | Yes | OIDC client ID. |
| `oidc.client_secret` | string | - | `HIVE_ROUTER_OIDC_SECRET` | Yes\* | OIDC client secret. |
| `oidc.redirect_uri` | string | - | - | Yes | OIDC callback URI. |
| `oidc.ca_cert_path` | string | - | - | No | Optional CA cert for OIDC TLS validation. |
| `oidc.bootstrap.client_id` | string | - | - | No | Bootstrap client ID for KEK retrieval. |
| `oidc.bootstrap.token_url` | string | - | - | No | Bootstrap token endpoint URL. |
| `oidc.bootstrap.admin_url` | string | - | - | No | Bootstrap Keycloak admin URL. |
| `oidc.bootstrap.kek_attribute` | string | `ion_drift_kek` | - | No | Keycloak user attribute name for KEK. |
| `session.cookie_name` | string | `ion_drift_session` | - | No | Session cookie name. |
| `session.max_age_seconds` | u64 | `86400` | - | No | Session max age in seconds. |
| `session.secure` | bool | `true` | - | No | Session cookie secure flag. |
| `session.same_site` | string | `lax` | - | No | Session cookie SameSite setting. |
| `session.session_secret` | string | generated if unset in legacy mode | `HIVE_ROUTER_SESSION_SECRET` | Yes\* | Session signing secret. |
| `tls.client_cert` | string | `/app/data/certs/client.crt` | - | No | Bootstrap mTLS client cert path. |
| `tls.client_key` | string | `/app/data/certs/client.key` | - | No | Bootstrap mTLS client key path. |
| `certwarden.base_url` | string | - | - | No | CertWarden API base URL. |
| `certwarden.cert_name` | string | - | - | No | CertWarden certificate name. |
| `certwarden.renewal_threshold_days` | u32 | `30` | - | No | Renewal threshold in days. |
| `certwarden.check_interval_hours` | u32 | `1` | - | No | Cert check interval in hours. |
| `syslog.port` | u16 | `5514` | - | No | Syslog UDP port. |
| `syslog.bind_address` | string | `0.0.0.0` | - | No | Syslog bind address. |
| `syslog.target_ip` | string | - | - | No | Optional target IP used during syslog setup. |

\* In bootstrap-enabled mode (`oidc.bootstrap.client_id` set), these secrets can be migrated to encrypted storage and env vars become optional fallbacks.

### Web config path resolution

1. CLI flag: `--config <path>`
2. Env var: `ION_DRIFT_CONFIG`
3. Default: `./server.toml`

## CLI (`cli.toml`)

| TOML Key | Type | Default | Env Override | Required | Description |
|---|---|---|---|---|---|
| `router.host` | string | `192.168.88.1` | `HIVE_ROUTER_HOST` | No | Router host/IP for CLI commands. |
| `router.port` | u16 | `443` | - | No | Router API port. |
| `router.tls` | bool | `true` | - | No | Use TLS for CLI router client. |
| `router.ca_cert_path` | string | - | `HIVE_ROUTER_CA_CERT` | No | CA cert path for CLI router TLS. |
| `router.username` | string | `admin` | `HIVE_ROUTER_USER` | No | Router username. |
| `router.password` | string | - | `HIVE_ROUTER_PASSWORD` | Yes | Router password (or `--password` flag). |

CLI path default: `~/.config/ion-drift/cli.toml`.

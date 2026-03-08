# ion-drift

Network monitoring and management platform for Mikrotik RouterOS environments. CLI + web dashboard with Keycloak OIDC authentication.

## Features

- **Multi-device management** — manage a primary router and multiple Mikrotik switches from one dashboard
- **CLI tool** — query system resources, interfaces, firewall rules, DHCP leases, routes, and logs from the terminal
- **Web dashboard** — React SPA with real-time polling, served by an Axum backend
- **OIDC authentication** — Keycloak integration with PKCE, server-side sessions, role-based access (admin/viewer)
- **Private CA support** — trusts certificates from a Smallstep CA; supports CertWarden auto-renewal
- **Behavior engine** — learns per-device baselines, detects anomalies (volume spikes, new destinations, port scans, protocol anomalies), confidence scoring
- **Alerting engine** — configurable alert rules with webhook and email channels, DHCP pool exhaustion and firewall drop spike detection
- **Sankey investigation** — multi-level drill-down from network overview → VLAN detail → device trace → conversation detail with CSV export
- **Link saturation monitor** — live per-port utilization with heat overlay on switch port grids, rate columns, and summary cards
- **Network topology** — auto-discovered topology map with interactive node positioning
- **Identity management** — passive device discovery, MAC-port bindings, port violation detection, manufacturer lookup
- **Connection tracking** — syslog-based connection capture, geo-enrichment (MaxMind), historical analysis, weekly snapshots
- **Switch port grid** — visual port status with VLAN coloring, traffic metrics, and role badges

## Quick Start

### CLI

```bash
cargo build --release --bin ion-drift
cp config/cli.example.toml ~/.config/ion-drift/cli.toml
# Edit config with your router details

export DRIFT_ROUTER_PASSWORD='your-router-password'
ion-drift system resources
ion-drift interfaces list
ion-drift firewall filter list
```

### Web Server

```bash
cargo build --release --bin ion-drift-web
cp config/server.example.toml config/server.toml
# Edit config with your settings

# Required environment variables:
# DRIFT_ROUTER_PASSWORD      — RouterOS API password
# DRIFT_OIDC_SECRET   — Keycloak OIDC client secret
# DRIFT_SESSION_SECRET — Session encryption key

cargo run --release --bin ion-drift-web -- --config config/server.toml
```

### Frontend Development

```bash
cd web
npm install
npm run dev     # Vite dev server with HMR
npm run build   # Production build to web/dist/
```

## Architecture

```
ion-drift/
├── crates/
│   ├── mikrotik-core/      # Shared RouterOS REST API client + SQLite stores
│   ├── ion-drift-cli/       # CLI binary (clap)
│   └── ion-drift-web/       # Axum web server + background tasks
├── web/                     # React frontend (Vite + TypeScript + TanStack Query + Tailwind)
├── config/                  # Configuration files
└── docker/                  # Dockerfile + docker-compose.yml
```

Uses the RouterOS v7 REST API (`/rest/`) with HTTP Basic Auth over HTTPS. Switch management uses both REST API and SwOS web scraping for non-RouterOS switches.

## Configuration

Configuration is TOML-based. See `config/server.example.toml` for all available options.

Key sections:
- `[server]` — listen address, port
- `[router]` — primary router host, port, TLS, WAN interface name, DNS server
- `[oidc]` — Keycloak realm, client ID, redirect URI, CA cert
- `[session]` — cookie name, TTL, SameSite policy
- `[tls]` — mTLS client cert/key for router API
- `[syslog]` — syslog listener port for connection tracking
- `[certwarden]` — optional CertWarden integration for cert auto-renewal

## Security

- All API routes require OIDC authentication
- Admin-only routes use `RequireAdmin` extractor (role-based)
- CSRF protection via Content-Type enforcement on mutating requests
- SameSite=Lax session cookies with CORS origin restriction
- Security headers: X-Frame-Options, CSP, X-Content-Type-Options
- Sensitive errors sanitized before API responses

## License

PolyForm Shield 1.0.0

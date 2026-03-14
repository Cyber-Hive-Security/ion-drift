# ion-drift

Network monitoring, security analytics, and device management for MikroTik RouterOS networks. Built in Rust with a React frontend.

## What It Does

Ion Drift connects to your MikroTik router's REST API, monitors your network in real time, learns what's normal, and alerts you when something changes. It tracks every connection, fingerprints every device, maps your topology, and gives you Sankey flow diagrams to investigate traffic patterns.

See [FEATURES.md](FEATURES.md) for the full feature list.

## Quick Start

```bash
docker compose up -d
```

Open `https://your-host:3000` in your browser. The setup wizard creates your admin account — no configuration files, environment variables, or external dependencies needed.

After setup, add your router connection in the web UI. Ion Drift begins monitoring immediately.

## Optional: OIDC Single Sign-On

Ion Drift works with any OpenID Connect provider (Keycloak, Authentik, Authelia). To enable SSO, add an `[oidc]` section to your config file. See [docs/configuration.md](docs/configuration.md) for provider-specific setup guides.

## Architecture

```
ion-drift/
├── crates/
│   ├── mikrotik-core/       # RouterOS REST + SNMP + SwOS client library
│   ├── ion-drift-storage/   # SQLite stores (behavior, switch, metrics, traffic)
│   ├── ion-drift-cli/       # CLI binary (clap)
│   └── ion-drift-web/       # Axum web server + background tasks
├── web/                     # React frontend (Vite + TypeScript + TanStack)
├── config/                  # Configuration templates (TOML)
└── docs/                    # Technical documentation and engine whitepapers
```

**Tech stack:** Rust (Axum, Tokio, SQLite), React 19 (Vite, TypeScript, TanStack Router + Query, Recharts, D3.js, Tailwind CSS 4)

Uses the RouterOS v7 REST API over HTTPS. Switch management supports RouterOS, SwOS, and SNMP v2c/v3.

## Docker Deployment

```bash
docker compose up -d
```

The `docker-compose.yml` bind-mounts:
- `config/production.toml` → `/app/config/server.toml` (optional — created via setup wizard if absent)
- `certs/root_ca.crt` → `/app/certs/root_ca.crt` (only if using a private CA)
- `ion-drift-data` volume → `/app/data` (SQLite databases, GeoIP data, encryption keys)

## Configuration

Configuration is optional for getting started. The setup wizard handles initial setup.

For advanced configuration (OIDC, syslog, CertWarden, custom bind address), see [docs/configuration.md](docs/configuration.md).

## Documentation

- [FEATURES.md](FEATURES.md) — Complete feature list
- [CHANGELOG.md](CHANGELOG.md) — Release history
- [SECURITY.md](SECURITY.md) — Vulnerability reporting policy
- [docs/configuration.md](docs/configuration.md) — Configuration reference with OIDC provider guides
- [docs/auth.md](docs/auth.md) — Authentication architecture
- [docs/behavior-engine-whitepaper.md](docs/behavior-engine-whitepaper.md) — Anomaly detection engine
- [docs/topology-engine-whitepaper.md](docs/topology-engine-whitepaper.md) — Network topology inference
- [docs/investigation-engine-whitepaper.md](docs/investigation-engine-whitepaper.md) — Automated investigation engine
- [docs/correlation-engine-whitepaper.md](docs/correlation-engine-whitepaper.md) — Identity correlation engine
- [docs/connection-store-whitepaper.md](docs/connection-store-whitepaper.md) — Connection tracking and GeoIP

## Security

- Secrets encrypted at rest (AES-256-GCM)
- Local auth with argon2id password hashing, or OIDC with any provider
- HMAC-SHA256 signed sessions with HttpOnly/Secure cookies
- CSRF protection, rate limiting, security headers
- No telemetry, no phone-home — runs fully air-gapped

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

[PolyForm Shield License 1.0.0](LICENSE) with the [Cyber Hive Security Use Agreement](USE-AGREEMENT).

**Personal home use is free.** Commercial use requires a license from [Cyber Hive Security](https://cyberhivesecurity.com/license).

Copyright (c) 2026 Cyber Hive Security LLC

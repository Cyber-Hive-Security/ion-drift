<p align="center">
  <img src="web/public/ion-drift_white.png" alt="Ion Drift" width="400">
</p>

<p align="center">
  Network monitoring, security analytics, and device management for MikroTik RouterOS networks.<br>
  Built in Rust with a React frontend.
</p>

---

![Dashboard](caps/ion-drift-dashboard.png)

## What It Does

Ion Drift connects to your MikroTik router's REST API, monitors your network in real time, learns what's normal, and alerts you when something changes. It tracks every connection, fingerprints every device, maps your topology, and gives you Sankey flow diagrams to investigate traffic patterns.

See [FEATURES.md](FEATURES.md) for the full feature list.

## Screenshots

### Network Topology
Auto-discovered network topology with VLAN grouping, device classification, and switch-level attachment inference.

![Topology](caps/ion-drift-topology.png)

### Sankey Flow Investigation
Multi-level drill-down: network overview, per-VLAN device flows, per-device protocol/destination breakdown, and conversation detail.

![Sankey Outbound](caps/ion-drift-sankey-outbound.png)
![Sankey Internal](caps/ion-drift-sankey-internal.png)

### World Map
GeoIP-enriched connection visualization with country and city summaries, flagged region monitoring, and arc overlays.

![World Map](caps/ion-drift-world-map.png)

### VLAN Traffic Flows
Inter-VLAN traffic volumes with real-time activity tracking.

![VLAN Flows](caps/ion-drift-vlan-flows.png)

### Interfaces
Live interface status with traffic rates, MTU, MAC addresses, and link state.

![Interfaces](caps/ion-drift-interfaces.png)

### Firewall
Firewall rule viewer with drop statistics and geo-enriched drop country attribution.

![Firewall](caps/ion-drift-firewall.png)

## Quick Start

```bash
cp docker-compose.example.yml docker-compose.yml
docker compose up -d
```

Open `http://your-host:3000` in your browser. The setup wizard creates your admin account — no configuration files, environment variables, or build tools needed.

After setup, add your router connection in the web UI. Ion Drift begins monitoring immediately.

Pre-built images are published to `ghcr.io/cyber-hive-security/ion-drift` on every release.

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
cp docker-compose.example.yml docker-compose.yml
docker compose up -d
```

Optional bind-mounts (uncomment in docker-compose.yml as needed):
- `config/server.toml` → `/app/config/server.toml` (custom config — setup wizard handles first-run without it)
- `certs/root_ca.crt` → `/app/certs/root_ca.crt` (only if your router or OIDC provider uses a private CA)
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

## AI Development Disclosure

Ion Drift was built entirely by AI coding agents under the direction and architectural guidance of [Scott Baird](https://github.com/scott-chs), founder of Cyber Hive Security LLC.

100% of the source code — backend, frontend, CLI, database schemas, authentication system, behavioral analytics engines, topology inference, and all supporting infrastructure — was written by [Claude Code](https://claude.ai/claude-code) (Anthropic) and [Codex](https://openai.com/codex) (OpenAI). This includes:

- All Rust backend code (Axum web server, RouterOS/SNMP/SwOS clients, SQLite storage, AES-256-GCM encryption, OIDC and local auth)
- All React/TypeScript frontend code (dashboard, topology map, Sankey diagrams, settings UI)
- Security reviews, code audits, and vulnerability remediation
- Refactoring, performance optimization, and architectural decisions
- Documentation, engine whitepapers, and configuration guides
- Licensing system, setup wizard, and deployment infrastructure
- Docker packaging and CI/CD configuration

No line of code was written by a human. Human contribution was limited to product vision, architecture direction, feature prioritization, acceptance testing, and deployment into the production homelab environment where Ion Drift runs today.

This project demonstrates that AI coding agents can produce production-grade, security-conscious software when guided by a knowledgeable operator who understands the problem domain.

## License

[PolyForm Shield License 1.0.0](LICENSE) with the [Cyber Hive Security Use Agreement](USE-AGREEMENT).

**Personal home use is free.** Commercial use requires a license from [Cyber Hive Security](https://www.mycyberhive.com/license).

Copyright (c) 2026 Cyber Hive Security LLC

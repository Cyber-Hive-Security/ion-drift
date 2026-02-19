# ion-drift

Mikrotik RouterOS management dashboard for a single-router homelab. CLI + web UI with Keycloak OIDC authentication.

## Features

- **CLI tool** — query system resources, interfaces, firewall rules, DHCP leases, routes, and logs from the terminal
- **Web dashboard** — React SPA with real-time polling, served by an Axum backend
- **OIDC authentication** — Keycloak integration with PKCE, server-side sessions
- **Private CA support** — trusts certificates from a Smallstep CA
- **Read-only** — monitoring and visibility first; write operations come later

## Quick Start

### CLI

```bash
cargo build --release --bin ion-drift
cp config/cli.example.toml ~/.config/ion-drift/cli.toml
# Edit config with your router details

export HIVE_ROUTER_PASSWORD='your-router-password'
ion-drift system resources
ion-drift interfaces list
ion-drift firewall filter list
```

### Web Server (Docker)

```bash
cp config/server.example.toml config/server.toml
# Edit config with your settings

docker compose -f docker/docker-compose.yml up -d
```

## Architecture

```
ion-drift/
├── crates/
│   ├── mikrotik-core/      # Shared RouterOS REST API client
│   ├── ion-drift-cli/       # CLI binary (clap)
│   └── ion-drift-web/       # Axum web server
├── web/                     # React frontend (Vite + TypeScript)
├── config/                  # Example configuration files
└── docker/                  # Dockerfile + docker-compose.yml
```

Uses the RouterOS v7 REST API (`/rest/`) with HTTP Basic Auth over HTTPS.

## License

MIT

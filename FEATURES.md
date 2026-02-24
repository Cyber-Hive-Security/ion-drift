# ion-drift — Feature List

## Overview

ion-drift is a Rust-based Mikrotik RouterOS management and monitoring dashboard for a single RB4011 router. Dual interface: CLI tool + Axum web server serving a React frontend. Authenticates via Keycloak OIDC. Deployed as Docker container behind Traefik.

**Tech Stack:**
- Backend: Rust (Axum, Tokio async runtime, SQLite)
- Frontend: React (Vite, TypeScript, TanStack Query, Recharts, D3.js, Tailwind CSS)
- Auth: Keycloak OIDC with PKCE flow, mTLS bootstrap for secrets encryption
- Router API: RouterOS v7 REST over HTTPS (Smallstep CA)

---

## Architecture

### Crate Structure

| Crate | Role |
|-------|------|
| `mikrotik-core` | Shared RouterOS REST API client, resource models, background engines (metrics, behavior, speedtest, tracker, VLAN flows) |
| `ion-drift-cli` | clap-based CLI binary with table/JSON/CSV output |
| `ion-drift-web` | Axum web server + React SPA, OIDC auth, 40+ API routes, 15 background tasks |
| `web/` | React frontend (Vite + TypeScript) |

### Deployment

- 3-stage Dockerfile (Rust build, Node build, Debian slim runtime)
- Docker Compose with health check (`GET /health`)
- Persistent volume for SQLite databases, certs, GeoIP data
- Reverse proxy: Traefik (commnet, 10.20.25.8)

---

## Authentication & Security

- **OIDC:** Keycloak (TheHolonet realm), PKCE flow, server-side sessions (DashMap + cookie)
- **mTLS Bootstrap:** Client cert to Keycloak for KEK (Key Encryption Key) retrieval
- **Secrets Encryption:** AES-256-GCM encrypted SQLite store, per-secret IVs, key fingerprint tracking
- **Managed Secrets:** Router credentials, OIDC client secret, session secret, CertWarden API keys, MaxMind credentials
- **Cert Rotation:** CertWarden integration, hourly expiry checks, auto-renewal within configurable threshold
- **Endpoints:** `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/status`

---

## Router Management

### Resources Polled (Read-Only)

- **System:** CPU, memory, HDD, uptime, board name, identity
- **Interfaces:** All interfaces with RX/TX counters, VLANs, bridges, real-time traffic monitoring
- **IP:** Addresses, routes, DHCP leases/servers, DNS static entries, pools, ARP table
- **Firewall:** Filter/NAT/mangle rules, active connections (conntrack), drop counters
- **Logging:** Actions, rules (for syslog configuration)
- **Log:** System log entries

### Write Operations

- **VLAN Flow Counters:** Auto-creates mangle rules for inter-VLAN + WAN traffic accounting
- **Syslog Configuration:** Auto-creates remote logging action, firewall topic routing rule, and filter log rules for new connections on forward + input chains
- **Firewall Log Rules:** `action=log, connection-state=new, log-prefix=ION` at top of forward and input chains

---

## Dashboard

| Card | Data Source |
|------|------------|
| CPU gauge | System resources (10s poll) |
| Memory gauge | System resources (10s poll) |
| Uptime | System resources |
| WAN Traffic | Interface RX/TX counters, live rate calculation |
| Connections | Conntrack count by protocol (TCP/UDP/other), flagged count |
| Firewall Drops | Drop rule byte/packet counters, rate chart |
| DHCP Leases | Active lease count, subnet utilization |
| Speedtest | Latest result (median Mbps), provider breakdown |
| VLAN Sankey | Inter-VLAN traffic flows (mangle rule byte counters) |
| VLAN Activity | Per-VLAN RX/TX rates (line chart) |
| Directional Port Sankeys | Outbound/Inbound/Internal port flows with anomaly detection |

---

## Connection Tracking

### Dual-Source Capture

| Source | Method | Captures |
|--------|--------|----------|
| Conntrack Polling | `GET /ip/firewall/connection` every 30s | Long-lived connections with byte counts |
| Syslog Listener | UDP 5514, RouterOS firewall logs | Brief/denied connections (pings, port scans) |

### Connection History

- **Table:** `connection_history` — protocol, src/dst IP:port, MAC, VLAN labels, bytes, TCP state, timestamps, GeoIP enrichment, flagged status
- **Merge Logic:** Syslog + poll entries matched by flow tuple; `data_source` = `poll`, `syslog`, or `both`
- **Retention:** 30 days, nightly pruning of closed connections
- **Stale Detection:** Connections absent from conntrack for 60s marked as closed

### APIs

- `/api/connections/summary` — Quick counts
- `/api/connections/page` — Paginated live table with geo info
- `/api/connections/history` — Historical query with filters (IP, port, protocol, VLAN, direction, date range)
- `/api/connections/geo-summary` — Country-level aggregation for world map
- `/api/connections/city-summary` — City-level dots for world map
- `/api/connections/port-summary` — Port flows (by direction)
- `/api/connections/port-summary-classified` — Port flows with anomaly classification
- `/api/connections/history/stats` — Retention stats

---

## GeoIP & World Map

### Dual Lookup Strategy

| Priority | Source | Performance | Data |
|----------|--------|-------------|------|
| 1 | MaxMind GeoLite2 (.mmdb) | Microsecond, in-memory | Country, city, ASN, org, lat/lon |
| 2 | ip-api.com (SQLite cache) | HTTP batch, 7-day TTL | Country, city, ISP, ASN, lat/lon |

- **Auto-Download:** If MaxMind credentials exist but `.mmdb` files are missing, downloads from MaxMind API on startup
- **Hot-Swap:** After download, databases loaded into memory without restart
- **Flagged Countries:** RU, CN, IR, KP, VE, BY, SY, CU

### World Map Visualization

- D3.js orthographic projection with Natural Earth TopoJSON
- Country-level arcs from home (Ogden, UT) to destination countries, width scaled by bytes
- City-level arcs to individual U.S. cities with log-scaled width
- City dots sized by connection count, colored by flagged status
- Zoom/pan controls (scroll zoom 1-12x, drag pan, +/-/reset buttons)
- Tooltip with country, connection count, unique IPs, bytes, top orgs

---

## Port Sankey & Anomaly Detection

### Directional Sankeys

- **Outbound:** `dst_is_external = 1` (internal -> external)
- **Inbound:** `dst_is_external = 0 AND src_vlan IS NULL` (external -> internal)
- **Internal:** `dst_is_external = 0 AND src_vlan IS NOT NULL` (both internal)
- Minimum 100KB traffic filter, ephemeral port suppression (>= 10000 unless > 1GB)

### Port Flow Baselines

- 7-day rolling averages stored in `port_flow_baseline` table
- Metrics: avg/max bytes per day, avg/max connections per day, days present, typical sources/destinations
- Computed nightly alongside device baselines
- Manual trigger: `POST /api/behavior/port-baseline/compute`

### Anomaly Classification

| Classification | Trigger | Visual |
|----------------|---------|--------|
| `new_port` | Port not in baseline | Red, pulsing glow, "NEW" badge |
| `volume_spike` | Bytes > 4x max baseline | Amber, pulsing glow, multiplier badge |
| `source_anomaly` | New source IPs not in typical_sources | Amber |
| `disappeared` | Baselined port absent from current data | Gray, dashed stroke, "MISSING" badge |
| `normal` | Within baseline parameters | Default styling |

- Alert banner when anomalies detected (red for critical, amber for warnings)
- Suppressed during initial baselining period (`has_baselines` flag)

---

## Behavior Engine

### Device Profiling

- **Collection:** Every 60s — ARP + DHCP correlation, active connections grouped by source MAC
- **Profile:** MAC, hostname, manufacturer (OUI), IP, VLAN, last_seen
- **Observations:** Daily aggregation of (protocol, dst_port, dst_subnet, direction) with bytes and flow counts

### Baselines & Anomaly Detection

- **Baseline Window:** 7 days of observations
- **Anomaly Types:** `new_port`, `volume_spike`, `source_anomaly`, `blocked_attempt`, `direction_anomaly`
- **Severity:** Based on VLAN sensitivity (IoT Restricted = critical, Trusted Services = warning, Loose VLANs = info)
- **Auto-Resolution:** TTL-based (Strict = never, Moderate = 48h, Loose = 24h)
- **Blocked Attempts:** Detected from firewall drop rules, correlated with GeoIP

### APIs

- `/api/behavior/overview` — Device count, anomaly breakdown
- `/api/behavior/anomalies` — Paginated anomaly list
- `/api/behavior/device/{mac}` — Device detail with observations
- `/api/behavior/alerts` — Critical + alert severity anomalies
- `POST /api/behavior/anomalies/{id}/resolve` — Mark resolved

---

## Metrics & Monitoring

| Metric | Interval | Storage |
|--------|----------|---------|
| CPU / Memory / HDD | 60s | `metrics` table |
| Firewall drops (packets + bytes) | 60s | `drop_metrics` table |
| Connection counts (TCP/UDP/other) | 60s | `connection_metrics` table |
| VLAN throughput (RX/TX bps) | 60s | `vlan_metrics` table |
| Log aggregation (drops, accepts, top sources/ports) | Hourly | `log_aggregates` table |

- 7-day retention with hourly cleanup
- APIs: `/api/metrics/history`, `/api/metrics/drops`, `/api/metrics/connections`, `/api/metrics/vlans`, `/api/metrics/log-trends`

---

## Speed Testing

- **Providers:** Cloudflare, Netflix (Fast.com), Akamai (Linode) — 6 concurrent workers per provider
- **Execution:** On-demand only (`POST /api/speedtest/run`)
- **Results:** Median download/upload Mbps across providers, per-provider breakdown, latency
- **Storage:** SQLite with aggregate + per-provider detail
- **Coordination:** Atomic flag prevents concurrent runs
- **APIs:** `/api/speedtest/run`, `/api/speedtest/status`, `/api/speedtest/latest`, `/api/speedtest/history`

---

## Network Map

- Interactive D3 force-directed topology
- Device discovery via ARP + DHCP mesh
- MAC -> manufacturer via bundled OUI database (~40K entries)
- VLAN color-coding, device sizing by importance
- Click-to-detail panel (IP, MAC, hostname, recent observations)
- API: `GET /api/network-map/status`

---

## Weekly Snapshots

- **Schedule:** Every Sunday, 6-hour startup delay
- **Captures:** `world_map` (geo summary) + `sankey_port` (port flows)
- **Storage:** `snapshots` table (week label, type, JSON data, summary text)
- **APIs:** `/api/history/snapshots` (list), `/api/history/snapshot/{week}/{type}` (retrieve)

---

## Settings Page

| Section | Features |
|---------|----------|
| Encrypted Secrets | Status of all 8 known secrets, add/update interface, key fingerprint |
| mTLS Certificate | Subject, issuer, expiry countdown, auto-renewal status |
| Encryption Key | KEK fingerprint, source (Keycloak mTLS), secrets integrity check |
| Syslog Listener | Status, port, event counts, RouterOS config reference |
| GeoIP Database | MaxMind loaded/not, credentials configured, fallback status |
| Connection History | Record count, database size, retention, oldest record |

---

## CLI Tool

```
ion-drift [global-options] <command> [subcommand]
```

| Command | Subcommands |
|---------|-------------|
| `system` | `resources`, `identity` |
| `interfaces` | `list`, `vlans`, `monitor {iface}` |
| `ip` | `addresses`, `routes`, `dhcp-leases`, `dhcp-servers`, `pools`, `arp`, `dns-static` |
| `firewall` | `filter`, `nat`, `mangle` |
| `logs` | (fetch system log) |
| `speedtest` | (run or display results) |
| `traffic` | (lifetime WAN counters) |

Output formats: `--format table|json|csv`

---

## Background Tasks

| Task | Interval | Purpose |
|------|----------|---------|
| Traffic poller | 10s | WAN RX/TX rates + lifetime totals |
| Metrics poller | 60s | CPU, memory, HDD |
| Drops poller | 60s | Firewall drop counters |
| Connection metrics | 60s | Live connection counts by protocol |
| VLAN metrics | 60s | Per-VLAN throughput |
| Log aggregation | Hourly | Drop/accept roll-ups, top sources/ports |
| Connection persister | 30s | Conntrack -> connection_history with GeoIP |
| Connection pruner | Daily | Prune closed connections > 30 days |
| Syslog listener | Realtime | UDP 5514, parse firewall logs |
| Behavior collector | 60s | Device observations, anomaly detection |
| Behavior maintenance | Daily | Baseline recompute, observation pruning, port flow baselines |
| Behavior auto-classifier | Hourly | Auto-resolve stale anomalies |
| Snapshot generator | Weekly | Geo + port Sankey snapshots |
| Session cleanup | 10 min | Expire old sessions |
| Cert rotation | Hourly | CertWarden expiry check + renewal |

---

## Data Persistence

| Database | Key Tables | Purpose |
|----------|------------|---------|
| `secrets.db` | `kek_cache`, `encrypted_secrets` | AES-256-GCM encrypted secrets |
| `traffic.db` | `traffic` | Lifetime WAN counters with reset detection |
| `speedtest.db` | `speedtest_results`, `speedtest_aggregates` | Speed test history |
| `metrics.db` | `metrics`, `drop_metrics`, `connection_metrics`, `vlan_metrics`, `log_aggregates` | Time-series metrics |
| `behavior.db` | `device_profiles`, `device_observations`, `baselines`, `anomalies` | Behavioral analysis |
| `connections.db` | `connection_history`, `port_flow_baseline`, `snapshots` | Connection history + snapshots |
| `geo.db` | `geo_cache` | ip-api.com lookup cache (7-day TTL) |

---

## Frontend Routes

| Route | Page | Key Visualizations |
|-------|------|--------------------|
| `/` | Dashboard | Stat cards, VLAN Sankey, VLAN activity chart, directional port Sankeys |
| `/connections` | Connections | Live table, geo summary, port Sankey |
| `/firewall` | Firewall | Filter/NAT/mangle rule tables, drop stats |
| `/interfaces` | Interfaces | Interface list with traffic counters |
| `/ip` | IP | Addresses, routes, DHCP, ARP, pools, DNS |
| `/logs` | Logs | Firewall log browser |
| `/network-map` | Network Map | D3 force-directed topology |
| `/behavior` | Behavior | Device profiles, anomalies, baselines |
| `/history` | History | World map (D3), weekly snapshots |
| `/speedtest` | Speedtest | Result display, provider breakdown, history |
| `/settings` | Settings | Secrets, cert, syslog, GeoIP, connection stats |

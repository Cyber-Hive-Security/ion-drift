# ion-drift — Feature List

## Overview

ion-drift is a Rust-based Mikrotik RouterOS management, monitoring, and network discovery platform. Manages a primary RB4011 router plus multiple managed switches with automatic device discovery, identity correlation, and topology visualization. Dual interface: CLI tool + Axum web server serving a React frontend. Authenticates via Keycloak OIDC. Deployed as Docker container behind Traefik.

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
| `mikrotik-core` | Shared RouterOS REST API client, resource models, SwitchStore (SQLite), BehaviorStore |
| `ion-drift-cli` | clap-based CLI binary with table/JSON/CSV output |
| `ion-drift-web` | Axum web server + React SPA, OIDC auth, 50+ API routes, 20+ background tasks |
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
- **Managed Secrets:** Router credentials, device credentials, OIDC client secret, session secret, CertWarden API keys, MaxMind credentials
- **Cert Rotation:** CertWarden integration, hourly expiry checks, auto-renewal within configurable threshold
- **Session Tokens:** 32-byte cryptographic random, login rate limiting
- **CORS:** Fail-closed (default reject, explicit allow list)
- **SSRF Guard:** Block private IP ranges in outbound requests
- **XSS Prevention:** HTML-escaped user input on display
- **Setup Mode:** Binds to localhost only until initial configuration completes
- **Endpoints:** `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/status`

---

## Multi-Device Management

### Device Registry

Supports registering and polling multiple Mikrotik devices (router + managed switches), each with independent credentials, polling interval, and TLS configuration. Device state is persisted in the encrypted secrets database.

- **Device Types:** `router` (one primary), `switch` (multiple)
- **Per-Device Config:** host, port, TLS toggle, custom CA cert path, polling interval (min 10s), model
- **Status Tracking:** Online (with RouterOS identity), Offline (with error), Unknown
- **Health Checks:** Per-device connectivity verification loop (30s startup delay)

### APIs

- `GET /api/devices` — List all devices with status
- `GET /api/devices/{id}` — Device details
- `POST /api/devices` — Register new device (tests connectivity first)
- `PUT /api/devices/{id}` — Update configuration
- `DELETE /api/devices/{id}` — Unregister (prevents primary router deletion)
- `POST /api/devices/{id}/test` — Health check
- `POST /api/devices/test` — Test arbitrary host (pre-registration validation)

---

## Switch Polling & Port Metrics

Background polling of each registered switch, collecting port metrics, MAC address tables, VLAN membership, and LLDP/MNDP neighbors.

### Polling Tasks

| Task | Interval | Data Collected |
|------|----------|----------------|
| Switch poller | Per-device interval | Ethernet interfaces, bridge hosts, bridge ports, bridge VLANs, port RX/TX metrics |
| Neighbor poller | 60s | LLDP/MNDP/CDP neighbor discovery from all devices |
| Device health check | Per-device interval | Connectivity status |

### Switch Data Tables

| Table | Purpose |
|-------|---------|
| `switch_port_metrics` | Per-port RX/TX bytes, packets, speed, running status (time-series) |
| `switch_mac_table` | MAC address learning: device_id, mac, port, bridge, vlan_id, is_local flag |
| `switch_vlan_membership` | Port-to-VLAN mapping with tagged/untagged status |
| `neighbor_discovery` | LLDP/MNDP neighbors: identity, platform, board, address, MAC |

### APIs

- `GET /api/devices/{id}/ports` — Port list with metrics
- `GET /api/devices/{id}/resources` — Switch resource metrics
- `GET /api/devices/{id}/mac-table` — Full MAC address table
- `GET /api/devices/{id}/vlans` — VLAN membership
- `GET /api/devices/{id}/port-roles` — Port role classifications
- `GET /api/devices/{id}/interfaces` — Interface details

---

## Correlation Engine

Runs every 60 seconds (90s startup delay) to synthesize unified network identities from disparate data sources. Five-stage pipeline:

### 1. Port Role Classification

Analyzes per-port MAC counts, VLAN counts, and LLDP neighbor presence to classify each switch port:

| Role | Criteria |
|------|----------|
| `trunk` | Multiple VLANs on port |
| `uplink` | LLDP neighbor present, or MAC count > 10 |
| `access` | Single MAC, no LLDP |
| `unused` | Zero MACs |

### 2. Switch-Local MAC Range Computation

Manufacturers assign sequential MACs to switch ports. Computes [min, max] range from `is_local=true` entries per device. All MACs in the range are filtered from identity assembly — prevents switch port MACs from leaking into endpoint identities.

### 3. Unified Identity Assembly

Merges data from 6 sources into a single identity per MAC address:

| Source | Fields Contributed |
|--------|-------------------|
| MAC table (all devices) | switch_device_id, switch_port, VLAN |
| LLDP/MNDP neighbors | IP, hostname, platform, device_type (0.95 confidence) |
| Router ARP table | MAC → IP |
| Router DHCP leases | MAC → IP + hostname (preferred over ARP) |
| PTR reverse DNS (Technitium) | Hostname for IPs without DHCP/LLDP name |
| OUI database | Manufacturer + device_type heuristic (0.5-0.6 confidence) |

### 4. VLAN Inference from IP

When VLAN not set by switch port, infers from IP subnet:
`10.2.2.x → VLAN 2`, `172.20.6.x → VLAN 6`, `10.20.25.x → VLAN 25`, `192.168.90.x → VLAN 90`, etc.

### 5. Port Binding Enforcement

Compares expected MACs (from `port_mac_bindings`) against actual on each port. Creates violations:
- `device_missing` — no MAC on bound port
- `mac_mismatch` — wrong MAC on bound port
- Auto-resolves when correct MAC reappears

### Confidence Scoring

Cumulative: IP (+0.2), hostname (+0.2), manufacturer (+0.15), switch_port (+0.15), discovery_protocol (+0.15), VLAN (+0.15). Max 1.0.

---

## OUI Database

Bundled IEEE OUI database (~40K entries) for MAC → manufacturer lookup. Loaded from `/data/oui.csv` at startup into an in-memory HashMap.

### Device Type Inference

Heuristic classification from manufacturer name with confidence scoring:

| Manufacturer Pattern | Inferred Type | Confidence |
|---------------------|---------------|------------|
| Hikvision, Dahua, Axis, Amcrest, Reolink | `camera` | 0.6 |
| Cisco, MikroTik, Ubiquiti, Netgear, TP-Link | `network_equipment` | 0.6 |
| HP, Canon, Epson, Brother | `printer` | 0.6 |
| Nest, Ecobee, Rachio, Ring, Wyze | `smart_home` | 0.6 |
| Nintendo, Sony Interactive, Valve | `gaming` | 0.6 |
| Synology, QNAP, Western Digital | `storage` | 0.6 |
| Roku, Amazon, Apple, Google, Sonos | `media_player` | 0.5 |
| Samsung, OnePlus, Xiaomi | `phone` | 0.5 |
| Dell, Lenovo, ASUS, Acer | `computer` | 0.5 |

---

## Passive Service Discovery

Replaces active nmap scanning with zero-traffic passive discovery via router connection tracking.

- **Method:** Reads router's firewall connection table, filters for `seen_reply=true` with internal destination IPs
- **Interval:** 120s (150s startup delay)
- **Storage:** `observed_services` table (IP, port, protocol, service_name, connection_count)
- **Retention:** Prunes services older than 7 days
- **Advantages:** No raw sockets, no elevated privileges, all VLANs simultaneously, continuous monitoring

---

## Network Identity Manager

User-facing interface for reviewing auto-discovered identities, setting manual overrides, and assigning security disposition tags.

### Disposition Tags

| Disposition | Meaning | Visual |
|-------------|---------|--------|
| `unknown` | Not yet categorized | Gray |
| `my_device` | Approved asset | Green |
| `external` | External/partner device | Blue |
| `ignored` | Intentionally hidden (filtered from topology) | Muted |
| `flagged` | Suspicious/alert-worthy | Red |

### Identity APIs

- `GET /api/network/identities/stats` — Summary statistics
- `GET /api/network/identities/review-queue` — Paginated unconfirmed identities
- `PUT /api/network/identities/{mac}` — Update device_type, human_label
- `POST /api/network/identities/bulk-confirm` — Batch confirm
- `PUT /api/network/identities/{mac}/disposition` — Set disposition
- `POST /api/network/identities/bulk-disposition` — Batch set disposition

### Port Binding APIs

- `GET /api/network/port-bindings` — List MAC-to-port bindings
- `POST /api/network/port-bindings` — Create binding
- `PUT /api/network/port-bindings/{device_id}/{port}` — Update binding
- `DELETE /api/network/port-bindings/{device_id}/{port}` — Remove binding
- `GET /api/network/port-violations` — Active violations
- `PUT /api/network/port-violations/{id}/resolve` — Resolve violation

### Observed Services API

- `GET /api/network/services` — Passively discovered services (optional IP filter)

### Frontend Features

- Stats dashboard: total/confirmed/unconfirmed counts, breakdowns by type/source/disposition
- Review queue table: inline edit for device_type and human_label, disposition badges
- Bulk actions: confirm multiple, set disposition for multiple
- Confidence indicators: green (confirmed), blue (LLDP), amber (automated), orange (low-confidence)
- Disposition filter: show all, hide ignored, or filter to specific disposition

---

## Network Topology

Auto-generated D3.js hierarchical topology map computed from device registry, LLDP neighbors, and correlated network identities.

### Topology Computation Engine

**Layer 1 — Infrastructure Skeleton:**
1. Registered devices (router + managed switches) with live Online/Offline status
2. LLDP/MNDP neighbors matched by identity name, IP, or MAC to registered devices
3. Unregistered neighbors with MikroTik platform → inferred infrastructure (UnmanagedSwitch or AccessPoint)
4. WAN-facing neighbors (router ether1) collapsed into single "WAN / ISP" node

**BFS Layer Assignment:**
Router = layer 0 → directly connected switches = layer 1 → downstream = layer N+1

**Layer 2 — Endpoint Placement:**
Network identities (excluding infrastructure MACs, registered device IPs, and switch-local MAC ranges) become endpoint nodes connected to their parent switch via access edges.

**Layer 3 — Orphan Handling:**
Endpoints without switch_device_id assigned to orphan layer.

### Deterministic Layout

- VLAN sectors sized proportionally to endpoint count per VLAN
- Infrastructure nodes centered across their served VLAN sectors
- Endpoints arranged in square grids within VLAN sectors below parent switch
- Grid spacing: 100px between nodes, 40px sector padding
- All collections sorted by primary key for deterministic positioning

### VLAN Configuration

| VLAN | Name | Color | Subnet |
|------|------|-------|--------|
| 2 | Network Mgmt | `#00f0ff` | 10.2.2.0/24 |
| 6 | Employer Isolated | `#888888` | 172.20.6.0/24 |
| 10 | Cyber Hive Security | `#ff4444` | 172.20.10.0/24 |
| 25 | Trusted Services | `#00b4d8` | 10.20.25.0/24 |
| 30 | Trusted Wired | `#22cc88` | 10.20.30.0/24 |
| 35 | Trusted Wireless | `#44ddaa` | 10.20.35.0/24 |
| 40 | Guest | `#ffaa00` | 10.20.40.0/24 |
| 90 | IoT Internet | `#666666` | 192.168.90.0/24 |
| 99 | IoT Restricted | `#444444` | 192.168.99.0/24 |

### Node Types

| Kind | Shape | Color |
|------|-------|-------|
| Router | Rounded rect 40x30 | Gold `#ffd700` |
| Managed/Unmanaged Switch | Rect 36x24 | VLAN color |
| Access Point | Circle r=14 + signal arcs | VLAN color |
| Server | Circle r=10 | VLAN color |
| Camera, IoT | Circle r=7 | VLAN color |
| Endpoint (default) | Circle r=8 | VLAN color or gray |

### Edge Types

| Kind | Style |
|------|-------|
| Trunk | Width 2.5, cyan, port labels at 15%/85% along edge |
| Uplink | Width 2, gold |
| Access | Width 0.8, subtle |
| Wireless | Width 0.8, dashed |

### D3 Visualization Features

- SVG layers: grid, VLAN backgrounds, edges, nodes, labels
- Zoom/pan (D3 zoom, scaleExtent 0.05–5x)
- Zoom-dependent labels: infra labels always visible, endpoint labels at scale > 0.5, IP sublabels at scale > 0.7, port labels at scale > 0.6
- Hover tooltip: label, kind, IP, MAC, VLAN, type, manufacturer, port
- Click → detail panel (right sidebar with full node info)
- Drag-to-reposition nodes (persists via position API)
- Pin icon for human-positioned nodes
- "N" badge for newly discovered nodes (< 24h)
- Flagged device: red dashed ring + warning icon
- External device: blue dashed border
- Status glow: green (online), red (offline), white (selected)
- VLAN filter chips (toggle VLAN visibility)
- Endpoint toggle (show/hide non-infrastructure)
- Search by label, IP, MAC, kind, manufacturer, VLAN
- Legend (collapsible, bottom-left)
- Status bar: device count, infrastructure count, endpoint count, connections, last computed

### Topology APIs

- `GET /api/network/topology` — Cached topology (30s frontend poll)
- `POST /api/network/topology/refresh` — Force recompute
- `GET /api/network/topology/positions` — All position records
- `PUT /api/network/topology/positions/{nodeId}` — Human position override
- `DELETE /api/network/topology/positions/{nodeId}` — Reset to auto layout

### Background Task

- Recomputes every 120s (120s startup delay)
- Logs: `nodes=N edges=N infra=N endpoints=N`

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
- Tooltip shows involved devices (hostname, IP, bytes, correlated indicator) for anomalous flows
- Banner includes device count per anomaly (e.g. "NEW port 445/SMB (12.3 GB, 2 devices)")

---

## Anomaly Cross-Reference (Unified Pipeline)

### Overview

Bridges the two independent anomaly systems (port flow baselines + device behavior) into a single correlated view. The `anomaly_links` table in connections.db stores cross-references between port-level and device-level anomalies.

### Correlation Engine

- **Background task:** Runs every 60s (5-minute startup delay)
- **Port -> Device:** For each anomalous port flow, identifies the devices (by MAC) generating traffic, checks for matching device anomalies in behavior.db
- **Device -> Port:** For each device anomaly (new_port/volume_spike), looks up the port's baseline status at the network level
- **Auto-creates:** Device anomalies from port flow detections when no behavior anomaly exists (source: "port_flow")
- **Auto-resolves:** Links older than 7 days or when underlying anomalies are resolved

### Severity Escalation

| Scenario | Correlated | Severity |
|----------|-----------|----------|
| Device uses new port + port also new at network level | Yes | **critical** |
| Device uses new port + port baselined (others use it) | No | **info** |
| Port new at network level + single device | — | **warning** |
| Port new at network level + multiple devices | — | **critical** |
| Both engines flag volume spike independently | Yes | **critical** |

### Data Model

- `anomaly_links` table: port_anomaly_type, flow_direction, protocol, dst_port, device_mac/ip/vlan/hostname, behavior_anomaly_id, correlated flag, source (port_flow/behavior/both), severity, device traffic stats, port baseline status

### APIs

- `GET /api/behavior/anomaly-links` — All unresolved cross-reference links
- `GET /api/behavior/anomaly-links/port/{protocol}/{port}?direction=` — Links for a specific port
- `GET /api/behavior/anomaly-links/device/{mac}` — Links for a specific device
- `POST /api/behavior/anomaly-links/{id}/resolve` — Resolve a link

### Frontend Integration

- **Sankey tooltip:** Anomalous flows show involved device list (name, IP, bytes, correlated bolt icon)
- **Sankey banner:** Each anomaly item includes device count
- **Behavior page:** Anomaly cards show "Network Context" section for correlator-created anomalies (source: port_flow), with device count and total network bytes
- **Device detail API:** Returns `port_flow_contexts` with port baseline status, correlated flag, other device count, network-level classification

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
- `/api/behavior/device/{mac}` — Device detail with observations + port flow contexts
- `/api/behavior/alerts` — Critical + alert severity anomalies
- `POST /api/behavior/anomalies/{id}/resolve` — Mark resolved
- `/api/behavior/anomaly-links` — Cross-reference links (see Anomaly Cross-Reference section)

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

## Tactical Network Map (Legacy)

- Hand-curated D3 force-directed topology (68 static nodes in `data.ts`)
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
| Network Devices | Device registry: add/edit/delete/test, per-device credentials, polling interval |
| Encrypted Secrets | Status of managed secrets, add/update interface, key fingerprint |
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
| Anomaly correlator | 60s | Cross-reference port flow + device anomalies |
| Snapshot generator | Weekly | Geo + port Sankey snapshots |
| Session cleanup | 10 min | Expire old sessions |
| Cert rotation | Hourly | CertWarden expiry check + renewal |
| Switch poller | Per-device | Port metrics, MAC tables, VLANs, bridge hosts |
| Neighbor poller | 60s | LLDP/MNDP/CDP discovery from all devices |
| Device health check | Per-device | Connectivity status for each registered device |
| Correlation engine | 60s | Port roles, MAC ranges, unified identity assembly |
| Topology updater | 120s | Recompute hierarchical graph from all data sources |
| Passive discovery | 120s | Service detection from conntrack (replaces nmap) |

---

## Data Persistence

| Database | Key Tables | Purpose |
|----------|------------|---------|
| `secrets.db` | `kek_cache`, `encrypted_secrets`, `devices`, `device_credentials` | AES-256-GCM encrypted secrets + device registry |
| `traffic.db` | `traffic` | Lifetime WAN counters with reset detection |
| `metrics.db` | `metrics`, `drop_metrics`, `connection_metrics`, `vlan_metrics`, `log_aggregates` | Time-series metrics |
| `behavior.db` | `device_profiles`, `device_observations`, `baselines`, `anomalies` | Behavioral analysis |
| `connections.db` | `connection_history`, `port_flow_baseline`, `anomaly_links`, `snapshots` | Connection history, anomaly cross-references, snapshots |
| `geo.db` | `geo_cache` | ip-api.com lookup cache (7-day TTL) |
| `switch.db` | `switch_port_metrics`, `switch_mac_table`, `switch_vlan_membership`, `neighbor_discovery`, `switch_port_roles`, `network_identities`, `observed_services`, `topology_positions`, `port_mac_bindings`, `port_violations` | Switch data, correlated identities, topology, port security |

---

## Frontend Routes

| Route | Page | Key Features |
|-------|------|--------------|
| `/` | Dashboard | Stat cards, VLAN Sankey, VLAN activity chart, directional port Sankeys |
| `/interfaces` | Interfaces | Interface list with traffic counters |
| `/ip` | IP | Addresses, routes, DHCP, ARP, pools, DNS |
| `/firewall` | Firewall | Filter/NAT/mangle rule tables, drop stats |
| `/connections` | Connections | Live table, geo summary, port Sankey |
| `/behavior` | Behavior | Device profiles, anomalies, baselines |
| `/history` | History | World map (D3), weekly snapshots |
| `/logs` | Logs | Firewall log browser |
| `/network-map` | Tactical Map | Hand-curated D3 force-directed topology (legacy) |
| `/network/identities` | Identity Manager | Review queue, disposition tags, MAC bindings, services |
| `/topology` | Network Topology | Auto-generated D3 hierarchical map, VLAN sectors, drag-to-pin |
| `/switches/$deviceId` | Switch Detail | Per-switch port metrics, MAC table, VLANs, port roles |
| `/settings` | Settings | Device registry, secrets, cert, syslog, GeoIP, connection stats |

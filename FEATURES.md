# ion-drift — Feature List

> **Last updated:** 2026-03-12 (`373892d`) — Authoritative VLAN ID lookup, security audit, investigation engine, drill-down navigation, settings refactor

## Overview

ion-drift is a Rust-based Mikrotik RouterOS management, monitoring, and network discovery platform. Manages a primary router plus multiple managed switches with automatic device discovery, identity correlation, and topology visualization. Dual interface: CLI tool + Axum web server serving a React frontend. Authenticates via OIDC (Keycloak or compatible). Deployed as Docker container behind a reverse proxy. All network configuration (VLANs, subnets, sensitivity levels) is stored in the database and configurable via UI — no hardcoded environment references in source code.

**Tech Stack:**
- Backend: Rust (Axum, Tokio async runtime, SQLite, `secrecy` for credential handling)
- Frontend: React 19 (Vite, TypeScript, TanStack Router v1 + Query v5, Recharts, D3.js, Tailwind CSS 4, `@tanstack/react-virtual` for table virtualization)
- Auth: Keycloak OIDC with PKCE flow, mTLS bootstrap for secrets encryption
- Router API: RouterOS v7 REST over HTTPS (Smallstep CA)

---

## Architecture

### Crate Structure

| Crate | Role |
|-------|------|
| `mikrotik-core` | RouterOS REST API client, SNMP client, SwOS client, resource models |
| `ion-drift-storage` | SQLite stores: BehaviorStore, SwitchStore, MetricsStore, TrafficTracker, VlanFlowManager |
| `ion-drift-cli` | clap-based CLI binary with table/JSON/CSV output |
| `ion-drift-web` | Axum web server + React SPA, OIDC auth, 60+ API routes, 22 background tasks |
| `web/` | React frontend (Vite + TypeScript) |

### Deployment

- 3-stage Dockerfile (Rust build, Node build, Debian slim runtime)
- Docker Compose with health check (`GET /health`)
- Config and CA cert provided at runtime via bind mounts (not baked into image)
- Persistent volume for SQLite databases, certs, GeoIP data
- Designed for deployment behind any reverse proxy (Traefik, nginx, etc.)
- **Demo mode:** `ION_DRIFT_MODE=demo` — sanitizes all IPs (mapped to 10.249.VLAN.host), VLAN names, IDs, and interface names for safe screenshots

---

## Authentication & Security

- **OIDC:** Keycloak (or any OIDC provider), PKCE flow, server-side sessions (DashMap + cookie)
- **mTLS Bootstrap:** Client cert to Keycloak for KEK (Key Encryption Key) retrieval
- **Secrets Encryption:** AES-256-GCM encrypted SQLite store, per-secret IVs, key fingerprint tracking
- **Managed Secrets:** Router credentials, device credentials, OIDC client secret, session secret, CertWarden API keys, MaxMind credentials
- **Cert Rotation:** CertWarden integration, hourly expiry checks, auto-renewal within configurable threshold
- **Session Tokens:** 32-byte cryptographic random, login rate limiting
- **CORS:** Fail-closed (default reject, explicit allow list)
- **SSRF Guard:** Block private IP ranges in outbound requests, URL-encoded bypass prevention
- **XSS Prevention:** HTML-escaped user input on display
- **Input Validation:** Centralized `validate_host()` and `validate_device_update()` for device management endpoints
- **Atomic Operations:** Device add/remove wrapped in SQLite transactions
- **Auth Logging:** Failed login attempts logged with session metadata
- **Password Handling:** `secrecy::SecretString` for router passwords (zeroized on drop)
- **Setup Mode:** Binds to localhost only until initial configuration completes
- **Endpoints:** `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/status`

---

## Multi-Device Management

### Device Registry

Supports registering and polling multiple Mikrotik devices (router + managed switches), each with independent credentials, polling interval, and TLS configuration. Device state is persisted in the encrypted secrets database.

- **Device Types:** `router` (one primary RouterOS), `switch` (RouterOS), `swos_switch` (SwOS HTTP), `snmp_switch` (SNMPv2c/v3)
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
| Switch poller (RouterOS) | Per-device interval | Ethernet interfaces, ethernet monitor (actual negotiated speed), bridge hosts, bridge ports, bridge VLANs, port RX/TX metrics |
| Switch poller (SwOS) | Per-device interval | Link status, port counters, VLAN membership, host table (HTTP Digest auth, serialized requests) |
| Switch poller (SNMP) | Per-device interval | ifTable/ifXTable (ifHighSpeed for actual link speed), ifHCInOctets/ifHCOutOctets, physical port filtering |
| Neighbor poller | 60s | LLDP/MNDP/CDP neighbor discovery from RouterOS devices |
| Device health check | Per-device interval | Connectivity status (all device types via `DeviceClient::test_connection()`) |

### Switch Data Tables

| Table | Purpose |
|-------|---------|
| `switch_port_metrics` | Per-port RX/TX bytes, packets, speed (actual negotiated from monitor/ifHighSpeed), running status (time-series) |
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

Runs every 60 seconds (90s startup delay) to synthesize unified network identities from disparate data sources. Seven-stage pipeline:

### 1. Port Role Classification

Analyzes per-port MAC counts, VLAN counts, and LLDP neighbor presence to classify each switch port. Runs across all device types (RouterOS, SwOS, SNMP):

| Role | Criteria |
|------|----------|
| `trunk` | Multiple VLANs on port |
| `uplink` | LLDP neighbor present, or MAC count > 10 |
| `access` | Single MAC, no LLDP |
| `unused` | Zero MACs |

Port names are **case-normalized** (`to_lowercase()`) on storage and lookup to prevent mismatches between polled data (e.g. "310-SFP+1") and backbone links (e.g. "310-sfp+1").

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

### 4. Depth-Based Priority Scoring

Switch binding priority uses BFS depth from the router through backbone links instead of flat tiers:

```
priority = base_class * 100 + depth * 10
```

| Base Class | Value | Description |
|------------|-------|-------------|
| Router trunk | 1 | Sees every MAC via ARP gateway |
| Switch trunk | 2 | Downstream aggregation |
| Access port | 3 | Directly connected |

**Examples:** Camera MAC on rb4011 trunk (depth 0) = 100, CRS326 trunk (depth 1) = 210, CRS310 trunk (depth 2) = 220, CRS326 access port (depth 1) = 310.

Equal priority → no change (eliminates flapping between same-class ports from alternating poll order). Trunk redirection uses `200 + peer_depth * 10` (downstream-only — higher depth redirects to lower depth peer). Access port priority inverted: shallower access wins (closer to router = higher priority). Switch depth computed from LLDP adjacency and backbone links.

### 5. WAP Attribution

Devices on wireless VLANs (determined by `vlan_config.media_type`) are re-attributed from their switch to a WAP when:
1. The device's current `switch_device_id` has exactly one WAP child in the backbone links
2. The WAP is identified via `device_type` = `access_point` or `wap` in infrastructure identities

This requires backbone links from edge switches to WAPs (configured via the Backbone Links page).

### 6. VLAN Inference from IP

When VLAN not set by switch port, infers from IP subnet using CIDR matching against `vlan_config` entries. Each configured VLAN's subnet is parsed and matched (longest prefix first) against the device's IP address.

### 7. Port Binding Enforcement

Compares expected MACs (from `port_mac_bindings`) against actual on each port. Creates violations:
- `device_missing` — no MAC on bound port
- `mac_mismatch` — wrong MAC on bound port
- Auto-resolves when correct MAC reappears

### Confidence Scoring

Cumulative: IP (+0.2), hostname (+0.2), manufacturer (+0.15), switch_port (+0.15), discovery_protocol (+0.15), VLAN (+0.15). Max 1.0.

---

## Topology Inference Engine

Probabilistic MAC attachment resolver that replaces the deterministic depth-based priority scoring (Section 4 above) with a weighted candidate scoring pipeline. Controlled by `TOPOLOGY_INFERENCE_MODE` environment variable.

### Operating Modes

| Mode | Behavior |
|------|----------|
| `legacy` | Old deterministic binding only. Inference disabled. |
| `shadow` | Both old and new run. New results logged but not applied to identities. |
| `active` | New inference replaces old binding logic. (Current mode.) |

### Pipeline

For each active MAC address in the observation window (10 minutes):

1. **Candidate Generation** — Each unique (device_id, port_name) pair from recent MAC observations becomes a candidate. Additional candidates generated for wireless parents (WAP attribution via AP feeder map) and human overrides.
2. **Pruning** — Candidates on trunk/uplink ports are suppressed (with reason). Router-bound candidates suppressed when access-port alternatives exist. Wired device types (`camera`, `printer`, `server`, `switch`, `router`) never generate WAP candidates.
3. **Scoring** — 13-feature weighted scoring per candidate:

| Feature | Weight | Description |
|---------|--------|-------------|
| Edge likelihood | 2.0 | Port role probability of being an access port |
| Persistence | 1.5 | Observation frequency within window |
| VLAN consistency | 1.2 | Match between candidate VLAN and identity VLAN |
| Downstream preference | 1.0 | Deeper switches preferred over upstream |
| Recency | 0.8 | More recent observations weighted higher |
| Graph depth | 0.6 | BFS depth from router in infrastructure graph |
| Device class fit | 0.6 | Device type matches expected port behavior |
| Transit penalty | -2.0 | Penalizes trunk/uplink candidates |
| Contradiction penalty | -1.5 | Penalizes candidates contradicting other evidence |
| Router penalty | -3.0 | Strongly suppresses router as attachment point |
| Wireless attachment likelihood | 0.5 | Wireless VLAN + WAP feeder port alignment |
| WAP path consistency | 0.3 | WAP candidate matches AP feeder topology |
| AP feeder penalty | -1.0 | Penalizes non-WAP candidates on WAP feeder ports |

4. **Winner Selection** — Highest-scoring non-suppressed candidate wins. Margin of victory (gap to runner-up) factors into confidence.

### Attachment State Machine

Per-MAC state tracked with confidence progression:

```
Unknown -> Candidate (1 win) -> Probable (3 wins) -> Stable (10 wins)
```

Additional states: `Roaming` (binding changed), `Conflicted` (low-margin winner), `HumanPinned` (manual override).

Each state tracks: current/previous device+port, score, confidence (0.0-1.0), consecutive wins/losses.

### Infrastructure Graph

BFS-computed graph of registered devices connected via LLDP neighbors and backbone links. Used for depth scoring and downstream preference calculations. Devices resolved by identity name, IP, or MAC to registered device IDs.

### SNMP Port Name Canonicalization

SNMP agents (e.g. Netgear MS510TXPP) expose the same physical port under multiple MIB naming conventions (`mg5`, `twopointfivegigabitethernet5`, `port5`). All are normalized to `portN` canonical form so MAC counts, VLAN counts, and role probabilities aggregate correctly.

### Divergence Analytics

When running in shadow or active mode, tracks divergences between inference bindings and legacy bindings. Categorized as:
- `port_alias_only` — Same device, canonical ports match (naming difference only)
- `router_fallback` — Legacy was bound to router, inference found a better switch
- `wireless_parent_preferred` — Inference resolved to a WAP
- `better_downstream_access` — Same device, inference found a better port
- `different_switch` — Completely different device

### APIs

- `GET /api/network/inference/status` — Mode, MAC count, state distribution, avg confidence, divergence stats
- `GET /api/network/inference/mac/{mac}` — Per-MAC detail: attachment state, current binding, scored candidates, explanation
- `GET /api/network/inference/observations` — Recent observation stats (total, unique MACs, per-device counts)
- `GET /api/network/inference/states` — All attachment state rows

### Frontend

`/inference` — Diagnostic dashboard with:
- Status cards: mode badge, total MACs, average confidence, divergence count
- State distribution breakdown
- Divergence category breakdown
- Attachment states table with state badges (color-coded by confidence level)
- Per-MAC drill-down: scored candidates with feature breakdowns, explanation text, current vs inferred binding comparison

### Background Task

- Runs as part of the correlation engine cycle (60s interval)
- In active mode: writes resolved bindings back to `network_identities`
- In shadow mode: writes attachment states only, does not modify identities

### Data Persistence

| Table | Database | Purpose |
|-------|----------|---------|
| `mac_observations` | `switch.db` | Recent MAC sightings per (device, port) with timestamps |
| `attachment_states` | `switch.db` | Per-MAC state machine state, scores, confidence |
| `port_role_probabilities` | `switch.db` | Per-port role probability distributions |

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

- `GET /api/network/identities/infrastructure` — Infrastructure-flagged identities (WAPs, unmanaged switches, network equipment)
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
- Review queue table: inline edit for device_type, human_label, switch binding, infrastructure flag
- Per-field reset buttons: revert individual overrides to auto-detected state
- Link speed column: shows polled port speed from switch_port_metrics (defaults to 1G when null)
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

- **Center-spine model:** Lowest VLAN ID rendered as vertical center spine; other VLANs balanced into left/right columns using greedy assignment by device count
- VLAN sectors sized proportionally to endpoint count per VLAN
- Infrastructure nodes centered across their served VLAN sectors
- Endpoints arranged in square grids within VLAN sectors below parent switch
- Grid spacing: 100px between nodes, 40px sector padding
- All collections sorted by primary key for deterministic positioning

### VLAN Configuration

VLAN metadata (name, color, subnet, media type, sensitivity) is stored in the `vlan_config` SQLite table, editable via Settings UI and API. Synced from router on startup (pulls VLAN interfaces with subnets). No hardcoded VLAN data in source code — unknown VLANs get a generic "VLAN N" label with gray color.

**Fields per VLAN:**
| Field | Description |
|-------|-------------|
| `name` | Display name (e.g. "Trusted Services") |
| `interface_name` | Router interface name (e.g. "V-90-IoT") — authoritative mapping for VLAN ID resolution |
| `media_type` | `wired`, `wireless`, or `mixed` — controls WAP attribution |
| `subnet` | CIDR notation (e.g. "10.20.25.0/24") — used for IP→VLAN matching |
| `color` | Hex color for UI rendering |
| `sensitivity` | Behavior engine sensitivity: `strictest`, `strict`, `moderate`, `loose`, `monitor` |

**Runtime Architecture:**
- **Backend:** `VlanRegistry` (in `ion-drift-storage/src/behavior.rs`) loaded from `vlan_config` table at startup, stored as `Arc<RwLock<VlanRegistry>>` in `AppState`. Provides CIDR-based IP→VLAN matching, sensitivity lookups, anomaly severity, and auto-resolve timeouts. Shared across all background tasks (behavior engine, connection store, syslog, anomaly correlator, scanner).
- **Frontend:** `useVlanLookup()` hook (in `hooks/use-vlan-lookup.ts`) fetches from `/api/network/vlan-config` via TanStack Query. Provides `configs`, `colors`, `names`, `subnets` maps plus `color()`, `name()`, `subnet()`, and `ipToVlanLabel()` helper functions with CIDR matching. All components use this hook — no hardcoded VLAN constants.

**VLAN Config APIs:**
- `GET /api/network/vlan-config` — List all VLAN configs
- `PUT /api/network/vlan-config/{vlan_id}` — Upsert config (validates media_type ∈ {wired, wireless, mixed})

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
| Trunk | Port labels at 15%/85% along edge |
| Uplink | Gold |
| Access | Subtle, width 0.8 |
| Wireless | Dashed, width 0.8 |

### Speed-Based Edge Styling

Edges are colored and sized by link speed (from polled port metrics or backbone link manual speed):

| Speed Tier | Color | Width |
|------------|-------|-------|
| 10G | Gold `#ffd700` | 3.5 |
| 5G | Dark orange `#ff8c00` | 2.5 |
| 2.5G | Silver `#c0c0c0` | 2.0 |
| 1G | Cyan `#00f0ff` | 1.2 |
| < 1G | Gray `#666666` | 0.8 |
| Unknown | Cyan `#00f0ff` | 1.2 |

### Traffic-Based Edge Thickness

When live traffic data is available, edge stroke width scales by log10 of bits per second (overrides speed-tier width). Range: 0.6px (idle) to 6px (heavy traffic). Traffic rate computed from delta between two most recent port metric samples.

### D3 Visualization Features

- SVG layers: grid, VLAN backgrounds, edges, nodes, labels
- Zoom/pan (D3 zoom, scaleExtent 0.05–5x)
- Zoom-dependent labels: registered infra always visible, unregistered infra at scale > 0.5, endpoint labels at scale > 0.5, port labels at scale > 0.8, endpoint label staggering (±5px alternating Y offset)
- Hover tooltip: label, kind, IP, MAC, VLAN, type, manufacturer, port
- Click → detail panel (right sidebar with full node info)
- Drag-to-reposition nodes (persists via position API)
- Draggable/resizable VLAN sectors (drag header label, resize bottom-right handle, persists via sector position API)
- Pin icon for human-positioned nodes and sectors (click to reset)
- "N" badge for newly discovered nodes (< 24h)
- Flagged device: red dashed ring + warning icon
- External device: blue dashed border
- Status glow: green (online), red (offline), white (selected)
- VLAN filter chips (toggle VLAN visibility)
- Endpoint toggle (show/hide non-infrastructure)
- Search by label, IP, MAC, kind, manufacturer, VLAN
- Legend (collapsible, draggable, bottom-left) with speed tier color key, node shapes, and edge styles
- Status bar: device count, infrastructure count, endpoint count, connections, last computed
- Collapsible sidebar on desktop

### Topology APIs

- `GET /api/network/topology` — Cached topology (30s frontend poll)
- `POST /api/network/topology/refresh` — Force recompute
- `GET /api/network/topology/positions` — All node position records
- `PUT /api/network/topology/positions/{nodeId}` — Human node position override
- `DELETE /api/network/topology/positions/{nodeId}` — Reset node to auto layout
- `GET /api/network/topology/sectors` — All sector position records
- `PUT /api/network/topology/sectors/{vlanId}` — Human sector position/size override
- `DELETE /api/network/topology/sectors/{vlanId}` — Reset sector to auto layout

### Backbone Links

Manual switch-to-switch interconnect configuration for devices without LLDP support (e.g. SwOS switches). Solves the problem where non-LLDP switches claim downstream devices because their uplink ports aren't classified as trunks.

**How it works:**
1. User defines a link between two devices (with optional port names and label)
2. Correlation engine forces linked ports to `trunk` role, overriding auto-detection
3. Correlation engine populates trunk peer map, enabling MAC redirection from the non-LLDP switch to the correct peer
4. Correlation engine uses backbone links for BFS depth computation (deeper switches = higher priority)
5. Topology engine creates trunk edges from backbone links (deduplicated against LLDP-discovered edges)

**Storage:** `backbone_links` table — device_a, port_a, device_b, port_b, label, link_type, speed_mbps, created_at. Devices normalized lexicographically on insert. Port names case-normalized to lowercase.

**APIs:**
- `GET /api/network/backbone-links` — List all backbone links
- `POST /api/network/backbone-links` — Create link (device_a, port_a?, device_b, port_b?, label?, link_type?, speed_mbps?)
- `PUT /api/network/backbone-links/{id}` — Update link (port_a, port_b, label, link_type, speed_mbps — devices not editable)
- `DELETE /api/network/backbone-links/{id}` — Delete link
- `GET /api/devices/{id}/ports` — Port list for port dropdowns

**Frontend:** `/network/backbone` — Configuration table with inline add form. Device selectors show two optgroups: "Managed Devices" (from device registry) and "Discovered Infrastructure" (WAPs, unmanaged switches from infrastructure identities API). Port dropdowns populated from device port-list API (managed devices) or free-text (infrastructure). Link type dropdown (DAC, Fiber, Ethernet, default). Speed dropdown (100M, 1G, 2.5G, 5G, 10G). Inline row editing: click pencil icon to edit ports/type/speed/label in-place with Save/Cancel. Delete button per row.

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

- **VLAN Flow Counters:** Auto-creates mangle rules for inter-VLAN + WAN traffic accounting. Flow data enriched with router-authoritative VLAN IDs from `/interface/vlan` (never parsed from interface names).
- **Syslog Configuration:** Auto-creates remote logging action, firewall topic routing rule, and filter log rules for new connections on forward + input chains
- **Firewall Log Rules:** `action=log, connection-state=new, log-prefix=ION` at top of forward and input chains

---

## Dashboard

| Card | Data Source |
|------|------------|
| Firewall Drops | Drop rule byte/packet counters, links to `/firewall` |
| WAN Traffic | Interface RX/TX counters, live rate calculation, links to `/connections` |
| Network Devices | Registered device status (online/offline) |
| Connections | Conntrack count by protocol (TCP/UDP/other), flagged count |
| Identity Overview | Device identity stats from correlation engine |
| DHCP Leases | Active lease count, subnet utilization |
| Investigations | Recent automated investigation verdicts |
| VLAN Activity | Per-VLAN RX/TX sparklines, expandable charts, investigate link per VLAN |
| System History | CPU load + memory usage area charts (24h / 7d toggle) |
| VLAN Sankey | Inter-VLAN traffic flows (mangle rule byte counters), click-to-investigate |
| Directional Port Sankeys | Outbound/Inbound/Internal port flows with anomaly detection |
| Uptime | System uptime |

**Resilience:** Each card wrapped in `CardErrorBoundary` — a single card failure doesn't crash the page. Range selector uses `keepPreviousData` to prevent flash on time-range toggle.

**VLAN ID Resolution:** Sankey click handler and VLAN Activity investigate links use router-authoritative VLAN IDs from `VlanFlow.source_vlan_id`/`target_vlan_id` and `VlanActivityEntry.vlan_id` — no regex parsing of interface names.

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

- **Auto-Download:** If MaxMind credentials exist but `.mmdb` files are missing, downloads from MaxMind API on startup
- **Hot-Swap:** After download, databases loaded into memory without restart
- **Monitored Regions:** Admin-configurable list of country codes (ISO 3166-1 alpha-2) highlighted on the world map. Empty by default — no countries flagged until explicitly configured via Settings > Monitored Regions. Persisted in `app_settings` SQLite table, loaded at startup, mutable at runtime via `RwLock`.

### World Map Visualization

- D3.js orthographic projection with Natural Earth TopoJSON
- Country-level arcs from home location to destination countries, width scaled by bytes
- City-level arcs to individual U.S. cities with log-scaled width
- City dots sized by connection count, colored by monitored region status
- Zoom/pan controls (scroll zoom 1-12x, drag pan, +/-/reset buttons)
- Tooltip with country, connection count, unique IPs, bytes, top orgs

---

## Port Sankey & Anomaly Detection

### Directional Sankeys

- **Outbound:** `dst_is_external = 1` (internal -> external)
- **Inbound:** `dst_is_external = 0 AND src_vlan IS NULL` (external -> internal)
- **Internal:** `dst_is_external = 0 AND src_vlan IS NOT NULL` (both internal)
- Minimum 100KB traffic filter
- **Ephemeral port noise filter** (`is_significant_port_flow`): Known service ports always included; ephemeral ports (>= 49152) require >= 1 GB to appear; other ports require >= 5 flows and >= 10 KB. Applied at baseline computation, anomaly classification, and disappeared-flow detection.

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

## Investigation Engine

Automated anomaly investigation that enriches each anomaly with contextual intelligence and produces a verdict + recommended action. Runs as part of the alert engine cycle — every new anomaly is investigated before alert delivery.

### Investigation Context

Each investigation gathers:

| Context | Source |
|---------|--------|
| Device profile | MAC, hostname, manufacturer, baseline status, disposition, first seen |
| VLAN sensitivity | From `vlan_config` table |
| Destination intelligence | Reverse DNS, GeoIP (country, city, ASN, org), CDN detection |
| Destination commonality | How many other devices talk to the same destination |
| Anomaly history | Prior anomaly counts (24h, 7d), same-pattern recurrence (24h) |
| Baseline coverage | Percentage of device's traffic covered by baselines |
| Volume context | Current bytes vs baseline bytes, volume ratio |
| Behavioral breadth | Unique destinations and ports in the last hour |
| Firewall correlation | Matching rule ID, action, comment |

### Verdicts

| Verdict | Meaning |
|---------|---------|
| `benign` | Normal behavior, no concern |
| `routine` | Expected pattern, low priority |
| `suspicious` | Warrants attention |
| `threat` | Active threat indicator |
| `inconclusive` | Insufficient context to determine |

Each verdict includes: `recommended_action`, `reason` (human-readable), `summary`, `evidence_chain` (structured JSON), and `duration_ms`.

### APIs

- `GET /api/sankey/network` — Network-level VLAN flow summary with anomaly counts
- `GET /api/sankey/vlan/{vlan_id}` — VLAN drill-down: devices, flows, flow states
- `GET /api/sankey/device/{mac}` — Device drill-down: protocols, destinations, individual flows
- `GET /api/sankey/conversation/{mac}/{dst_ip}` — Conversation detail: timeline, connection list
- `GET /api/sankey/destination/{dst_ip}/peers` — All devices talking to a destination

### Frontend: Drill-Down Navigation

Multi-level investigation flow from dashboard to individual conversations:

```
Dashboard VLAN Sankey → /sankey (network overview)
  → Click VLAN → VLAN detail (devices + flows)
    → Click device → Device detail (protocols + destinations)
      → Click destination → Conversation detail (timeline + connections)
```

Each level is a `/sankey` route with progressive URL search params (`vlan`, `dest`, `mac`, `country`). Investigate links (microscope icon) appear on dashboard cards, VLAN activity rows, behavior anomalies, and connection tables.

---

## Behavior Engine (v3)

Treats firewall policy as the authoritative definition of network intent. All anomalies are classified against firewall policy, enriched with zone and traffic class metadata, and fed through operator workflow tools.

### Processing Pipeline

```
Network Telemetry → Event Normalization → Traffic Classification →
Firewall Policy Correlation → Policy Outcome Classification →
Context Enrichment → Behavioral Baseline Analysis →
Correlation Engine → Anomaly Queue → Operator Review
```

### Device Profiling

- **Collection:** Every 60s — ARP + DHCP correlation, active connections grouped by source MAC
- **Profile:** MAC, hostname, manufacturer (OUI), IP, VLAN, last_seen
- **Observations:** Per-cycle aggregation of (protocol, dst_port, dst_subnet, direction) with bytes and flow counts

### Traffic Classification

Every event is classified into a traffic type based on direction, protocol, and destination port:

| Class | Trigger |
|-------|---------|
| `internet_scan` | Inbound unsolicited traffic |
| `dhcp_activity` | DHCP ports (67/68) |
| `broadcast_service` | ARP or broadcast protocols |
| `internal_service_access` | Internal-to-internal non-lateral |
| `external_service_access` | Outbound to external |
| `management_protocol` | SSH, SNMP, WinBox, API ports (22, 23, 161, 443, 8291, etc.) |
| `lateral_movement` | Lateral traffic to SSH, SMB, RDP (22, 445, 3389) |
| `unknown` | Unclassified |

### Firewall Policy Correlation

Every anomaly is correlated against cached RouterOS firewall filter rules (`/ip/firewall/filter`). Cache refreshed every 5 minutes.

**Policy Outcomes:**

| Outcome | Meaning | Action |
|---------|---------|--------|
| `expected_allow` | Matches a permit rule | Baseline tracking only |
| `expected_deny` | Matches a deny rule (blocked attempts) | Informational telemetry |
| `policy_unknown` | No matching rule found | Full anomaly analysis |

Correlation matches on source/destination IP (CIDR), protocol, and destination port (ranges supported). Matching rules contribute rule ID and comment to the anomaly record.

### Network Zone Model

VLANs are mapped to trust zones based on VLAN name heuristics:

| Zone | VLAN Name Pattern |
|------|-------------------|
| WAN | External/non-internal IPs |
| Services | Contains "service" or "server" |
| Management | Contains "manage" or "admin" |
| IoT | Contains "iot" |
| Guest | Contains "guest" |
| Infrastructure | Contains "infra" |
| Trusted | Default for internal VLANs |

Source and destination zones are recorded on every anomaly for cross-zone analysis.

### Baselines & Anomaly Detection

- **Baseline Window:** 7 days of observations
- **Device Lifecycle:** `new_device` → `learning` (7 days) → `sparse` / `baselined`
- **Anomaly Types:** `new_port`, `new_protocol`, `new_destination`, `volume_spike`, `blocked_attempt`
- **Volume Spike Thresholds:** projected_hourly > baseline_max × 3 AND > baseline_avg × 5 AND > 5 MB floor, with multi-window persistence (2+ elevated observations in 300s)
- **Severity:** Based on per-VLAN `sensitivity` setting (strictest → critical, strict → alert/warning, moderate → warning/info, loose/monitor → info), escalated by priority boosts from operator flagging
- **Auto-Resolution:** TTL-based per sensitivity level (strictest = never, strict = 72h, moderate = 48h, loose = 24h, monitor = 12h)
- **Blocked Attempts:** Detected from firewall drop rules, correlated with GeoIP, always classified as `expected_deny`
- **Confidence Model:** Factors: baseline maturity, observation count, baseline age, policy alignment, VLAN sensitivity, priority boosts. Range: 0.0–1.0.

### Anomaly Queue Management

**Queue States:** `pending` → `accepted` / `dismissed` / `flagged` / `auto_dismissed` → `archived`

**Bulk Actions:**
- Bulk accept/dismiss/flag by anomaly IDs
- Archive reviewed (moves accepted/dismissed/flagged/auto_dismissed → archived)
- Delete archived (hard delete, admin only)

**Safe Queue Clearing:** Archive reviewed clears the queue without losing data. Hard delete requires explicit `delete_archived` action.

### Pattern Suppression

Operators can suppress repeating anomaly patterns. Suppression rules match on any combination of:

| Field | Match |
|-------|-------|
| `device_id` | Specific MAC or NULL (any device) |
| `vlan` | Specific VLAN or NULL (any) |
| `protocol` | tcp/udp/icmp or NULL |
| `destination_port` | Specific port or NULL |
| `traffic_class` | Specific class or NULL |

Most-specific rule wins (ranked by number of non-NULL fields). Suppressed anomalies are skipped during detection. Suppression rules stored in `anomaly_suppressions` table.

### Operator Feedback Loop

Resolving an anomaly triggers side effects:

| Action | Effect |
|--------|--------|
| `accepted` | Recompute device baselines (reinforces the behavior as normal) |
| `dismissed` | Auto-create suppression rule for that anomaly's pattern |
| `flagged` | Increment priority boost — future matching anomalies get escalated severity and higher confidence |

Priority boosts stored in `anomaly_priority_boosts` table, keyed by pattern (device + vlan + protocol + port + traffic_class).

### CSV Export

Export anomalies with full policy context for offline analysis.

**Fields:** severity, device, device_mac, device_ip, anomaly_type, flow, vlan, confidence, timestamp, status, anomaly_id, policy_outcome, traffic_class, source_zone, destination_zone

**Filename:** `ion-drift-anomalies-YYYYMMDD.csv`

Supports filtering by status, severity, VLAN, and limit. All fields properly quoted for CSV safety.

### Anomaly Detail Fields

Each anomaly record includes:

| Field | Source |
|-------|--------|
| `policy_outcome` | Firewall correlation result |
| `traffic_class` | Traffic classification |
| `source_zone` | VLAN-to-zone mapping |
| `destination_zone` | VLAN-to-zone mapping |
| `firewall_correlation` | Match type (expected_allow/deny/policy_unknown) |
| `firewall_rule_id` | RouterOS rule `.id` |
| `firewall_rule_comment` | Rule comment from RouterOS |

### APIs

- `GET /api/behavior/overview` — Device count, anomaly breakdown, per-VLAN summaries
- `GET /api/behavior/anomalies` — Filtered anomaly list (status, severity, vlan, limit)
- `GET /api/behavior/anomalies/export.csv` — CSV export with policy fields
- `GET /api/behavior/device/{mac}` — Device detail with baselines, anomalies, port flow contexts
- `GET /api/behavior/vlan/{vlan_id}` — VLAN detail with devices and anomalies
- `GET /api/behavior/alerts` — Pending anomaly counts (total, critical, warning)
- `POST /api/behavior/anomalies/{id}/resolve` — Resolve with feedback loop (accepted/dismissed/flagged)
- `POST /api/behavior/anomalies/bulk` — Bulk resolve/archive/delete
- `GET /api/behavior/suppressions` — List pattern suppression rules
- `POST /api/behavior/suppressions` — Create suppression rule
- `DELETE /api/behavior/suppressions/{id}` — Delete suppression rule
- `GET /api/behavior/anomaly-links` — Cross-reference links (see Anomaly Cross-Reference section)

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

Tabbed layout with URL-synced tab selection (`/settings?tab=...`). Each tab is a separate component for code splitting.

| Tab | Section | Features |
|-----|---------|----------|
| Devices | Network Devices | Device registry: add/edit/delete/test, per-device credentials, polling interval |
| VLANs | VLAN Configuration | Editable table: VLAN ID, name, interface name (read-only, from router), media type dropdown, subnet, color picker. Auto-saves on change. |
| Security | Encrypted Secrets | Status of managed secrets, add/update interface, key fingerprint |
| Security | mTLS Certificate | Subject, issuer, expiry countdown, auto-renewal status |
| Security | Encryption Key | KEK fingerprint, source (Keycloak mTLS), secrets integrity check |
| Alerts | Alert Rules | Event-type triggers, severity/VLAN/disposition filters, delivery channels (ntfy, webhook), cooldown, alert history |
| System | Monitored Regions | Tag-based add/remove of ISO 3166-1 alpha-2 country codes |
| System | Syslog Listener | Status, port, event counts, RouterOS config reference |
| System | GeoIP Database | MaxMind loaded/not, credentials configured, fallback status |
| System | Connection History | Record count, database size, retention, oldest record |

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
| Behavior collector | 60s | Device observations, anomaly detection, firewall correlation, suppression matching, priority boost application |
| Behavior maintenance | Daily | Baseline recompute, observation pruning, port flow baselines, traffic pattern classification |
| Behavior auto-classifier | Hourly | Auto-resolve stale anomalies per VLAN timeout |
| Alert engine | 60s | Evaluate alert rules against anomalies, send notifications |
| Anomaly correlator | 60s | Cross-reference port flow + device anomalies |
| Snapshot generator | Weekly | Geo + port Sankey snapshots |
| Session cleanup | 10 min | Expire old sessions |
| Cert rotation | Hourly | CertWarden expiry check + renewal |
| Switch poller | Per-device | Port metrics, MAC tables, VLANs, bridge hosts |
| Neighbor poller | 60s | LLDP/MNDP/CDP discovery from all devices |
| Device health check | Per-device | Connectivity status for each registered device |
| Correlation engine | 60s | Port roles, MAC ranges, unified identity assembly |
| Topology inference | 60s | Probabilistic MAC attachment scoring (runs within correlation cycle) |
| Topology updater | 120s | Recompute hierarchical graph from all data sources |
| Passive discovery | 120s | Service detection from conntrack (replaces nmap) |

---

## Data Persistence

| Database | Key Tables | Purpose |
|----------|------------|---------|
| `secrets.db` | `kek_cache`, `encrypted_secrets`, `devices`, `device_credentials` | AES-256-GCM encrypted secrets + device registry |
| `traffic.db` | `traffic` | Lifetime WAN counters with reset detection |
| `metrics.db` | `metrics`, `drop_metrics`, `connection_metrics`, `vlan_metrics`, `log_aggregates` | Time-series metrics |
| `behavior.db` | `device_profiles`, `device_observations`, `device_baselines`, `device_anomalies`, `anomaly_suppressions`, `anomaly_priority_boosts`, `engine_metadata`, `scheduler_watermarks` | Behavioral analysis, pattern suppression, operator feedback |
| `connections.db` | `connection_history`, `port_flow_baseline`, `anomaly_links`, `snapshots` | Connection history, anomaly cross-references, snapshots |
| `geo.db` | `geo_cache` | ip-api.com lookup cache (7-day TTL) |
| `switch.db` | `switch_port_metrics`, `switch_mac_table`, `switch_vlan_membership`, `neighbor_discovery`, `switch_port_roles`, `network_identities`, `observed_services`, `topology_positions`, `topology_sector_positions`, `backbone_links`, `vlan_config`, `port_mac_bindings`, `port_violations`, `mac_observations`, `attachment_states`, `port_role_probabilities` | Switch data, correlated identities, topology, backbone links, VLAN config, port security, inference state |

---

## Frontend Routes

| Route | Page | Key Features |
|-------|------|--------------|
| `/` | Dashboard | Stat cards, VLAN Sankey, VLAN activity chart, system history, directional port Sankeys |
| `/interfaces` | Interfaces | Interface list with traffic counters |
| `/ip` | IP | Addresses, routes, DHCP, ARP, pools, DNS |
| `/firewall` | Firewall | Filter/NAT/mangle rule tables, drop stats |
| `/connections` | Connections | Live table, geo summary, port Sankey |
| `/behavior` | Behavior | Device profiles, anomalies, baselines (virtualized tables) |
| `/sankey` | Investigation | Multi-level drill-down: network → VLAN → device → conversation |
| `/history` | History | World map (D3), weekly snapshots |
| `/logs` | Logs | Firewall log browser |
| `/network-map` | Tactical Map | Hand-curated D3 force-directed topology (legacy) |
| `/network/identities` | Identity Manager | Review queue, disposition tags, MAC bindings, services |
| `/network/backbone` | Backbone Links | Manual switch-to-switch interconnect config for non-LLDP devices |
| `/inference` | Inference Diagnostics | Mode badge, state distribution, divergence analytics, per-MAC drill-down |
| `/topology` | Network Topology | Auto-generated D3 hierarchical map, VLAN sectors, drag-to-pin |
| `/switches/$deviceId` | Switch Detail | Per-switch port metrics, MAC table, VLANs, port roles |
| `/settings` | Settings | Tabbed: Devices, VLANs, Security, Alerts, System |

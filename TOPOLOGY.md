# How the Topology Map Works

> **Last updated:** 2026-03-06 — commit `de128ae`

This document explains the complete data pipeline from device polling through correlation to the rendered D3.js topology map. It covers every stage: what data feeds in, how the correct switch is chosen for each device, how identities are correlated, how the graph is computed, how layout is determined, and how the frontend renders it.

---

## Table of Contents

1. [End-to-End Data Flow](#1-end-to-end-data-flow)
2. [Data Sources](#2-data-sources)
3. [Correlation Engine](#3-correlation-engine)
4. [Topology Computation Engine](#4-topology-computation-engine)
5. [Layout Algorithm](#5-layout-algorithm)
6. [Speed and Traffic Resolution](#6-speed-and-traffic-resolution)
7. [D3 Visualization](#7-d3-visualization)
8. [Position Persistence](#8-position-persistence)
9. [Background Tasks and Timing](#9-background-tasks-and-timing)

---

## 1. End-to-End Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DEVICE POLLING                               │
│                                                                     │
│  RouterOS (REST)    SwOS (HTTP Digest)    SNMP (v2c/v3)            │
│  ├─ ethernet        ├─ link.b (speeds)    ├─ ifTable               │
│  ├─ ethernet/monitor├─ fdb.b (MACs)       ├─ ifXTable (ifHighSpeed)│
│  ├─ bridge/host     ├─ vlan.b (VLANs)    ├─ dot1dTpFdb (MACs)     │
│  ├─ bridge/vlan     └─ stats.b (counters) └─ ifHCInOctets/Out      │
│  ├─ bridge/port                                                     │
│  ├─ ip/neighbor                                                     │
│  ├─ ip/arp                                                          │
│  ├─ ip/dhcp-server/lease                                            │
│  └─ ip/firewall/connection                                          │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     SQLite TABLES (switch.db)                       │
│                                                                     │
│  switch_port_metrics   — per-port RX/TX, speed, running (series)   │
│  switch_mac_table      — MAC → device, port, bridge, VLAN, is_local│
│  switch_vlan_membership— port → VLAN (tagged/untagged)             │
│  neighbor_discovery    — LLDP/MNDP/CDP neighbor records            │
│  backbone_links        — manual switch-to-switch interconnects      │
│  vlan_config           — VLAN metadata (name, color, media_type)   │
│  switch_port_roles     — classified port roles (trunk/uplink/etc)  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
┌──────────────────────┐  ┌──────────────────────┐
│  CORRELATION ENGINE  │  │  (other consumers)   │
│  (60s cycle)         │  │  behavior, services  │
│                      │  └──────────────────────┘
│  1. Port roles       │
│  2. MAC ranges       │
│  3. Identity assembly│
│  4. WAP attribution  │
│  5. VLAN inference   │
│  6. Port enforcement │
└──────────┬───────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 network_identities TABLE                            │
│                                                                     │
│  One row per MAC address — the unified view of every device on     │
│  the network. Fields: IP, hostname, manufacturer, switch binding,  │
│  VLAN, device_type, confidence, disposition, infrastructure flag.  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│               TOPOLOGY COMPUTATION ENGINE                           │
│               (120s cycle)                                          │
│                                                                     │
│  Layer 1: Infrastructure skeleton (devices, LLDP, backbone)        │
│  Layer 2: Endpoint placement (from network_identities)             │
│  Layer 3: Orphan handling                                          │
│  + Layout computation (center-spine VLAN model)                    │
│  + Speed/traffic resolution (from switch_port_metrics)             │
│  + Human position overrides (from topology_positions)              │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    CACHED NetworkTopology                           │
│                                                                     │
│  nodes: Vec<TopologyNode>   — all devices with positions           │
│  edges: Vec<TopologyEdge>   — all connections with speed/traffic   │
│  vlan_groups: Vec<VlanGroup> — VLAN sector bounding boxes          │
│  stats: TopologyStats        — counts and timestamp                │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                    GET /api/network/topology (30s frontend poll)
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 D3.js VISUALIZATION (frontend)                      │
│                                                                     │
│  SVG layers: stars → grid → VLAN backgrounds → edges → nodes →    │
│              labels → sector drag handles                          │
│  Hexagonal nodes with device-type icons                            │
│  Speed-tier colored edges with traffic-based thickness             │
│  Zoom/pan, drag-to-pin, VLAN filters, search                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Sources

Every piece of data that feeds the topology map originates from a device poll, a user action, or a DNS lookup. This section traces each data element from its source API through storage into the engine that consumes it.

### 2.1 Device Registry

Managed in `secrets.db` (AES-256-GCM encrypted). Each device has:
- `id` — unique identifier (UUID)
- `name` — display name (e.g. "RB4011", "CRS326")
- `device_type` — `router`, `switch`, `swos_switch`, `snmp_switch`
- `host`, `port`, `tls`, `ca_cert_path`, `poll_interval_secs`
- `model` — hardware model string

One device must be type `router` (the primary Mikrotik RB4011). All other devices are switches.

**Consumed by:** Topology engine (Layer 1 — every registered device becomes a node), Correlation engine (gets list of all switch IDs + router ID for port role classification).

### 2.2 RouterOS REST API (router + RouterOS switches)

Polled by `switch_poller.rs` at each device's configured interval. All six endpoints are fetched concurrently via `tokio::join!`.

#### Port Metrics — `/rest/interface/ethernet` + `/rest/interface/ethernet/monitor`

**Source fields:** `name`, `rx-byte`, `tx-byte`, `rx-packet`, `tx-packet`, `speed`, `running` from ethernet; `name`, `rate`, `status`, `full-duplex` from monitor.

**Storage:** `switch_port_metrics` table — one row per port per poll cycle (time-series):
```
device_id | port_name | timestamp | rx_bytes | tx_bytes | rx_packets | tx_packets | speed | running
```
The `speed` column is set by preferring the monitor's `rate` field (actual negotiated speed like `"1Gbps"`, `"10Gbps"`) and falling back to the ethernet `speed` field (configured speed, often NULL on auto-negotiate).

**Consumed by:**
- Topology engine → `get_port_speeds(device_id)` queries the latest `speed` per port, parses via `parse_speed_mbps()`, returns `HashMap<port_name, u32>`. Used to color/size trunk edges.
- Topology engine → `get_port_traffic_bps(device_id)` takes the two most recent rows per port, computes `(delta_bytes / delta_time) * 8` = bits/sec. Used for traffic-based edge thickness.
- Identity Manager → `link_speed_mbps` field on each identity is a correlated subquery: `SELECT speed FROM switch_port_metrics WHERE device_id = identity.switch_device_id AND LOWER(port_name) = LOWER(identity.switch_port) ORDER BY id DESC LIMIT 1`.

#### MAC Address Table — `/rest/bridge/host`

**Source fields:** `mac-address`, `on-interface`, `bridge`, `local` (bool).

**Storage:** `switch_mac_table` table via `upsert_mac_entry()`:
```
device_id | mac_address | port_name | bridge | vlan_id | is_local | first_seen | last_seen
```
Port name is lowercased on storage. Upsert keyed on `(device_id, mac_address, port_name)` — same MAC on same port updates `last_seen`; same MAC on different port creates a new row.

**The `is_local` flag is critical:** When `local=true`, this MAC belongs to the switch itself (one of its port addresses). These MACs are used to compute switch-local MAC ranges (Phase 1b of correlation) and are excluded from identity assembly.

**Consumed by:**
- Correlation engine Phase 1 → `get_mac_table(device_id)` for port role classification (count non-local MACs per port).
- Correlation engine Phase 1b → `get_mac_table(device_id)` filtered to `is_local=true` for switch-local MAC range computation.
- Correlation engine Phase 2 → `get_mac_table(None)` (all devices) for identity assembly. Each MAC entry is evaluated against the priority formula to determine which switch/port "owns" this MAC.

#### VLAN Membership — `/rest/bridge/vlan`

**Source fields:** `vlan-ids`, `tagged` (comma-separated port list), `untagged` (comma-separated port list).

**Storage:** `switch_vlan_membership` table via `set_vlan_membership()` (full replace per device per cycle):
```
device_id | port_name | vlan_id | tagged (bool)
```

**Consumed by:**
- Correlation engine Phase 1 → `get_vlan_membership(device_id)` for port role classification (count VLANs per port; >1 VLAN = trunk).
- Topology engine → used for VLAN sector membership computation (which VLANs does each switch serve).

#### LLDP/MNDP Neighbors — `/rest/ip/neighbor`

**Source fields:** `interface` (or `interface-name`), `mac-address`, `address` (or `address4`), `identity`, `platform`, `board`, `version`.

**Storage:** `neighbor_discovery` table via `upsert_neighbor()`:
```
device_id | interface | mac_address | address | identity | platform | board | version | first_seen | last_seen
```

**Consumed by:**
- Correlation engine Phase 1 → `get_neighbors(device_id)` for port role classification (port has LLDP = uplink).
- Correlation engine Phase 2a → `get_neighbors(None)` for building trunk peer map: `(device_id, port) → peer_device_id`. LLDP identity or IP is resolved against the device registry.
- Correlation engine Phase 2 → neighbor records enrich identities with IP, hostname, platform, device_type (LLDP devices get `device_type = "network_equipment"` at 0.95 confidence).
- Topology engine Layer 1 → creates trunk edges between devices, infers unregistered infrastructure (MikroTik platform → UnmanagedSwitch or AccessPoint).

#### ARP Table — `/rest/ip/arp` (router only)

**Source fields:** `mac-address`, `address` (IP).

**Not stored in a table.** Fetched live by the correlation engine each cycle (`router_client.arp_table()`).

**Consumed by:** Correlation engine Phase 2 → sets `best_ip` on the identity for each MAC, but only if `best_ip` is not already set (LLDP and DHCP take precedence).

#### DHCP Leases — `/rest/ip/dhcp-server/lease` (router only)

**Source fields:** `mac-address`, `address` (IP), `host-name`.

**Not stored in a table.** Fetched live by the correlation engine each cycle (`router_client.dhcp_leases()`).

**Consumed by:** Correlation engine Phase 2 → sets `best_ip` (overwrites ARP — DHCP is authoritative) and `hostname` (only if not already set by LLDP) for each MAC.

#### Bridge Hosts (router only) — `/rest/bridge/host`

The router's bridge hosts are fetched separately at the start of the correlation cycle (not in the switch poller). This ensures the router's own port MACs are present in `switch_mac_table` with `is_local=true`, so they can be included in the switch-local MAC range computation.

### 2.3 SwOS HTTP API (SwOS switches like CRS310)

Polled by `swos_poller.rs`. SwOS devices use HTTP Digest authentication. Requests are serialized (one at a time) because SwOS crashes on concurrent connections.

| Endpoint | Data | Stored In |
|----------|------|-----------|
| `link.b` | Port link status, speed codes, port names | `switch_port_metrics` (speed + running) |
| `fdb.b` | Forwarding database (MAC → port) | `switch_mac_table` |
| `vlan.b` | VLAN membership | `switch_vlan_membership` |
| `stats.b` | Port RX/TX byte/packet counters | `switch_port_metrics` |

All four endpoints store data in the same tables as RouterOS, using the same `upsert_mac_entry()`, `set_vlan_membership()`, and `record_port_metrics()` functions. The correlation engine processes SwOS data identically to RouterOS data.

**Known limitation:** SwOS `link.b` returns incorrect speed codes for SFP+ ports (reports 1G instead of 10G). The backbone link manual `speed_mbps` is the authoritative source for these ports.

### 2.4 SNMP (e.g. Netgear MS510TXPP)

Polled by `snmp_poller.rs`. Supports SNMPv2c and SNMPv3.

| OID | Data | Stored In |
|-----|------|-----------|
| `ifDescr` / `ifName` | Port names | `switch_port_metrics.port_name` |
| `ifHighSpeed` | **Actual link speed in Mbps** | `switch_port_metrics.speed` (stored as `"{n}Mbps"`) |
| `ifHCInOctets` / `ifHCOutOctets` | 64-bit byte counters | `switch_port_metrics.rx_bytes`, `tx_bytes` |
| `ifOperStatus` | Port up/down | `switch_port_metrics.running` |
| `dot1dTpFdbTable` | MAC forwarding table | `switch_mac_table` |

Virtual/aggregate interfaces are filtered out — only physical port names are stored. `ifHighSpeed` is the most accurate speed source of any device type.

### 2.5 Reverse DNS (PTR Lookups)

**Source:** Technitium DNS server at 10.20.25.6 (hardcoded in `correlation_engine.rs`).

**Not stored in a table.** Performed live during each correlation cycle for any MAC that has an IP but no hostname (not set by LLDP or DHCP). Each lookup has a 500ms timeout. Results are written directly into the `IdentityBuilder.hostname` field.

**Consumed by:** Correlation engine Phase 2 → sets `hostname` for devices that have DNS records but don't advertise via DHCP or LLDP.

### 2.6 OUI Database

**Source:** Bundled IEEE OUI database (~40K entries) loaded from `/data/oui.csv` at startup into an in-memory `HashMap<[u8; 3], &str>`.

**Not stored in a table.** Queried in-memory by the correlation engine each cycle.

**Consumed by:** Correlation engine Phase 2 → sets `manufacturer` from MAC prefix, and infers `device_type` + `device_type_confidence` from manufacturer name heuristics (e.g. "Hikvision" → `camera` at 0.6, "MikroTik" → `network_equipment` at 0.6).

### 2.7 Backbone Links (manual configuration)

User-defined switch-to-switch interconnects for devices that don't support LLDP (SwOS switches, WAPs, unmanaged switches). Created via the Backbone Links UI page (`/network/backbone`).

**Storage:** `backbone_links` table:
```
id | device_a | port_a | device_b | port_b | label | link_type | speed_mbps | created_at
```

- Devices are normalized lexicographically on insert (device_a < device_b)
- Port names are lowercased on insert
- `link_type`: DAC, Fiber, Ethernet, or NULL
- `speed_mbps`: manual speed override (e.g. 10000 for 10G DAC)

**Consumed by (Correlation engine):**
1. `get_backbone_links()` → forces linked ports into the `trunk_ports` set (overriding auto-detection). Calls `set_port_role()` to persist the trunk classification.
2. Backbone link port pairs are added to the `trunk_peer` map: `(device_a, port_a) → device_b` and vice versa. This enables trunk redirection — MACs on a backbone trunk port are redirected to the peer device.
3. Backbone link adjacency feeds into `compute_switch_depths()` — BFS from the router determines each switch's depth, which directly affects the priority score for switch binding.

**Consumed by (Topology engine):**
1. `get_backbone_links()` → creates trunk edges in the graph. If a device referenced by a backbone link isn't already a node (e.g. a WAP that has no device registry entry), the topology engine creates it using data from `get_infrastructure_identities()`.
2. `speed_mbps` on the backbone link is the highest-priority speed source for the resulting edge — overrides polled port speed.
3. `port_a` / `port_b` are rendered as port labels at 15%/85% along the trunk edge.

### 2.8 VLAN Configuration

**Storage:** `vlan_config` table:
```
vlan_id | name | media_type | subnet | color | created_at
```

Synced from the router each correlation cycle via `sync_vlan_config_from_router()` — discovers VLAN interfaces and their IP subnets, inserts new VLANs (never overwrites human edits). Also editable via Settings UI.

**Consumed by (Correlation engine):**
1. `media_type` field → builds the `wireless_vlans` set. Any VLAN with `media_type = 'wireless'` or `'mixed'` triggers WAP attribution for devices on that VLAN.
2. `subnet` field → used for VLAN-from-IP inference. When a MAC has an IP but no VLAN from the switch MAC table, the engine tries to match the IP against each VLAN's subnet (CIDR match). Falls back to third-octet heuristic.

**Consumed by (Topology engine):**
1. `name`, `color` → VLAN sector labels and background colors.
2. VLAN IDs → group endpoints into VLAN sectors for layout.

---

## 3. Correlation Engine

**File:** `crates/ion-drift-web/src/correlation_engine.rs`
**Schedule:** Every 60 seconds (90-second startup delay)

The correlation engine synthesizes all the raw polled data into unified `network_identities` records — one per MAC address. This is the single source of truth for "what is this device, where is it connected, and what do we know about it."

### 3.1 Phase 0: Data Pruning

Before each cycle:
- `prune_stale_mac_entries(3600)` — remove MAC table entries older than 1 hour
- `prune_renamed_port_metrics(3600)` — clean up artifacts from port renames
- `prune_stale_port_roles(3600)` — remove stale role classifications
- `sync_vlan_config_from_router()` — discover VLANs from router interfaces

### 3.2 Phase 1: Port Role Classification

Every port on every switch (RouterOS, SwOS, SNMP) is classified based on observed behavior:

| Role | Criteria |
|------|----------|
| `trunk` | Multiple VLANs seen on this port |
| `uplink` | LLDP/MNDP neighbor present on this port, OR MAC count > 10 |
| `access` | Single MAC, no LLDP neighbor |
| `unused` | Zero MACs observed |

**Backbone link override:** Ports explicitly listed in backbone links are forced to `trunk` role regardless of auto-detection. This is essential for SwOS switches that don't support LLDP.

Results are stored in `switch_port_roles` table.

### 3.3 Phase 1b: Switch-Local MAC Range Computation

Each switch's own port MACs must be excluded from endpoint identities. The engine:

1. Queries `switch_mac_table` for entries where `is_local = true` per device
2. Sorts the MACs numerically
3. If the range is sequential and < 128 addresses, stores as [min, max] range
4. Otherwise falls back to an exact set

Any MAC within a device's local range is filtered out during identity assembly. This prevents switch port MACs from appearing as endpoints on the topology map.

### 3.4 Phase 2: Unified Identity Assembly

This is the core of the correlation engine. It processes every MAC address seen across all switches and builds a unified identity.

#### 3.4a: Trunk Detection and Peer Resolution

Before processing MACs, the engine builds several lookup maps:

1. **Trunk ports set** — all ports classified as `trunk` or `uplink`
2. **Backbone trunk peers** — from backbone links: `(device_id, port) → peer_device_id`
3. **LLDP trunk peers** — from neighbor discovery: `(device_id, port) → peer_device_id`
4. **Device resolution maps** — `identity_name → device_id`, `ip → device_id`, `mac → device_id`
5. **Switch depths** — BFS distance from router (see below)
6. **Wireless VLANs** — set of VLAN IDs where `media_type = 'wireless'`

#### 3.4b: Switch Depth Computation (BFS)

Switch depth determines priority when a MAC appears on multiple switches. Computed via BFS from the router:

```
Router = depth 0
  ├─ CRS326 (LLDP neighbor on sfp+1) = depth 1
  │   ├─ CRS310 (backbone link on ether18) = depth 2
  │   └─ WAP-MainFloor (backbone link on ether9) = depth 2
  └─ Netgear MS510 (backbone link on ether1) = depth 1
```

Sources for adjacency: LLDP neighbor records + backbone links. Both are traversed.

#### 3.4c: Priority-Based Switch Binding

When a MAC address appears on multiple switches (common — trunk ports see all downstream MACs), the engine must decide which switch is the "correct" one. This uses a priority score:

```
priority = base_class_value + depth_modifier
```

| Port Type | Base Value | Depth Modifier | Logic |
|-----------|------------|----------------|-------|
| Router (any port) | 100 | — | Always lowest priority (router sees everything via ARP gateway) |
| Switch trunk | 200 | + depth × 10 | **Deeper trunk = higher priority** (closer to the device) |
| Access port | 400 | - depth × 10 | **Shallower access = higher priority** (more trustworthy) |
| Unknown depth | 250 | — | Neutral (prevents unregistered switches from stealing MACs) |

**Why invert depth for access ports?** A MAC can appear on multiple switch access ports when a deeper switch's uplink is misclassified as access. The shallower switch's access port is more likely the genuine connection point.

**Equal priority → no change.** This eliminates flapping when two ports of the same class at the same depth see the same MAC on alternating poll cycles.

**Example priority scores:**

| Scenario | Priority | Wins? |
|----------|----------|-------|
| Camera MAC on RB4011 trunk (depth 0) | 100 | No |
| Camera MAC on CRS326 trunk (depth 1) | 210 | No |
| Camera MAC on CRS310 trunk (depth 2) | 220 | No |
| Camera MAC on CRS310 access port (depth 2) | 380 | **Yes** |

#### 3.4d: Trunk Redirection (Downstream Only)

MACs seen on trunk ports are redirected to the trunk's peer device. But only **downstream** (higher depth → lower depth peer). Never upstream toward the router.

This prevents the router's trunk port from claiming MACs that rightfully belong to downstream access ports.

```
MAC on CRS326:ether18 (trunk, depth 1)
  → peer is CRS310 (depth 2, deeper)
  → redirect: MAC reassigned to CRS310
  → CRS310 will assign it to the correct access port in a subsequent pass

MAC on RB4011:sfp+1 (trunk, depth 0)
  → peer is CRS326 (depth 1, deeper)
  → redirect: MAC reassigned to CRS326
```

#### 3.4e: Data Enrichment Pipeline

After switch binding is resolved, each identity is enriched from multiple sources in order. Each MAC gets an `IdentityBuilder` — a temporary struct that accumulates fields during the enrichment pipeline before being upserted to the `network_identities` table:

```
IdentityBuilder {
    best_ip, hostname, manufacturer,
    switch_device_id, switch_port, vlan_id,
    discovery_protocol, remote_identity, remote_platform,
    device_type, device_type_source, device_type_confidence,
    binding_priority,    // internal: used for priority comparison
    binding_last_seen,   // internal: tie-break same-priority bindings
}
```

| Step | Source | Fields Set | Notes |
|------|--------|------------|-------|
| 1 | MAC table (all devices) | `switch_device_id`, `switch_port`, `vlan_id`, `binding_priority`, `binding_last_seen` | Priority-based binding (see above). Only overwrites if new priority > current priority, or same priority + more recent `last_seen`. |
| 2 | LLDP/MNDP neighbors | `best_ip`, `hostname`, `discovery_protocol`, `remote_identity`, `remote_platform`, `device_type`, `device_type_source` = `"lldp"`, `device_type_confidence` = `0.95` | LLDP is the most authoritative identity source. Sets `device_type` to `"network_equipment"` for all LLDP-discovered devices. |
| 3 | Router ARP table | `best_ip` | Only if `best_ip` is not already set by LLDP. ARP provides MAC → IP mapping from the router's ARP cache. |
| 4 | Router DHCP leases | `best_ip`, `hostname` | Overwrites ARP IP (DHCP is more authoritative). Hostname only set if not already set by LLDP. |
| 5 | Reverse DNS (PTR) | `hostname` | Only for IPs without hostname from steps 2-4. Queries Technitium (10.20.25.6), 500ms timeout per lookup. |
| 6 | OUI database | `manufacturer`, `device_type`, `device_type_source` = `"oui"`, `device_type_confidence` = `0.5-0.6` | `device_type` only set if not already set by LLDP. Manufacturer heuristics: "Hikvision" → `camera` (0.6), "MikroTik" → `network_equipment` (0.6), etc. |

**Human overrides are preserved:** If `switch_binding_source = 'human'`, the automated binding never overwrites `switch_device_id` or `switch_port`.

#### 3.4f: WAP Attribution

Devices on wireless VLANs (determined by `vlan_config.media_type = 'wireless'`) are re-attributed from their physical switch to a WAP when:

1. The device's current `switch_device_id` has WAP children in the backbone links
2. WAPs are identified via `device_type` = `access_point` or `wap` in infrastructure identities

If a switch has exactly one WAP child, all wireless VLAN devices on that switch are attributed to it. If multiple WAPs exist, devices are distributed via deterministic round-robin (prevents flapping).

### 3.5 Phase 3: VLAN Inference from IP

When VLAN is not set by the MAC table (device not seen on a switch port), the engine infers from IP:

1. **Exact CIDR match:** Check each VLAN's configured subnet (e.g. `10.20.25.0/24` → VLAN 25)
2. **Third-octet heuristic fallback:** `10.20.25.x → VLAN 25`, `192.168.90.x → VLAN 90`

### 3.6 Phase 4: Confidence Scoring

Each identity gets a cumulative confidence score (0.0 – 1.0):

| Field Present | Score Added |
|---------------|-------------|
| IP address | +0.20 |
| Hostname | +0.20 |
| Manufacturer (OUI) | +0.15 |
| Switch port binding | +0.15 |
| Discovery protocol (LLDP) | +0.15 |
| VLAN ID | +0.15 |

Maximum possible: 1.0. LLDP-discovered devices with all fields typically score 0.85-0.95.

### 3.7 Phase 5: Port Binding Enforcement

Compares expected MACs (from `port_mac_bindings` table, set by user) against actual MACs on each port:

- **`device_missing`** — no MAC on a bound port
- **`mac_mismatch`** — wrong MAC on a bound port
- Auto-resolves when the correct MAC reappears

### 3.8 Output: network_identities Table

One row per MAC address with all correlated data:

```sql
mac_address, best_ip, hostname, manufacturer,
switch_device_id, switch_port, vlan_id,
discovery_protocol, remote_identity, remote_platform,
device_type, device_type_source, device_type_confidence,
human_confirmed, human_label, disposition,
is_infrastructure, switch_binding_source,
first_seen, last_seen, confidence
```

---

## 4. Topology Computation Engine

**File:** `crates/ion-drift-web/src/topology.rs`
**Schedule:** Every 120 seconds (120-second startup delay)
**Function:** `compute_topology()`

The topology engine reads from the correlation output (network_identities) plus device registry, LLDP neighbors, and backbone links to build a hierarchical graph.

### 4.1 Layer 1: Infrastructure Skeleton

**Step 1 — Registered Devices:**
All devices from the device registry become topology nodes. The router gets `NodeKind::Router`, all others get `NodeKind::ManagedSwitch`. Status (Online/Offline) comes from the device health check.

**Step 2 — LLDP/MNDP Neighbors:**
For each neighbor record:
1. Try to match to a registered device by identity name, IP, or MAC (using fuzzy matching: lowercase, strip punctuation)
2. If matched → create a trunk edge between the reporting device and the matched device
3. If unmatched but has MikroTik platform → create an `UnmanagedSwitch` or `AccessPoint` node (inferred infrastructure)
4. If the neighbor is on the router's WAN-facing port (ether1) → collapse into a single "WAN / ISP" placeholder node

**Step 3 — Backbone Links:**
For each backbone link:
1. Create a trunk edge between device_a and device_b
2. If either device doesn't exist as a node yet (e.g. WAP from infrastructure identities), create it
3. Deduplicate against LLDP-discovered edges (same device pair → keep LLDP, skip backbone)

**Step 4 — BFS Layer Assignment:**
Starting from the router (layer 0), BFS through trunk edges:
- Router = layer 0
- Directly connected switches = layer 1
- Downstream switches = layer 2, 3, etc.

### 4.2 Layer 2: Endpoint Placement

For each `network_identity` record:
1. Skip if MAC matches a registered device IP or MAC
2. Skip if MAC falls within any switch-local MAC range
3. Skip if `disposition = 'ignored'`
4. Skip if the identity is already represented as infrastructure (matched by IP, MAC, or identity name)
5. Convert `device_type` to `NodeKind` (camera → Camera, server → Server, etc.)
6. Create a topology node with `parent_id = switch_device_id` (the correlated switch binding)
7. Create an access edge from the parent switch to this endpoint
8. Edge kind is `Wireless` if the VLAN's `media_type = 'wireless'`, otherwise `Access`

### 4.3 Layer 3: Orphan Handling

Endpoints without a `switch_device_id` (not seen on any switch port) are placed in an orphan group. They still appear on the map but are visually separated.

### 4.4 VLAN Group Computation

Nodes are grouped by VLAN ID. Each VLAN group tracks:
- `vlan_id`, `name`, `color` (from vlan_config)
- `node_ids` — all nodes in this VLAN
- Bounding box: `x`, `y`, `width`, `height` (computed by layout)

### 4.5 VLAN Membership for Infrastructure

Infrastructure nodes (switches, router) serve multiple VLANs. Their VLAN list is computed from:
- `switch_vlan_membership` table (which VLANs are configured on the device)
- Downstream endpoint VLANs (the VLANs of devices connected to this switch)

### 4.6 Identity Matching: How Nodes Are Deduplicated

The topology engine must match LLDP neighbors, backbone link references, and network identities to the same physical device. It uses progressively built lookup maps:

1. **`identity_to_device`** — normalized identity string → device_id (e.g. "crs326" → "uuid-xxx")
2. **`ip_to_device`** — IP address → device_id
3. **`mac_to_device`** — MAC address → device_id

Normalization: lowercase, strip non-alphanumeric characters. So "CRS326-24G+2Q+" matches "crs326-24g2q".

When an LLDP neighbor reports identity "MikroTik CRS310" with IP 10.2.2.3:
1. Normalize → "mikrotik crs310"
2. Check identity_to_device → not found
3. Check ip_to_device for 10.2.2.3 → matches registered device "CRS310" → trunk edge

### 4.7 How Identity Manager Fields Affect the Topology

Every field set in the Identity Manager UI flows through `network_identities` into the topology computation. Here's exactly what each one does:

| Identity Manager Field | Effect on Topology Map |
|------------------------|----------------------|
| **`device_type`** | Determines node shape/icon. `camera` → camera icon, `server` → server icon, `access_point` → AP icon with signal arcs, etc. Infrastructure types (`router`, `switch`, `network_equipment`, `access_point`) promote the node to infrastructure tier. |
| **`human_label`** | Overrides the auto-discovered hostname as the node's display label. Priority: `human_label` > `hostname` > `manufacturer` > MAC address. |
| **`disposition`** | Controls visibility and visual treatment: `ignored` → **hidden entirely** (filtered out before node creation). `flagged` → **red dashed hexagon ring** + warning styling. `external` → **blue dashed border** + reduced opacity (40%). `my_device` / `unknown` → normal rendering. |
| **`is_infrastructure`** | Tri-state override for infrastructure classification: `true` → node renders as infrastructure (switch/AP shape, centered in spine, participates in BFS layering). `false` → forces node to endpoint tier even if LLDP reports it as infrastructure (overrides LLDP). `null` (Auto) → falls through to heuristic detection. |
| **`switch_device_id` + `switch_port`** | When `switch_binding_source = 'human'`, these override the automated priority-based binding. The node is placed under the specified switch on the topology map regardless of which switch's MAC table sees it. |
| **`human_confirmed`** | A human-confirmed non-infrastructure device type overrides LLDP infrastructure inference. E.g., if LLDP says a device is a switch but a human confirms it as a "server", the identity wins and it renders as an endpoint. |
| **`vlan_id`** | Determines which VLAN sector the node is placed in. Affects sector sizing and column balancing. |
| **`confidence`** | Unregistered infrastructure nodes with confidence < 1.0 get an orange indicator ring to flag them for review. |

**Identity vs. LLDP conflict resolution:** When an LLDP neighbor and a network identity refer to the same device, the `identity_overrides_lldp()` function decides:
- `is_infrastructure = false` (human override) → identity wins, device is an endpoint
- Human-confirmed non-infrastructure type → identity wins
- Auto-detected non-infrastructure type with ≥ 0.8 confidence → identity wins
- Otherwise → LLDP inference stands (device remains infrastructure)

### 4.8 How Backbone Links Feed Into the Topology

Backbone links affect the topology at three levels:

**1. Correlation Engine (switch binding accuracy):**

| Backbone Link Property | Correlation Effect |
|----------------------|-------------------|
| `device_a` + `device_b` | Establishes adjacency for BFS depth computation. Depth affects the priority score that determines which switch "owns" each MAC. |
| `port_a` + `port_b` | Forces these ports to `trunk` role, overriding auto-detection. Critical for SwOS switches without LLDP — without this, their uplink ports would be classified as `access` or `uplink`, breaking MAC redirection. |
| (adjacency itself) | Enables downstream trunk redirection. MACs on device_a's trunk port are redirected to device_b (or vice versa, depending on depth), allowing the correlation engine to trace MACs to their actual access port. |

**2. Topology Computation (graph structure):**

| Backbone Link Property | Topology Effect |
|----------------------|----------------|
| `device_a` + `device_b` | Creates a trunk edge between the two devices. If either device doesn't exist as a node (e.g. a WAP referenced only by backbone link), the topology engine creates it from infrastructure identities. |
| `port_a` + `port_b` | Shown as port labels at 15%/85% along the trunk edge (visible at zoom > 0.8). |
| `label` | Displayed as edge label on hover tooltip. |
| `speed_mbps` | **Highest priority speed source.** If set, this speed determines the edge color (gold/orange/silver/cyan/gray) and stroke width. Overrides polled port speed. Essential for SwOS SFP+ ports where the API reports wrong speeds. |
| `link_type` | Stored but not currently used for visual differentiation (DAC, Fiber, Ethernet all render the same). Available in the data for future use. |

**3. D3 Visualization (rendering):**

Backbone link edges render identically to LLDP-discovered trunk edges — same speed-tier coloring, traffic-based thickness, port labels, and animated particles. If both an LLDP edge and a backbone link exist for the same device pair, the LLDP edge takes precedence (backbone is deduplicated).

**Example flow — adding a WAP:**
1. User creates backbone link: CRS326 ↔ WAP-MainFloor (port ether9, speed 1G)
2. Correlation engine: forces CRS326:ether9 to `trunk` role, computes WAP depth = 2, builds trunk peer map
3. Correlation engine: MACs on CRS326:ether9 trunk get redirected to WAP-MainFloor
4. Correlation engine: wireless VLAN devices on CRS326 attributed to WAP-MainFloor (WAP attribution)
5. Topology engine: creates WAP-MainFloor node (from infrastructure identities), trunk edge to CRS326
6. Topology engine: wireless endpoints placed under WAP-MainFloor instead of CRS326
7. D3: WAP renders as AP icon with signal arcs, trunk edge shows "ether9" port label, colored cyan (1G)

---

## 5. Layout Algorithm

**Function:** `compute_layout()` in `topology.rs`

The layout uses a **center-spine model** — VLAN 2 (Network Management) runs as a vertical spine down the center, with other VLANs stacked in two columns on either side.

### 5.1 Layout Constants

```
CANVAS_W     = 4000px    Total canvas width
LAYER_SPACING = 300px    Vertical distance between infrastructure layers
NODE_SPACING  = 120px    Grid spacing between endpoint nodes
TOP_MARGIN    = 150px    Top padding
SPINE_WIDTH   = 300px    Width of center spine (VLAN 2)
SECTOR_PADDING = 40px    Padding inside VLAN sector boxes
```

### 5.2 Infrastructure Positioning

Infrastructure nodes (router, switches) are positioned along the center spine:

```
Layer 0 (router):    centered at (CANVAS_W/2, TOP_MARGIN)
Layer 1 (switches):  spread horizontally across center, Y = TOP_MARGIN + LAYER_SPACING
Layer 2 (switches):  Y = TOP_MARGIN + 2 * LAYER_SPACING
...
```

Within each layer, nodes are distributed evenly across the available width.

### 5.3 VLAN Sector Layout

1. **VLAN 2** (Management) is placed as the center spine
2. All other VLANs are assigned to left or right columns using a **greedy balancing algorithm**: each VLAN goes to whichever column currently has fewer total devices
3. Column heights are proportional to device count per VLAN
4. VLANs stack vertically within each column

### 5.4 Endpoint Grid Layout

Within each VLAN sector, endpoints are arranged in a square grid:
- Grid starts below the parent infrastructure node
- Columns = ceil(sqrt(device_count))
- Spacing = NODE_SPACING (120px)
- Padding = SECTOR_PADDING (40px) on all sides
- Collections sorted by MAC or node_id for deterministic ordering

### 5.5 Human Position Overrides

After auto-layout, human-positioned overrides are applied:
- **Node positions** from `topology_positions` table (source = "human")
- **Sector positions** from `topology_sector_positions` table (source = "human")

These override the computed x/y (and optionally width/height for sectors). A pin icon appears on repositioned nodes/sectors in the UI.

---

## 6. Speed and Traffic Resolution

### 6.1 Port Speed Sources

Speed data comes from different places depending on device type:

| Device Type | Speed Source | Format | Accuracy |
|-------------|-------------|--------|----------|
| RouterOS | `/rest/interface/ethernet/monitor` → `rate` field | `"1Gbps"`, `"10Gbps"` | Actual negotiated speed |
| RouterOS (fallback) | `/rest/interface/ethernet` → `speed` field | `"1Gbps"` or empty | Configured speed (empty on auto-negotiate) |
| SNMP | `ifHighSpeed` OID | Integer (Mbps) → stored as `"1000Mbps"` | Actual link speed |
| SwOS | `link.b` speed codes | `"1G"`, `"100M"` | **Unreliable for SFP+ ports** |
| Backbone link | Manual `speed_mbps` field | Integer (Mbps) | User-specified override |

### 6.2 Speed String Parsing

The `parse_speed_mbps()` function handles all formats:

```
"1000Mbps" → 1000    (RouterOS/SNMP)
"10Gbps"   → 10000   (RouterOS v7)
"2.5G"     → 2500    (SwOS)
"100M"     → 100     (SwOS)
```

### 6.3 Speed Resolution for Topology Edges

During topology computation, edge speed is resolved in priority order:

1. **Backbone link `speed_mbps`** — if the edge corresponds to a backbone link with manual speed, use it
2. **Polled port speed** — query `switch_port_metrics` for the latest speed on the edge's port, parse and merge (take the higher of device_a's port speed and device_b's port speed)
3. **NULL** — no speed data available (displayed as cyan 1.2px default)

### 6.4 Traffic Rate Computation

Live traffic rate is computed from the two most recent `switch_port_metrics` samples per port:

```
delta_bytes = (rx1 + tx1) - (rx0 + tx0)
delta_time  = timestamp1 - timestamp0
bps         = (delta_bytes / delta_time) * 8
```

Traffic is resolved per-edge by matching the edge's port name (lowercased) to the port metrics for each device. The higher of the two endpoints' traffic is used.

### 6.5 Frontend Speed Visualization

Edges are colored and sized by speed tier:

| Speed | Color | Stroke Width | Label |
|-------|-------|-------------|-------|
| ≥ 10G | Gold `#ffd700` | 3.5 | "10G" |
| ≥ 5G | Dark orange `#ff8c00` | 2.5 | "5G" |
| ≥ 2.5G | Silver `#c0c0c0` | 2.0 | "2.5G" |
| ≥ 1G | Cyan `#00f0ff` | 1.2 | "1G" |
| < 1G | Gray `#666666` | 0.8 | "{n}M" |
| Unknown | Cyan `#00f0ff` | 1.2 | — |

When live traffic data is available, edge stroke width overrides the speed-tier width using log10 scaling:

```
width = 0.6 + (log10(bps) - 2) * 0.55
```

Clamped to range [0.6, 6.0] pixels. This means:
- 100 bps → 0.6px (barely visible)
- 1 Mbps → ~2px
- 100 Mbps → ~4px
- 1 Gbps → ~5px
- 10 Gbps → ~5.5px

---

## 7. D3 Visualization

**File:** `web/src/features/topology/hooks/use-d3-topology.ts`

### 7.1 SVG Layer Stack

The visualization uses ordered SVG groups (bottom to top):

1. **Stars** — decorative background dots
2. **Grid** — subtle reference grid
3. **VLAN backgrounds** — colored rectangles with labels per VLAN sector
4. **Edges** — connection lines between nodes
5. **Particles** — animated dots along trunk/uplink edges (visual traffic indicator)
6. **Nodes** — hexagonal device icons
7. **Labels** — text labels for nodes
8. **Sector drag** — invisible drag handles for VLAN sector repositioning

### 7.2 Node Rendering

All nodes are rendered as hexagons with a device-type icon inside:

- **Size:** Infrastructure nodes use larger hexagons (radius ~18), endpoints use smaller ones (radius ~10)
- **Color:** VLAN color, or gold for router
- **Icon:** Material Design icon paths for each NodeKind (router, switch, AP, server, camera, etc.)
- **Hub pulse:** Router and managed switches get animated concentric rings
- **Badges:**
  - "NEW" — devices discovered in the last 24 hours
  - Red dashed ring — flagged devices
  - Blue dashed border — external devices
  - Orange dot — unregistered infrastructure
  - Pin icon — human-positioned nodes

### 7.3 Edge Rendering

- **Color:** Speed-tier based (see section 6.5)
- **Width:** Traffic-based (log10) or speed-tier fallback
- **Style:** Solid for wired, dashed for wireless
- **Port labels:** Shown at 15% and 85% along trunk edges (visible at zoom > 0.8)
- **Particles:** Animated dots travel along trunk/uplink edges

### 7.4 VLAN Sector Interaction

VLAN background rectangles support:
- **Drag** (via header label) — moves the entire sector, persists position via API
- **Resize** (via bottom-right corner handle) — changes sector dimensions
- **Pin indicator** — shows when sector has been manually positioned
- **Click pin to reset** — removes human override, returns to auto-layout

### 7.5 Node Interaction

- **Hover** — tooltip with label, kind, IP, MAC, VLAN, type, manufacturer, port
- **Click** — detail panel (right sidebar) with full node info
- **Right-click** — context menu (alias, hide, flag, device type override)
- **Drag** — reposition node, persists via position API. Dragged positions are cached client-side to prevent snap-back from stale data fetches
- **Pin click** — reset to auto-layout position

### 7.6 Zoom-Dependent Visibility

| Element | Visible When |
|---------|-------------|
| Registered infrastructure labels | Always |
| Unregistered infrastructure labels | zoom > 0.5 |
| Endpoint labels | zoom > 0.5 |
| Port labels on trunk edges | zoom > 0.8 |
| Endpoint label staggering (±5px Y offset) | Always (prevents overlap) |

### 7.7 Filters and Search

- **VLAN filter chips** — toggle individual VLANs on/off
- **Endpoint toggle** — show/hide non-infrastructure devices
- **Search** — matches against label, IP, MAC, kind, manufacturer, VLAN name. Highlights matching nodes and zooms to first match.

### 7.8 Legend

Collapsible, draggable legend panel (bottom-left) showing:
- Node types with hex icons and colors
- Speed tier color key
- Edge type styles (trunk, uplink, access, wireless)
- VLAN colors
- Status indicators (online glow, offline glow, pinned)

---

## 8. Position Persistence

### 8.1 Node Positions

**Table:** `topology_positions`

```sql
node_id TEXT PRIMARY KEY,
x REAL, y REAL,
source TEXT DEFAULT 'auto',  -- 'auto' or 'human'
updated_at TEXT
```

- **Auto positions** are written by the topology computation engine on each cycle
- **Human positions** are written when a user drags a node. They override auto positions.
- **Delete** removes the human override, reverting to auto-layout on next recompute

**APIs:**
- `PUT /api/network/topology/positions/{nodeId}` — set human position
- `DELETE /api/network/topology/positions/{nodeId}` — reset to auto

### 8.2 Sector Positions

**Table:** `topology_sector_positions`

```sql
vlan_id INTEGER PRIMARY KEY,
x REAL, y REAL,
width REAL, height REAL,
source TEXT DEFAULT 'auto',
updated_at TEXT
```

- Same auto/human override pattern as node positions
- Width and height can also be overridden (sector resizing)

**APIs:**
- `PUT /api/network/topology/sectors/{vlanId}` — set human position/size
- `DELETE /api/network/topology/sectors/{vlanId}` — reset to auto

### 8.3 Frontend Position Caching

The D3 hook maintains a `draggedPositions` Map client-side. When a user drags a node:
1. Position saved to the Map immediately (prevents visual snap-back)
2. PUT request sent to backend
3. On next topology data fetch, the auto-computed position is overridden by the Map entry
4. Map is cleared when the position has been confirmed in the backend data

---

## 9. Background Tasks and Timing

### 9.1 Task Schedule

```
T=0s    Server starts
T=5s    Device health check starts (60s interval)
T=30s   Switch pollers start (per-device interval, min 10s)
T=60s   Neighbor discovery poller starts (120s interval)
T=90s   Correlation engine starts (60s interval)
T=120s  Topology computation starts (120s interval)
```

### 9.2 Data Freshness

| Data | Max Staleness | Why |
|------|---------------|-----|
| Port metrics | Device poll interval (10-60s) | Collected each poll cycle |
| MAC table | Device poll interval + prune window (1h) | Pruned after 1 hour |
| LLDP neighbors | 120s (neighbor poller interval) | Also collected in switch poller |
| Port roles | 60s (correlation interval) | Recomputed each correlation cycle |
| Network identities | 60s (correlation interval) | Upserted each correlation cycle |
| Topology graph | 120s (topology interval) | Recomputed from all sources |
| Frontend display | 30s (API poll interval) | React Query refetch interval |

### 9.3 Why Two Separate Engines?

The correlation engine (60s) and topology engine (120s) are decoupled because:

1. **Correlation is the expensive one** — it processes every MAC, every ARP entry, every DHCP lease, does DNS lookups, OUI lookups, priority scoring. It needs to run frequently to keep identities fresh.
2. **Topology is the consumer** — it reads the already-correlated identities and builds the visual graph. Running it at half the frequency is sufficient since the underlying data doesn't change drastically every 60 seconds.
3. **Separation of concerns** — correlation owns data quality (which switch? which port? what type?), topology owns visualization (positions, layout, VLAN grouping).

---

## Appendix A: Key Database Tables

| Table | Database | Purpose |
|-------|----------|---------|
| `switch_port_metrics` | switch.db | Time-series port counters + speed |
| `switch_mac_table` | switch.db | Which MAC is on which port |
| `switch_vlan_membership` | switch.db | Port-to-VLAN mapping |
| `neighbor_discovery` | switch.db | LLDP/MNDP neighbor records |
| `switch_port_roles` | switch.db | Classified port roles |
| `network_identities` | switch.db | Unified identity per MAC |
| `backbone_links` | switch.db | Manual switch-to-switch links |
| `vlan_config` | switch.db | VLAN metadata |
| `topology_positions` | switch.db | Node position overrides |
| `topology_sector_positions` | switch.db | VLAN sector position overrides |
| `devices` | secrets.db | Device registry |

## Appendix B: API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/topology` | GET | Cached topology graph (30s poll) |
| `/api/network/topology/refresh` | POST | Force immediate recompute |
| `/api/network/topology/positions` | GET | All node positions |
| `/api/network/topology/positions/{id}` | PUT | Set human position override |
| `/api/network/topology/positions/{id}` | DELETE | Reset to auto-layout |
| `/api/network/topology/sectors` | GET | All sector positions |
| `/api/network/topology/sectors/{vlanId}` | PUT | Set human sector position |
| `/api/network/topology/sectors/{vlanId}` | DELETE | Reset sector to auto |
| `/api/network/backbone-links` | GET | List backbone links |
| `/api/network/backbone-links` | POST | Create backbone link |
| `/api/network/backbone-links/{id}` | PUT | Update backbone link |
| `/api/network/backbone-links/{id}` | DELETE | Delete backbone link |
| `/api/network/identities` | GET | All correlated identities |
| `/api/network/identities/infrastructure` | GET | Infrastructure-only identities |
| `/api/network/vlan-config` | GET | VLAN configuration |
| `/api/devices/{id}/ports` | GET | Port list for a device |

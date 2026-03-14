# Ion Drift Topology Engine

## Overview

The topology engine constructs a live, hierarchical network graph from data
collected by Ion Drift's switch pollers and correlation engine. It answers the
question every network operator asks first: "what is connected to what?"

The engine runs server-side in the `ion-drift-web` crate. It reads from
multiple data stores (MAC tables, LLDP/MNDP neighbors, ARP, DHCP, port roles,
backbone links, and network identities), builds a graph of `TopologyNode` and
`TopologyEdge` objects, assigns a deterministic layout, and caches the result
in `AppState` for the React frontend to render.

## Data Sources

| Source | Collected By | Provides |
|--------|-------------|----------|
| **LLDP / MNDP neighbors** | Switch pollers (RouterOS REST) | Switch-to-switch links, platform strings, identity names, MACs |
| **MAC tables** | Switch pollers | Per-port MAC address lists; primary input for endpoint attachment inference |
| **ARP tables** | Router poller | MAC-to-IP bindings |
| **DHCP leases** | Router poller | IP, hostname, MAC, VLAN (via subnet matching) |
| **Port role classification** | Correlation engine | Per-port role probabilities (trunk, uplink, access, unused) |
| **Backbone links** | Operator-defined (API/UI) | Manual switch-to-switch connections for non-LLDP devices (WAPs, SwOS) |
| **Network identities** | Correlation engine | Unified device records merging MAC, OUI, ARP, DHCP, DNS, and inference data |
| **VLAN membership** | Switch pollers | Which VLANs are configured on each switch port |
| **VLAN config** | Database (operator-editable) | VLAN names, colors, subnets, media types (wired/wireless) |
| **Port metrics** | Switch pollers | Link speed (Mbps) and traffic rate (bps) per port |
| **Device manager** | Registration/health checks | Registered device records, online/offline status, RouterOS identity |

## Graph Construction

Topology computation happens in `topology::compute_topology()` and follows a
layered approach.

### Layer 1 -- Infrastructure Skeleton

1. **Registered devices** -- Every device in the device manager becomes a node.
   Routers get `NodeKind::Router`; all others get `NodeKind::ManagedSwitch`.
   Confidence is 1.0 and disposition is `my_device`.

2. **LLDP/MNDP neighbors** -- For each neighbor record the engine attempts to
   match it to a registered device by identity name, IP address, or MAC
   address (in that priority order). Matching uses both exact and normalized
   fuzzy keys. Matched neighbors produce `Trunk` edges between known devices.
   Unmatched neighbors with a platform string create **inferred infrastructure
   nodes** (`UnmanagedSwitch` or `AccessPoint`) at confidence 0.7.

3. **Backbone links** -- Operator-defined links create `Trunk` edges. If an
   endpoint has no node yet, one is auto-created from infrastructure identity
   metadata. When a backbone link duplicates an LLDP-discovered edge, port
   names and speed from the backbone link are merged in (manual data wins).

4. **WAN node** -- LLDP neighbors on WAN-facing interfaces (e.g. `ether1`) are
   collapsed into a single "WAN / ISP" placeholder node connected via an
   `Uplink` edge.

5. **Neighbor aliases** -- Operators can alias a MAC or identity to a
   registered device (merging duplicates) or hide it entirely from the graph.

### Layer 2 -- Endpoint Placement

Network identities that are not already infrastructure nodes become endpoint
nodes. Each endpoint is classified by `device_type` (see Node Classification
below) and assigned to a VLAN via its `vlan_id`. The `parent_id` and
`switch_port` fields link it to its inferred upstream switch.

Endpoints with a `parent_id` get an `Access` edge to that parent. If the
parent switch serves a wireless VLAN and the endpoint sits on that VLAN, the
edge becomes `Wireless` instead.

Orphan endpoints (no parent) are placed on a dedicated orphan layer below the
main endpoint layer.

### BFS Layer Assignment

Starting from the router (layer 0), a breadth-first traversal over `Trunk`
edges assigns integer layers to infrastructure nodes. Unreachable
infrastructure gets `max_layer + 1`. The WAN node is pinned to layer 0
alongside the router.

## Node Classification

Each node receives a `NodeKind` that drives its icon and layout behavior:

| Kind | How Determined |
|------|---------------|
| `Router` | Registered device with `device_type = "router"` |
| `ManagedSwitch` | Any other registered device |
| `UnmanagedSwitch` | LLDP neighbor with MikroTik/RouterOS/SwOS platform, or backbone link target |
| `AccessPoint` | LLDP platform containing "cap", "wap", or "wireless"; or infrastructure identity typed `access_point` |
| `Server` | Network identity `device_type` = "server" |
| `Workstation` | Network identity `device_type` = "workstation" |
| `Camera` | Network identity `device_type` = "camera" |
| `Printer` | Network identity `device_type` = "printer" |
| `Phone` | Network identity `device_type` = "phone" |
| `IoT` | Network identity `device_type` = "iot" |
| `SmartHome` | Network identity `device_type` = "smart_home" |
| `MediaPlayer` | Network identity `device_type` = "media_player" |
| `Unknown` | Fallback when no classification is available |

Device types are assigned by the correlation engine using OUI manufacturer
lookups, DHCP hostnames, DNS names, and operator overrides stored in the
network identity record.

## Edge Types

| Edge Kind | Meaning | How Determined |
|-----------|---------|---------------|
| `Trunk` | Switch-to-switch link carrying multiple VLANs | LLDP/MNDP neighbor match between two infrastructure nodes, or backbone link |
| `Access` | Endpoint connected to a switch port | Endpoint has a `parent_id` pointing to a switch, on a wired VLAN |
| `Wireless` | Endpoint connected via WiFi | Same as Access, but the parent switch serves a wireless VLAN matching the endpoint's VLAN |
| `Uplink` | WAN / ISP connection | Router's WAN-facing interface to the collapsed WAN node |

Edge metadata includes `source_port`, `target_port`, `speed_mbps` (from port
metrics or backbone link config), `traffic_bps` (live rate from port counters),
and `vlans` carried.

Speed resolution picks the bottleneck (minimum) when both sides report.
Traffic resolution picks the maximum of both sides (same traffic seen from
each end).

## VLAN Grouping

Endpoint nodes are clustered into VLAN groups for visual organization. Each
`VlanGroup` contains:

- `vlan_id`, `name`, `color`, `subnet` -- from the VLAN config database
- `node_count` -- number of endpoints in this VLAN
- `bbox_x`, `bbox_y`, `bbox_w`, `bbox_h` -- bounding box for the frontend to
  draw a colored region behind the nodes

VLANs are laid out in a fixed horizontal order defined by `VLAN_ORDER`:
`[2, 6, 10, 25, 30, 35, 40, 90, 99]`. Any VLAN not in this list is appended
at the end. Empty VLANs receive a narrow placeholder width.

Sector positions can be overridden by operators via the
`/api/network/topology/sectors/{vlanId}` endpoint, allowing drag-and-drop
rearrangement that persists across recomputes.

## Layout Algorithm

The layout is fully deterministic and layer-based. No force-directed physics
or randomness is involved.

**Constants:**

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `CANVAS_W` | 4000 px | Total canvas width |
| `LAYER_SPACING` | 300 px | Vertical distance between layers |
| `NODE_SPACING` | 120 px | Horizontal distance between nodes in a sector |
| `TOP_MARGIN` | 150 px | Top padding |
| `ENDPOINT_OFFSET` | 200 px | Extra vertical offset for endpoint layer |
| `SECTOR_PADDING` | 40 px | Padding inside each VLAN sector box |
| `VLAN_SECTOR_MIN_W` | 200 px | Minimum sector width |

**Steps:**

1. **Sector widths** -- Each VLAN sector's width is proportional to its node
   count (`node_count * NODE_SPACING`), clamped to `VLAN_SECTOR_MIN_W`.
2. **Horizontal distribution** -- Sectors are laid out left-to-right across
   `CANVAS_W` in `VLAN_ORDER` sequence.
3. **Infrastructure positioning** -- Infrastructure nodes at each layer are
   centered horizontally. The router sits at the canvas center.
4. **Endpoint positioning** -- Endpoints are placed within their VLAN sector
   column at the endpoint layer's Y coordinate, spaced by `NODE_SPACING`.
5. **WAN node** -- Positioned 300 px to the left of the router at the same Y.
6. **Position overrides** -- Operators can pin individual nodes via the
   positions API. Pinned nodes keep their saved `(x, y)` and set
   `position_source = "saved"` instead of `"auto"`. Overrides persist in the
   database and survive recomputes.

## Topology Inference

The `topology_inference` module infers which switch port each endpoint device
is physically attached to, using MAC table correlation. This is the primary
mechanism for populating `parent_id` and `switch_port` on endpoint nodes.

### Infrastructure Graph

The `graph` submodule builds an `InfrastructureGraph` from backbone links,
representing the known switch-to-switch topology. It provides:

- **Graph depth** -- BFS distance from the router for each switch
- **Upstream/downstream relationships** -- used to distinguish transit MACs
  from locally-attached MACs
- **Device resolution maps** -- identity, IP, and MAC lookups to match
  neighbor records to registered devices

### Candidate Generation

For each MAC address seen in any switch's MAC table, the `candidates`
submodule generates `AttachmentCandidate` entries. Each candidate represents
a (MAC, switch, port) triple with an observation count tracking how many
poll cycles the MAC has been seen on that port.

Candidate types include:
- **Direct** -- MAC seen on a port classified as `access`
- **InferredEdge** -- MAC on a trunk/uplink port with edge-like characteristics
- **ApFeeder** -- MAC seen behind a known access point feeder port

### Feature Scoring

The `scorer` submodule computes a feature vector for each candidate:

| Feature | Weight | Description |
|---------|--------|-------------|
| `edge_likelihood` | High | Port role probability of being an access/edge port |
| `persistence` | High | Fraction of poll cycles where the MAC was observed |
| `vlan_consistency` | Medium | Whether the port's VLANs match the device's known VLAN |
| `downstream_preference` | Medium | Prefers switches deeper in the graph (closer to edge) |
| `recency` | Low | Bonus for recent observations |
| `graph_depth_score` | Medium | Normalized BFS depth of the candidate switch |
| `device_class_fit` | Low | Whether the port profile matches the device type |
| `transit_penalty` | Negative | Penalty for ports that look like transit/trunk |
| `contradiction_penalty` | Negative | Penalty when multiple strong candidates conflict |

### Attachment Resolution

The `resolver` submodule picks the winning candidate per MAC. It supports two
modes:

- **Full** -- Score all candidates, pick highest, apply state machine
- **Quick** -- Fast path for stable attachments that haven't changed

The winner's switch becomes `parent_id` and its port becomes `switch_port`
on the network identity. Results are persisted to the database.

### Attachment State Machine

Each MAC's attachment progresses through confidence states:

```
Unknown -> Candidate (1 win) -> Probable (3 wins) -> Stable (10 wins)
```

Special states: `Roaming` (attachment changed switches), `Conflicted`
(multiple strong candidates), `HumanPinned` (operator override).

Explanation reasons are generated for each attachment decision, documenting
why a particular switch/port was chosen (e.g., "Seen consistently (92% of
polls)", "Port strongly resembles edge/access attachment").

## Update Cycle

- The **correlation engine** runs every **60 seconds** (after a 90-second
  startup delay to let pollers collect initial data). Each cycle:
  1. Prunes stale MAC entries, port metrics, and port roles (older than 1 hour)
  2. Syncs VLAN config from the router (insert-only, never overwrites edits)
  3. Classifies port roles using MAC counts, VLAN counts, and LLDP presence
  4. Builds network identities from MAC/ARP/DHCP/OUI/DNS data
  5. Runs topology inference to resolve switch attachments

- The **topology graph** is recomputed after each correlation cycle and cached
  in `AppState`. The frontend polls the cached result.

- An **on-demand refresh** is available via `POST /api/network/topology/refresh`
  which forces an immediate recompute outside the regular cycle.

- **Port role classification** uses a probability model:
  - High MAC count + single VLAN + no LLDP = likely `access`
  - Low MAC count + LLDP neighbor = likely `trunk` or `uplink`
  - Known backbone link port = boosted `trunk` probability
  - Wireless VLAN presence adjusts classification accordingly
  - Ports with zero MACs and no LLDP = `unused`

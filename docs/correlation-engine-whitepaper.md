# Ion Drift Correlation Engine

## Overview

The correlation engine is Ion Drift's central data-fusion subsystem. It runs as a
long-lived async task that unifies raw observations from switches, routers, DHCP,
ARP, DNS, LLDP/CDP, and the OUI database into two primary outputs:

1. **Network Identities** -- coherent per-device records keyed by MAC address,
   enriched with IP, hostname, manufacturer, VLAN, switch attachment, and
   device-type metadata.
2. **Port Role Classifications** -- per-port labels (access, trunk, uplink,
   wireless, unused) with probabilistic confidence scores.

These outputs feed the topology inference engine, the behavior/anomaly engine,
and the web UI's device inventory and network map views.

## Identity Unification

Each device on the network is represented by a `NetworkIdentity`, built
incrementally by an `IdentityBuilder` that merges data from six sources:

| Source | Contributes | Priority |
|--------|------------|----------|
| **Switch MAC tables** | MAC address (primary key), switch port binding, VLAN ID, first/last seen | Foundation -- every identity starts here |
| **Router ARP table** | MAC-to-IP mapping | Populates `best_ip` for every active L3 device |
| **Router DHCP leases** | IP address, hostname (`host_name`) | Fills `best_ip` and `hostname` when present |
| **LLDP/CDP neighbors** | Remote identity, platform, IP address, discovery protocol | Sets `hostname`, `remote_platform`, `discovery_protocol` |
| **OUI database** | Manufacturer name, device-type hint | Populates `manufacturer` and may set `device_type` |
| **DNS reverse lookups** | PTR-record hostname | Fills `hostname` for devices that have an IP but no DHCP/LLDP name |

The MAC address is the immutable primary key. When the same MAC appears in
multiple sources, the builder merges fields with a first-writer-wins policy for
hostname (LLDP > DHCP > DNS) and a priority-based binding model for switch
attachment (access ports outrank trunk ports; most-recently-seen breaks ties).

Infrastructure MACs (switch-local addresses from managed devices) are detected
and excluded so they do not pollute the endpoint identity table.

## Port Role Classification

Every port on every managed switch is classified each cycle. Two parallel
systems produce complementary outputs:

### Discrete Classification (`classify_port_role`)

A simple decision tree applied to each port:

| Condition | Role |
|-----------|------|
| VLAN count > 1 | trunk |
| LLDP neighbor present | uplink |
| MAC count > 10 | uplink |
| MAC count = 0 | unused |
| Otherwise | access |

### Probabilistic Classification (`compute_port_role_probabilities`)

An additive evidence model that returns normalized probabilities across four
roles: trunk, uplink, access, and wireless.

**Signals and weights:**

| Signal | Role boosted | Weight |
|--------|-------------|--------|
| Known backbone link | trunk | +0.75 |
| VLAN count > 3 | trunk | +0.9 |
| VLAN count > 1 | trunk | +0.6 |
| LLDP neighbor present | uplink | +0.7 |
| MAC count > 20 | uplink | +0.5 |
| MAC count 11-20 | uplink | +0.3 |
| MAC count 1-3, no LLDP, single VLAN | access | +0.8 |
| MAC count 1-10, no LLDP | access | +0.5 |
| Port carries wireless/mixed VLANs | wireless | +0.4 |
| Majority of port VLANs are wireless | wireless | +0.3 |
| No evidence at all | (all zero -- unused) | 0.0 |

Raw weights are normalized so probabilities sum to 1.0. The probabilistic
output is stored as `PortRoleProbability` and used downstream by the observation
confidence and topology inference systems.

## Device Type Inference

Device type classification uses a layered approach where higher-confidence
sources override lower ones:

| Source | Example output | Confidence |
|--------|---------------|------------|
| **LLDP platform string** | `network_equipment` (if platform contains "routeros" or "mikrotik") | 0.95 |
| **OUI manufacturer** | Device type inferred via `OuiDb::device_type_from_manufacturer()` | Variable (set by OUI rules) |
| **Infrastructure identity store** | `access_point`, `wap` (pre-labeled infrastructure devices) | Pre-assigned |

The `device_type`, `device_type_source`, and `device_type_confidence` fields
track both the classification and its provenance. A higher-confidence source
will not be overwritten by a lower-confidence one within the same cycle.

The `is_infrastructure` boolean flag on `NetworkIdentity` distinguishes
infrastructure devices (switches, routers, APs) from endpoints.

## Confidence Scoring

Identity confidence is a composite score (0.0 to 1.0) based on data
completeness:

| Field present | Score contribution |
|--------------|-------------------|
| `best_ip` | +0.20 |
| `hostname` | +0.20 |
| `manufacturer` | +0.15 |
| `switch_port` | +0.15 |
| `discovery_protocol` | +0.15 |
| `vlan_id` | +0.15 |

A fully-enriched identity scores 1.0. A MAC-only identity with no correlated
data scores 0.0.

Separately, **observation confidence** quantifies how reliable a single MAC
table observation is, based on the port role where the MAC was seen:

```
observation_confidence = access_prob * 0.9
                       + wireless_prob * 0.7
                       + uplink_prob * 0.2
                       + trunk_prob * 0.1
```

Observations on access ports are highly trusted (the MAC is almost certainly
directly connected), while observations on trunk ports carry low confidence
(the MAC is transiting, not attached). The topology inference engine uses a
minimum confidence threshold of 0.5 before writing binding changes.

## Update Cycle

The correlation engine runs on a fixed schedule:

- **Startup delay:** 90 seconds after application launch, allowing switch
  pollers to collect initial MAC tables, neighbor data, and port metrics.
- **Cycle interval:** 60 seconds between correlation runs.
- **Stale data pruning:** Each cycle prunes MAC table entries, port metrics,
  port roles, and MAC observations older than configurable thresholds
  (default: 1 hour for tables/metrics, 20 minutes for observations).
- **VLAN config sync:** Each cycle discovers VLANs from the router's VLAN
  interfaces and IP addresses, inserting new entries without overwriting
  human edits.

## Data Flow

```
  Switch Pollers          Router Client         DNS Resolver
  (SNMP/API)              (Mikrotik API)        (Technitium)
       |                       |                      |
       v                       v                      v
  MAC Tables              ARP + DHCP              PTR Lookups
  Neighbors               VLAN Interfaces
  Port Metrics
       |                       |                      |
       +----------+------------+----------+-----------+
                  |                       |
                  v                       v
        Port Role Classification   Identity Assembly
        (discrete + probabilistic)  (IdentityBuilder)
                  |                       |
                  v                       v
           PortRoleProbability     NetworkIdentity
                  |                       |
       +----------+-----------+-----------+----------+
       |                      |                      |
       v                      v                      v
  Topology Inference    Behavior Engine         Web UI
  (InfrastructureGraph,  (anomaly detection,    (device inventory,
   backbone links,        baseline tracking)     network map,
   switch-port binding                           port details)
   resolution)
```

The correlation engine writes all outputs to the `SwitchStore` (SQLite-backed),
which serves as the shared state between subsystems. The topology inference
engine reads port role probabilities and MAC observations to resolve which
switch port each device is truly attached to, distinguishing direct attachment
from transit observations on trunk/uplink ports.

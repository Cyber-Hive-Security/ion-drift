# Ion-Drift Behavior & Anomaly Detection Engine
## Technical Whitepaper

**Version:** 1.0
**Date:** 2026-03-13
**Author:** svc-claude
**Scope:** Complete technical documentation of the behavioral anomaly detection system

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Data Collection Pipeline](#2-data-collection-pipeline)
3. [Device Profiling & Lifecycle](#3-device-profiling--lifecycle)
4. [Baseline Computation](#4-baseline-computation)
5. [Anomaly Detection](#5-anomaly-detection)
6. [Port Flow Baselines & Classification](#6-port-flow-baselines--classification)
7. [Anomaly Correlation](#7-anomaly-correlation)
8. [Investigation Engine](#8-investigation-engine)
9. [VLAN Sensitivity & Auto-Resolution](#9-vlan-sensitivity--auto-resolution)
10. [Suppression Rules & Priority Boosting](#10-suppression-rules--priority-boosting)
11. [Deduplication](#11-deduplication)
12. [Confidence Scoring](#12-confidence-scoring)
13. [Severity Determination](#13-severity-determination)
14. [Scheduled Tasks & Timing](#14-scheduled-tasks--timing)
15. [API Surface](#15-api-surface)
16. [Database Schema](#16-database-schema)
17. [Constants & Thresholds Reference](#17-constants--thresholds-reference)
18. [Known Limitations](#18-known-limitations)

---

## 1. Architecture Overview

Ion-drift's behavior engine is a multi-stage pipeline that observes device network activity, learns behavioral baselines, detects deviations, correlates them across two independent detection layers, and automatically investigates findings to produce verdicts.

### 1.1 Pipeline Flow

```
RouterOS Connection Tracking + ARP + DHCP
    │ (every 60 seconds)
    ▼
Observation Collection ──► device_observations table
    │
    ▼
Device Profiling ──► device_profiles table
    │ (learning → sparse → baselined)
    ▼
Baseline Computation ──► device_baselines table
    │ (nightly @ 3 AM, 7-day window)
    ▼
Anomaly Detection ──► device_anomalies table
    │ (every 60 seconds, baselined/sparse devices only)
    ├─► Firewall Correlation
    ├─► Suppression/Priority Check
    │
    ▼
Port Flow Correlation ──► anomaly_links table
    │ (cross-links device anomalies with network-level port anomalies)
    ▼
Investigation Engine ──► investigations table
    │ (automated verdict: benign / routine / suspicious / threat / inconclusive)
    ▼
Operator Action ──► accept / dismiss / flag
    │
    ├─► accept: recompute baselines (incorporate new behavior)
    ├─► dismiss: create suppression rule (block future pattern)
    └─► flag: increment priority boost (escalate future instances)
```

### 1.2 Two Detection Layers

The system operates at two independent levels that cross-correlate:

- **Device Behavior Layer** — Per-MAC fingerprinting. Tracks each device's protocol/port/destination/direction patterns. Detects when a specific device deviates from its own learned baseline.

- **Network Flow Layer** — Per-port aggregation across all devices. Tracks network-wide port usage patterns. Detects when a port's total traffic, source count, or existence deviates from the network baseline.

The anomaly correlator links findings from both layers to produce compound verdicts and avoid duplicate investigations.

### 1.3 Source Files

| File | Purpose |
|------|---------|
| `crates/ion-drift-web/src/behavior_engine.rs` | Core detection: observations, volume spikes, novelty, blocked attempts (~1000 lines) |
| `crates/ion-drift-web/src/tasks/behavior.rs` | Scheduled collection & maintenance tasks (~380 lines) |
| `crates/ion-drift-storage/src/behavior.rs` | Storage layer: profiles, baselines, observations, anomalies, suppressions (~2300 lines) |
| `crates/ion-drift-web/src/anomaly_correlator.rs` | Port flow ↔ device anomaly cross-correlation (~440 lines) |
| `crates/ion-drift-web/src/connection_store.rs` | Connection history, port flow baselines, scan noise filter (~3000+ lines) |
| `crates/ion-drift-web/src/investigation.rs` | Automated investigation with verdict determination (~740 lines) |
| `crates/ion-drift-web/src/routes/behavior.rs` | REST API endpoints |

---

## 2. Data Collection Pipeline

**Function:** `collect_observations()` in `behavior_engine.rs`
**Frequency:** Every 60 seconds
**Startup Delay:** 3 minutes (server stabilization)

### 2.1 Data Sources

The collector fetches three data sources from RouterOS concurrently:

1. **ARP Table** — Maps IP addresses to MAC addresses
2. **DHCP Leases** — Maps IP addresses to hostnames
3. **Firewall Connection Tracking** — All active and recently-closed connections with src/dst IP, port, protocol, bytes

### 2.2 Collection Algorithm

1. Build lookup tables: IP→MAC, IP→hostname
2. Upsert `device_profiles` for all observed IPs (creates new profiles or updates `last_seen`)
3. For each firewall connection:
   - Resolve source MAC from IP→MAC table
   - Normalize protocol (`6`→`tcp`, `17`→`udp`, `1`→`icmp`)
   - Classify destination subnet via `VlanRegistry`
   - Classify direction (outbound/inbound/lateral/internal)
4. Aggregate connections by tuple: `(mac, protocol, dst_port, dst_subnet, direction)`
5. Create `DeviceObservation` records with aggregated bytes and connection count
6. Batch-insert all observations to `device_observations` table

### 2.3 Destination Classification

The `VlanRegistry` classifies destination IPs into subnet groups:

- **Known VLAN subnet:** Returns that VLAN's CIDR (e.g., `10.20.25.0/24`)
- **RFC1918 private (10.x, 172.16-31.x, 192.168.x):** Returns `/24` grouping
- **External/public IPs:** Returns `/16` grouping (reduces baseline fragmentation)

### 2.4 Direction Classification

| Source | Destination | Direction |
|--------|------------|-----------|
| Internal VLAN | External | `outbound` |
| External | Internal VLAN | `inbound` |
| Internal VLAN A | Internal VLAN B | `lateral` |
| Same VLAN | Same VLAN | `internal` |

### 2.5 Observation Record

```
DeviceObservation {
    mac: String,               // Device MAC address
    timestamp: i64,            // Unix epoch
    ip: String,                // Source IP at time of observation
    vlan: i64,                 // Source VLAN
    protocol: String,          // "tcp", "udp", "icmp", "other"
    dst_port: Option<i64>,     // Destination port (None for ICMP)
    dst_subnet: String,        // Classified destination (e.g., "1.2.0.0/16")
    direction: String,         // "outbound", "inbound", "lateral", "internal"
    bytes_sent: i64,           // Total bytes sent in this tuple
    bytes_recv: i64,           // Total bytes received in this tuple
    connection_count: i64,     // Number of active connections in this tuple
}
```

---

## 3. Device Profiling & Lifecycle

### 3.1 Device Profile

Every device observed on the network gets a profile in `device_profiles`:

```
DeviceProfile {
    mac: String,               // Primary key
    hostname: Option<String>,  // From DHCP leases
    manufacturer: Option<String>, // From OUI database lookup
    current_ip: Option<String>,
    current_vlan: Option<i64>,
    first_seen: i64,           // Unix epoch
    last_seen: i64,
    learning_until: i64,       // first_seen + 7 days
    baseline_status: String,   // "learning" | "sparse" | "baselined"
    notes: Option<String>,
}
```

### 3.2 Lifecycle States

```
[First Observed]
    │
    ▼
 LEARNING (7 days)
    │ learning_until expires
    ▼
 ┌──────────────┐
 │ Promotion    │
 │ Check        │
 └──┬───────┬───┘
    │       │
    ▼       ▼
BASELINED  SPARSE
```

**Promotion criteria** (checked nightly at 3 AM):

| Condition | Result |
|-----------|--------|
| `learning_until <= now` AND `baseline_entries >= 3` AND `total_observations >= 50` | **Baselined** |
| `learning_until <= now` AND above conditions NOT met | **Sparse** |
| `learning_until > now` | Remains **Learning** |

- **Learning:** Device is building its profile. Anomaly detection is skipped entirely. Only blocked connection attempts are flagged immediately.
- **Sparse:** Device has insufficient data for full profiling. Anomaly detection runs but confidence scores are reduced by 0.1.
- **Baselined:** Full anomaly detection with highest confidence scoring.

---

## 4. Baseline Computation

**Function:** `recompute_all_baselines()` in `behavior.rs`
**Triggered:** Nightly at 3 AM; also on-demand when operator accepts an anomaly
**Window:** 7 days (604,800 seconds)

### 4.1 Algorithm

For each unique flow tuple `(mac, protocol, dst_port, dst_subnet, direction)`:

1. Query all observations matching this tuple within the 7-day window
2. Compute:
   - `avg_bytes_per_hour = AVG(bytes_sent + bytes_recv) × 60` (observations are 60s intervals, projected to hourly)
   - `max_bytes_per_hour = MAX(bytes_sent + bytes_recv) × 60`
   - `observation_count = COUNT(*)`
3. Upsert to `device_baselines` table (ON CONFLICT update)

### 4.2 Baseline Record

```
DeviceBaseline {
    mac: String,
    protocol: String,
    dst_port: Option<i64>,
    dst_subnet: String,
    direction: String,
    avg_bytes_per_hour: f64,
    max_bytes_per_hour: f64,
    observation_count: i64,
    computed_at: i64,
}
```

### 4.3 Baseline as Identity

A device's baseline is effectively its behavioral fingerprint — the set of all `(protocol, dst_port, dst_subnet, direction)` tuples it has been observed using, along with the traffic volume profile for each. Any observation that doesn't match an existing baseline entry is a candidate for anomaly detection.

---

## 5. Anomaly Detection

**Function:** `detect_anomalies()` in `behavior_engine.rs`
**Frequency:** Every 60 seconds (after observation collection)
**Scope:** Only devices with `baseline_status` of `"baselined"` or `"sparse"`

### 5.1 Anomaly Types

| Type | Description | Detection Method |
|------|-------------|-----------------|
| `volume_spike` | Traffic volume exceeds baseline thresholds | Statistical comparison against avg/max bytes |
| `new_destination` | Device contacts a subnet not in its baseline | Baseline lookup miss (subnet not found) |
| `new_port` | Device uses a port not in its baseline for a known destination | Baseline lookup miss (port not found for known subnet) |
| `new_protocol` | Device uses a protocol not in its baseline for a known destination | Baseline lookup miss (protocol not found for known subnet) |
| `blocked_attempt` | Firewall dropped an inbound connection attempt | Firewall log parsing (action=drop) |

### 5.2 Volume Spike Detection

Multi-stage validation to reduce false positives:

**Stage 1 — Absolute Floor:**
```
hourly_projected = (bytes_sent + bytes_recv) × 60
Must exceed: 5,000,000 bytes/hour (5 MB/hr)
```

**Stage 2 — Baseline Comparison (both must be true):**
```
hourly_projected > baseline.max_bytes_per_hour × 3.0
hourly_projected > baseline.avg_bytes_per_hour × 5.0
```

**Stage 3 — Multi-Window Persistence:**
```
Count observations in last 300 seconds where bytes > baseline.max × 3.0
Must have: elevated_count >= 2 (at least 2 of the last 5 polls)
```

This three-stage approach prevents transient spikes (single-poll bursts) from generating anomalies.

### 5.3 Novelty Detection (New Destination/Port/Protocol)

For each current observation, check if its flow tuple exists in the device's baseline:

```
if baseline has NO entry for this dst_subnet:
    → "new_destination"
elif baseline has this dst_subnet but NOT this protocol:
    → "new_protocol"
elif baseline has this dst_subnet + protocol but NOT this dst_port:
    → "new_port"
else:
    → normal (check for volume spike instead)
```

### 5.4 Blocked Attempt Detection

**Source:** RouterOS firewall log (entries with action=`"drop"`)

For each drop log entry:
1. Parse log fields: src_ip, dst_ip, dst_port, protocol, TCP flags, GeoIP
2. Look up source MAC from IP→MAC table
3. Enrich with hostname, manufacturer, VLAN, GeoIP
4. Apply dedup check
5. Create anomaly with `firewall_correlation = "expected_deny"`

### 5.5 Traffic Classification

Each anomaly is enriched with a `traffic_class` label:

| Class | Criteria |
|-------|----------|
| `dhcp_activity` | Ports 67, 68 |
| `management_protocol` | Ports 22, 23, 161, 162, 443, 8291, 8728, 8729 |
| `internet_scan` | Inbound direction |
| `lateral_movement` | Lateral direction + SSH/RDP/SMB/WinRM ports |
| `internal_service_access` | Lateral or internal direction, non-management ports |
| `broadcast_service` | Internal ARP |
| `external_service_access` | Outbound direction |
| `unknown` | No match |

### 5.6 Zone Classification

Source and destination IPs are mapped to security zones:

| Zone | Criteria |
|------|----------|
| `Guest` | Guest VLAN |
| `IoT` | IoT VLANs |
| `Services` | Server/service VLANs |
| `Management` | Management VLANs |
| `Infrastructure` | Infrastructure VLANs |
| `Trusted` | Other internal VLANs |
| `WAN` | External/public IPs |

### 5.7 Firewall Rule Correlation

Each anomaly is correlated against the cached RouterOS firewall ruleset:

**Matching criteria:** Protocol, source CIDR, destination CIDR, destination port (including ranges like `"1024-65535"` and lists like `"22,443"`)

**Correlation results:**

| Firewall Action | Correlation Type |
|----------------|-----------------|
| `accept` / `passthrough` | `expected_allow` |
| `drop` / `reject` | `expected_deny` |
| No rule match | `policy_unknown` |

The correlation enriches each anomaly with `firewall_correlation`, `firewall_rule_id`, and `firewall_rule_comment`.

### 5.8 Anomaly Record

```
NewAnomaly {
    mac: String,
    anomaly_type: String,
    severity: String,           // "info", "warning", "alert", "critical"
    confidence: f64,            // 0.0–1.0
    description: String,        // Human-readable summary
    details: Option<String>,    // JSON blob with full context
    vlan: i64,
    firewall_correlation: Option<String>,
    firewall_rule_id: Option<String>,
    firewall_rule_comment: Option<String>,
}
```

**Details JSON structure:**
```json
{
    "src_ip": "10.20.25.27",
    "src_hostname": "game-server",
    "src_manufacturer": "Intel Corporation",
    "dst_subnet": "1.2.0.0/16",
    "dst_ip": "1.2.3.4",
    "dst_vlan": null,
    "dst_vlan_name": null,
    "dst_hostname": null,
    "dst_country": { "country": "United States", "code": "US" },
    "protocol": "tcp",
    "dst_port": 443,
    "direction": "outbound",
    "policy_outcome": "policy_unknown",
    "traffic_class": "external_service_access",
    "source_zone": "Services",
    "destination_zone": "WAN"
}
```

---

## 6. Port Flow Baselines & Classification

### 6.1 Port Flow Baseline Computation

**Triggered:** Nightly via maintenance task
**Window:** 7 days of `connection_history`

For each `(flow_direction, protocol, dst_port)` tuple:

1. Group connections by day bucket
2. For each day: sum bytes, count connections, collect unique source/destination IPs
3. Aggregate across all 7 days:
   - `avg_bytes_per_day`, `max_bytes_per_day`
   - `avg_connections_per_day`, `max_connections_per_day`
   - `typical_sources` (JSON array, up to 50 IPs)
   - `typical_destinations` (JSON array, up to 50 IPs)
4. **Apply scan noise filter** before baseline entry
5. Upsert to `port_flow_baseline` table
6. Prune baselines older than 14 days

### 6.2 Scan Noise Filter

The `is_significant_port_flow()` function gates what enters the baseline:

```
if port is in KNOWN_SERVICE_PORTS:
    → always significant (baseline it)

if port >= 49152 (ephemeral range):
    → significant only if total_bytes >= 1 GB

otherwise:
    → significant only if flow_count >= 5 AND total_bytes >= 10 KB
```

**Known Service Ports (37 ports):** 20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 161, 443, 445, 554, 587, 993, 995, 1433, 1883, 3000, 3306, 3389, 5060, 5228, 5432, 5672, 6379, 8080, 8443, 8554, 8883, 9001, 9090, 9443, 27017, 32400

This filter prevents internet scan probes (low-traffic, single-flow hits on random ports) from polluting the baseline.

### 6.3 Port Flow Classification

**Function:** `classified_port_summary()`

For each current port flow, compare against the baseline:

| Classification | Condition |
|---------------|-----------|
| `VolumeSpike` | Current bytes > `max_bytes_per_day × 4.0` |
| `SourceAnomaly` | New source IPs not in `typical_sources` |
| `NewPort` | No baseline entry for this `(protocol, port)` |
| `Disappeared` | Baseline entry with `days_present >= 5` not seen in current flows (only for well-known ports or high-traffic ports averaging >= 100KB/day) |
| `Normal` | Within expected parameters |

---

## 7. Anomaly Correlation

**File:** `anomaly_correlator.rs`
**Frequency:** Every 60 seconds (5-minute startup delay)

### 7.1 Purpose

The correlator cross-links device-level anomalies (from the behavior engine) with network-level port anomalies (from port flow classification). This produces compound context: "Device X is responsible for the anomalous traffic on port Y."

### 7.2 Port → Device Correlation

For each anomalous port flow (NewPort, VolumeSpike, SourceAnomaly):

1. Identify devices contributing traffic to that port
2. For each involved device:
   - Search for a matching pending behavior anomaly
   - Create an `anomaly_link` record connecting port anomaly to device
   - If no behavior anomaly exists, create one from port flow data (type `source_anomaly`)

### 7.3 Device → Port Correlation

For each recent pending device anomaly (new_port, volume_spike):

1. Extract protocol and port from the anomaly details
2. Look up port context from `port_flow_baseline`
3. Create `anomaly_link` enriching the device anomaly with network context

### 7.4 Severity Escalation

Correlated anomalies (both device AND port layer detect the same issue) receive elevated severity:

| Condition | Severity |
|-----------|----------|
| Correlated + NewPort + multiple devices | `critical` (lateral movement pattern) |
| Correlated (any) | `critical` |
| NewPort, port not baselined, single device | Per-VLAN sensitivity |
| Port is baselined, device is new to it | `info` |
| Default | `warning` |

### 7.5 Auto-Resolution

Links are automatically resolved when:
- The underlying behavior anomaly is no longer pending (operator acted on it)
- The link is older than 7 days

---

## 8. Investigation Engine

**File:** `investigation.rs`
**Triggered:** Asynchronously after anomaly detection, for each new uninvestigated anomaly (up to 100 per cycle, looking back 5 minutes)

### 8.1 Investigation Pipeline

```
Load Anomaly
    │
    ▼
Gather Context (5 layers)
    ├── Device Context (hostname, manufacturer, baseline status, age)
    ├── Destination Context (GeoIP, ASN, CDN check, reverse DNS, commonality)
    ├── Behavioral Context (anomaly counts 24h/7d, same-pattern count, baseline coverage)
    ├── Traffic Context (volume, baseline comparison, unique destinations/ports)
    └── Firewall Context (rule match, action, comment)
    │
    ▼
Apply 10 Verdict Rules (in order, first match wins)
    │
    ▼
Generate Summary & Evidence Chain
    │
    ▼
Record Investigation
```

### 8.2 Context Layers

**Device Context:**
- Hostname, manufacturer, disposition
- First seen timestamp, baseline status
- VLAN sensitivity level
- Whether device is still in learning period

**Destination Context:**
- IP address, GeoIP (country, city, ASN, org)
- CDN detection (ASN checked against 25+ major CDN/cloud providers)
- Reverse DNS lookup
- Commonality: how many other devices have talked to this IP in the last 7 days
- Whether the destination country is in the monitored/flagged country list

**CDN ASN Whitelist (partial):** Cloudflare (13335), Akamai (20940), AWS (16509), Google (15169), Microsoft (8075, 8068-8070), GitHub (36459), Apple (714, 6185), Fastly (54113), DigitalOcean (14061), and others.

**Behavioral Context:**
- Total anomaly count for this device in last 24h and 7d
- Count of same-type anomalies in last 24h (`same_pattern_24h`)
- Baseline coverage percentage: `(baseline_entries / unique_flow_tuples) × 100`

**Traffic Context:**
- Current projected hourly volume (from anomaly details)
- Baseline max hourly volume (from anomaly details)
- Volume ratio (current / baseline)
- Unique destinations contacted in last hour
- Unique ports used in last hour

### 8.3 Verdict Rules

Rules are applied in order. The first matching rule determines the verdict.

| # | Rule | Condition | Verdict | Action |
|---|------|-----------|---------|--------|
| 1 | Flagged Device | `device.disposition == "flagged"` | **suspicious** | escalate |
| 2 | WAN Blocked Inbound | `type == "blocked_attempt"` AND `source_zone == "WAN"` | **routine** | no_action |
| 3 | Expected Firewall Deny | `type == "blocked_attempt"` AND `fw.correlation == "expected_deny"` | **benign** | no_action |
| 4 | CDN Destination | `type == "new_destination"` AND `dest.is_cdn == true` | **benign** | no_action |
| 5 | Common Destination | `type == "new_destination"` AND `dest.seen_by_device_count >= 3` | **benign** | no_action |
| 6 | Roaming Protocol | `type == "new_port"` AND `port IN (53,67,68,123,137,138,1900,3478,5353)` | **benign** | no_action |
| 7 | Volume Spike Assessment | `type == "volume_spike"` AND `ratio < 5.0` AND `baseline == "sparse"` | **routine** | monitor |
|   | | `type == "volume_spike"` AND `ratio > 20.0` | **suspicious** | investigate |
| 8 | Flagged Country | `type == "new_destination"` AND `dest.is_flagged_country` | **suspicious** | investigate |
| 9 | Learning Device | `device.is_learning == true` | **routine** | no_action |
| 10 | Recurring Pattern | `same_pattern_24h >= 3` | **suspicious** | investigate |
| — | Default | No rule matched | **inconclusive** | monitor |

### 8.4 Verdicts

| Verdict | Meaning |
|---------|---------|
| `benign` | Expected behavior, no risk |
| `routine` | Normal operational noise, low priority |
| `suspicious` | Warrants operator attention |
| `threat` | Active threat indicator (not currently triggered by any rule — reserved for future ML/threat intel integration) |
| `inconclusive` | Insufficient evidence to determine |

---

## 9. VLAN Sensitivity & Auto-Resolution

### 9.1 Sensitivity Levels

Each VLAN is configured with a sensitivity level that controls anomaly severity and auto-resolution behavior:

| Sensitivity | Blocked Attempt / Volume Spike | Other Anomalies | Auto-Resolve Timeout |
|-------------|-------------------------------|-----------------|---------------------|
| `Strictest` | `critical` | `critical` | Never |
| `Strict` | `alert` | `warning` | Never |
| `Moderate` | `warning` | `info` | 48 hours |
| `Loose` | `warning` (blocked only) | `info` | 24 hours |
| `Monitor` | `info` | `info` | 72 hours |

### 9.2 Auto-Resolution

Stale anomalies are automatically resolved based on the VLAN timeout:

- Only applies to anomalies with severity NOT `critical` or `alert`
- Sets status to `auto_dismissed`
- Run hourly by the auto-classifier task
- VLANs with sensitivity `Strictest` or `Strict` never auto-resolve

---

## 10. Suppression Rules & Priority Boosting

### 10.1 Pattern Suppression

Suppression rules prevent specific anomaly patterns from being created. Each rule has optional fields that act as filters (NULL = wildcard):

```
PatternSuppression {
    device_id: Option<String>,        // MAC or NULL (any device)
    vlan: Option<i64>,                // VLAN or NULL (any VLAN)
    protocol: Option<String>,         // "tcp"/"udp" or NULL
    destination_port: Option<i64>,    // Port or NULL
    traffic_class: Option<String>,    // Classification or NULL
    action: String,                   // "suppress", "dismissed", "accepted"
}
```

**Matching:** All non-NULL fields must match. Rules are ranked by specificity (most non-NULL fields wins). First match determines outcome.

**Auto-creation:** When an operator dismisses an anomaly, a suppression rule is automatically created with the exact pattern from that anomaly, preventing future duplicates.

### 10.2 Priority Boosting

When an operator flags an anomaly for review, the system creates/increments a priority boost record:

```
AnomalyPriorityBoost {
    pattern_key: String,    // "{device|*}|{vlan|*}|{protocol|*}|{port|*}|{class|*}"
    boost: i64,             // Incremented each time operator flags this pattern
}
```

**Effect:** Each boost level escalates the base severity by one step:
```
info → warning → alert → critical
```

Priority boosts persist indefinitely and never auto-decrement.

---

## 11. Deduplication

### 11.1 Mechanism

**Function:** `has_recent_anomaly()` in `behavior.rs`

Before creating any anomaly, the system checks for an existing pending anomaly matching the same device and pattern:

```sql
SELECT COUNT(*) FROM device_anomalies
WHERE mac = ?1
  AND anomaly_type = ?2
  AND status = 'pending'
  AND timestamp >= ?3
  AND (details LIKE '%' || ?4 || '%' OR ?4 = '')
```

Parameters:
- `?1` = device MAC
- `?2` = anomaly type
- `?3` = cutoff timestamp (now - window)
- `?4` = dedup key (substring searched in JSON details)

### 11.2 Dedup Keys by Type

| Anomaly Type | Dedup Key Format | Window |
|-------------|-----------------|--------|
| `volume_spike` | `"{dst_subnet}:{dst_port}"` | 3600s (1 hour) |
| `new_destination` / `new_port` / `new_protocol` | `"{dst_subnet}:{protocol}:{dst_port}"` | 3600s (1 hour) |
| `blocked_attempt` | `"{dst_ip}:{dst_port}"` | 3600s (1 hour) |

### 11.3 Spike Candidate Persistence

Volume spikes have an additional in-memory dedup layer:

```
SpikeCandidates {
    candidates: HashMap<(mac, dedup_key), u32>  // consecutive count
}
```

A volume spike requires 2 consecutive elevated observations (within 5 minutes) before it fires. The candidate map is pruned every 10 minutes.

---

## 12. Confidence Scoring

**Function:** `compute_confidence()` in `behavior.rs`

Each anomaly receives a confidence score from 0.0 to 1.0 based on multiple factors:

| Factor | Condition | Adjustment |
|--------|-----------|------------|
| **Base score** | — | 0.50 |
| **Baseline status** | `baselined` | +0.15 |
| | `sparse` | -0.10 |
| | `learning` | -0.20 |
| **Observation count** | > 1000 | +0.10 |
| | > 100 | +0.05 |
| | < 10 | -0.10 |
| **Baseline age** | > 30 days | +0.10 |
| | > 7 days | +0.05 |
| **Firewall correlated** | Match found | +0.15 |
| **VLAN sensitivity** | Strictest / Strict | +0.10 |
| | Loose / Monitor | -0.05 |
| **Anomaly type** | `blocked_attempt` | +0.10 |
| | `new_destination` | +0.05 |

Final score is clamped to `[0.0, 1.0]`, then adjusted by `priority_boost × 0.05`.

**Interpretation:**
- >= 0.80: High confidence (green badge)
- >= 0.60: Moderate confidence (amber badge)
- < 0.60: Low confidence (grey badge)

---

## 13. Severity Determination

### 13.1 Base Severity

Determined by the VLAN sensitivity level and anomaly type (see Section 9.1).

### 13.2 Escalation

Priority boosts escalate the base severity:

```
final_severity = base_severity + priority_boost steps

Ladder: info → warning → alert → critical (clamped at critical)
```

Example: A `new_destination` on a Moderate VLAN has base severity `info`. If the operator has flagged this pattern twice (boost=2), the final severity becomes `alert`.

---

## 14. Scheduled Tasks & Timing

### 14.1 Behavior Collector

| Event | Timing |
|-------|--------|
| First collection | T+3 minutes after startup |
| Collection cycle | Every 60 seconds |
| Spike candidate pruning | Every 10 cycles (600s) |
| Investigation spawn | After each detection cycle, for uninvestigated anomalies in last 5 minutes (up to 100) |

**Per-cycle operations:**
1. Snapshot VlanRegistry
2. Refresh firewall rules cache (if > 5 minutes old)
3. Collect observations from RouterOS
4. Detect anomalies (volume spikes + novelty) on baselined/sparse devices
5. Detect blocked attempts from firewall logs
6. Spawn async investigations for new anomalies

### 14.2 Behavior Maintenance

| Event | Timing |
|-------|--------|
| Startup check | T+5 minutes (runs if no maintenance in last 6 hours) |
| Nightly run | 3:00 AM daily |

**Maintenance operations:**
1. Recompute all device baselines (7-day window)
2. Promote devices (learning → baselined/sparse)
3. Prune observations older than 30 days
4. Auto-resolve stale anomalies (per-VLAN timeouts)
5. Compute port flow baselines (7-day window, noise-filtered)
6. Classify device traffic patterns
7. Persist `last_maintenance` watermark

### 14.3 Auto-Classifier

| Event | Timing |
|-------|--------|
| Startup | Immediately |
| Cycle | Every 60 minutes |

Applies VLAN auto-resolve timeouts to stale non-critical/non-alert anomalies.

### 14.4 Anomaly Correlator

| Event | Timing |
|-------|--------|
| First run | T+5 minutes |
| Cycle | Every 60 seconds |

Operations:
1. Port → Device correlation
2. Device → Port correlation
3. Auto-resolve expired links (> 7 days or underlying anomaly resolved)

---

## 15. API Surface

### 15.1 Overview & Device Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/behavior/overview` | GET | Stats: device counts, anomaly counts, VLAN summaries |
| `/api/behavior/vlan/{vlan_id}` | GET | Devices + pending anomalies for a VLAN |
| `/api/behavior/device/{mac}` | GET | Full device detail: profile, baselines, anomalies, port flow contexts |
| `/api/behavior/alerts` | GET | Alert counts (pending, critical, warning) |

### 15.2 Anomaly Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/behavior/anomalies` | GET | Query by status/severity/vlan/limit |
| `/api/behavior/anomalies` | DELETE | Delete all anomalies |
| `/api/behavior/anomalies/{id}/resolve` | POST | Resolve single: `{"action": "accepted\|flagged\|dismissed"}` |
| `/api/behavior/anomalies/bulk` | POST | Bulk resolve, archive reviewed, or delete archived |
| `/api/behavior/anomalies/export.csv` | GET | CSV export with full context |

### 15.3 Suppression & Priority Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/behavior/suppressions` | GET | List all suppression rules |
| `/api/behavior/suppressions` | POST | Create suppression rule |
| `/api/behavior/suppressions/{id}` | DELETE | Delete suppression rule |

### 15.4 Investigation Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/investigations` | GET | Query by verdict/mac/limit/offset |
| `/api/investigations/anomaly/{id}` | GET | Investigation for specific anomaly |
| `/api/investigations/device/{mac}` | GET | All investigations for a device |
| `/api/investigations/stats` | GET | Verdict distribution counts |

### 15.5 Anomaly Link Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/behavior/anomaly-links` | GET | All unresolved links |
| `/api/behavior/anomaly-links/port/{protocol}/{port}` | GET | Links for specific port |
| `/api/behavior/anomaly-links/device/{mac}` | GET | Links for specific device |
| `/api/behavior/anomaly-links/{id}/resolve` | POST | Resolve a link |

### 15.6 Reset

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/behavior/reset` | POST | Full engine reset: deletes all anomalies, baselines, observations, profiles, boosts, watermarks. Preserves suppression rules. |

---

## 16. Database Schema

### 16.1 Core Tables

```sql
-- Device fingerprints
device_profiles (
    mac TEXT PRIMARY KEY,
    hostname TEXT, manufacturer TEXT,
    current_ip TEXT, current_vlan INTEGER,
    first_seen INTEGER, last_seen INTEGER, learning_until INTEGER,
    baseline_status TEXT DEFAULT 'learning',
    notes TEXT
)

-- Raw per-flow observations (60s intervals)
device_observations (
    id INTEGER PRIMARY KEY,
    mac TEXT, timestamp INTEGER, ip TEXT, vlan INTEGER,
    protocol TEXT, dst_port INTEGER, dst_subnet TEXT, direction TEXT,
    bytes_sent INTEGER, bytes_recv INTEGER, connection_count INTEGER
)  -- Indexed on (mac, timestamp)

-- Learned behavior patterns
device_baselines (
    id INTEGER PRIMARY KEY,
    mac TEXT, protocol TEXT, dst_port INTEGER, dst_subnet TEXT, direction TEXT,
    avg_bytes_per_hour REAL, max_bytes_per_hour REAL,
    observation_count INTEGER, computed_at INTEGER,
    UNIQUE(mac, protocol, dst_port, dst_subnet, direction)
)

-- Detected deviations
device_anomalies (
    id INTEGER PRIMARY KEY,
    mac TEXT, timestamp INTEGER,
    anomaly_type TEXT, severity TEXT, confidence REAL,
    description TEXT, details TEXT,  -- JSON blob
    vlan INTEGER,
    firewall_correlation TEXT, firewall_rule_id TEXT, firewall_rule_comment TEXT,
    status TEXT DEFAULT 'pending',   -- pending|accepted|dismissed|flagged|auto_dismissed|archived
    resolved_at INTEGER, resolved_by TEXT
)  -- Indexed on (mac), (status)

-- Suppression rules
anomaly_suppressions (
    id INTEGER PRIMARY KEY,
    device_id TEXT, vlan INTEGER, protocol TEXT,
    destination_port INTEGER, traffic_class TEXT,
    action TEXT, created_by TEXT, created_at INTEGER
)

-- Operator escalation signals
anomaly_priority_boosts (
    pattern_key TEXT PRIMARY KEY,
    device_id TEXT, vlan INTEGER, protocol TEXT,
    destination_port INTEGER, traffic_class TEXT,
    boost INTEGER, updated_at INTEGER
)

-- Automated verdicts
investigations (
    id INTEGER PRIMARY KEY,
    anomaly_id INTEGER UNIQUE,
    device_mac TEXT, device_hostname TEXT, device_manufacturer TEXT,
    device_disposition TEXT, device_first_seen INTEGER, device_baseline_status TEXT,
    vlan_id INTEGER, vlan_sensitivity TEXT,
    dst_ip TEXT, dst_country TEXT, dst_city TEXT,
    dst_asn INTEGER, dst_org TEXT, dst_is_cdn INTEGER,
    dst_reverse_dns TEXT, dst_seen_by_device_count INTEGER,
    anomaly_type TEXT,
    prior_anomaly_count_24h INTEGER, prior_anomaly_count_7d INTEGER,
    same_pattern_count_24h INTEGER, baseline_coverage_pct REAL,
    current_volume_bytes INTEGER, baseline_volume_bytes INTEGER, volume_ratio REAL,
    unique_destinations_1h INTEGER, unique_ports_1h INTEGER,
    other_devices_same_dest INTEGER,
    firewall_rule_id TEXT, firewall_action TEXT,
    firewall_rule_comment TEXT, firewall_correlation TEXT,
    verdict TEXT, recommended_action TEXT, reason TEXT,
    summary TEXT, evidence_chain TEXT,
    investigated_at TEXT, duration_ms INTEGER
)

-- Network-wide port usage baselines
port_flow_baseline (
    flow_direction TEXT, protocol TEXT, dst_port INTEGER,
    service_name TEXT,
    avg_bytes_per_day INTEGER, max_bytes_per_day INTEGER,
    avg_connections_per_day INTEGER, max_connections_per_day INTEGER,
    days_present INTEGER,
    typical_sources TEXT,      -- JSON array
    typical_destinations TEXT, -- JSON array
    computed_at TEXT
)  -- Indexed on (flow_direction)

-- Cross-correlation between device and port anomalies
anomaly_links (
    id INTEGER PRIMARY KEY,
    port_anomaly_type TEXT, flow_direction TEXT,
    protocol TEXT, dst_port INTEGER,
    device_mac TEXT, device_ip TEXT, device_vlan INTEGER, device_hostname TEXT,
    behavior_anomaly_id INTEGER, correlated INTEGER, source TEXT,
    severity TEXT, device_bytes INTEGER, device_connections INTEGER,
    port_is_baselined INTEGER, port_days_in_baseline INTEGER,
    created_at TEXT, resolved_at TEXT, resolved_by TEXT
)  -- Indexed on (protocol, dst_port, device_mac)

-- Task scheduling watermarks
engine_metadata (key TEXT PRIMARY KEY, value TEXT)
scheduler_watermarks (task_name TEXT PRIMARY KEY, last_run TEXT, updated_at TEXT)
```

---

## 17. Constants & Thresholds Reference

### 17.1 Timing

| Parameter | Value |
|-----------|-------|
| Observation polling interval | 60 seconds |
| Startup delay (collector) | 180 seconds |
| Startup delay (correlator) | 300 seconds |
| Firewall rules cache TTL | 5 minutes |
| Spike candidate pruning | Every 10 cycles (600s) |
| Auto-classifier cycle | 60 minutes |
| Nightly maintenance | 3:00 AM |
| Maintenance skip threshold | 6 hours |

### 17.2 Baseline Computation

| Parameter | Value |
|-----------|-------|
| Baseline window | 7 days (604,800s) |
| Learning period | 7 days |
| Min baseline entries for "baselined" | 3 distinct flow tuples |
| Min observations for "baselined" | 50 total observations |
| Observation retention | 30 days |
| Port flow baseline retention | 14 days |

### 17.3 Anomaly Detection

| Parameter | Value |
|-----------|-------|
| Volume spike absolute floor | 5,000,000 bytes/hour (5 MB/hr) |
| Volume spike max multiplier | 3.0× baseline max |
| Volume spike avg multiplier | 5.0× baseline avg |
| Volume spike persistence window | 300 seconds (5 minutes) |
| Volume spike persistence threshold | 2 elevated observations |
| Port flow volume spike ratio | 4.0× max_bytes_per_day |
| Disappeared port minimum baseline days | 5 |
| Disappeared port minimum avg bytes/day | 100,000 (100 KB) |

### 17.4 Deduplication

| Parameter | Value |
|-----------|-------|
| Dedup window (all types) | 3,600 seconds (1 hour) |
| Dedup method | LIKE search in JSON details blob |
| Spike candidate persistence | 2 consecutive cycles |

### 17.5 Scan Noise Filter

| Parameter | Value |
|-----------|-------|
| Known service ports | 37 ports (see Section 6.2) |
| Ephemeral port threshold (>= 49152) | 1 GB total bytes |
| General port minimum flows | 5 |
| General port minimum bytes | 10,000 (10 KB) |

### 17.6 Investigation

| Parameter | Value |
|-----------|-------|
| CDN ASN whitelist | 25+ major providers |
| Roaming protocol ports | 53, 67, 68, 123, 137, 138, 1900, 3478, 5353 |
| Common destination threshold | seen_by_device_count >= 3 |
| Volume spike suspicious ratio | > 20.0× |
| Recurring pattern threshold | same_pattern_24h >= 3 |
| Max investigations per cycle | 100 |
| Investigation lookback | 300 seconds |

### 17.7 Auto-Resolution Timeouts

| VLAN Sensitivity | Timeout |
|-----------------|---------|
| Strictest | Never |
| Strict | Never |
| Moderate | 48 hours |
| Loose | 24 hours |
| Monitor | 72 hours |

### 17.8 Anomaly Link Expiry

| Parameter | Value |
|-----------|-------|
| Link auto-resolve age | 7 days |

---

## 18. Known Limitations

1. **No machine learning.** Baselines are purely statistical (avg/max). No clustering, time-series forecasting, or learned models.

2. **Linear suppression matching.** O(N) scan of all suppression rules per anomaly. Acceptable for < 1000 rules but will degrade at scale.

3. **Dedup searches JSON with LIKE.** The `has_recent_anomaly()` function uses `LIKE '%' || dedup_key || '%'` on the details JSON blob. This is fragile — substring matching in JSON is unreliable when the dedup key appears in different JSON fields or is formatted differently.

4. **1-hour dedup window.** Persistent behaviors (NTP, HTTPS to CDN) that are genuinely new will re-fire every hour indefinitely until the operator acts on them or they age into the baseline.

5. **No WAN blocked_attempt aggregation.** Every unique internet scan probe creates a separate anomaly. On a public IP, this generates thousands of low-value anomalies per day.

6. **Priority boosts never decay.** Once an operator flags a pattern, the boost persists indefinitely, potentially over-escalating long after the threat has passed.

7. **Device disposition not integrated.** The `device.disposition` field exists in the investigation schema but is not populated — Rule 1 (flagged device) never fires.

8. **No active response.** Detection and investigation only. No automated blocking, quarantine, or firewall rule creation.

9. **Single-device baselines.** No cross-device behavioral patterns (e.g., detecting coordinated activity across multiple devices that individually appear normal).

10. **Firewall rule matching is simplified.** Supports CIDR and port ranges but not RouterOS address-lists, interface matchers, or nested rule sets.

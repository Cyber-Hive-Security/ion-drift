# Behavior Engine v2 — Quality Overhaul Plan

## Executive Summary

The behavior engine generates ~10,000 anomalies per 8-hour window. 70% are WAN firewall drops that the engine itself labels `expected_deny` but records anyway. Another 20% are baseline-learning noise from devices doing normal things (NTP pool rotation, HTTPS to CDNs, WireGuard management traffic). Actual signal is buried under ~90% noise.

This plan restructures the engine around one principle: **if the firewall policy says "drop" and the traffic was dropped, that's the firewall working — not an anomaly.**

Ion Drift becomes a **policy-aware behavioral NDR platform** — comparable to Darktrace, Vectra, and ExtraHop, with the unique advantage of firewall-policy-aware anomaly detection.

---

## Problem Breakdown (from 10,000-row CSV analysis)

| Category | Count | % | Root Cause |
|----------|-------|---|------------|
| WAN→WAN blocked_attempt (expected_deny) | 7,006 | 70% | Every firewall drop becomes an anomaly |
| wg-beacon-1 new_port/new_destination | 1,109 | 11% | Baseline too narrow for management devices |
| 00:E0:4C:68:00:43 NTP udp:123 new_dest | 775 | 8% | NTP pool rotation = "new destination" per server |
| Samsung volume_spike tcp:443 | 243 | 2.4% | Consumer HTTPS is bursty by nature |
| Other legitimate traffic | ~867 | 8.7% | Mixed — some real signal buried here |

---

## Detection Pipeline (v2)

```
Traffic Event (connection tracking / syslog)
    ↓
Firewall Policy Evaluation
    ↓ expected_deny → suppress (WAN: aggregate to threat intel)
    ↓ expected_allow → demote severity + confidence
    ↓ policy_unknown → full evaluation
    ↓
Traffic Classification (expanded 20-class taxonomy)
    ↓
Protocol Awareness (roaming / CDN / infrastructure)
    ↓ roaming protocol → suppress new_destination
    ↓ CDN destination → suppress new_destination
    ↓
Baseline Deviation Detection
    ↓
Statistical Validation (dual-gate: EMA Z-score AND MAD Z-score)
    ↓ both must exceed threshold to fire
    ↓
Confidence Scoring (Bayesian log-odds with time decay)
    ↓
Aggregation into Anomaly Groups (by mac + type + traffic_class)
    ↓
WAN Threat Intelligence Correlation (port entropy scoring)
    ↓
Anomaly Output (grouped, ranked by confidence)
```

---

## Phase 1: Policy-Aware Filtering (Kill the Noise)

### 1A. Drop `expected_deny` anomalies at the source

**File:** `behavior_engine.rs:638–834` (`detect_blocked_attempts`)

**Current behavior:** Every firewall drop log entry → `blocked_attempt` anomaly with `policy_outcome: expected_deny`.

**New behavior:** Only create anomalies for drops that are *unexpected* or *noteworthy*.

```
                    ┌──────────────────┐
                    │  Firewall Drop   │
                    │  Log Entry       │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │ Is src internal? │
                    └──┬───────────┬───┘
                       │ YES       │ NO (WAN scanner)
                       │           │
                       ▼           ▼
               Create anomaly   Aggregate into
               (internal device  wan_threat_summary
                was blocked)     (not an anomaly)
```

**Logic change in `detect_blocked_attempts()`:**

```rust
// BEFORE: create anomaly for every drop
// AFTER:
let src_is_internal = registry.is_internal_ip(src_ip);

if !src_is_internal {
    // WAN scanner → don't create anomaly, just count it
    // (Phase 3 handles aggregated WAN threat intel)
    store.upsert_wan_threat(src_ip, dst_port, protocol, geo_info).await?;
    continue;
}

// Internal device blocked — this IS noteworthy
// An internal device tried to reach something and got dropped
// → create anomaly as before
```

**Impact:** Eliminates 7,006 of 10,000 anomalies (70%).

### 1B. Firewall-policy pre-check for `new_*` and `volume_spike` anomalies

**File:** `behavior_engine.rs:289–636` (`detect_anomalies`)

**Current behavior:** Firewall correlation happens, but the anomaly is created regardless of outcome. A `new_destination` with `expected_allow` is just as alarming as one with `policy_unknown`.

**New behavior:** Use firewall correlation to modulate whether an anomaly is created and at what severity.

```
Policy Outcome     → Action
─────────────────────────────────────────────
expected_deny      → Suppress (don't create anomaly)
expected_allow     → Reduce severity by 1 tier, halve confidence
policy_unknown     → Create at full severity (no matching rule = suspicious)
```

**Rationale:** If your firewall has an explicit `accept` rule for traffic, that traffic is sanctioned. It's still worth noting as a baseline deviation, but it's not alarming. If there's *no rule at all*, that's the most interesting case — it means the traffic pattern is outside your explicit policy.

**Implementation in `detect_anomalies()` at line ~507–599:**

```rust
let (fw_corr, fw_rule_id, fw_rule_comment) = correlate_with_firewall(...);

// Policy-aware gating
match fw_corr.as_str() {
    "expected_deny" => continue,  // Firewall will/did handle it
    "expected_allow" => {
        // Sanctioned traffic — reduce severity, still track
        base_severity = demote_severity(base_severity);
        confidence_modifier = 0.5;  // halve confidence
    }
    _ => {} // policy_unknown — full severity (most interesting)
}
```

---

## Phase 2: Intelligent Baseline Learning

### 2A. Protocol & CDN-aware roaming detection

**Problem:** NTP (udp:123) contacts a *pool* of servers. DNS contacts multiple resolvers. DHCP broadcasts. CDN-backed services rotate edge servers. STUN rotates NAT traversal servers for video calls. These protocols and services inherently rotate destinations — treating each new server as `new_destination` is wrong.

**File:** `behavior_engine.rs:507–517` (new behavior classification)

**Two layers of roaming detection:**

#### Layer 1: Port-based roaming protocols

Protocols where destination rotation is inherent:

```rust
const ROAMING_PROTOCOLS: &[(i64, &str)] = &[
    (53,   "dns"),       // DNS resolver rotation
    (67,   "dhcp"),      // DHCP broadcasts
    (68,   "dhcp"),      // DHCP client
    (123,  "ntp"),       // NTP pool rotation
    (137,  "netbios"),   // NetBIOS name service
    (138,  "netbios"),   // NetBIOS datagram
    (1900, "ssdp"),      // SSDP/UPnP discovery
    (3478, "stun"),      // STUN/WebRTC NAT traversal
    (5353, "mdns"),      // mDNS multicast
];

fn is_roaming_protocol(dst_port: Option<i64>) -> bool {
    dst_port.map_or(false, |p| ROAMING_PROTOCOLS.iter().any(|(port, _)| *port == p))
}
```

#### Layer 2: ASN-based CDN detection

Consumer devices rotate between CDN edge servers constantly. We already have GeoLite2-ASN loaded — use it to identify CDN providers by ASN.

```rust
/// Known CDN/cloud ASNs where destination rotation is expected.
/// Looked up via GeoLite2-ASN (already loaded in GeoCache).
const CDN_ASNS: &[u32] = &[
    13335,  // Cloudflare
    20940,  // Akamai
    54113,  // Fastly
    16509,  // Amazon CloudFront
    15169,  // Google
    8075,   // Microsoft Azure CDN
    14618,  // Amazon AWS
    16625,  // Akamai (alternate)
    46489,  // Twitch
    32934,  // Facebook/Meta
    13414,  // Twitter/X
    36459,  // GitHub
    2906,   // Netflix
];

fn is_cdn_destination(geo_cache: &GeoCache, dst_ip: &str) -> bool {
    if let Some(geo) = geo_cache.lookup_cached(dst_ip) {
        if let Some(asn) = geo.asn {
            return CDN_ASNS.contains(&asn);
        }
    }
    false
}
```

**Change in anomaly detection:**

```rust
// In the "new behavior" branch (line ~507):
if is_roaming_protocol(obs.dst_port) {
    // Don't fire new_destination — destination rotation is expected
    // Still check for volume_spike against port-class baseline
    continue;
}

// CDN check for outbound HTTPS
if obs.direction == "outbound"
    && obs.protocol == "tcp"
    && matches!(obs.dst_port, Some(443 | 80))
    && is_cdn_destination(geo_cache, &obs.dst_subnet)
{
    continue; // CDN edge rotation is not anomalous
}
```

**Impact:** Eliminates the 775 NTP anomalies, similar DNS/mDNS noise, and CDN false positives.

### 2B. Adaptive volume thresholds by VLAN sensitivity

**Problem:** The Samsung phone triggers 243 `volume_spike` anomalies for normal HTTPS bursts. Consumer devices are inherently bursty — loading a webpage spikes traffic for 2-5 seconds, then goes quiet.

**Current thresholds (one-size-fits-all):**
- `hourly_projected > max * 3.0`
- `hourly_projected > avg * 5.0`
- Floor: 5 MB/hr

**New thresholds by VLAN sensitivity:**

| VLAN Sensitivity | Max Multiplier | Avg Multiplier | Floor | Rationale |
|-----------------|----------------|----------------|-------|-----------|
| Strictest (IoT restricted) | 2.0× | 3.0× | 1 MB/hr | Any deviation matters |
| Strict (IoT internet) | 2.5× | 4.0× | 3 MB/hr | Moderate tolerance |
| Moderate (servers) | 3.0× | 5.0× | 5 MB/hr | Current defaults |
| Loose (user devices) | 5.0× | 8.0× | 20 MB/hr | Users are bursty |
| Monitor | 10.0× | 15.0× | 50 MB/hr | Only extreme spikes |

**File:** `behavior_engine.rs:346–368`

```rust
struct VolumeThresholds {
    max_multiplier: f64,
    avg_multiplier: f64,
    floor_bytes_per_hour: f64,
}

fn volume_thresholds(sensitivity: VlanSensitivity) -> VolumeThresholds {
    match sensitivity {
        VlanSensitivity::Strictest => VolumeThresholds {
            max_multiplier: 2.0, avg_multiplier: 3.0, floor_bytes_per_hour: 1_000_000.0
        },
        VlanSensitivity::Strict => VolumeThresholds {
            max_multiplier: 2.5, avg_multiplier: 4.0, floor_bytes_per_hour: 3_000_000.0
        },
        VlanSensitivity::Moderate => VolumeThresholds {
            max_multiplier: 3.0, avg_multiplier: 5.0, floor_bytes_per_hour: 5_000_000.0
        },
        VlanSensitivity::Loose => VolumeThresholds {
            max_multiplier: 5.0, avg_multiplier: 8.0, floor_bytes_per_hour: 20_000_000.0
        },
        VlanSensitivity::Monitor => VolumeThresholds {
            max_multiplier: 10.0, avg_multiplier: 15.0, floor_bytes_per_hour: 50_000_000.0
        },
    }
}
```

### 2C. Dual-gate statistical baselines (EMA + MAD)

**Problem:** Current baselines use simple `AVG`/`MAX` over a 7-day window. This treats traffic from 6 days ago as equally important as traffic from 1 hour ago. A device that legitimately changed behavior 2 days ago still triggers anomalies because the old baseline dilutes the new pattern.

**New approach:** Two complementary statistical models that must *both* agree before a volume spike fires.

#### Model 1: Exponential Moving Average (EMA)

Tracks the trend — weights recent observations more heavily.

```
EMA_t = α · x_t + (1 - α) · EMA_{t-1}

where:
  α = 2 / (N + 1)
  N = 168 (hourly granularity over 7 days)
  α ≈ 0.0118
  Half-life ≈ 58 hours (~2.5 days)
```

EMA variance tracks how noisy a flow normally is:

```
Var_t = α · (x_t - EMA_t)² + (1 - α) · Var_{t-1}
StdDev_t = √Var_t
Z_EMA = (observed - EMA) / StdDev
```

#### Model 2: Median Absolute Deviation (MAD)

Handles bursty traffic better than variance. Variance is sensitive to outliers (one big download skews the distribution). MAD is robust — the median doesn't move when a single observation spikes.

```
MAD = median(|x_i - median(x)|)

Scaled MAD (for normal-like distributions):
σ_MAD = 1.4826 × MAD

Z_MAD = (observed - median) / σ_MAD
```

**Why 1.4826?** For normally distributed data, `MAD × 1.4826 ≈ standard deviation`. This scaling makes Z_MAD comparable to Z_EMA, so we can use the same thresholds for both.

#### Dual-gate detection rule

**Both** Z-scores must exceed the threshold to fire a volume spike:

```
if Z_EMA > threshold AND Z_MAD > threshold:
    anomaly = volume_spike
```

**Why dual-gate?** Each model catches what the other misses:
- EMA alone: can be fooled by gradual drift (boiling frog)
- MAD alone: can miss sustained but moderate spikes
- Both together: a spike must be both trend-abnormal AND distribution-abnormal

| VLAN Sensitivity | Z Threshold | Probability above (normal) |
|-----------------|-------------|---------------------------|
| Strictest | 2.5σ | 0.62% |
| Strict | 3.0σ | 0.13% |
| Moderate | 3.5σ | 0.023% |
| Loose | 4.0σ | 0.003% |
| Monitor | 5.0σ | 0.00003% |

**Example:** A phone that normally transfers 10 MB/hr with high burstiness (MAD = 8 MB) won't flag until `10 + 4.0 × 1.4826 × 8 ≈ 57 MB/hr` on a Loose VLAN. But a server that transfers 10 MB/hr with low burstiness (MAD = 0.5 MB) flags at `10 + 3.5 × 1.4826 × 0.5 ≈ 12.6 MB/hr` on a Moderate VLAN. The math adapts to each device.

**New baseline schema:**

```sql
ALTER TABLE device_baselines ADD COLUMN ema_bytes_per_hour REAL DEFAULT 0;
ALTER TABLE device_baselines ADD COLUMN ema_variance REAL DEFAULT 0;
ALTER TABLE device_baselines ADD COLUMN median_bytes_per_hour REAL DEFAULT 0;
ALTER TABLE device_baselines ADD COLUMN mad_bytes_per_hour REAL DEFAULT 0;
ALTER TABLE device_baselines ADD COLUMN last_activity INTEGER DEFAULT 0;
```

**File:** `behavior.rs:925–981` (baseline recomputation)

**EMA computation** (during nightly recomputation):

```rust
let alpha = 0.0118; // 7-day half-life at hourly granularity
let mut ema = 0.0_f64;
let mut ema_var = 0.0_f64;
let mut initialized = false;

for obs in observations.iter().rev() { // oldest first
    let x = (obs.bytes_sent + obs.bytes_recv) as f64 * 60.0; // hourly projected
    if !initialized {
        ema = x;
        ema_var = 0.0;
        initialized = true;
    } else {
        let delta = x - ema;
        ema = alpha * x + (1.0 - alpha) * ema;
        ema_var = alpha * delta * delta + (1.0 - alpha) * ema_var;
    }
}
```

**MAD computation:**

```rust
let mut hourly_values: Vec<f64> = observations
    .iter()
    .map(|o| (o.bytes_sent + o.bytes_recv) as f64 * 60.0)
    .collect();
hourly_values.sort_by(|a, b| a.partial_cmp(b).unwrap());

let median = if hourly_values.is_empty() {
    0.0
} else {
    hourly_values[hourly_values.len() / 2]
};

let mut abs_devs: Vec<f64> = hourly_values.iter().map(|x| (x - median).abs()).collect();
abs_devs.sort_by(|a, b| a.partial_cmp(b).unwrap());

let mad = if abs_devs.is_empty() {
    0.0
} else {
    abs_devs[abs_devs.len() / 2]
};
```

### 2D. Grace period for newly-baselined devices

**Problem:** When a device transitions from `learning` → `baselined`, the very first detection cycle floods anomalies for every flow that doesn't exactly match the sparse 7-day baseline.

**New behavior:** 24-hour grace period after promotion. During grace:
- Only `volume_spike` anomalies fire (clear statistical deviations)
- `new_destination`, `new_port`, `new_protocol` are suppressed
- After grace, full detection resumes

**File:** `behavior.rs` (device_profiles schema) + `behavior_engine.rs:302-306`

```sql
ALTER TABLE device_profiles ADD COLUMN baselined_at INTEGER;
```

```rust
// In detect_anomalies():
let grace_period = 86400; // 24 hours
let in_grace = profile.baselined_at
    .map(|t| BehaviorStore::now_unix_pub() - t < grace_period)
    .unwrap_or(false);

if in_grace && anomaly_type != "volume_spike" {
    continue; // Suppress new_* during grace period
}
```

---

## Phase 3: Aggregated WAN Threat Intelligence

### 3A. Replace per-drop anomalies with aggregated threat summaries

**Problem:** 7,006 individual `blocked_attempt` records for internet scanners. Each one says "79.124.62.122 tried TCP SYN on port X" — 1,488 times for one IP. This is useless as individual anomalies but valuable as aggregated intelligence.

**New table:** `wan_threat_summary`

```sql
CREATE TABLE wan_threat_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 1,
    protocols TEXT,         -- JSON: ["tcp", "udp"]
    ports_targeted TEXT,    -- JSON: [22, 443, 8080, ...]
    geo_country TEXT,
    geo_asn INTEGER,
    geo_org TEXT,
    threat_score REAL,     -- computed from frequency + port profile + entropy
    status TEXT DEFAULT 'active',
    UNIQUE(source_ip)
);
CREATE INDEX idx_wan_threat_last_seen ON wan_threat_summary(last_seen);
CREATE INDEX idx_wan_threat_score ON wan_threat_summary(threat_score);
```

Instead of creating anomalies, the blocked attempt detector upserts into `wan_threat_summary`:

```rust
if !src_is_internal {
    store.upsert_wan_threat(src_ip, dst_port, protocol, geo_info).await?;
    continue;
}
```

### 3B. Threat scoring with port entropy

**Scoring formula:**

```
threat_score = frequency_score + port_profile_score + persistence_score + entropy_score
```

**Component 1 — Frequency:**

```
hits < 10       → 0.1
hits 10-100     → 0.2
hits 100-1000   → 0.35
hits > 1000     → 0.5
```

**Component 2 — Port profile (what they're targeting):**

```
Management ports (22, 8291, 8728)    → +0.2
Database ports (3306, 5432, 27017)   → +0.2
Common exploit ports (445, 3389)     → +0.15
Web ports (80, 443, 8080)            → +0.05
```

Take the maximum across all targeted ports.

**Component 3 — Persistence:**

```
Active < 1 hour    → 0.0
Active 1-24 hours  → 0.05
Active > 24 hours  → 0.1
Active > 7 days    → 0.15
```

**Component 4 — Port entropy (scanning breadth):**

Shannon entropy of the port distribution:

```
H = -Σ p(port) × log₂(p(port))

where p(port) = hits_on_port / total_hits
```

Entropy tells us how *focused* vs *scattered* the scanning is:

```
H = 0       → single port (targeted attack)
H = 1-3     → handful of ports (service enumeration)
H = 5-8     → wide port scan (reconnaissance)
H > 8       → near-random scanning (automated scanner)
```

Entropy score:

```
H < 1       → 0.0   (focused — could be legit retry)
H 1-3       → 0.05  (service enumeration)
H 3-6       → 0.1   (moderate scan)
H > 6       → 0.15  (wide/random scanning)
```

**Total: clamp to [0.0, 1.0]**

**Only create an actual anomaly** when `threat_score > 0.8` (sustained, targeted scanning). This would flag 79.124.62.122 (1,488 hits, management ports, persistent, high entropy) as ONE high-confidence anomaly instead of 1,488 low-value ones.

### 3C. New API endpoint and frontend card

**File:** `routes/behavior.rs` + `web/src/routes/behavior.tsx`

```
GET /api/behavior/wan-threats?limit=50&min_score=0.5
```

Returns aggregated threat intelligence for the UI — top scanners, their targeted ports, countries of origin, entropy scores. This replaces the wall of individual `blocked_attempt` entries with a useful threat dashboard.

---

## Phase 4: Anomaly Aggregation

### 4A. Group by (mac, anomaly_type, traffic_class) with dst_subnet drill-down

**Problem:** Same device, same anomaly type, slightly different flow → individual records. wg-beacon-1 gets 1,109 anomalies for variations of "management device connected to management port."

**Grouping key:** `(mac, anomaly_type, traffic_class, vlan)` — groups by *what kind of behavior* a device is exhibiting, not by individual destinations.

**Drill-down detail:** `unique_destinations` and `unique_ports` stored as JSON arrays within each group for investigation.

```sql
CREATE TABLE anomaly_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    anomaly_type TEXT NOT NULL,
    traffic_class TEXT NOT NULL,
    vlan INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    max_severity TEXT NOT NULL,
    max_confidence REAL NOT NULL,
    sample_details TEXT,       -- JSON: first 5 individual anomaly details
    unique_destinations TEXT,  -- JSON: unique dst_subnets in group (drill-down)
    unique_ports TEXT,         -- JSON: unique dst_ports in group (drill-down)
    status TEXT DEFAULT 'pending',
    resolved_at INTEGER,
    resolved_by TEXT,
    UNIQUE(mac, anomaly_type, traffic_class, vlan)
);
```

**Aggregation window:** 1 hour (matches current dedup window). After 1 hour of no new events, the group is "closed" and a new one starts.

**File:** `behavior_engine.rs` — replace `has_recent_anomaly()` check:

```rust
// BEFORE:
if !store.has_recent_anomaly(&mac, anomaly_type, &dedup_key, 3600).await? {
    store.record_anomaly(...).await?;
}

// AFTER:
store.record_or_aggregate_anomaly(&mac, anomaly_type, traffic_class, vlan, details).await?;
```

Where `record_or_aggregate_anomaly` either:
1. Finds existing open group → increments `event_count`, updates `last_seen`, appends destination/port to unique sets, appends to sample_details if < 5
2. No open group → creates new group + first individual anomaly

**Impact:** wg-beacon-1's 1,109 anomalies become ~5-10 anomaly groups ("management traffic from wg-beacon-1, 326 events, ports: 443, 80, 8080, 143").

### 4B. Individual anomalies stored for drill-down

Keep the `device_anomalies` table as-is for the raw event log. The `anomaly_groups` table is the *presentation layer* — what the UI shows by default. Each group links to its constituent anomalies.

```sql
ALTER TABLE device_anomalies ADD COLUMN group_id INTEGER REFERENCES anomaly_groups(id);
```

The UI shows groups as collapsed rows. Expanding a group shows the individual events, with `unique_destinations` and `unique_ports` visible as tags/chips for quick investigation.

---

## Phase 5: Confidence Scoring Overhaul

### 5A. Bayesian log-odds confidence with time decay

**Problem:** Current confidence is additive (start at 0.5, add/subtract fixed increments). This creates unintuitive values — a brand-new device with no data can score 0.75 just from being firewall-correlated on a Strict VLAN.

**New approach:** Multiply likelihood ratios, then apply time decay.

```
Prior:     odds = 1:1 (50% — no information)
Evidence:  multiply by likelihood ratio for each factor
Time:      decay older anomalies

Posterior: confidence = (odds / (1 + odds)) × decay
```

**Likelihood ratios:**

| Factor | Ratio | Rationale |
|--------|-------|-----------|
| Device baselined >30 days | 4:1 | Mature baseline, deviations are meaningful |
| Device baselined 7-30 days | 2:1 | Moderate confidence in baseline |
| Device sparse | 0.7:1 | Slightly less reliable |
| Device learning | 0.3:1 | Baseline not established |
| >1000 observations | 2:1 | Rich behavioral data |
| >100 observations | 1.5:1 | Adequate data |
| <10 observations | 0.5:1 | Sparse data |
| Firewall: expected_allow | 0.3:1 | Policy says this is fine |
| Firewall: policy_unknown | 2:1 | No matching rule — suspicious |
| Port-device correlated | 3:1 | Two independent systems agree |
| Z_EMA > 5σ | 5:1 | Extreme EMA outlier |
| Z_EMA > 3σ | 2:1 | Notable EMA outlier |
| Z_MAD > 5σ | 4:1 | Extreme MAD outlier |
| Z_MAD > 3σ | 1.5:1 | Notable MAD outlier |
| On Strictest/Strict VLAN | 2:1 | Higher baseline sensitivity |
| On Loose/Monitor VLAN | 0.7:1 | Expected to be noisy |
| Flagged source country | 3:1 | Geographic risk |
| Management port targeted | 2:1 | Higher-value target |
| Database port targeted | 2.5:1 | High-value target |

**Time decay:**

Older unreviewed anomalies lose relevance:

```
decay = exp(-Δt / τ)

where:
  Δt = seconds since anomaly was created
  τ  = 21600 (6 hours)
```

After 6 hours: confidence × 0.37
After 12 hours: confidence × 0.14
After 24 hours: confidence × 0.02

This makes fresh anomalies naturally float to the top of the list. Stale anomalies that nobody acted on fade to near-zero — the system assumes that if you didn't act within hours, it probably wasn't important.

**Note:** Time decay applies to *display confidence* only. The stored confidence remains unchanged for audit. Decay is computed at query time.

**Calculation example (high-confidence):**

```
Device: baselined 45 days, 2000 obs, Strict VLAN
Anomaly: new_port to unknown destination, no firewall rule, Z_EMA=3.2, Z_MAD=3.5
Age: 10 minutes

Prior odds:           1.0
× baselined (>30d):   × 4.0  = 4.0
× >1000 obs:          × 2.0  = 8.0
× policy_unknown:     × 2.0  = 16.0
× Z_EMA > 3σ:         × 2.0  = 32.0
× Z_MAD > 3σ:         × 1.5  = 48.0
× Strict VLAN:        × 2.0  = 96.0

Base confidence: 96 / (1 + 96) = 0.990
× decay(600s):  × exp(-600/21600) = × 0.973

Display confidence: 96.3%
```

**Calculation example (low-confidence):**

```
Device: sparse, 30 obs, Loose VLAN
Anomaly: new_destination, expected_allow by firewall
Age: 4 hours

Prior odds:           1.0
× sparse:             × 0.7  = 0.7
× expected_allow:     × 0.3  = 0.21
× Loose VLAN:         × 0.7  = 0.147

Base confidence: 0.147 / (1 + 0.147) = 0.128
× decay(14400s): × exp(-14400/21600) = × 0.513

Display confidence: 6.6%
```

**File:** `behavior.rs:307–364` (replace `compute_confidence`)

```rust
pub struct ConfidenceFactor {
    pub name: &'static str,
    pub likelihood_ratio: f64,
}

pub fn compute_confidence_v2(factors: &[ConfidenceFactor]) -> f64 {
    let mut odds = 1.0_f64;
    for factor in factors {
        odds *= factor.likelihood_ratio;
    }
    let confidence = odds / (1.0 + odds);
    confidence.clamp(0.01, 0.99) // never 0% or 100%
}

/// Time-decayed confidence for display (computed at query time).
pub fn display_confidence(stored_confidence: f64, age_seconds: i64) -> f64 {
    let tau = 21600.0; // 6-hour half-life
    let decay = (-age_seconds as f64 / tau).exp();
    (stored_confidence * decay).clamp(0.01, 0.99)
}
```

### 5B. Confidence-based filtering threshold

**New query parameter:** Minimum confidence to surface anomalies in the UI.

```
GET /api/behavior/anomalies?min_confidence=0.3
```

Default: 0.3 (30%). Anomalies below this threshold are still stored (for audit) but hidden from the default view. This lets the math do the filtering instead of requiring manual suppression rules for every noisy pattern.

---

## Phase 6: Enhanced Traffic Classification

### 6A. Expand traffic class taxonomy

**Current:** 8 classes (dhcp_activity, management_protocol, internet_scan, lateral_movement, internal_service_access, broadcast_service, external_service_access, unknown).

**New taxonomy (backward-compatible, adds granularity):**

```rust
fn classify_traffic_class_v2(
    direction: &str,
    protocol: &str,
    dst_port: Option<i64>,
    dst_ip: &str,
    geo_cache: &GeoCache,
) -> &'static str {
    let port = dst_port.unwrap_or(-1);

    // Infrastructure protocols (never anomalous on their own)
    if matches!(port, 67 | 68) { return "dhcp"; }
    if matches!(port, 53) { return "dns"; }
    if matches!(port, 123) { return "ntp"; }
    if matches!(port, 5353) { return "mdns"; }
    if matches!(port, 1900) { return "ssdp_discovery"; }
    if matches!(port, 3478) { return "stun"; }
    if protocol == "icmp" { return "icmp"; }

    // Management protocols (high value)
    if matches!(port, 22 | 23 | 161 | 162 | 8291 | 8728 | 8729) {
        return "management";
    }
    if matches!(port, 443 | 8443) && direction == "lateral" {
        return "management_web";
    }

    // Database protocols (high value if lateral)
    if matches!(port, 3306 | 5432 | 27017 | 6379 | 1433) {
        return "database";
    }

    // File sharing / lateral movement indicators
    if matches!(port, 445 | 139 | 3389 | 5900..=5999) {
        return "lateral_file_or_remote";
    }

    // CDN detection via ASN (outbound HTTPS)
    if matches!(port, 80 | 443) && direction == "outbound" {
        if is_cdn_destination(geo_cache, dst_ip) {
            return "cdn";
        }
        return "web_outbound";
    }
    if matches!(port, 8080 | 8443) && direction == "outbound" {
        return "web_outbound";
    }

    // Email
    if matches!(port, 25 | 465 | 587 | 993 | 143) {
        return "email";
    }

    // VPN/tunnel
    if matches!(port, 1194 | 51820 | 4500 | 500) {
        return "vpn_tunnel";
    }

    // Media streaming
    if matches!(port, 32400 | 8096 | 554 | 1935) {
        return "media_streaming";
    }

    // Direction fallback
    match direction {
        "inbound" => "inbound_unknown",
        "lateral" => "lateral_unknown",
        "internal" => "internal_unknown",
        "outbound" => "outbound_unknown",
        _ => "unknown",
    }
}
```

### 6B. Severity modulation by traffic class

Not all `new_destination` anomalies are equal. A new database connection is far more concerning than a new web connection.

```rust
fn traffic_class_severity_modifier(class: &str) -> i8 {
    match class {
        "database" | "lateral_file_or_remote" => +1,  // escalate
        "management" | "management_web"       => +1,  // escalate
        "web_outbound" | "media_streaming"    => -1,  // demote
        "cdn"                                 => -2,  // CDN rotation is noise
        "dhcp" | "dns" | "ntp" | "mdns"
        | "ssdp_discovery" | "icmp" | "stun"  => -2,  // infrastructure
        _ => 0,
    }
}
```

---

## Phase 7: Baseline Decay & Pruning

### 7A. Adaptive baseline TTL

**Problem:** Once a flow enters the baseline, it stays forever (until device reset). A device that connected to a server once 25 days ago still has that in its baseline, making the baseline increasingly permissive over time.

**New behavior:** Adaptive TTL based on how frequently the flow was observed:

```
TTL = max(14 days, 3 × average_interval_between_observations)
```

A flow observed daily has `TTL = max(14d, 3 × 1d) = 14 days`.
A flow observed weekly has `TTL = max(14d, 3 × 7d) = 21 days`.
A flow observed monthly has `TTL = max(14d, 3 × 30d) = 90 days`.

This keeps tight baselines for frequent flows while giving infrequent-but-legitimate flows (like monthly backups) time to re-appear.

**During nightly recomputation:**

```rust
// For each baseline entry, check if the flow has been observed recently
let ttl_seconds = (3 * avg_interval_seconds).max(14 * 86400);
if now - last_activity > ttl_seconds {
    store.delete_baseline_entry(entry.id).await?;
}
```

### 7B. Baseline size cap per device

**Problem:** Servers with diverse traffic patterns accumulate hundreds of baseline entries, making anomaly detection slow and memory-heavy.

**Cap:** 500 baseline entries per device. If exceeded during recomputation, prune the least-active entries.

```sql
-- Keep top 500 by observation_count, drop the rest
DELETE FROM device_baselines
WHERE mac = ? AND id NOT IN (
    SELECT id FROM device_baselines
    WHERE mac = ?
    ORDER BY observation_count DESC
    LIMIT 500
);
```

---

## Implementation Priority & Order

```
Phase 1A: Drop WAN expected_deny         → Immediate 70% noise reduction
Phase 1B: Policy-aware gating            → Further noise reduction
Phase 2A: Roaming protocol + CDN detect  → Kills NTP/DNS/mDNS/CDN noise
Phase 2D: Grace period after promotion   → Prevents baseline promotion floods
Phase 4A: Anomaly aggregation            → Collapses remaining noise into groups
Phase 3A: WAN threat summary table       → Replaces lost WAN visibility
Phase 5A: Bayesian confidence + decay    → Better signal ranking
Phase 2B: Adaptive volume thresholds     → Fixes Samsung-class false positives
Phase 6:  Enhanced traffic classification → Better context + CDN class
Phase 2C: Dual-gate EMA + MAD baselines  → Long-term accuracy improvement
Phase 7:  Baseline decay (adaptive TTL)  → Keeps baselines tight
Phase 3B: Threat scoring + port entropy  → WAN intelligence
Phase 5B: Confidence filtering           → UI improvement
Phase 3C: WAN threat API + UI            → Dashboard visibility
Phase 4B: Group drill-down              → UI improvement
```

**Phases 1A + 2A + 2D alone** should reduce anomaly volume by ~85-90%.

---

## Database Migrations

```sql
-- Migration: behavior_engine_v2

-- 1. New columns on device_baselines
ALTER TABLE device_baselines ADD COLUMN ema_bytes_per_hour REAL DEFAULT 0;
ALTER TABLE device_baselines ADD COLUMN ema_variance REAL DEFAULT 0;
ALTER TABLE device_baselines ADD COLUMN median_bytes_per_hour REAL DEFAULT 0;
ALTER TABLE device_baselines ADD COLUMN mad_bytes_per_hour REAL DEFAULT 0;
ALTER TABLE device_baselines ADD COLUMN last_activity INTEGER DEFAULT 0;

-- 2. New column on device_profiles
ALTER TABLE device_profiles ADD COLUMN baselined_at INTEGER;

-- 3. New column on device_anomalies
ALTER TABLE device_anomalies ADD COLUMN group_id INTEGER;

-- 4. WAN threat summary
CREATE TABLE IF NOT EXISTS wan_threat_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL UNIQUE,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 1,
    protocols TEXT,
    ports_targeted TEXT,
    geo_country TEXT,
    geo_asn INTEGER,
    geo_org TEXT,
    threat_score REAL DEFAULT 0,
    status TEXT DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_wan_threat_last_seen ON wan_threat_summary(last_seen);
CREATE INDEX IF NOT EXISTS idx_wan_threat_score ON wan_threat_summary(threat_score);

-- 5. Anomaly groups
CREATE TABLE IF NOT EXISTS anomaly_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    anomaly_type TEXT NOT NULL,
    traffic_class TEXT NOT NULL,
    vlan INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    max_severity TEXT NOT NULL,
    max_confidence REAL NOT NULL,
    sample_details TEXT,
    unique_destinations TEXT,
    unique_ports TEXT,
    status TEXT DEFAULT 'pending',
    resolved_at INTEGER,
    resolved_by TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_anomaly_groups_key
    ON anomaly_groups(mac, anomaly_type, traffic_class, vlan);
```

---

## Expected Outcomes

| Metric | Before | After (projected) |
|--------|--------|-------------------|
| Anomalies per 8 hours | ~10,000 | ~100-300 |
| WAN drop noise | 7,006 (70%) | 0 (moved to threat summary) |
| NTP/DNS/mDNS/CDN noise | ~800 (8%) | 0 (roaming + CDN detection) |
| Volume spike false positives | ~250 (2.5%) | ~10-20 (dual-gate EMA+MAD) |
| Baseline learning floods | ~1,100 (11%) | ~50 (grace period + aggregation) |
| Signal-to-noise ratio | ~10% | ~70-80% |
| Actionable anomalies visible | Buried | Top of list (by decayed confidence) |

---

## Future: Policy Drift Detection

Once v2 is stable, the next major capability should be **Policy Drift Detection** — monitoring for unexpected changes in firewall rules:

- New permissive rules added
- Existing rules disabled or reordered
- Rules that haven't matched any traffic in 30+ days (dead rules)
- Rules that are shadowed by earlier rules (unreachable)

This closes the loop: the behavior engine watches *traffic*, policy drift detection watches *rules*.

---

## Files Modified

| File | Changes |
|------|---------|
| `crates/ion-drift-web/src/behavior_engine.rs` | Phases 1A, 1B, 2A, 2B, 2D, 3A, 4A, 6A, 6B |
| `crates/ion-drift-storage/src/behavior.rs` | Phases 2C, 3A, 4A, 5A, 7A, 7B, migrations |
| `crates/ion-drift-web/src/routes/behavior.rs` | Phase 3C (WAN threat API), 5B (confidence filter) |
| `crates/ion-drift-web/src/anomaly_correlator.rs` | Phase 4A (group-aware correlation) |
| `crates/ion-drift-web/src/tasks/behavior.rs` | Phase 7A (baseline pruning in maintenance) |
| `crates/ion-drift-web/src/geo.rs` | Phase 2A (CDN ASN lookup helper) |
| `web/src/routes/behavior.tsx` | Phase 3C (WAN threat card), 4B (group drill-down) |
| `web/src/api/queries.ts` | Phase 3C (WAN threat query), 5B (confidence param) |

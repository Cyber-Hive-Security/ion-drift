# Ion Drift Behavior Engine — Technical Reference

## Overview

The behavior engine learns normal traffic patterns for every device on the network, then detects anomalies when behavior deviates. It operates on a **7-day learning period** per device, after which the device is promoted to "baselined" and anomaly detection activates.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│               OBSERVATION COLLECTION (every 60s)             │
│         Starts 180s after server boot                        │
├──────────────────────────────────────────────────────────────┤
│ 1. Fetch ARP table + DHCP leases → build IP↔MAC maps        │
│ 2. Upsert device_profiles (set learning_until = now + 7d)    │
│ 3. Fetch full connection tracking table from router           │
│ 4. Aggregate by (MAC, protocol, dst_port, dst_subnet, dir)  │
│ 5. Insert into device_observations                           │
│ 6. Run anomaly detection for baselined devices               │
│ 7. Parse firewall drop logs for blocked attempts             │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│            NIGHTLY MAINTENANCE (every 24 hours)              │
│         First run: 24 hours after server start               │
├──────────────────────────────────────────────────────────────┤
│ 1. Recompute device baselines from last 7 days of obs        │
│ 2. Promote 'learning' → 'baselined' if learning_until ≤ now │
│ 3. Prune observations older than 30 days                     │
│ 4. Compute port-level (network-wide) baselines               │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│           ANOMALY CORRELATION (every 60s)                     │
│         Starts 300s after server boot                        │
├──────────────────────────────────────────────────────────────┤
│ 1. Link port-level anomalies to device-level anomalies       │
│ 2. Link device anomalies to port-flow context                │
│ 3. Auto-resolve stale links (> 7 days)                       │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│           AUTO-CLASSIFIER (every 1 hour)                     │
├──────────────────────────────────────────────────────────────┤
│ Auto-dismiss stale pending anomalies based on VLAN           │
│ sensitivity (24–72 hour timeouts for non-critical VLANs)     │
└──────────────────────────────────────────────────────────────┘
```

---

## Data Pipeline

### Step 1: Observation Collection

**Frequency:** Every 60 seconds (after 180-second startup delay)

**Source code:** `crates/ion-drift-web/src/behavior_engine.rs`

The collector performs these operations each cycle:

1. **Fetch ARP + DHCP** from the router REST API to build IP→MAC and IP→hostname lookup maps.

2. **Upsert device profiles** — for each MAC address seen, create or update a record in `device_profiles`. On first creation:
   - `first_seen` = current timestamp
   - `learning_until` = current timestamp + 604,800 seconds (7 days)
   - `baseline_status` = `'learning'`

3. **Fetch connection tracking** — pull the full connection state table from the router (all TCP, UDP, ICMP, and other tracked sessions).

4. **Aggregate connections** — group by `(source_mac, protocol, dst_port, dst_subnet, direction)` and sum bytes sent/received and connection count.

5. **Record observations** — insert aggregated rows into `device_observations`.

### Step 2: Anomaly Detection

**Frequency:** Every 60 seconds (same task as collection, runs immediately after)

**Prerequisite:** Device must have `baseline_status = 'baselined'`

For each baselined device, the engine:

1. Loads the device's baselines from `device_baselines`.
2. Fetches the last 120 seconds of observations.
3. Compares each observation against baselines.

### Step 3: Nightly Baseline Recomputation

**Frequency:** Every 24 hours (first run: 24 hours after server start)

**Source code:** `crates/mikrotik-core/src/behavior.rs` — `recompute_baselines()`

For each device with observations:

1. Query observations from the last 7 days.
2. Group by `(protocol, dst_port, dst_subnet, direction)`.
3. Compute:
   - `avg_bytes_per_hour` = AVG(bytes_sent + bytes_recv) × 3600 / 60
   - `max_bytes_per_hour` = MAX(bytes_sent + bytes_recv) × 3600 / 60
   - `observation_count` = number of samples
4. Upsert into `device_baselines`.
5. **Promotion check:** If `baseline_status = 'learning'` AND `learning_until ≤ now`, promote to `'baselined'`.

### Step 4: Observation Pruning

During nightly maintenance, observations older than 30 days are deleted. Baselines only use the most recent 7 days, so older data is not needed.

---

## Learning Period & Baseline Promotion

### Timeline (Exact Behavior)

```
Day 0, 14:00  Device first seen
              ├─ learning_until = Day 7, 14:00
              ├─ baseline_status = 'learning'
              └─ Observations start collecting every 60s

Day 1–7       Observations accumulate (~10,080 samples per device
              at 1/min if device has active connections)

Day 7, 14:00  learning_until reached
              BUT promotion only happens at next nightly maintenance

Day 8, ~14:00 Nightly maintenance runs (24h after server start)
              ├─ Baselines recomputed from 7 days of observations
              ├─ learning_until (Day 7 14:00) ≤ now (Day 8 14:00)? YES
              ├─ baseline_status → 'baselined'
              └─ Anomaly detection now active for this device
```

### Key Points

- **Minimum time to baseline:** 7 days + time until next nightly maintenance = **7–8 days**.
- **Promotion is NOT instant** — it only happens during the nightly maintenance task.
- **If the server restarts**, the 24-hour maintenance timer resets. This can delay promotion.
- **Empty baselines are valid** — a device with no traffic during learning still gets promoted. It will then trigger `new_port`/`new_destination` anomalies for any traffic it generates.

### Baseline Status Values

| Status | Meaning |
|--------|---------|
| `learning` | Within 7-day learning window. Observations collected but no anomaly detection. |
| `baselined` | Learning complete. Anomaly detection active. Baselines recomputed nightly. |

---

## Anomaly Types

### Device-Level Anomalies

These require the device to be `baselined`.

#### `volume_spike`
- **Trigger:** Observed hourly-projected bytes > baseline max × 3.0
- **Calculation:** `projected = observation_bytes × 60` (scale 60s sample to 1 hour)
- **Dedup:** Same MAC + dst_subnet + dst_port within 3,600 seconds
- **Example:** Device normally sends 500KB/hr to external:443, suddenly sends 1.5MB/hr

#### `new_port`
- **Trigger:** Observation has a dst_port not present in any baseline for that (dst_subnet, protocol)
- **Dedup:** Same MAC + dst_subnet + protocol + port within 3,600 seconds
- **Example:** Device starts connecting to port 4444 outbound — never seen before

#### `new_protocol`
- **Trigger:** Observation uses a protocol not seen in baselines for that dst_subnet
- **Dedup:** Same MAC + dst_subnet + protocol within 3,600 seconds
- **Example:** Device starts using UDP to a subnet where only TCP was baselined

#### `new_destination`
- **Trigger:** Observation targets a dst_subnet not present in any baseline
- **Dedup:** Same MAC + dst_subnet within 3,600 seconds
- **Example:** Device on VLAN 30 starts talking to VLAN 99 (IoT restricted) — never seen before

### Firewall-Level Anomalies

These do NOT require baselines — they come from firewall drop logs.

#### `blocked_attempt`
- **Trigger:** Firewall dropped a connection (log topic contains "firewall", action = "drop")
- **Enrichment:** GeoIP lookup, hostname resolution, VLAN context
- **Dedup:** Same MAC + dst_ip + dst_port within 3,600 seconds
- **Example:** Device attempts outbound connection to port 22 and gets dropped by firewall rule

### Port-Level Anomalies (Network-Wide)

Computed during nightly maintenance from `connection_history`. These are network-wide, not per-device.

#### `new_port` (network-level)
- Port/protocol combination has no baseline entry (first 7 days of observation)

#### `volume_spike` (network-level)
- Network-wide traffic on a port exceeds baseline thresholds

#### `source_anomaly` (network-level)
- Unexpected source IPs or VLANs appear on an established port flow

---

## Severity Calculation

Severity is determined by VLAN sensitivity combined with anomaly type.

### VLAN Sensitivity Tiers

| Tier | VLANs | Rationale |
|------|-------|-----------|
| **Strictest** | IoT Restricted | No-internet devices; any anomaly is suspicious |
| **Strict** | IoT Internet, Network Management | Limited expected behavior |
| **Moderate** | Trusted Services, Security Operations | Servers/services with diverse but predictable traffic |
| **Loose** | Trusted Wired, Trusted Wireless, Guest Isolated | User devices with variable traffic |
| **Monitor** | All other VLANs | Baseline monitoring only |

### Severity Matrix

| VLAN Tier | `blocked_attempt` | `volume_spike` | `new_port` / `new_destination` / `new_protocol` |
|-----------|-------------------|----------------|--------------------------------------------------|
| Strictest | critical | critical | critical |
| Strict | alert | alert | warning |
| Moderate | warning | warning | info |
| Loose | warning | info | info |
| Monitor | info | info | info |

---

## Database Schema

### `device_profiles`

Tracks every device seen on the network.

```sql
CREATE TABLE device_profiles (
    mac              TEXT PRIMARY KEY,
    hostname         TEXT,
    manufacturer     TEXT,
    current_ip       TEXT,
    current_vlan     INTEGER,
    first_seen       INTEGER NOT NULL,      -- Unix timestamp
    last_seen        INTEGER NOT NULL,      -- Unix timestamp
    learning_until   INTEGER NOT NULL,      -- first_seen + 604800
    baseline_status  TEXT DEFAULT 'learning', -- 'learning' | 'baselined'
    notes            TEXT
);
```

### `device_observations`

Raw traffic samples collected every 60 seconds.

```sql
CREATE TABLE device_observations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    mac              TEXT NOT NULL,
    timestamp        INTEGER NOT NULL,      -- Unix timestamp
    ip               TEXT NOT NULL,
    vlan             INTEGER NOT NULL,
    protocol         TEXT NOT NULL,          -- tcp, udp, icmp, other
    dst_port         INTEGER,               -- NULL for ICMP
    dst_subnet       TEXT NOT NULL,          -- VLAN name or 'external'
    direction        TEXT NOT NULL,          -- outbound, lateral, internal, inbound
    bytes_sent       INTEGER DEFAULT 0,
    bytes_recv       INTEGER DEFAULT 0,
    connection_count INTEGER DEFAULT 0
);
CREATE INDEX idx_observations_mac_ts ON device_observations(mac, timestamp);
```

### `device_baselines`

Computed traffic profiles (recomputed nightly from 7-day observation window).

```sql
CREATE TABLE device_baselines (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    mac                TEXT NOT NULL,
    protocol           TEXT NOT NULL,
    dst_port           INTEGER,
    dst_subnet         TEXT NOT NULL,
    direction          TEXT NOT NULL,
    avg_bytes_per_hour REAL DEFAULT 0,
    max_bytes_per_hour REAL DEFAULT 0,
    observation_count  INTEGER DEFAULT 0,
    computed_at        INTEGER NOT NULL,
    UNIQUE(mac, protocol, dst_port, dst_subnet, direction)
);
```

### `device_anomalies`

Detected anomalies with resolution tracking.

```sql
CREATE TABLE device_anomalies (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    mac                   TEXT NOT NULL,
    timestamp             INTEGER NOT NULL,
    anomaly_type          TEXT NOT NULL,       -- volume_spike, new_port, new_protocol, new_destination, blocked_attempt
    severity              TEXT NOT NULL,       -- critical, alert, warning, info
    description           TEXT NOT NULL,
    details               TEXT,               -- JSON with context (src_ip, dst_subnet, projected_hourly, etc.)
    vlan                  INTEGER NOT NULL,
    firewall_correlation  TEXT,
    firewall_rule_id      TEXT,
    firewall_rule_comment TEXT,
    status                TEXT DEFAULT 'pending', -- pending, accepted, flagged, dismissed, auto_dismissed
    resolved_at           INTEGER,
    resolved_by           TEXT
);
CREATE INDEX idx_anomalies_mac ON device_anomalies(mac);
CREATE INDEX idx_anomalies_status ON device_anomalies(status);
```

### `port_flow_baseline` (Network-Wide)

Aggregate port-level baselines computed from connection history.

```sql
CREATE TABLE port_flow_baseline (
    id                       INTEGER PRIMARY KEY,
    flow_direction           TEXT NOT NULL,       -- outbound, internal
    protocol                 TEXT NOT NULL,
    dst_port                 INTEGER NOT NULL,
    service_name             TEXT,
    avg_bytes_per_day        INTEGER,
    max_bytes_per_day        INTEGER,
    avg_connections_per_day  INTEGER,
    max_connections_per_day  INTEGER,
    days_present             INTEGER,             -- Out of 7, how many days this port appeared
    typical_sources          TEXT,                -- JSON array
    typical_destinations     TEXT,                -- JSON array
    computed_at              TEXT,                -- ISO 8601
    UNIQUE(flow_direction, protocol, dst_port)
);
```

---

## API Endpoints

### Overview

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/behavior/overview` | Summary: total devices, baselined count, learning count, per-VLAN stats |
| GET | `/api/behavior/alerts` | Pending anomaly counts (total, critical, warning, affected MACs) |
| GET | `/api/behavior/anomalies` | Query anomalies with filters (status, severity, VLAN, limit) |
| POST | `/api/behavior/anomalies/:id/resolve` | Resolve anomaly (accepted / flagged / dismissed) |
| GET | `/api/behavior/vlan/:vlan_id` | VLAN detail: devices + anomalies for a VLAN |
| GET | `/api/behavior/device/:mac` | Device detail: profile, baselines, anomalies, port context |
| GET | `/api/behavior/anomaly-links` | Cross-system anomaly correlations |
| POST | `/api/behavior/anomaly-links/:id/resolve` | Resolve a correlation link |

### Key Response Structures

**Device Profile:**
```json
{
  "mac": "AA:BB:CC:DD:EE:FF",
  "hostname": "my-laptop",
  "manufacturer": "Dell",
  "current_ip": "192.168.1.100",
  "current_vlan": 30,
  "first_seen": 1707123456,
  "last_seen": 1707209856,
  "learning_until": 1707728256,
  "baseline_status": "learning",
  "notes": null
}
```

**Device Baseline (one per traffic flow):**
```json
{
  "mac": "AA:BB:CC:DD:EE:FF",
  "protocol": "tcp",
  "dst_port": 443,
  "dst_subnet": "external",
  "direction": "outbound",
  "avg_bytes_per_hour": 250000.0,
  "max_bytes_per_hour": 500000.0,
  "observation_count": 168,
  "computed_at": 1707209856
}
```

**Anomaly:**
```json
{
  "id": 42,
  "mac": "AA:BB:CC:DD:EE:FF",
  "timestamp": 1707209800,
  "anomaly_type": "volume_spike",
  "severity": "warning",
  "description": "Traffic volume spike to external (tcp 443): 1.5MB/hr vs baseline max 500KB/hr",
  "details": {
    "src_ip": "192.168.1.100",
    "dst_subnet": "external",
    "protocol": "tcp",
    "dst_port": 443,
    "direction": "outbound",
    "projected_hourly": 1500000.0,
    "baseline_max": 500000.0
  },
  "vlan": 30,
  "status": "pending"
}
```

---

## Configuration

### Hardcoded Constants

| Constant | Value | Location | Description |
|----------|-------|----------|-------------|
| Learning window | 604,800s (7 days) | behavior.rs:367 | Time before baseline promotion |
| Baseline computation window | 604,800s (7 days) | behavior.rs:999 | Observation window for baseline stats |
| Observation TTL | 2,592,000s (30 days) | behavior.rs:1004 | Old observations pruned |
| Volume spike threshold | 3.0× baseline max | behavior_engine.rs:~240 | Trigger for volume_spike anomaly |
| Anomaly dedup window | 3,600s (1 hour) | behavior_engine.rs:~270 | Same anomaly type suppressed within window |
| Collection interval | 60s | main.rs:~966 | Observation + anomaly detection cycle |
| Collection startup delay | 180s | main.rs:~964 | Wait before first collection |
| Maintenance interval | 86,400s (24 hours) | main.rs:~996 | Nightly recomputation cycle |
| Correlation startup delay | 300s | main.rs:~980 | Wait before correlation starts |
| Correlation interval | 60s | main.rs:~980 | Correlation cycle |
| Auto-resolve interval | 3,600s (1 hour) | main.rs:~990 | Stale anomaly check |
| Port baseline stale | 1,209,600s (14 days) | connection_store.rs | Prune if not recomputed |

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `HIVE_ROUTER_PASSWORD` | Router REST API password |
| `HIVE_ROUTER_HOST` | Override router host (default: from config) |
| `HIVE_ROUTER_USER` | Override router username |
| `HIVE_ROUTER_CA_CERT` | Override CA certificate path |
| `RUST_LOG` | Log level filter |

---

## Anomaly Resolution Workflow

### Status Transitions

```
pending ──┬──→ accepted      (operator confirmed as expected; baseline updates)
          ├──→ flagged        (operator confirmed as suspicious; investigate)
          ├──→ dismissed      (operator marked as not concerning; no baseline update)
          └──→ auto_dismissed (system auto-resolved after timeout)
```

### Auto-Dismiss Timeouts (by VLAN tier)

| VLAN Tier | Auto-Dismiss After |
|-----------|-------------------|
| Strictest (99) | Never |
| Strict (90, 2) | Never |
| Moderate (25, 10) | 72 hours |
| Loose (30, 35, 6) | 24 hours |
| Monitor (other) | 24 hours |

---

## Troubleshooting: Why Baselines Might Not Form

### 1. Nightly Maintenance Never Runs

**Symptom:** All devices stuck at `baseline_status = 'learning'` even after 7+ days.

**Cause:** The maintenance task runs on a 24-hour interval starting from server boot. If the server restarts frequently, the timer resets each time and may never complete a full 24-hour cycle.

**Diagnosis:**
- Check logs for: `behavior maintenance: recomputing baselines`
- Query the database:
  ```sql
  SELECT baseline_status, COUNT(*) FROM device_profiles GROUP BY baseline_status;
  ```

### 2. No Observations Being Collected

**Symptom:** `device_observations` table is empty or has very few rows.

**Cause:** The observation collector depends on successful ARP + DHCP + connection tracking fetches from the router. If any of these fail, no observations are recorded.

**Diagnosis:**
- Check logs for: `behavior: observation collection failed`
- Query:
  ```sql
  SELECT COUNT(*) FROM device_observations;
  SELECT mac, COUNT(*) as obs_count FROM device_observations GROUP BY mac ORDER BY obs_count DESC LIMIT 10;
  ```

### 3. Observations Exist But Baselines Are Empty

**Symptom:** Observations present but `device_baselines` table has no rows after maintenance.

**Cause:** The baseline SQL aggregates observations from the last 7 days. If all observations are older than 7 days (e.g., collection stopped for a period), the query returns no rows.

**Diagnosis:**
  ```sql
  SELECT COUNT(*) FROM device_observations
  WHERE timestamp >= (strftime('%s', 'now') - 604800);

  SELECT COUNT(*) FROM device_baselines;
  ```

### 4. Promotion Condition Never Met

**Symptom:** `learning_until` is in the past but device stays `'learning'`.

**Cause:** The promotion SQL requires `baseline_status = 'learning' AND learning_until <= now`. If maintenance doesn't run after `learning_until` passes, promotion is delayed.

**Diagnosis:**
  ```sql
  SELECT mac, baseline_status, learning_until,
         strftime('%s', 'now') AS now_ts,
         CASE WHEN learning_until <= strftime('%s', 'now') THEN 'SHOULD PROMOTE' ELSE 'STILL LEARNING' END AS status
  FROM device_profiles
  WHERE baseline_status = 'learning'
  ORDER BY learning_until;
  ```

### 5. Server Restarts Reset the Maintenance Timer

**Symptom:** Maintenance runs on unpredictable schedule.

**Cause:** The maintenance task sleeps for 24 hours on startup before its first run. Each restart resets this timer. If the server restarts daily, maintenance may never complete.

**Diagnosis:** Check server uptime and restart logs. The behavior maintenance task needs at least 24 hours of continuous uptime to run once.

---

## Source Code Locations

| File | Path | Lines | Purpose |
|------|------|-------|---------|
| Behavior store | `crates/mikrotik-core/src/behavior.rs` | ~1,004 | Data models, SQL schema, baseline computation, observation storage |
| Behavior engine | `crates/ion-drift-web/src/behavior_engine.rs` | ~500 | Collection loop, anomaly detection, blocked attempt parsing |
| Anomaly correlator | `crates/ion-drift-web/src/anomaly_correlator.rs` | ~300 | Cross-system anomaly linking |
| Connection store | `crates/ion-drift-web/src/connection_store.rs` | ~1,650 | Port-level baselines, connection history |
| API routes | `crates/ion-drift-web/src/routes/behavior.rs` | ~400 | REST endpoints for behavior data |
| Task spawning | `crates/ion-drift-web/src/main.rs` | Lines 933–1157 | Spawns collector, maintenance, correlator, auto-classifier |
| Frontend | `web/src/routes/behavior.tsx` | ~650 | Behavior page UI |

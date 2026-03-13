# Behavior Engine v3: Authoritative Sync + Tiered Anomaly Architecture

**Date:** 2026-03-13
**Status:** Draft — awaiting approval before implementation
**Builds on:** [behavior-engine-whitepaper.md](behavior-engine-whitepaper.md) (current engine documentation)

---

## Design Principle

The router configuration is the single source of truth. The behavior engine's learned baselines remain the foundation for detecting behavioral shifts, but the router's authoritative policy — DHCP options, DNS config, firewall rules, address lists — becomes the primary arbiter of what is legitimate. Anomalies are classified into tiers based on whether they conform to or deviate from that policy.

**The core question changes from:**
> "Is this device doing something it hasn't done before?"

**To:**
> "Is this device doing something the network policy says it shouldn't?"

Baselines still matter — they detect volume shifts, pattern changes, and behavioral drift that policy can't express. But policy violations are always higher priority than behavioral novelty.

---

## Table of Contents

1. [Infrastructure Discovery Service](#1-infrastructure-discovery-service)
2. [Anomaly Tier System](#2-anomaly-tier-system)
3. [Policy vs. Behavior Investigation Matrix](#3-policy-vs-behavior-investigation-matrix)
4. [Firewall Comment Tags](#4-firewall-comment-tags)
5. [Dedup Overhaul](#5-dedup-overhaul)
6. [WAN Scan Pressure Aggregation](#6-wan-scan-pressure-aggregation)
7. [Implementation Phases](#7-implementation-phases)
8. [Database Changes](#8-database-changes)
9. [API Changes](#9-api-changes)
10. [Files Modified](#10-files-modified)

---

## 1. Infrastructure Discovery Service

A new background worker polls the RouterOS API every 60 minutes (configurable) to build and maintain a **Global Policy Map** — an authoritative record of what services should exist on the network and which endpoints are legitimate for each protocol.

### 1.1 Data Sources

All of these API endpoints already exist in `mikrotik-core` except address lists.

| Policy Type | RouterOS API | What It Yields |
|---|---|---|
| **NTP Servers** | `GET /rest/ip/dhcp-server/network` | DHCP Option 42 per-pool NTP server IPs |
| **DNS Servers** | `GET /rest/ip/dhcp-server/network` | DHCP Option 6 per-pool DNS server IPs |
| **DNS Upstreams** | `GET /rest/ip/dns` | Upstream resolvers the router itself uses |
| **DNS Static** | `GET /rest/ip/dns/static` | Internal DNS records (authoritative names) |
| **Gateways** | `GET /rest/ip/route` | Default + static route gateway IPs |
| **Address Lists** | `GET /rest/ip/firewall/address-list` | **NEW endpoint needed.** Named groups: management nets, trusted ranges, blocked lists |
| **DHCP Pools** | `GET /rest/ip/dhcp-server` + `/network` | Pool→interface→VLAN mapping, options per pool |
| **Firewall Rules** | `GET /rest/ip/firewall/filter` | Rule comments for `[ION-IGNORE]` / `[ION-CRITICAL]` tags + policy correlation |

### 1.2 Policy Map Schema

**New table: `infrastructure_policy`**

```sql
CREATE TABLE IF NOT EXISTS infrastructure_policy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL,           -- 'ntp', 'dns', 'gateway', 'dhcp', 'management', 'custom'
    protocol TEXT,                   -- 'udp', 'tcp', or NULL (any)
    port INTEGER,                    -- 123, 53, etc. or NULL (any)
    authorized_targets TEXT NOT NULL, -- JSON array: ["10.20.25.5", "1.1.1.1", "10.20.25.0/24"]
    vlan_scope TEXT,                 -- JSON array of VLAN IDs this policy applies to, or NULL (all)
    source TEXT NOT NULL,            -- 'dhcp_option_42', 'dhcp_option_6', 'ip_route', 'address_list:management', 'firewall_comment', 'manual'
    priority TEXT NOT NULL DEFAULT 'high', -- 'critical', 'high', 'medium', 'low'
    last_synced INTEGER NOT NULL,    -- Unix timestamp of last successful sync
    router_entity_id TEXT,           -- RouterOS .id of the source record (for change tracking)
    UNIQUE(service, protocol, port, vlan_scope)
);

CREATE INDEX IF NOT EXISTS idx_policy_service ON infrastructure_policy(service, protocol, port);
CREATE INDEX IF NOT EXISTS idx_policy_vlan ON infrastructure_policy(vlan_scope);
```

### 1.3 Discovery Worker Logic

**Location:** New file `crates/ion-drift-web/src/tasks/policy_sync.rs`

```
spawn_policy_sync(client, store, vlan_registry)
    │
    ├─ Startup: run immediately, then every 60 minutes
    │
    ├─ 1. Fetch DHCP server networks
    │     For each pool/network:
    │       - Extract ntp-server option → policy(service='ntp', targets=[...], vlan_scope=[pool_vlan])
    │       - Extract dns-server option → policy(service='dns', targets=[...], vlan_scope=[pool_vlan])
    │       - Extract gateway option    → policy(service='gateway', targets=[...], vlan_scope=[pool_vlan])
    │
    ├─ 2. Fetch DNS server config
    │     - Extract upstream servers → policy(service='dns', targets=[upstreams], vlan_scope=NULL)
    │
    ├─ 3. Fetch IP routes
    │     - Default routes (0.0.0.0/0) → policy(service='gateway', targets=[gw_ip])
    │     - Static routes → policy(service='routing', targets=[gw_ip], note dst_address)
    │
    ├─ 4. Fetch address lists (NEW API endpoint)
    │     For each list name:
    │       - 'management' / 'trusted' / 'servers' → policy(service='management', targets=[IPs])
    │       - Custom lists → policy(service='custom', targets=[IPs], source='address_list:{name}')
    │
    ├─ 5. Fetch firewall filter rules
    │     For each rule with comment containing [ION-...]:
    │       - Parse tags (Section 4)
    │       - Store tag metadata in policy map
    │
    └─ 6. Diff against existing policy map
          - INSERT new policies
          - UPDATE changed policies (targets changed, new DHCP option)
          - Mark stale policies (router entity removed) — don't delete, flag for review
```

### 1.4 Per-VLAN Policy

DHCP servers typically serve different options per pool/interface. The policy map keys by VLAN scope:

- A policy with `vlan_scope = [90]` means "IoT VLAN devices should use these NTP servers"
- A policy with `vlan_scope = NULL` means "all VLANs" (e.g., the router's own DNS upstream)
- A policy with `vlan_scope = [25, 30, 35]` means "trusted VLANs share this DNS policy"

When evaluating a device's traffic, the engine checks:
1. Policies scoped to the device's VLAN
2. Policies scoped to NULL (global)
3. If no policy exists for this service+VLAN → skip policy check, fall through to behavioral baseline

### 1.5 New API Endpoint: Address Lists

**Add to `mikrotik-core/src/resources/firewall.rs`:**

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AddressListEntry {
    #[serde(rename = ".id")]
    pub id: String,
    pub list: String,             // List name: "management", "trusted_dns", etc.
    pub address: String,          // IP or CIDR: "10.20.25.0/24"
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub creation_time: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
}
```

**Add to `mikrotik-core/src/client.rs`:**

```rust
pub async fn firewall_address_lists(&self) -> Result<Vec<AddressListEntry>> {
    self.get("ip/firewall/address-list").await
}
```

---

## 2. Anomaly Tier System

Every anomaly gets a `tier` assignment that controls visibility and urgency.

### 2.1 Tier Definitions

| Tier | Name | When Shown | Purpose |
|------|------|-----------|---------|
| **1** | **Alert** | Always visible, badge count in sidebar | Policy violations, threats, operator-escalated items |
| **2** | **Digest** | Collapsed summary rows, expandable | Behavioral shifts that are policy-compliant |
| **3** | **Telemetry** | Hidden by default, available via toggle | Benign/routine detections for forensic lookback |

### 2.2 Tier Assignment Logic

Tier is determined by the investigation verdict AND policy compliance:

```
if investigation.verdict == "threat":
    tier = 1

elif investigation.verdict == "suspicious":
    tier = 1

elif anomaly matches a policy violation (Section 3, Step 3):
    tier = 1  (Shadow Service / policy misconfiguration)

elif anomaly matches [ION-CRITICAL] firewall rule:
    tier = 1

elif anomaly matches [ION-IGNORE] firewall rule:
    tier = 3

elif investigation.verdict == "routine":
    tier = 3

elif investigation.verdict == "benign":
    tier = 3

elif investigation.verdict == "inconclusive":
    tier = 2

elif anomaly_type == "volume_spike" AND policy_compliant:
    tier = 2  (behavioral shift, not a policy issue)

elif anomaly_type in ("new_destination", "new_port") AND policy_compliant:
    tier = 2

else:
    tier = 2  (default: digest)
```

### 2.3 Digest Aggregation

Tier 2 anomalies are grouped in the UI by `(device_mac, anomaly_type)` into digest rows:

> **BC:24:11:52:4C:E7** (wg-beacon-1) — 416 volume spikes on tcp:443 over 11 hours. Policy-compliant. [Expand]

Clicking [Expand] shows the individual entries. The digest row shows:
- Device identity
- Anomaly type + flow summary
- Count + time span
- Policy compliance badge

### 2.4 Database Column

```sql
ALTER TABLE device_anomalies ADD COLUMN tier INTEGER NOT NULL DEFAULT 2;
CREATE INDEX IF NOT EXISTS idx_anomaly_tier ON device_anomalies(tier, status);
```

---

## 3. Policy vs. Behavior Investigation Matrix

The investigation engine (currently 10 rules) gets new rules inserted at the top of the evaluation chain. Policy rules take precedence over behavioral rules.

### 3.1 New Rules (inserted before existing Rule 1)

**New Rule P1: Authoritative Service — Destination in Policy Map**

```
Condition:
    anomaly.anomaly_type IN ("new_destination", "new_port", "volume_spike")
    AND protocol+port matches a service in infrastructure_policy
    AND destination IP is IN the authorized_targets for this service+VLAN

Verdict: "benign"
Action: "no_action"
Tier: 3
Reason: "Destination {ip} is authoritative for {service} (source: {policy.source})"
```

This eliminates NTP pool rotation noise, DNS resolver traffic, and gateway heartbeats in one rule.

**New Rule P2: Shadow Service — Not in Policy, But Allowed by Firewall**

```
Condition:
    anomaly.anomaly_type IN ("new_destination", "new_port")
    AND protocol+port matches a service in infrastructure_policy
    AND destination IP is NOT IN the authorized_targets
    AND firewall_correlation == "expected_allow"

Verdict: "threat"
Action: "escalate"
Tier: 1
Severity: escalated to "alert" (minimum)
Reason: "Shadow {service}: device {mac} using non-authoritative {service} server {ip}
         — firewall allows this traffic but router policy does not authorize it.
         Possible: rogue {service} server, DNS hijack, misconfigured firewall rule."
```

This is the high-value detection. A device using a DNS server that isn't in the DHCP options, and the firewall lets it through — that's either a misconfiguration or an attack.

**New Rule P3: Blocked Non-Authoritative — Firewall Caught It**

```
Condition:
    anomaly.anomaly_type == "blocked_attempt"
    AND protocol+port matches a service in infrastructure_policy
    AND source IP is NOT IN the authorized_targets
    AND firewall_correlation == "expected_deny"

Verdict: "routine"
Action: "no_action"
Tier: 3
Reason: "Non-authoritative {service} attempt blocked by firewall rule {rule_id}"
```

The firewall already handled it. Log for telemetry, don't alert.

**New Rule P4: ION-CRITICAL Firewall Rule Match**

```
Condition:
    firewall_rule_comment contains "[ION-CRITICAL]"

Verdict: "threat"
Action: "escalate"
Tier: 1
Severity: "critical"
Reason: "Traffic matched critical firewall rule: {rule_comment}"
```

**New Rule P5: ION-IGNORE Firewall Rule Match**

```
Condition:
    firewall_rule_comment contains "[ION-IGNORE]"

Verdict: "benign"
Action: "no_action"
Tier: 3
Reason: "Traffic matched operator-ignored firewall rule: {rule_comment}"
```

### 3.2 Updated Rule Order

```
P1: Authoritative Service (policy match → benign, tier 3)
P2: Shadow Service (policy miss + allowed → threat, tier 1)
P3: Blocked Non-Authoritative (policy miss + blocked → routine, tier 3)
P4: ION-CRITICAL match (→ threat, tier 1)
P5: ION-IGNORE match (→ benign, tier 3)
───────────────────────────────────────────────
 1: Flagged Device (→ suspicious, tier 1)
 2: Blocked Inbound from WAN (→ routine, tier 3)     ** changed: was tier unassigned **
 3: Expected Firewall Deny (→ benign, tier 3)
 4: CDN Destination (→ benign, tier 3)
 5: Common Destination (→ benign, tier 3)
 6: Roaming Protocol (→ benign, tier 3)
 7: Volume Spike Assessment (sparse→routine tier 3, extreme→suspicious tier 1)
 8: Flagged Country (→ suspicious, tier 1)
 9: Learning Device (→ routine, tier 3)
10: Recurring Pattern (→ suspicious, tier 1)
Default: inconclusive → tier 2
```

### 3.3 Protocol Coverage

The policy map initially covers these critical protocols:

| Service | Protocol | Port | Detection Focus |
|---------|----------|------|----------------|
| NTP | UDP | 123 | Rogue NTP server, time manipulation |
| DNS | UDP/TCP | 53 | DNS hijacking, exfiltration over DNS |
| DHCP | UDP | 67, 68 | Rogue DHCP server |
| LDAP | TCP | 389, 636 | Rogue directory service |
| SMB | TCP | 445 | Lateral movement, rogue file shares |
| SNMP | UDP | 161, 162 | Unauthorized network management |
| Syslog | UDP | 514 | Log redirection |
| SMTP | TCP | 25, 587 | Unauthorized mail relay |

For protocols not in the policy map (e.g., tcp:443 HTTPS), the engine falls through to behavioral baseline rules. Baselines remain the primary detection mechanism for general traffic — the policy map handles only protocols where "authorized servers" is a meaningful concept.

---

## 4. Firewall Comment Tags

The engine parses firewall rule comments for structured tags that control anomaly behavior. Tags use bracket syntax: `[ION-<TAG>]`.

### 4.1 Supported Tags

| Tag | Effect | Example Comment |
|-----|--------|----------------|
| `[ION-IGNORE]` | Any traffic matching this rule → Tier 3, verdict benign | `allow IoT to cloud [ION-IGNORE]` |
| `[ION-CRITICAL]` | Any traffic matching this rule → Tier 1, verdict threat, severity critical | `deny VLAN 99 to management [ION-CRITICAL]` |
| `[ION-DIGEST]` | Any traffic matching this rule → Tier 2, verdict routine | `allow guest internet [ION-DIGEST]` |

### 4.2 Parsing Logic

```rust
fn parse_ion_tags(comment: &str) -> Vec<IonTag> {
    // Regex: \[ION-(IGNORE|CRITICAL|DIGEST)\]
    // Returns all matched tags (a rule can have multiple)
    // Case-insensitive matching
}
```

### 4.3 Tag Precedence

If a rule has multiple tags (unusual but possible), `ION-CRITICAL` wins over `ION-IGNORE`.

Priority: `CRITICAL` > `DIGEST` > `IGNORE`

### 4.4 Caching

Tags are extracted during the policy sync cycle (every 60 minutes) and stored alongside the firewall rules cache. The behavior engine consumes them during anomaly detection — no per-anomaly API call needed.

**New table: `firewall_ion_tags`**

```sql
CREATE TABLE IF NOT EXISTS firewall_ion_tags (
    rule_id TEXT PRIMARY KEY,         -- RouterOS .id
    chain TEXT NOT NULL,
    action TEXT NOT NULL,
    tag TEXT NOT NULL,                -- 'ignore', 'critical', 'digest'
    comment TEXT NOT NULL,            -- Full comment text
    rule_summary TEXT NOT NULL,       -- "chain=forward src=10.20.25.0/24 dst=any proto=tcp dport=443"
    last_synced INTEGER NOT NULL
);
```

---

## 5. Dedup Overhaul

### 5.1 Problem

The current dedup uses `LIKE '%' || dedup_key || '%'` on the JSON `details` blob with a 1-hour window. This:
- Fails to match reliably (JSON formatting differences)
- Creates duplicate anomalies every hour for persistent behaviors
- Generates 2,829 excess entries in 11 hours

### 5.2 Solution: Dedicated Dedup Column + "Until Resolved" Window

**Add column:**

```sql
ALTER TABLE device_anomalies ADD COLUMN dedup_key TEXT;
CREATE INDEX IF NOT EXISTS idx_anomaly_dedup
    ON device_anomalies(mac, anomaly_type, dedup_key, status);
```

**New dedup check:**

```sql
SELECT id, timestamp FROM device_anomalies
WHERE mac = ?1
  AND anomaly_type = ?2
  AND dedup_key = ?3
  AND status IN ('pending', 'flagged')
LIMIT 1
```

No time window. If a pending/flagged anomaly exists for this exact pattern, don't create another. Instead, update the existing anomaly:

```sql
UPDATE device_anomalies
SET timestamp = ?1,             -- Update to latest occurrence
    occurrence_count = occurrence_count + 1,
    last_occurrence = ?1
WHERE id = ?2
```

**New columns for occurrence tracking:**

```sql
ALTER TABLE device_anomalies ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE device_anomalies ADD COLUMN last_occurrence INTEGER;
```

### 5.3 Dedup Key Format

Exact, deterministic keys (no JSON searching):

| Anomaly Type | Dedup Key |
|---|---|
| `volume_spike` | `{dst_subnet}\|{protocol}\|{dst_port}` |
| `new_destination` | `{dst_subnet}\|{protocol}\|{dst_port}` |
| `new_port` | `{dst_subnet}\|{protocol}\|{dst_port}` |
| `new_protocol` | `{dst_subnet}\|{protocol}` |
| `blocked_attempt` | `{protocol}\|{dst_port}` (NOT per-source-IP) |

**Key change for blocked_attempt:** Dedup by what port is being targeted, not by who's scanning it. All SYN scans to port 8728 from any source IP are the same anomaly.

---

## 6. WAN Scan Pressure Aggregation

### 6.1 Remove Per-Probe Anomalies

Stop creating individual `blocked_attempt` anomalies for VLAN -1 (WAN interface). Instead, maintain a rolling aggregate.

**New table: `wan_scan_pressure`**

```sql
CREATE TABLE IF NOT EXISTS wan_scan_pressure (
    bucket INTEGER NOT NULL,          -- Unix timestamp rounded to 5-minute intervals
    total_probes INTEGER NOT NULL DEFAULT 0,
    unique_sources INTEGER NOT NULL DEFAULT 0,
    unique_ports INTEGER NOT NULL DEFAULT 0,
    top_ports TEXT,                    -- JSON: [{"port": 8728, "count": 45}, ...]
    top_countries TEXT,                -- JSON: [{"country": "CN", "count": 120}, ...]
    PRIMARY KEY (bucket)
);
```

### 6.2 Scan Pressure Alert

Instead of 8,207 individual anomalies, the engine creates **one** Tier 1 alert when scan pressure deviates from its own baseline:

```
Condition:
    current_5min_probe_count > rolling_7day_avg_5min × 10.0
    OR current_5min_unique_ports > rolling_7day_avg_ports × 5.0

Anomaly:
    type: "wan_scan_surge"
    tier: 1
    severity: "warning"
    description: "Unusual inbound scan pressure: {N} probes in 5 minutes
                  (normal: ~{avg}). Top targeted ports: {ports}.
                  Top source countries: {countries}."
```

### 6.3 Dashboard Widget

The `wan_scan_pressure` table feeds a new dashboard card:
- Time-series sparkline of probe rate
- Top 5 targeted ports (current hour)
- Top 5 source countries (current hour)
- Alert indicator if surge threshold exceeded

---

## 7. Implementation Phases

### Phase 1: Foundation (dedup + tiers + WAN aggregation)

**Goal:** Reduce 10,000 → ~50 visible anomalies immediately, before policy sync exists.

1. Add `tier`, `dedup_key`, `occurrence_count`, `last_occurrence` columns to `device_anomalies`
2. Rewrite `has_recent_anomaly()` to use dedicated `dedup_key` column with "until resolved" semantics
3. Update `detect_anomalies()` and `detect_blocked_attempts()` to populate `dedup_key`
4. Add `wan_scan_pressure` table and aggregation logic
5. Stop creating individual WAN blocked_attempt anomalies; route to aggregation
6. Assign tiers based on existing investigation verdicts (no policy rules yet):
   - `suspicious` / `threat` → Tier 1
   - `inconclusive` → Tier 2
   - `benign` / `routine` → Tier 3
7. Update anomalies API to accept `tier` filter parameter
8. Update frontend Behavior page:
   - Default view: Tier 1 only
   - Tab or toggle for Tier 2 (digests with grouping)
   - Toggle for Tier 3 (telemetry, hidden by default)
   - WAN Scan Pressure card
9. Fix column overlap in DataTable (add `width` property to Column)

**Estimated scope:** ~600 lines Rust, ~200 lines TypeScript

### Phase 2: Policy Sync + Investigation Rules

**Goal:** Router becomes authoritative. Shadow Service detection goes live.

1. Add `AddressListEntry` struct and `firewall_address_lists()` to mikrotik-core
2. Add `infrastructure_policy` table
3. Implement `spawn_policy_sync()` worker:
   - DHCP network options → NTP/DNS/gateway policies per VLAN
   - DNS config → upstream resolver policy
   - IP routes → gateway policy
   - Address lists → management/custom policies
4. Implement `firewall_ion_tags` table and tag parser
5. Add new investigation rules P1–P5 (policy-based)
6. Update tier assignment to incorporate policy compliance
7. Add API endpoint: `GET /api/policy` (view current policy map)
8. Add frontend Policy Map page (read-only, shows what the router declares)

**Estimated scope:** ~800 lines Rust, ~300 lines TypeScript

### Phase 3: Refinement

**Goal:** Polish, edge cases, operator workflow.

1. Add `GET /api/wan-scan-pressure` API with time-range query
2. Dashboard WAN Scan Pressure widget (sparkline + top ports/countries)
3. Policy change detection (diff current vs. previous sync, log changes)
4. Per-VLAN DHCP option extraction (map pool → interface → VLAN)
5. `[ION-DIGEST]` tag support
6. Digest grouping in the anomalies table (collapse repeated Tier 2 entries)
7. "Why this tier?" explainer tooltip on each anomaly (shows which rule assigned the tier)

**Estimated scope:** ~400 lines Rust, ~400 lines TypeScript

---

## 8. Database Changes Summary

### New Tables

| Table | Phase | Purpose |
|-------|-------|---------|
| `infrastructure_policy` | 2 | Authoritative service→target mappings from router config |
| `firewall_ion_tags` | 2 | Parsed `[ION-*]` tags from firewall rule comments |
| `wan_scan_pressure` | 1 | 5-minute aggregated inbound scan metrics |

### Altered Tables

| Table | Column | Phase | Purpose |
|-------|--------|-------|---------|
| `device_anomalies` | `tier INTEGER DEFAULT 2` | 1 | Anomaly visibility tier (1/2/3) |
| `device_anomalies` | `dedup_key TEXT` | 1 | Deterministic dedup key |
| `device_anomalies` | `occurrence_count INTEGER DEFAULT 1` | 1 | How many times this exact anomaly fired |
| `device_anomalies` | `last_occurrence INTEGER` | 1 | Timestamp of most recent recurrence |

### New Indexes

```sql
CREATE INDEX idx_anomaly_tier ON device_anomalies(tier, status);
CREATE INDEX idx_anomaly_dedup ON device_anomalies(mac, anomaly_type, dedup_key, status);
CREATE INDEX idx_policy_service ON infrastructure_policy(service, protocol, port);
```

---

## 9. API Changes

### New Endpoints

| Endpoint | Method | Phase | Description |
|----------|--------|-------|-------------|
| `GET /api/policy` | GET | 2 | Current infrastructure policy map |
| `GET /api/policy/sync` | POST | 2 | Force immediate policy sync |
| `GET /api/wan-scan-pressure` | GET | 3 | Scan pressure time-series (query: `?range=24h`) |

### Modified Endpoints

| Endpoint | Change | Phase |
|----------|--------|-------|
| `GET /api/behavior/anomalies` | Add `tier` query parameter (1, 2, 3, or omit for all) | 1 |
| `GET /api/behavior/overview` | Add `tier1_count`, `tier2_count`, `tier3_count` to response | 1 |
| `GET /api/behavior/alerts` | Alert count reflects Tier 1 only | 1 |
| `GET /api/behavior/anomalies/export.csv` | Add `tier`, `occurrence_count`, `dedup_key` columns | 1 |

---

## 10. Files Modified

### Phase 1

| File | Changes |
|------|---------|
| `crates/ion-drift-storage/src/behavior.rs` | Add columns, rewrite `has_recent_anomaly()`, add `wan_scan_pressure` table, update anomaly queries for tier filter |
| `crates/ion-drift-web/src/behavior_engine.rs` | Populate `dedup_key` on anomaly creation, skip WAN blocked_attempt creation, route to scan aggregation, assign preliminary tier |
| `crates/ion-drift-web/src/routes/behavior.rs` | Add `tier` query param to anomalies endpoint, update overview response |
| `web/src/routes/behavior.tsx` | Tier tabs/toggles, digest grouping, scan pressure card |
| `web/src/api/queries.ts` | Add tier param to anomaly queries |
| `web/src/api/types.ts` | Add tier, occurrence_count to DeviceAnomaly type |
| `web/src/components/data-table.tsx` | Add `width` property to Column interface (already started) |

### Phase 2

| File | Changes |
|------|---------|
| `crates/mikrotik-core/src/resources/firewall.rs` | Add `AddressListEntry` struct |
| `crates/mikrotik-core/src/client.rs` | Add `firewall_address_lists()` method |
| `crates/ion-drift-web/src/tasks/policy_sync.rs` | **New file.** Discovery worker |
| `crates/ion-drift-web/src/tasks/mod.rs` | Register policy_sync task |
| `crates/ion-drift-web/src/investigation.rs` | Add rules P1–P5, update tier assignment |
| `crates/ion-drift-storage/src/behavior.rs` | Add `infrastructure_policy` and `firewall_ion_tags` tables, query methods |
| `crates/ion-drift-web/src/routes/mod.rs` | Add policy routes |
| `web/src/routes/policy.tsx` | **New file.** Policy map viewer |

### Phase 3

| File | Changes |
|------|---------|
| `crates/ion-drift-web/src/routes/behavior.rs` | WAN scan pressure endpoint |
| `web/src/components/dashboard/scan-pressure-card.tsx` | **New file.** Dashboard widget |
| `web/src/routes/index.tsx` | Add scan pressure card to dashboard |

---

## Appendix A: Example Scenarios

### Scenario 1: NTP Pool Rotation (current: 485 anomalies → proposed: 0 visible)

**Device:** 00:E0:4C:68:00:43 on VLAN 30 (Trusted Wired)
**Behavior:** Contacts different NTP servers via udp:123 every poll cycle

**Phase 1 (dedup fix):** 485 anomalies → 1 anomaly with `occurrence_count=485`
**Phase 2 (policy sync):** DHCP Option 42 declares NTP servers. Rule P1 checks: is the destination in the authorized NTP list?
- If yes → Tier 3 telemetry. Invisible.
- If the device is hitting a non-authorized NTP server AND the firewall allows it → **Tier 1 alert: Shadow NTP server.** This is genuinely worth investigating — possible time manipulation attack.

### Scenario 2: WAN Internet Scans (current: 8,207 anomalies → proposed: 1 dashboard card)

**Device:** 18:FD:74:00:6E:1F (WAN interface)
**Behavior:** 2,067 unique source IPs probing 7,088 port combinations

**Phase 1:** All 8,207 anomalies become rows in `wan_scan_pressure`. Zero anomalies created. Dashboard card shows: "908 probes/hour, top ports: 5678 (UDP), 8080, 8728, 8443."

If probe rate spikes to 10x normal → single Tier 1 alert: "WAN scan surge."

### Scenario 3: WireGuard Endpoint (current: 759 anomalies → proposed: 1 digest + possible alert)

**Device:** BC:24:11:52:4C:E7 (wg-beacon-1, VLAN 25)
**Behavior:** 416 volume spikes + 214 new destinations on tcp:443

**Phase 1 (dedup):** 759 → ~12 unique anomalies (deduped by flow). Tier 2 digests.
**Phase 2 (policy):** tcp:443 has no policy entry (no "authorized HTTPS servers" concept). Falls through to behavioral rules. Volume spikes on a VPN endpoint with sparse baseline → Rule 7a: routine, Tier 3.

BUT: if this device contacts tcp:443 on an IP in a flagged country → Rule 8: suspicious, Tier 1. The behavioral baseline still catches this.

### Scenario 4: Shadow DNS Server (current: invisible → proposed: Tier 1 alert)

**Device:** IoT thermostat on VLAN 90
**Behavior:** Sends DNS queries to 8.8.4.4 (Google DNS)
**DHCP Option 6 for VLAN 90:** `["10.20.25.5"]` (AdGuard Home)
**Firewall:** Allows VLAN 90 → any on udp:53 (misconfigured — should restrict to AdGuard)

**Current engine:** Creates "new_destination" anomaly, investigation says "benign" (common destination, CDN ASN). Lost in 10,000 other anomalies.

**Phase 2 engine:** Rule P2 fires: "Shadow DNS: thermostat using non-authoritative DNS server 8.8.4.4. Router DHCP policy authorizes only 10.20.25.5 for VLAN 90. Firewall allows this traffic — possible misconfiguration."

**Tier 1 alert.** The operator now knows:
1. The IoT device is bypassing the local DNS filter
2. The firewall rule needs tightening
3. The device might be hardcoded to use Google DNS (common with cheap IoT)

### Scenario 5: Firewall Comment Tag (current: N/A → proposed: instant ignore/escalate)

**Firewall rule:** `chain=forward action=accept src-address-list=guest dst-address=0.0.0.0/0 comment="allow guest internet [ION-IGNORE]"`

Any anomaly from guest VLAN devices hitting this rule → Tier 3 instantly, no investigation needed. The operator said "I know about this, don't bother me."

**Firewall rule:** `chain=forward action=drop src-address=192.168.99.0/24 dst-address=10.20.25.0/24 comment="IoT must not reach services [ION-CRITICAL]"`

If ANY traffic matches this rule (even a single dropped packet) → Tier 1, severity critical, verdict threat. Something on the IoT VLAN tried to reach the services VLAN — that's never supposed to happen.

# Drill-Down & Automated Investigation Plan

## Problem Statement

Ion Drift has two critical gaps:

1. **Broken drill-down navigation.** The 4-level Sankey investigation page (`/sankey`) exists but is disconnected from the rest of the app. Clicking a flow on the dashboard Sankey, a country on the world map, a device on the topology, or an anomaly on the behavior page should all lead to deeper investigation — most of those paths are broken or missing.

2. **No automated investigation.** When the behavior engine detects an anomaly, it stores it, fires an alert, and waits for a human. There's no system that automatically asks: *Who is this device? What else has it been doing? Is the destination known-bad? Has this pattern happened before? What's the verdict?* The operator gets a notification that says "anomaly detected" — not "here's what happened and here's what it means."

The drill-down fixes make human investigation possible. The automated investigation engine makes it unnecessary for the 90% of anomalies that can be explained programmatically. When the engine can't explain it, the notification includes everything the human needs to pick up where the engine left off.

---

## Architecture: Investigation Engine

### Where It Lives

New module: `crates/ion-drift-web/src/investigation.rs`

Not a separate crate. The investigation engine needs direct access to:
- `BehaviorStore` — anomaly details, device profiles, baselines
- `ConnectionStore` — connection history, GeoIP data
- `SwitchStore` — switch port state, device disposition
- `GeoCache` — ASN/country/city lookups
- `AlertEngine` — notification delivery

All of these are already shared via `Arc<AppState>` in the web crate. A separate crate would require re-plumbing all of those dependencies for no architectural benefit. The investigation logic is tightly coupled to the data stores — it's a consumer, not a standalone service.

### Trigger Point

The investigation engine hooks into the anomaly lifecycle at **record_anomaly()** return. Currently:

```
detect_anomalies() → record_anomaly() → (optional auto-dismiss) → done
```

New flow:

```
detect_anomalies() → record_anomaly() → (optional auto-dismiss) → investigate(anomaly_id)
                                                                         │
detect_blocked_attempts() → record_anomaly() → ─────────────────────────┘
```

`investigate()` runs asynchronously — it doesn't block the 60-second detection cycle. Anomalies that are auto-dismissed by suppression rules skip investigation entirely.

### Investigation Pipeline

Each investigation follows a fixed 6-step pipeline. Steps are cheap (SQLite queries + in-memory lookups), not external API calls. Total time target: <500ms per anomaly.

```
Step 1: Device Context
  ├── Who is this device? (profile, hostname, manufacturer, disposition)
  ├── When was it first seen? How long has it been baselined?
  ├── What VLAN is it on? What's the VLAN sensitivity tier?
  └── Is it flagged, registered, or unknown?

Step 2: Destination Analysis
  ├── GeoIP: country, city, ASN, org name
  ├── Is the ASN a known CDN? (Cloudflare, Akamai, Fastly, AWS, Google, etc.)
  ├── Reverse DNS (if cached from connection history)
  ├── Has this destination been seen by OTHER devices on the network?
  └── If blocked_attempt: who initiated — internal device or external scanner?

Step 3: Behavioral Context
  ├── Is this device's first anomaly, or has it triggered before?
  ├── Same anomaly type recently? (repeat offender check)
  ├── Recent anomaly count (last 24h, last 7d)
  ├── Baseline coverage: how many flows are baselined vs. total observed?
  └── Is the device still in learning period?

Step 4: Traffic Pattern
  ├── Current traffic volume vs. baseline (if volume_spike)
  ├── How many unique destinations in last hour?
  ├── How many unique ports in last hour?
  ├── Any other devices talking to the same destination?
  └── Connection frequency: burst or sustained?

Step 5: Firewall Correlation
  ├── Which rule matched (if any)?
  ├── Rule action: allow, drop, reject?
  ├── Is this an expected block (firewall doing its job)?
  ├── Rule comment (operator intent)
  └── Has this rule matched other anomalies recently?

Step 6: Verdict
  ├── Apply decision matrix (see below)
  ├── Assign investigation_verdict: benign | routine | suspicious | threat | inconclusive
  ├── Generate human-readable summary (2-3 sentences)
  └── Attach recommended_action: no_action | monitor | investigate | block | escalate
```

### Decision Matrix

The verdict isn't ML — it's a deterministic rule cascade. Order matters; first match wins.

```
IF anomaly auto-dismissed by suppression rule:
  → SKIP investigation entirely

IF device.disposition == "flagged":
  → verdict: suspicious
  → action: escalate
  → reason: "Device was previously flagged by operator"

IF blocked_attempt AND source_zone == "WAN":
  → verdict: routine
  → action: no_action
  → reason: "Inbound scan blocked by firewall — normal internet noise"

IF blocked_attempt AND source_zone == "LAN" AND firewall_correlation == "expected_deny":
  → verdict: benign
  → action: no_action
  → reason: "Internal traffic blocked by expected firewall rule: {rule_comment}"

IF new_destination AND destination is CDN (ASN match):
  → verdict: benign
  → action: no_action
  → reason: "New destination is CDN provider ({org_name})"

IF new_destination AND destination seen by 3+ other devices:
  → verdict: benign
  → action: no_action
  → reason: "Destination {ip} is common — seen by {n} other devices"

IF new_port AND port in ROAMING_PROTOCOLS (53, 67, 68, 123, 137, 138, 1900, 3478, 5353):
  → verdict: benign
  → action: no_action
  → reason: "Port {port} is a standard infrastructure protocol"

IF volume_spike AND ratio < 5x AND device.baseline_status == "sparse":
  → verdict: routine
  → action: monitor
  → reason: "Moderate volume increase on device with sparse baseline"

IF volume_spike AND ratio > 20x:
  → verdict: suspicious
  → action: investigate
  → reason: "{ratio}x volume spike — significant deviation from baseline"

IF new_destination AND country in flagged_countries:
  → verdict: suspicious
  → action: investigate
  → reason: "New connection to flagged country: {country}"

IF device.baseline_status == "learning":
  → verdict: routine
  → action: no_action
  → reason: "Device is still in learning period — establishing baseline"

IF repeat_count >= 3 in last 24h (same type, same pattern):
  → verdict: suspicious
  → action: investigate
  → reason: "Recurring anomaly — {count} occurrences in 24h"

DEFAULT:
  → verdict: inconclusive
  → action: monitor
  → reason: "No clear determination — manual review recommended"
```

### Data Model

```sql
CREATE TABLE investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    anomaly_id INTEGER NOT NULL UNIQUE,      -- 1:1 with device_anomalies

    -- Device context (Step 1)
    device_mac TEXT NOT NULL,
    device_hostname TEXT,
    device_manufacturer TEXT,
    device_disposition TEXT,                  -- unknown | registered | flagged
    device_first_seen INTEGER,
    device_baseline_status TEXT,              -- learning | sparse | baselined
    vlan_id INTEGER NOT NULL,
    vlan_sensitivity TEXT,                    -- strictest | strict | moderate | loose | monitor

    -- Destination analysis (Step 2)
    dst_ip TEXT,
    dst_country TEXT,
    dst_city TEXT,
    dst_asn INTEGER,
    dst_org TEXT,
    dst_is_cdn INTEGER DEFAULT 0,            -- boolean
    dst_reverse_dns TEXT,
    dst_seen_by_device_count INTEGER,         -- how many other devices talk to this dest

    -- Behavioral context (Step 3)
    anomaly_type TEXT NOT NULL,
    prior_anomaly_count_24h INTEGER DEFAULT 0,
    prior_anomaly_count_7d INTEGER DEFAULT 0,
    same_pattern_count_24h INTEGER DEFAULT 0, -- same type + same dest pattern
    baseline_coverage_pct REAL,               -- % of observed flows that have baselines

    -- Traffic pattern (Step 4)
    current_volume_bytes INTEGER,
    baseline_volume_bytes INTEGER,
    volume_ratio REAL,                        -- current / baseline
    unique_destinations_1h INTEGER,
    unique_ports_1h INTEGER,
    other_devices_same_dest INTEGER,           -- corroboration count

    -- Firewall correlation (Step 5)
    firewall_rule_id TEXT,
    firewall_action TEXT,                     -- allow | drop | reject
    firewall_rule_comment TEXT,
    firewall_correlation TEXT,                -- expected_allow | expected_deny | policy_unknown

    -- Verdict (Step 6)
    verdict TEXT NOT NULL,                    -- benign | routine | suspicious | threat | inconclusive
    recommended_action TEXT NOT NULL,          -- no_action | monitor | investigate | block | escalate
    reason TEXT NOT NULL,                     -- human-readable explanation
    summary TEXT NOT NULL,                    -- 2-3 sentence narrative

    -- Metadata
    investigated_at INTEGER NOT NULL,
    duration_ms INTEGER,                      -- how long the investigation took

    FOREIGN KEY (anomaly_id) REFERENCES device_anomalies(id)
);

CREATE INDEX idx_investigations_anomaly ON investigations(anomaly_id);
CREATE INDEX idx_investigations_verdict ON investigations(verdict);
CREATE INDEX idx_investigations_device ON investigations(device_mac);
CREATE INDEX idx_investigations_time ON investigations(investigated_at);
```

### Notification Enhancement

Currently, alert notifications look like:

```
🔴 Critical Anomaly Detected
Device: printer-office (AA:BB:CC:DD:EE:FF)
Type: volume_spike
VLAN: 25 (Trusted Services)
Confidence: 0.82
```

With the investigation engine, they become:

```
🟡 Routine — No Action Needed
Device: printer-office (AA:BB:CC:DD:EE:FF)
Type: volume_spike | VLAN 25

Investigation: Moderate volume increase (3.2x baseline) on device
with sparse baseline. Printer has been online for 12 days but only
has 4 baselined flows. Volume spike correlates with print job timing.

Verdict: routine | Action: monitor
Prior anomalies: 2 in 24h, 8 in 7d (all routine)
```

And for things that matter:

```
🔴 Suspicious — Investigation Needed
Device: unknown-device (FF:EE:DD:CC:BB:AA)
Type: new_destination | VLAN 25

Investigation: Unknown device (first seen 3 hours ago, no baseline)
initiated connection to 185.220.101.42 (Russia, AS204428 — not CDN).
No other devices on the network communicate with this IP. Device has
triggered 5 anomalies in the last hour.

Verdict: suspicious | Action: investigate
Destination: 185.220.101.42 (RU) — unique to this device
🔗 Investigate: https://ion-drift.local/sankey?mac=FF:EE:DD:CC:BB:AA
```

**Integration with existing alerting:**

The alert engine already fires on `anomaly_critical`, `anomaly_warning`, and `anomaly_correlated` events. The change:

1. Alert engine waits for investigation to complete before firing (adds <500ms)
2. Alert payload includes `investigation_verdict`, `summary`, and `recommended_action`
3. New alert rule filter: `verdict_filter` — e.g., only alert on `suspicious` or `threat` verdicts
4. Existing ntfy/webhook/SMTP delivery unchanged — just richer payloads
5. Webhook payload gets full investigation JSON for automation consumers (n8n, SOAR, etc.)

This means operators can create rules like:
- "Only notify me for suspicious or threat verdicts" (skip the noise)
- "Send all investigations to webhook for n8n processing" (automation)
- "Email me threats, ntfy me suspicious, ignore routine" (tiered delivery)

---

## Current State Audit

### What Works

| Source | Click Target | Action | Status |
|--------|-------------|--------|--------|
| Dashboard VLAN Sankey | Flow link | `navigate("/sankey?vlan={src}&dest={dst}")` | **Works** — navigates to Sankey investigation Level 1 |
| Dashboard Network Devices | Device row | `navigate("/switches/{deviceId}")` | **Works** — for switch-type devices only |
| Dashboard Connections card | Card | `navigate("/connections")` | **Works** |
| Dashboard Identities card | Card | `navigate("/network/identities")` | **Works** |
| Switch Detail port grid | Port cell | Filters MAC table + traffic table | **Works** |
| Connections page world map | Country polygon/dot/arc | Filters connections table to that country | **Works** — but limited (see below) |

### What's Broken or Missing

| Source | Expected Behavior | Actual Behavior | Issue |
|--------|-------------------|-----------------|-------|
| Port Sankey (outbound/internal) | Click flow → drill down to devices on that port | **No click handler** — display only | Port Sankey has no `onLinkClick` prop |
| World map country click | Show all connections to that country with device breakdown | Filters connections table, but **no device-level drill-down** | Just sets a column filter — no path to "which device is talking to Brazil?" |
| World map city click | Filter to city-level | **Ignores city name**, falls back to country filter | `handleMapCityClick` discards the `city` parameter |
| Topology node click | Drill down to device connections/behavior | **Opens read-only detail panel** — no navigation | No link to connections, behavior, or Sankey for that device |
| Topology node right-click | Context menu with investigation options | Only offers "This is...", "Hide", "Flag" | No "Investigate", "View connections", or "View behavior" options |
| Identity manager row | Click device to investigate | **No row click handler** — only inline editing | No way to navigate from identity to that device's traffic |
| Behavior anomaly row | Click anomaly to investigate the traffic | **Only select for bulk action** — no navigation | No link to the connection/device that triggered the anomaly |
| Dashboard VLAN activity | Click device row to investigate | **Only expands accordion** — no navigation | No path to device connections or Sankey |
| Sankey investigation page | Loaded via URL params from other pages | **Data doesn't display** (reported by user) | Needs debugging — likely query param mismatch or API response issue |
| Firewall rule row | Click rule to see matched connections | **No click handler** — display only | No way to see what traffic a specific rule is matching |
| History page | Click connection row to investigate | **No click handler** — display only | Dead-end page with no drill-down |

---

## Design Principles

1. **Every data point is a doorway.** If something is displayed, clicking it should take you deeper.
2. **Context travels with you.** When you drill down, the destination should pre-filter to what you clicked — no re-searching.
3. **Two interaction patterns:**
   - **Left-click** = navigate/drill-down (tables, cards, data points)
   - **Right-click context menu** = multiple options (topology nodes, identity rows where multiple actions exist)
4. **The Sankey investigation page is the universal drill-down destination for traffic analysis.** Everything that says "show me the traffic for X" lands there at the appropriate level.
5. **Behavior page is the drill-down destination for security analysis.** Anomalies link to behavior; behavior links to traffic.
6. **Machines investigate first, humans verify.** Every anomaly gets an automated investigation. Notifications include the verdict, not just the alert.

---

## Phase 1: Fix the Sankey Investigation Page

**Priority: Highest — everything else routes here**

### 1A. Debug why data doesn't display

The Sankey investigation page reads URL params on initial load:

```typescript
const params = new URLSearchParams(window.location.search);
const vlan = params.get("vlan");
```

But TanStack Router validates search params in the route definition:

```typescript
validateSearch: (search) => ({
  vlan: (search.vlan as string) || undefined,
  dest: (search.dest as string) || undefined,
})
```

**Likely issue:** The page reads `window.location.search` directly instead of using TanStack Router's `useSearch()` hook. If the router strips or transforms params, the page won't see them.

**Fix:** Replace `window.location.search` parsing with `useSearch({ from: sankeyRoute })` and ensure the route validation passes params through correctly.

**Files:** `web/src/features/sankey/sankey-investigation-page.tsx` (lines 221-229)

### 1B. Add `mac` URL parameter for direct device navigation

Currently the page only accepts `vlan` and `dest`. Add `mac` to jump directly to Level 2 (Device Trace):

```typescript
validateSearch: (search) => ({
  vlan: (search.vlan as string) || undefined,
  dest: (search.dest as string) || undefined,
  mac: (search.mac as string) || undefined,
})
```

On load, if `mac` is present, skip to Level 2:

```typescript
if (mac) {
  return { level: "device", mac };
} else if (vlan) {
  return { level: "vlan", vlanId: vlan, destVlan: dest };
}
return { level: "network" };
```

**Files:** `web/src/routes/router.ts`, `web/src/features/sankey/sankey-investigation-page.tsx`

### 1C. Add `country` URL parameter for geographic drill-down

Add a country param that starts at Level 0 but pre-filters to show only connections to that country:

```typescript
validateSearch: (search) => ({
  vlan: ..., dest: ..., mac: ...,
  country: (search.country as string) || undefined,
})
```

This requires a new backend query or client-side filtering on the network overview to highlight/filter flows involving that country.

**Files:** `web/src/routes/router.ts`, `web/src/features/sankey/sankey-investigation-page.tsx`, potentially new API endpoint

### 1D. Update URL as user navigates levels

Currently the page uses client-side state only — clicking through levels doesn't update the browser URL. This means:
- Back button doesn't work within the investigation
- You can't share a link to a specific investigation state
- Browser history is lost

**Fix:** Sync view state with URL search params:

```typescript
// When user clicks a VLAN:
navigate({ search: { vlan: vlanId, dest: destVlan } });

// When user clicks a device:
navigate({ search: { mac: deviceMac } });

// When user clicks back:
navigate({ search: { vlan: vlanId } }); // or {} for network level
```

**Files:** `web/src/features/sankey/sankey-investigation-page.tsx`

---

## Phase 2: Port Sankey Drill-Down

### 2A. Add click handlers to port Sankey flows

**Current:** The outbound and internal port Sankey diagrams (`port-sankey.tsx`) are display-only.

**New behavior:** Click a flow (protocol → port) to navigate to the Sankey investigation page filtered to that port's traffic.

This requires a new URL param and backend support:

```typescript
// Navigate to investigation filtered by port
navigate({ to: "/sankey", search: { protocol: "tcp", port: "443", direction: "outbound" } });
```

**New API support needed:** The Sankey network endpoint should accept optional `protocol`, `port`, and `direction` filters to show only VLANs/devices involved in that specific port flow.

**Files:**
- `web/src/features/world-map/port-sankey.tsx` — add `onLinkClick` prop and handler
- `web/src/routes/connections.tsx` — wire up the handler
- `web/src/features/sankey/sankey-investigation-page.tsx` — handle port filter params
- `crates/ion-drift-web/src/routes/connections.rs` — add filter params to Sankey API

### 2B. Add "involved devices" expansion on port Sankey

The backend already returns `involved_devices` in `ClassifiedPortFlow`. Show them in a tooltip or expandable panel when hovering/clicking a port flow — before navigating away.

**Files:** `web/src/features/world-map/port-sankey.tsx`

---

## Phase 3: World Map Deep Drill-Down

### 3A. Country click → investigation with device breakdown

**Current:** Clicking a country just sets a column filter on the connections table. You see connections but can't easily answer "which of my devices is talking to Russia?"

**New behavior:** Country click opens a **country investigation panel** (slide-in or modal) showing:
1. Top devices by connection count to that country
2. Top destination IPs/orgs in that country
3. Port distribution for traffic to that country
4. Timeline of connections (when did this start?)
5. "Investigate in Sankey" button → `/sankey?country={code}`

**Backend support:** Most of this data can be derived from existing `/api/connections/history?country={code}` with client-side aggregation, or a new endpoint:

```
GET /api/connections/country/{code}/summary?days=30
```

Returns: top devices, top dest IPs, top ports, timeline buckets, total bytes.

**Files:**
- `web/src/features/world-map/world-map.tsx` — keep click handler
- `web/src/routes/connections.tsx` — add country investigation panel component
- `crates/ion-drift-web/src/routes/connections.rs` — new country summary endpoint

### 3B. Fix city-level filtering

**Current:** `handleMapCityClick` ignores the city name.

**Fix:** Pass city to connection history filter:

```typescript
handleMapCityClick = (city: string, countryCode: string) => {
  setColumnFilters({ country: new Set([countryCode]), city: new Set([city]) });
  setActiveTab("connections");
};
```

Requires adding `city` as a filterable column in the connections table (already available in `geo_city` field).

**Files:** `web/src/routes/connections.tsx`

---

## Phase 4: Topology Drill-Down

### 4A. Expand context menu with investigation options

**Current context menu:** "This is...", "Hide from topology", "Flag device"

**New context menu items for endpoints (devices with MAC):**

```
── Investigation ──────────
  View Connections          → navigate("/sankey", { mac })
  View Behavior             → navigate("/behavior", { mac })  [new param]
  Connection History        → navigate("/connections", { src_ip: ip })

── Management ─────────────
  Edit Identity             → navigate("/network/identities", { search: mac })
  This is...                → (existing device picker)
  Hide from topology        → (existing)
  Flag device               → (existing)
```

**For infrastructure nodes (switches/routers):**

```
── Investigation ──────────
  View Device Details       → navigate("/switches/{deviceId}")
  View Connections          → navigate("/sankey", { mac })

── Management ─────────────
  This is...                → (existing)
  Hide from topology        → (existing)
```

**Files:** `web/src/features/topology/topology-page.tsx` (context menu, lines 322-526)

### 4B. Double-click node to investigate

In addition to context menu, double-click a node to go straight to its traffic in Sankey:

```typescript
onNodeDoubleClick: (node) => {
  if (node.mac) {
    navigate({ to: "/sankey", search: { mac: node.mac } });
  }
}
```

**Files:** `web/src/features/topology/topology-page.tsx`, `web/src/features/topology/hooks/use-d3-topology.ts`

---

## Phase 5: Behavior Page Drill-Down

### 5A. Anomaly row click → investigation

**Current:** Clicking an anomaly row selects it for bulk action.

**New behavior:** Single-click still selects. But add an **"Investigate" button** (magnifying glass icon) on each anomaly row that navigates to the Sankey investigation page with the anomaly's device pre-loaded:

```typescript
// Extract from anomaly details
const mac = anomaly.mac;
const dstIp = anomaly.details?.dst_ip;

// If we have both, go straight to conversation level
if (dstIp) {
  navigate({ to: "/sankey", search: { mac, dest_ip: dstIp } });
} else {
  navigate({ to: "/sankey", search: { mac } });
}
```

**Files:** `web/src/routes/behavior.tsx`

### 5B. Show investigation verdict inline

When an anomaly has an associated investigation record, show the verdict badge and summary directly in the anomaly table row. Color-coded: green (benign), blue (routine), yellow (suspicious), red (threat), gray (inconclusive).

Clicking the verdict badge expands to show the full investigation summary without leaving the page.

**Files:** `web/src/routes/behavior.tsx`, `web/src/api/queries.ts`

### 5C. Add `mac` filter to behavior page URL

Allow linking directly to a specific device's anomalies:

```
/behavior?mac=AA:BB:CC:DD:EE:FF
```

Pre-filters the anomaly list to that device. Used by topology context menu "View Behavior" option.

**Files:** `web/src/routes/behavior.tsx`, `web/src/routes/router.ts`

---

## Phase 6: Identity Manager Drill-Down

### 6A. Add row action buttons

The identity table currently only supports inline editing. Add an actions column with:

- **Investigate** (magnifying glass) → `navigate("/sankey", { mac })`
- **View Behavior** (brain icon) → `navigate("/behavior", { mac })`

These appear as icon buttons in a new "Actions" column, separate from the inline-edit cells.

**Files:** `web/src/features/identity/identity-manager-page.tsx`

---

## Phase 7: Dashboard Drill-Down

### 7A. VLAN activity device click → investigate

**Current:** Device rows in VLAN activity only expand an accordion.

**New behavior:** Add a small "investigate" icon button on each device row:

```typescript
onClick={() => navigate({ to: "/sankey", search: { mac: device.mac } })
```

Keep the accordion expand on row click — the investigate button is separate.

**Files:** `web/src/components/dashboard/vlan-activity.tsx`

### 7B. Firewall drops card click → firewall page

**Current:** Firewall drops card is display-only.

**New behavior:** Click the card to navigate to the firewall page:

```typescript
<Link to="/firewall">
```

**Files:** `web/src/components/dashboard/firewall-drops-card.tsx`

### 7C. WAN traffic card click → connections page

**Current:** WAN traffic card is display-only.

**New behavior:** Click to navigate to connections page (world map tab):

```typescript
<Link to="/connections">
```

**Files:** `web/src/components/dashboard/traffic-card.tsx`

---

## Phase 8: Connection History & Firewall Page Drill-Down

### 8A. Connection history row click → conversation detail

**Current:** History page rows are not clickable.

**New behavior:** Click a row to navigate to the Sankey conversation level:

```typescript
onRowClick={(row) => {
  navigate({
    to: "/sankey",
    search: { mac: row.src_mac, dest_ip: row.dst_ip }
  });
}}
```

**Files:** `web/src/routes/history.tsx`

### 8B. Firewall rule row click → matched connections

**Current:** Firewall rules are display-only.

**New behavior:** Click a rule to navigate to connection history filtered by that rule's criteria:

```typescript
onRowClick={(rule) => {
  navigate({
    to: "/connections",
    search: {
      tab: "connections",
      protocol: rule.protocol,
      dst_port: rule.dst_port,
      // Additional filters from rule src/dst address
    }
  });
}}
```

This shows you the actual traffic that matches a specific firewall rule.

**Files:** `web/src/routes/firewall.tsx`, `web/src/routes/connections.tsx` (accept URL search params as initial filters)

---

## Phase 9: Connections Page Accept URL Filters

### 9A. Pre-filter from URL parameters

Multiple drill-down paths land on `/connections` with filters. The page needs to read URL search params and apply them as initial filters:

```typescript
validateSearch: (search) => ({
  tab: search.tab as string || "world-map",
  country: search.country as string || undefined,
  city: search.city as string || undefined,
  protocol: search.protocol as string || undefined,
  dst_port: search.dst_port as string || undefined,
  src_ip: search.src_ip as string || undefined,
  dst_ip: search.dst_ip as string || undefined,
})
```

On load, apply these as initial column filters.

**Files:** `web/src/routes/connections.tsx`, `web/src/routes/router.ts`

---

## Phase 10: Investigation Engine (Backend)

### 10A. Create `investigation.rs` module

New file: `crates/ion-drift-web/src/investigation.rs`

Core struct and pipeline:

```rust
pub struct InvestigationEngine {
    behavior_store: Arc<BehaviorStore>,
    connection_store: Arc<ConnectionStore>,
    switch_store: Arc<SwitchStore>,
    geo_cache: Arc<GeoCache>,
}

impl InvestigationEngine {
    /// Run the full investigation pipeline for a single anomaly.
    /// Returns the investigation record ready for storage.
    pub async fn investigate(&self, anomaly_id: i64) -> Result<Investigation, String> {
        let anomaly = self.behavior_store.get_anomaly(anomaly_id).await?;

        let device_ctx = self.gather_device_context(&anomaly).await?;
        let dest_ctx = self.gather_destination_context(&anomaly).await?;
        let behavior_ctx = self.gather_behavioral_context(&anomaly).await?;
        let traffic_ctx = self.gather_traffic_pattern(&anomaly).await?;
        let fw_ctx = self.gather_firewall_context(&anomaly).await?;

        let verdict = self.determine_verdict(
            &anomaly, &device_ctx, &dest_ctx,
            &behavior_ctx, &traffic_ctx, &fw_ctx
        );

        let summary = self.generate_summary(
            &anomaly, &device_ctx, &dest_ctx, &verdict
        );

        Ok(Investigation { /* ... */ })
    }
}
```

**Key design decisions:**
- All queries are against local SQLite — no external API calls in the hot path
- Investigation is synchronous within the async runtime (no external I/O waits)
- Each `gather_*` method does 1-3 SQLite queries
- `determine_verdict` is the decision matrix (pure logic, no I/O)
- `generate_summary` is template-based string formatting

### 10B. Add investigation storage to BehaviorStore

Add to `crates/ion-drift-storage/src/behavior.rs`:

- `investigations` table (schema above)
- `record_investigation()` — insert after pipeline completes
- `get_investigation(anomaly_id)` — fetch by anomaly ID
- `get_investigations_by_device(mac, limit)` — device history
- `get_investigation_stats()` — verdict distribution for dashboard
- `get_investigations(filters)` — paginated query with verdict/device/time filters

### 10C. Wire investigation into detection cycle

In `behavior_engine.rs`, after `record_anomaly()` returns an ID:

```rust
let anomaly_id = store.record_anomaly(&new_anomaly).await?;

// Skip investigation for auto-dismissed anomalies
if suppression_action.as_deref() != Some("suppress") {
    let engine = investigation_engine.clone();
    tokio::spawn(async move {
        match engine.investigate(anomaly_id).await {
            Ok(investigation) => {
                let _ = store.record_investigation(&investigation).await;
            }
            Err(e) => {
                tracing::warn!("Investigation failed for anomaly {}: {}", anomaly_id, e);
            }
        }
    });
}
```

Investigation failures are logged but don't block anomaly creation. The anomaly exists with or without an investigation — the investigation is enrichment, not gating.

### 10D. CDN detection helper

In `investigation.rs`, add CDN ASN detection using the already-loaded GeoLite2-ASN database:

```rust
const CDN_ASNS: &[u32] = &[
    13335,  // Cloudflare
    20940,  // Akamai
    54113,  // Fastly
    16509,  // Amazon (AWS)
    15169,  // Google
    8075,   // Microsoft
    14618,  // Amazon
    16625,  // Akamai
    32934,  // Facebook/Meta
    46489,  // Twitch
    2906,   // Netflix
    36183,  // Akamai
    21342,  // Akamai
    23454,  // Akamai
    23455,  // Akamai
    34164,  // Akamai
    35994,  // Akamai
    393234, // Cloudflare
];

fn is_cdn(&self, ip: &IpAddr) -> bool {
    self.geo_cache
        .lookup_asn(ip)
        .map(|asn_info| CDN_ASNS.contains(&asn_info.asn))
        .unwrap_or(false)
}
```

### 10E. "Destination commonality" query

New query in `ConnectionStore` — how many unique MACs have connected to a given IP in the last 7 days:

```sql
SELECT COUNT(DISTINCT src_mac)
FROM connection_history
WHERE dst_ip = ?1 AND timestamp > ?2
```

If 5+ devices talk to the same destination, it's almost certainly legitimate infrastructure (DNS, NTP, CDN, cloud services).

---

## Phase 11: Investigation-Enriched Notifications

### 11A. Alert engine waits for investigation

Modify `alerting.rs` to check for investigation records before composing alert payloads:

```rust
// In collect_anomaly_alerts():
for anomaly in new_anomalies {
    // Wait up to 2 seconds for investigation to complete
    let investigation = timeout(
        Duration::from_secs(2),
        wait_for_investigation(anomaly.id)
    ).await.ok().flatten();

    // Build enriched alert payload
    let (title, body) = if let Some(inv) = &investigation {
        build_investigated_alert(&anomaly, inv)
    } else {
        build_basic_alert(&anomaly)  // fallback if investigation timed out
    };

    pending_alerts.push(PendingAlert { title, body, investigation, .. });
}
```

The 2-second timeout prevents investigation delays from blocking alerts. If the investigation hasn't completed (it should — target is <500ms), the alert fires with the basic format.

### 11B. Verdict-based alert filtering

Add `verdict_filter` to `AlertRule`:

```sql
ALTER TABLE alert_rules ADD COLUMN verdict_filter TEXT;
-- NULL = no filter (all verdicts)
-- "suspicious,threat" = only these verdicts
-- "!benign,!routine" = exclude these (alternative syntax)
```

In alert evaluation:

```rust
if let Some(verdict_filter) = &rule.verdict_filter {
    if let Some(inv) = &alert.investigation {
        let allowed: Vec<&str> = verdict_filter.split(',').collect();
        if !allowed.contains(&inv.verdict.as_str()) {
            continue; // skip this alert — verdict filtered out
        }
    }
}
```

This is the biggest quality-of-life improvement: operators can say "don't bother me with benign/routine verdicts" and only get notified for things the engine couldn't explain.

### 11C. Enhanced notification payloads

**ntfy:**
```
Title: {verdict_emoji} {verdict} — {recommended_action}
Body:
Device: {hostname} ({mac})
Type: {anomaly_type} | VLAN {vlan}

{summary}

Verdict: {verdict} | Action: {recommended_action}
Prior: {count_24h} in 24h, {count_7d} in 7d
```

**Webhook (JSON):**
```json
{
  "event_type": "anomaly_critical",
  "investigation": {
    "verdict": "suspicious",
    "recommended_action": "investigate",
    "reason": "New connection to flagged country",
    "summary": "Unknown device initiated...",
    "device": { "mac": "...", "hostname": "...", "disposition": "unknown" },
    "destination": { "ip": "...", "country": "RU", "asn": 204428, "is_cdn": false },
    "prior_anomalies": { "24h": 5, "7d": 12 }
  }
}
```

The webhook payload is the most important — it enables n8n workflows, SOAR integration, and custom automation. An n8n workflow could: receive webhook → check verdict → if threat, auto-block IP on Mikrotik → send Slack message.

### 11D. Investigation link in notifications

All notification channels include a deep link to the investigation:

```
https://{ion_drift_host}/sankey?mac={device_mac}&anomaly_id={id}
```

The `anomaly_id` param (new) causes the Sankey page to show an investigation summary panel alongside the traffic visualization.

---

## Phase 12: Investigation API & Frontend

### 12A. API endpoints

New routes in `crates/ion-drift-web/src/routes/behavior.rs` (or new `routes/investigations.rs`):

```
GET /api/investigations                    — List with filters (verdict, device, time range)
GET /api/investigations/:anomaly_id        — Single investigation by anomaly ID
GET /api/investigations/device/:mac        — All investigations for a device
GET /api/investigations/stats              — Verdict distribution (for dashboard widget)
GET /api/investigations/stats/timeline     — Verdict counts by hour (for trend chart)
```

### 12B. Investigation panel on behavior page

When viewing anomalies, each row with an investigation shows:
- Verdict badge (color-coded)
- One-line reason
- Expandable: full summary, device context, destination details, decision reasoning

### 12C. Dashboard investigation summary widget

New dashboard card: **Investigation Summary (24h)**

```
┌─────────────────────────────────┐
│ Investigations (24h)            │
│                                 │
│  ● 142 benign     ● 23 routine │
│  ● 3 suspicious   ● 0 threat   │
│  ● 1 inconclusive              │
│                                 │
│  [View All →]                   │
└─────────────────────────────────┘
```

Click → navigates to behavior page filtered by verdict.

### 12D. Sankey page investigation overlay

When navigating to `/sankey?mac={mac}&anomaly_id={id}`, show a slide-in panel with the investigation summary alongside the Sankey visualization. The operator sees the traffic AND the engine's analysis at the same time.

---

## New Backend Endpoints (Complete)

| Endpoint | Purpose | Phase |
|----------|---------|-------|
| `GET /api/connections/country/{code}/summary` | Country investigation panel — top devices, IPs, ports, timeline | 3A |
| `GET /api/sankey/network` with `?protocol&port&direction` | Filter Sankey network view by port | 2A |
| `GET /api/investigations` | Paginated investigation list with filters | 12A |
| `GET /api/investigations/:anomaly_id` | Single investigation record | 12A |
| `GET /api/investigations/device/:mac` | Device investigation history | 12A |
| `GET /api/investigations/stats` | Verdict distribution (dashboard widget) | 12A |
| `GET /api/investigations/stats/timeline` | Verdict trend by hour | 12A |

---

## Implementation Priority

```
Phase 1A:  Fix Sankey page data display       → Unblocks all drill-down
Phase 10A: Investigation engine module         → Core engine
Phase 10B: Investigation storage               → Persist results
Phase 10C: Wire into detection cycle           → Engine goes live
Phase 10D: CDN detection helper                → Reduce false positives
Phase 10E: Destination commonality query       → Reduce false positives
Phase 11A: Alert engine waits for investigation → Enriched notifications
Phase 11B: Verdict-based alert filtering       → Noise reduction for operators
Phase 11C: Enhanced notification payloads      → Rich context in alerts
Phase 11D: Investigation deep link             → One-click from alert to context
Phase 1B:  Add mac URL param to Sankey         → Enables direct device investigation
Phase 1D:  Sync Sankey URL with view state     → Back button + shareable links
Phase 5B:  Investigation verdict inline        → See verdicts in anomaly table
Phase 12A: Investigation API endpoints         → Frontend can query investigations
Phase 12B: Investigation panel on behavior     → Full investigation detail view
Phase 12C: Dashboard investigation widget      → At-a-glance verdict summary
Phase 4A:  Topology context menu               → Most-requested drill-down
Phase 5A:  Anomaly investigate button          → Security workflow
Phase 7A:  Dashboard VLAN activity investigate → Most visible entry point
Phase 3A:  World map country investigation     → Geographic analysis
Phase 2A:  Port Sankey click handlers          → Traffic analysis
Phase 6A:  Identity manager actions            → Device management workflow
Phase 8A:  History row click                   → Connection investigation
Phase 4B:  Topology double-click               → Power user shortcut
Phase 7B-C: Dashboard card navigation          → Quick nav polish
Phase 3B:  City-level filtering                → Geographic detail
Phase 8B:  Firewall rule → connections         → Policy audit
Phase 9A:  Connections URL filter params        → Deep linking
Phase 1C:  Country URL param for Sankey        → Geographic + Sankey integration
Phase 2B:  Port Sankey device expansion        → Inline preview
Phase 5C:  Behavior page mac filter            → Direct device behavior view
Phase 12D: Sankey investigation overlay        → Traffic + analysis side-by-side
```

---

## Navigation Map (Target State)

```
Dashboard
├── Firewall Drops card ──────────→ /firewall
├── WAN Traffic card ─────────────→ /connections
├── Network Devices card ─────────→ /switches/{id}
├── Connections card ─────────────→ /connections
├── Identities card ──────────────→ /network/identities
├── Investigation Summary card ───→ /behavior?verdict={type}
├── VLAN Activity device [icon] ──→ /sankey?mac={mac}
└── VLAN Sankey flow click ───────→ /sankey?vlan={src}&dest={dst}

Connections Page
├── World Map country click ──────→ Country investigation panel
│   └── "Investigate in Sankey" ──→ /sankey?country={code}
├── World Map city click ─────────→ Filter connections to city
├── Port Sankey flow click ───────→ /sankey?protocol={p}&port={port}&direction={dir}
└── Connection row click ─────────→ /sankey?mac={mac}&dest_ip={ip}

Topology
├── Double-click node ────────────→ /sankey?mac={mac}
└── Right-click node
    ├── View Connections ─────────→ /sankey?mac={mac}
    ├── View Behavior ────────────→ /behavior?mac={mac}
    ├── Connection History ───────→ /connections?src_ip={ip}
    └── Edit Identity ────────────→ /network/identities?search={mac}

Behavior Page
├── Anomaly [Investigate] button ─→ /sankey?mac={mac}&dest_ip={ip}
├── Anomaly verdict badge ────────→ Expand investigation summary (inline)
└── URL: /behavior?mac={mac} ─────→ Pre-filtered to device

Identity Manager
├── [Investigate] button ─────────→ /sankey?mac={mac}
└── [View Behavior] button ───────→ /behavior?mac={mac}

Firewall Page
└── Rule row click ───────────────→ /connections?protocol={p}&dst_port={port}

History Page
└── Row click ────────────────────→ /sankey?mac={mac}&dest_ip={ip}

Sankey Investigation (/sankey)
├── Level 0: Network Overview
│   └── Click VLAN ───────────────→ Level 1
├── Level 1: VLAN Detail
│   └── Click device ─────────────→ Level 2
├── Level 2: Device Trace
│   └── Click destination ────────→ Level 3
├── Level 3: Conversation Detail
│   └── Export CSV
└── ?anomaly_id={id} ────────────→ Investigation overlay panel

Alert Notification (ntfy/webhook/SMTP)
└── Investigation deep link ──────→ /sankey?mac={mac}&anomaly_id={id}
```

---

## Anomaly Lifecycle (Target State)

```
Observation collected (every 60s)
│
├─→ Anomaly detected
│   ├─→ Suppression rule match?
│   │   ├── "suppress" → discard (no anomaly, no investigation)
│   │   └── "dismissed"/"accepted" → record anomaly, auto-resolve, skip investigation
│   │
│   └─→ record_anomaly() → anomaly_id
│       │
│       └─→ investigate(anomaly_id)          ← NEW
│           ├── Step 1: Device context
│           ├── Step 2: Destination analysis (GeoIP, CDN, commonality)
│           ├── Step 3: Behavioral context (history, repeats, baseline)
│           ├── Step 4: Traffic pattern (volume, ports, destinations)
│           ├── Step 5: Firewall correlation
│           └── Step 6: Verdict + summary
│               │
│               └─→ record_investigation()
│                   │
│                   └─→ Alert engine picks up anomaly
│                       ├── Checks verdict filter on rules
│                       ├── Builds enriched notification with investigation summary
│                       ├── Includes deep link to /sankey?mac=...&anomaly_id=...
│                       └── Delivers via ntfy / webhook / SMTP
│
├─→ Operator receives notification
│   ├── Clicks deep link → Sankey page with investigation overlay
│   ├── Reviews automated analysis
│   └── Takes action: accept / dismiss / flag / escalate
│       ├── "accepted" → recompute baselines
│       ├── "dismissed" → create suppression rule
│       └── "flagged" → bump priority boost → future detections more severe
│
└─→ Hourly: auto-resolve stale anomalies (per VLAN timeout)
    Nightly: recompute baselines, prune old data, classify patterns
```

---

## Files Modified (Complete Summary)

### Frontend

| File | Changes |
|------|---------|
| `web/src/routes/router.ts` | Add URL params to sankey, behavior, connections routes |
| `web/src/features/sankey/sankey-investigation-page.tsx` | Fix data loading, add mac/country/port/anomaly_id params, sync URL with state, investigation overlay |
| `web/src/features/world-map/world-map.tsx` | No changes (click handlers already work) |
| `web/src/features/world-map/port-sankey.tsx` | Add onLinkClick prop and click handlers |
| `web/src/routes/connections.tsx` | Add country investigation panel, accept URL filter params, port Sankey wiring |
| `web/src/features/topology/topology-page.tsx` | Expand context menu, add double-click handler |
| `web/src/features/topology/hooks/use-d3-topology.ts` | Add onNodeDoubleClick callback |
| `web/src/routes/behavior.tsx` | Add investigate button, investigation verdict inline, accept mac URL param |
| `web/src/features/identity/identity-manager-page.tsx` | Add actions column with investigate/behavior buttons |
| `web/src/components/dashboard/vlan-activity.tsx` | Add investigate icon button per device |
| `web/src/components/dashboard/firewall-drops-card.tsx` | Wrap in Link to /firewall |
| `web/src/components/dashboard/traffic-card.tsx` | Wrap in Link to /connections |
| `web/src/components/dashboard/investigation-summary.tsx` | **New** — investigation verdict summary card |
| `web/src/routes/history.tsx` | Add row click → Sankey navigation |
| `web/src/routes/firewall.tsx` | Add row click → connections navigation |
| `web/src/api/queries.ts` | Add investigation query hooks |

### Backend

| File | Changes |
|------|---------|
| `crates/ion-drift-web/src/investigation.rs` | **New** — investigation engine (pipeline, verdict logic, CDN detection, summary generation) |
| `crates/ion-drift-web/src/behavior_engine.rs` | Hook investigation after record_anomaly() |
| `crates/ion-drift-web/src/alerting.rs` | Wait for investigation, verdict filter, enriched payloads |
| `crates/ion-drift-web/src/routes/connections.rs` | Country summary endpoint, port filter on Sankey API |
| `crates/ion-drift-web/src/routes/behavior.rs` | Investigation API endpoints (or new routes/investigations.rs) |
| `crates/ion-drift-storage/src/behavior.rs` | investigations table, CRUD methods |
| `crates/ion-drift-storage/src/connection.rs` | Destination commonality query |
| `crates/ion-drift-web/src/main.rs` | Register investigation routes |

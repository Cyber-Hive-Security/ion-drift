# Drill-Down Navigation Overhaul Plan

## Problem Statement

Ion Drift has a rich 4-level Sankey investigation page (`/sankey`) with network → VLAN → device → conversation drill-down, but it's disconnected from the rest of the app. Clicking a flow on the dashboard Sankey, a country on the world map, a device on the topology, or an anomaly on the behavior page should all lead to deeper investigation — and most of those paths are either broken or missing.

The investigation infrastructure exists on the backend (Sankey APIs, connection history with filtering, GeoIP enrichment). The frontend just doesn't connect the dots.

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

### 5B. Add `mac` filter to behavior page URL

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

## New Backend Endpoints Needed

| Endpoint | Purpose | Used By |
|----------|---------|---------|
| `GET /api/connections/country/{code}/summary` | Country investigation panel — top devices, IPs, ports, timeline | World map country click (Phase 3A) |
| `GET /api/sankey/network` with `?protocol=tcp&port=443&direction=outbound` | Filter Sankey network view by port | Port Sankey click (Phase 2A) |

All other drill-downs use existing endpoints with parameters already supported.

---

## Implementation Priority

```
Phase 1A: Fix Sankey page data display       → Unblocks everything
Phase 1B: Add mac URL param to Sankey         → Enables direct device investigation
Phase 1D: Sync Sankey URL with view state     → Back button + shareable links
Phase 4A: Topology context menu               → Most-requested drill-down
Phase 5A: Anomaly investigate button          → Security workflow
Phase 7A: Dashboard VLAN activity investigate → Most visible entry point
Phase 3A: World map country investigation     → Geographic analysis
Phase 2A: Port Sankey click handlers          → Traffic analysis
Phase 6A: Identity manager actions            → Device management workflow
Phase 8A: History row click                   → Connection investigation
Phase 4B: Topology double-click              → Power user shortcut
Phase 7B-C: Dashboard card navigation         → Quick nav polish
Phase 3B: City-level filtering                → Geographic detail
Phase 8B: Firewall rule → connections         → Policy audit
Phase 9A: Connections URL filter params       → Deep linking
Phase 1C: Country URL param for Sankey        → Geographic + Sankey integration
Phase 2B: Port Sankey device expansion        → Inline preview
Phase 5B: Behavior page mac filter            → Direct device behavior view
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
└── Level 3: Conversation Detail
    └── Export CSV
```

---

## Files Modified (Summary)

### Frontend

| File | Changes |
|------|---------|
| `web/src/routes/router.ts` | Add URL params to sankey, behavior, connections routes |
| `web/src/features/sankey/sankey-investigation-page.tsx` | Fix data loading, add mac/country/port params, sync URL with state |
| `web/src/features/world-map/world-map.tsx` | No changes (click handlers already work) |
| `web/src/features/world-map/port-sankey.tsx` | Add onLinkClick prop and click handlers |
| `web/src/routes/connections.tsx` | Add country investigation panel, accept URL filter params, port Sankey wiring |
| `web/src/features/topology/topology-page.tsx` | Expand context menu, add double-click handler |
| `web/src/features/topology/hooks/use-d3-topology.ts` | Add onNodeDoubleClick callback |
| `web/src/routes/behavior.tsx` | Add investigate button per anomaly, accept mac URL param |
| `web/src/features/identity/identity-manager-page.tsx` | Add actions column with investigate/behavior buttons |
| `web/src/components/dashboard/vlan-activity.tsx` | Add investigate icon button per device |
| `web/src/components/dashboard/firewall-drops-card.tsx` | Wrap in Link to /firewall |
| `web/src/components/dashboard/traffic-card.tsx` | Wrap in Link to /connections |
| `web/src/routes/history.tsx` | Add row click → Sankey navigation |
| `web/src/routes/firewall.tsx` | Add row click → connections navigation |

### Backend

| File | Changes |
|------|---------|
| `crates/ion-drift-web/src/routes/connections.rs` | Add country summary endpoint, add port filter to Sankey network query |
| `crates/ion-drift-web/src/connection_store.rs` | Add country summary query method |

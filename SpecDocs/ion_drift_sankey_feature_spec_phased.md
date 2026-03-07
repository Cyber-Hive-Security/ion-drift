
# Ion Drift Feature Spec
## Interactive Sankey Investigation Tool — Phased Implementation Plan

> This document restructures the Interactive Sankey Investigation Tool into a safer, execution-ready **4-phase feature plan**.
>
> The product direction remains the same:
> - evolve Sankey from static overview into a drill-down investigation workflow
> - keep the existing Dashboard Sankey untouched
> - use `connection_history` as the primary evidence source
>
> The main change is delivery strategy:
> **build this in four phases instead of one monolithic implementation**.

---

# 1. Executive Summary

The Interactive Sankey Investigation Tool is a high-value feature for Ion Drift because it transforms Sankey visualization from a passive dashboard element into an analyst investigation workflow.

The concept is strong, but the original scope is too dense for a single delivery.

This phased plan breaks the work into:

1. **Investigation Foundation**
2. **Device Trace Investigation**
3. **Conversation Detail Investigation**
4. **UX and Interaction Polish**

This structure reduces implementation risk, keeps the backend and frontend manageable, and allows each layer to be validated before the next is added.

---

# 2. Product Goals

## Primary goals
- enable investigation from VLAN-level flows down to endpoint-level behavior
- provide clear behavioral context using existing baselines and anomaly pipelines
- keep drill-down navigation fast, intuitive, and URL-addressable
- avoid destabilizing existing Sankey, connection capture, or behavior systems

## Secondary goals
- improve analyst workflow
- provide more actionable anomaly context
- create a reusable investigation surface for future expansions

## Non-goals
- no Zeek integration
- no firewall rule matching engine
- no CrowdSec enrichment in this feature
- no replacement of the existing Dashboard Sankey
- no changes to connection capture or baseline computation logic

---

# 3. Scope Boundary

## Existing systems that remain unchanged
- Dashboard Inter-VLAN Sankey
- Directional Port Sankeys
- anomaly cross-reference pipeline
- behavioral engine computation
- connection history capture pipeline
- existing pages outside the new Sankey investigation area

## New feature area
A dedicated investigation surface under:

```text
/sankey
```

with phased route expansion.

---

# 4. Shared Design Principles Across All Phases

1. **Use `connection_history` as the investigation source of truth**
2. **Use URL state for navigation and time range persistence**
3. **Use existing behavioral baselines and anomaly sources as read-only context**
4. **Prefer stable and simple interactions before animated polish**
5. **Do not overbuild analyst features before the core drill-down path is working**
6. **Keep performance visible and queryable at each phase**

---

# 5. Shared Technical Foundations

These are required across phases.

## 5.1 Query parameter
All Sankey investigation routes accept:

```text
?range=1h|6h|24h|7d|30d
```

Default:
```text
24h
```

## 5.2 Shared frontend components
These should be introduced in Phase 1 and reused later:
- Time Range Selector
- Breadcrumb
- Shared loading / empty / error state patterns
- Shared anomaly glow styles

## 5.3 Shared backend helper
Introduce a reusable backend helper for:
- parsing time range
- deriving start timestamp
- optionally suggesting aggregation bucket size

Recommended internal abstraction:
- `ParsedRange { label, start_ts, maybe_bucket }`

## 5.4 Shared indexes
Before feature queries are used, inspect existing indexes on `connection_history` and add any missing:

```sql
CREATE INDEX IF NOT EXISTS idx_conn_hist_timestamp ON connection_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_conn_hist_src_vlan_ts ON connection_history(src_vlan, timestamp);
CREATE INDEX IF NOT EXISTS idx_conn_hist_src_mac_ts ON connection_history(src_mac, timestamp);
CREATE INDEX IF NOT EXISTS idx_conn_hist_dst_ip_ts ON connection_history(dst_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_conn_hist_mac_dst ON connection_history(src_mac, dst_ip, timestamp);
```

---

# 6. Phase 1 — Investigation Foundation

## 6.1 Goal
Deliver the first usable drill-down workflow:
- network overview
- VLAN detail
- time range selector
- breadcrumb navigation
- anomaly overlays
- URL-based navigation

This phase proves the product direction without introducing the highest-complexity UI surfaces.

## 6.2 Routes included
- `/sankey`
- `/sankey/vlan/:vlanId`

## 6.3 Backend scope

### Endpoint A — Network Overview
```text
GET /api/sankey/network?range=24h
```

#### Responsibilities
- aggregate `connection_history` by `(src_vlan, dst_vlan)` in selected range
- treat NULL destination or source VLAN as external traffic where appropriate
- return bytes, connection counts, and anomaly overlay summaries
- return VLAN summaries for tooltips / supporting UI

#### Notes
- this is a new investigation data source
- it does **not** replace the Dashboard VLAN Sankey

---

### Endpoint B — VLAN Detail
```text
GET /api/sankey/vlan/{vlan_id}?range=24h&dest_vlan={optional}
```

#### Responsibilities
- show devices within a selected VLAN
- aggregate device → destination flows
- support optional `dest_vlan` filter from clicked Level 0 flow
- classify flow baseline state:
  - baselined
  - unbaselined
  - blocked
  - learning

#### Important constraints
- use syslog-sourced blocked evidence only for blocked classification
- do not attempt firewall rule reconstruction
- use baseline state as read-only behavioral context

#### Destination grouping rules for Phase 1
To avoid unstable right-side Sankey behavior, use this grouping logic:

1. internal VLAN destinations get explicit nodes
2. `WAN / External` aggregate node always exists
3. external breakout nodes are allowed only if:
   - destination group > 20% of device’s external traffic
   - and exceeds a minimum byte threshold
   - and exceeds a minimum connection count

Recommended thresholds:
- minimum bytes: `5 MB`
- minimum connections: `3`

All other external traffic remains grouped into `WAN / External`.

This constraint is required for visual stability.

---

## 6.4 Frontend scope

### Level 0 — Network Overview
Build a dedicated page using the existing D3 Sankey approach as the base.

#### Interactions
- click VLAN node → navigate to VLAN detail
- click flow band → navigate to VLAN detail with `dest_vlan` filter
- hover → tooltip with bytes, connection count, anomaly count

#### Visual requirements
- left/right nodes colored by VLAN palette
- flows width scaled logarithmically
- anomalous flows glow amber/red

---

### Level 1 — VLAN Detail
Render device-level Sankey.

#### Visual requirements
- left nodes = devices
- right nodes = destination VLANs / external groups
- flow colors:
  - green = baselined
  - amber = unbaselined
  - red dashed = blocked
  - gray = learning

#### Interactions
- click device → navigate to future Level 2 route
- hover device → tooltip with identity context
- click destination → local in-page filter is optional in later phases, not required in Phase 1

#### Not in Phase 1
- no right-click context menu
- no side panel
- no crossfade transitions
- no prefetch on hover yet

---

## 6.5 Shared frontend items introduced in Phase 1

### Time Range Selector
- dropdown
- persists via URL param
- refetches data on change

### Breadcrumb
- derived from URL
- clickable back-navigation path

### Anomaly Glow
- reusable amber/red pulsing style

---

## 6.6 TanStack Query hooks in Phase 1

```text
useSankeyNetwork(range)
useSankeyVlan(vlanId, range, destVlan?)
```

Recommended polling:
- 30 seconds

---

## 6.7 Acceptance criteria for Phase 1
- `/sankey` loads and renders network overview from `connection_history`
- `/sankey/vlan/:id` loads and renders VLAN detail
- time range persists through navigation
- breadcrumb works
- anomaly overlays render correctly
- flow baseline states render in correct colors
- Dashboard Sankey remains unchanged

---

# 7. Phase 2 — Device Trace Investigation

## 7.1 Goal
Add device-focused traceability for a selected endpoint:
- what protocols it uses
- where it talks
- which flows are baselined or anomalous
- who else is talking to a destination

## 7.2 Routes included
- `/sankey/device/:mac`

## 7.3 Backend scope

### Endpoint C — Device Trace
```text
GET /api/sankey/device/{mac}?range=24h
```

#### Responsibilities
- show complete traffic picture for a single device
- structure data as:
  - device
  - protocols
  - destinations
  - flows

#### Important implementation constraint
For v1 of Level 2, treat the Sankey as **egress-first**.

That means:
- prioritize traffic where the selected device is the source
- inbound traffic may appear in side stats / summary context
- do not attempt a fully bidirectional Sankey in this phase

This prevents protocol and destination semantics from becoming ambiguous.

#### Protocol grouping rules
- service-name mapping for common ports
- ephemeral ports grouped unless individually significant

---

### Endpoint D — Destination Peers
```text
GET /api/sankey/destination/{ip}/devices?range=24h
```

#### Responsibilities
- return all devices communicating with a destination IP
- used for "Who Else?" investigation
- top 100 devices max by traffic volume

#### Performance note
This endpoint must use the `dst_ip, timestamp` index if available.

---

## 7.4 Frontend scope

### Level 2 — Device Trace
Three-column Sankey:
- left = selected device
- middle = protocol/service nodes
- right = destinations

#### Interactions
- click destination → navigate to future conversation detail
- click protocol → local filter
- "Show Anomalies Only" toggle
- “Who Else?” side panel

### Side Panel — Device Profile
Add a collapsible right panel showing:
- identity summary
- baseline summary
- active anomalies
- disposition

---

## 7.5 Not in Phase 2
- no crossfade transitions yet
- no right-click context menu yet
- no behavioral prose block
- no export tooling

---

## 7.6 TanStack Query hooks in Phase 2

```text
useSankeyDevice(mac, range)
useSankeyDestinationPeers(ip, range)
```

Polling:
- device trace: 30 seconds
- destination peers: on-demand only

---

## 7.7 Acceptance criteria for Phase 2
- clicking a device from Level 1 opens Level 2
- device trace renders with correct protocol grouping
- destination grouping distinguishes internal vs external
- anomaly-only filter works
- “Who Else?” side panel loads on demand
- Level 1 and Phase 1 behaviors remain intact

---

# 8. Phase 3 — Conversation Detail Investigation

## 8.1 Goal
Deliver the analyst detail surface for one device ↔ one destination pair:
- timeline
- summary
- paginated connections
- CSV export
- analyst action

This phase is intentionally separated because it is a different UI surface than Sankey.

## 8.2 Routes included
- `/sankey/device/:mac/:destIp`

## 8.3 Backend scope

### Endpoint E — Conversation Detail
```text
GET /api/sankey/device/{mac}/destination/{ip}?range=24h&page=1&per_page=100
```

#### Responsibilities
- return summary statistics
- return bucketed timeline
- return paginated connections
- return device/destination context
- return blocked attempt counts
- return baseline context

#### Important note
This endpoint is not a Sankey response and should be treated as a separate data shape.

---

## 8.4 Frontend scope

### Level 3 — Conversation Detail
This is a timeline + table investigation view.

#### Components
- summary header
- timeline visualization
- sparkline / area chart
- behavioral context panel
- paginated connection table

#### Required actions
- row click highlights corresponding timeline entry where practical
- export CSV
- flag conversation action

### Behavioral Context Panel
This may generate prose from summary fields, but this should be simple deterministic rendering, not model-generated text.

---

## 8.5 Refresh behavior
No automatic polling at Level 3.
Use manual refresh only.

---

## 8.6 TanStack Query hook in Phase 3

```text
useSankeyConversation(mac, destIp, range, page)
```

No polling.

---

## 8.7 Acceptance criteria for Phase 3
- clicking a destination from Level 2 opens Level 3
- summary and timeline load correctly
- table pagination works
- CSV export works
- flag conversation action works
- no regressions to prior Sankey levels

---

# 9. Phase 4 — UX and Interaction Polish

## 9.1 Goal
Add higher-value usability improvements and polish after core workflows are validated.

This phase should only begin after Phases 1–3 are stable.

## 9.2 Scope

### Prefetch on Hover
Add TanStack Query prefetch for:
- VLAN nodes at Level 0
- device nodes at Level 1

### Context Menus
Add custom right-click menu where useful:
- Trace Device
- View in Topology
- View Identity
- Copy MAC
- Copy IP

### Crossfade Navigation Transitions
Add simple anchor-based crossfade transitions:
- 0 → 1
- 1 → 2
- back-navigation reverse fades

Do **not** attempt path morphing.

### Expanded loading / empty state polish
Improve:
- loading skeletons
- no-data states
- filter empty states
- error retry affordances

### Additional protocol naming / UI refinement
Add more static service mappings and visual polish.

---

## 9.3 Not required in Phase 4
- no deep animation system
- no fancy force-layout morphing
- no automatic narrative generation

---

## 9.4 Acceptance criteria for Phase 4
- prefetch makes drill-down feel faster
- context menu works reliably
- transitions remain under 400 ms and do not break layout
- loading / empty / error states feel complete
- core investigative behavior remains unchanged

---

# 10. Shared Backend Data Contracts by Phase

## Phase 1
- `SankeyNetworkResponse`
- `SankeyVlanResponse`

## Phase 2
- `SankeyDeviceResponse`
- `DestinationPeersResponse`

## Phase 3
- `ConversationDetailResponse`

Phase 4 does not introduce major new backend contracts unless interaction affordances require small additions.

---

# 11. Shared Performance Guidance

## Query limits
- destination peers capped at top 100 devices
- paginated connection detail required at Level 3
- external breakout nodes gated by thresholds

## Query validation
For each new endpoint:
- run `EXPLAIN QUERY PLAN`
- verify index use
- test `24h`, `7d`, and `30d` ranges explicitly

## Frontend refresh discipline
- Levels 0–2 may poll every 30 seconds
- Level 3 should not auto-poll

---

# 12. Shared UX Rules

1. URL is the source of navigation state
2. range persists across drill-down
3. breadcrumb is derived, not separately stored
4. tooltip content should be concise and operationally relevant
5. anomaly colors are consistent across phases
6. investigation pages should prioritize clarity over visual complexity

---

# 13. What Not to Build in Any Phase

- Zeek integration
- firewall rule matching engine
- CrowdSec threat enrichment
- changes to baseline computation
- changes to connection ingestion
- replacement of existing dashboard Sankey
- non-deterministic AI-generated analyst narratives

---

# 14. Recommended Implementation Order

## Phase 1
- shared range parser helper
- verify/add indexes
- backend network endpoint
- backend VLAN endpoint
- `/sankey` route
- `/sankey/vlan/:id` route
- range selector
- breadcrumb
- anomaly glow
- Level 0 + Level 1 rendering

## Phase 2
- backend device endpoint
- backend destination peers endpoint
- `/sankey/device/:mac`
- Level 2 rendering
- side panel
- anomalies-only toggle
- “Who Else?” panel

## Phase 3
- backend conversation detail endpoint
- `/sankey/device/:mac/:destIp`
- timeline view
- summary panel
- connection table
- CSV export
- flag conversation action

## Phase 4
- prefetch on hover
- context menus
- crossfade transitions
- loading/empty/error polish
- additional service-name polish

---

# 15. Risk Register

## Risk: Query cost on large time ranges
Mitigation:
- verify indexes
- cap result sets where appropriate
- paginate Level 3
- gate external breakout nodes

## Risk: Sankey instability from over-granular destinations
Mitigation:
- minimum bytes + minimum connections thresholds for breakout groups

## Risk: ambiguous inbound/outbound modeling on Level 2
Mitigation:
- make Level 2 egress-first in initial implementation

## Risk: UI complexity expands before core path works
Mitigation:
- defer transitions, context menus, and polish to Phase 4

## Risk: anomaly context becomes inconsistent across levels
Mitigation:
- define authoritative anomaly source per level during implementation
- keep anomaly usage read-only and explicit

---

# 16. Build and Validation Checklist by Phase

## Phase 1
- `cargo build` passes
- `npm run build` passes
- `/sankey` loads
- `/sankey/vlan/:id` loads
- time range persists
- breadcrumb works
- dashboard unchanged

## Phase 2
- device route loads
- protocol breakdown correct
- internal vs external destinations render correctly
- “Who Else?” works
- side panel displays identity/baseline context

## Phase 3
- conversation route loads
- timeline and table align
- CSV export works
- flag conversation action works

## Phase 4
- prefetch works without incorrect stale data behavior
- context menu behaves correctly
- transitions are reliable and fast
- empty/error states are complete

---

# 17. Final Recommendation

This feature should absolutely be built.

But it should be built in **four disciplined phases**, not one all-at-once implementation.

The most important strategic move is:
- start with **Investigation Foundation**
- prove the drill-down workflow
- then add device and conversation depth
- then add polish

This maximizes the chance that the feature ships cleanly, remains understandable, and becomes a real analyst tool instead of an overgrown chart project.


# Ion Drift Feature Spec
## Link Saturation Monitor — Phased Implementation Plan

> This document restructures the Link Saturation Monitor into a safer, execution-ready **4-phase feature plan**.
>
> The product direction remains the same:
> - add live link saturation visibility to the existing Switch Detail surface
> - use existing metrics already collected in `switch_port_metrics`
> - avoid new polling loops, new persistence layers, or new pages
>
> The main change is delivery strategy:
> **build this in four phases instead of one broad implementation pass**.

---

# 1. Executive Summary

The Link Saturation Monitor is a strong feature because it adds immediate operator value without requiring any new telemetry source.

The concept is solid:
- compute current utilization from the two most recent samples
- overlay that data onto the existing port grid and port metrics table
- add a small summary signal for busy or saturated links

The original spec is technically feasible, but it still bundles:
- a new backend endpoint
- a shared frontend utility layer
- two enhanced switch detail views
- a summary card
- possible router-specific logic

That is too much for one pass if the goal is a clean, low-risk delivery.

This phased plan breaks the work into:

1. **Backend Utilization Foundation**
2. **Switch Detail Heat Overlay**
3. **Operational Summary and UX Refinement**
4. **Router Surface Extension**

This structure reduces risk, isolates the uncertain router portion, and lets the core switch experience ship quickly.

---

# 2. Product Goals

## Primary goals
- expose live per-port utilization using existing metrics
- make heavily used links visually obvious at a glance
- preserve the existing Switch Detail structure and interactions
- avoid schema changes, new polling, or historical charting

## Secondary goals
- improve operator awareness of hot links
- make bandwidth consumption easier to interpret than raw counters
- create a reusable utilization utility layer for future surfaces

## Non-goals
- no historical trend charts
- no new alerting engine logic
- no per-direction dual heat visualization
- no utilization persistence tables
- no changes to topology edge rendering
- no changes to polling frequency

---

# 3. Scope Boundary

## Existing surfaces that remain unchanged
- Switch Detail page route and general layout
- MAC table, VLAN audit, and system info tabs
- topology map speed-based edge coloring
- switch polling loop and intervals
- `switch_port_metrics` schema
- all non-switch pages

## New feature area
A live utilization layer added to:
- existing switch port grid
- existing port metrics table
- existing switch header area
- router interface/port display only if current telemetry path supports it cleanly

---

# 4. Shared Design Principles Across All Phases

1. **Use existing telemetry only**
2. **Compute utilization on demand**
3. **Preserve existing page behavior**
4. **Prioritize correctness over color polish**
5. **Treat router support as conditional, not assumed**
6. **Do not let the visual layer force backend architectural drift**

---

# 5. Shared Technical Foundations

These are required across phases.

## 5.1 Utilization model
For each port:
- compute delta between the two most recent samples
- compute RX/TX rates
- derive rated speed by precedence:
  1. polled `speed_mbps`
  2. `backbone_links.speed_mbps`
  3. default 1 Gbps
- compute:
  - `rx_util`
  - `tx_util`
  - `utilization = max(rx_util, tx_util)`

## 5.2 Data freshness rules
Skip ports when:
- fewer than 2 samples exist
- elapsed interval <= 0
- elapsed interval > 120 seconds

This should be handled centrally and consistently.

## 5.3 Shared frontend utility layer
Introduce a dedicated utility module:

```text
utils/utilization.ts
```

with:
- `utilizationColor(util)`
- `utilizationLabel(util)`
- `formatBitrate(bps)`

## 5.4 Shared style rule
Ports with `running = false` always render as inactive/dark regardless of computed utilization.

That rule must be preserved on all surfaces.

---

# 6. Phase 1 — Backend Utilization Foundation

## 6.1 Goal
Deliver a clean, correct, reusable backend endpoint and frontend utility layer without yet changing all switch visuals.

This phase proves the math and the data shape first.

## 6.2 Backend scope

### Endpoint A — Port Utilization
```text
GET /api/devices/{id}/port-utilization
```

#### Responsibilities
- compute current rates from the two most recent `switch_port_metrics` samples
- determine denominator speed using explicit precedence
- return utilization values per port
- return speed source metadata
- return running status as included context

#### Response contract
The response shape from the original spec is retained.

## 6.3 Backend implementation recommendations

### Query strategy
Do not do one SQL round trip per port if avoidable.

Instead, prefer:
- one query fetching recent rows for all ports on the device
- grouping in Rust by `port_name`
- selecting top two timestamps per port in memory

Why:
- avoids N-per-port query overhead
- keeps endpoint behavior predictable on large switch models
- easier to reason about and test

### Speed resolution helper
Create a dedicated backend helper for:
- speed source selection
- denominator normalization
- speed source string generation

This prevents duplication and keeps tooltip/source logic consistent.

### Clamp and fallback behavior
- clamp util ratios to `0.0..1.0`
- if rate math produces nonsense from counter reset or wrap, clamp to zero and continue
- do not fail the whole endpoint because one port has invalid delta data

## 6.4 Frontend scope in Phase 1

### Utility module only
Implement:
- `utilizationColor`
- `utilizationLabel`
- `formatBitrate`

### Hook
Add:
```text
usePortUtilization(deviceId)
```

Recommended config:
- `refetchInterval: 10_000`
- `staleTime: 8_000`
- `enabled: !!deviceId`

### No UI replacement yet
Phase 1 should not yet fully repaint the port grid background.
Instead, verify that utilization data merges correctly with existing port data.

## 6.5 Acceptance criteria for Phase 1
- backend endpoint returns correct per-port utilization data
- speed precedence works
- stale or invalid sample pairs are skipped
- frontend hook fetches and caches correctly
- utility functions return stable color/label/bitrate output
- no existing switch page behavior changes yet

---

# 7. Phase 2 — Switch Detail Heat Overlay

## 7.1 Goal
Add the utilization visualization to the existing Switch Detail page:
- port grid heat overlay
- metrics table utilization column
- tooltip enrichment

This is the first user-visible release of the feature.

## 7.2 Frontend scope

### Port Grid Enhancement
Add:
- utilization-based tile background
- thin bottom utilization bar
- tooltip utilization details

#### Important recommendation
Do **not** move VLAN color out of the current design until you confirm how readable the grid remains.

Instead, implement this in two steps:
1. try a subtler heat overlay with existing VLAN indicator preserved
2. only move VLAN color to a top stripe if background conflict is real

Reason:
The spec’s proposed VLAN move is sensible, but it is still a visual regression risk.
Do not hard-code that design decision before validating the current component.

### Port Metrics Table Enhancement
Add:
- new Utilization column
- inline progress bar
- utilization label
- RX/TX rates as primary values
- cumulative totals remain visible as secondary line or tooltip if already present

#### Important implementation note
Keep raw/cumulative totals available.
Do not replace them entirely with rates.

### Tooltip Enhancement
Add:
- RX rate
- TX rate
- utilization %
- rated speed
- speed source

## 7.3 Not in Phase 2
- no Saturated Links summary card yet
- no router enhancement yet
- no additional sorting/filtering logic unless trivially available
- no historical mini-charts

## 7.4 Acceptance criteria for Phase 2
- switch port grid shows live utilization heat
- metrics table shows utilization and rates
- down ports remain visually inactive
- tooltips show correct rate/utilization context
- utilization refreshes every 10 seconds
- existing tile layout and click behavior remain intact

---

# 8. Phase 3 — Operational Summary and UX Refinement

## 8.1 Goal
Add the summary signal and refine usability after the core utilization views are stable.

## 8.2 Scope

### Saturated Links Summary Card
Add a compact summary card to the Switch Detail header area.

#### Behavior
- render only when at least one port has `utilization > 0.05`
- amber styling when any port > 0.80
- red styling when any port > 0.95
- otherwise neutral informative styling

#### Content recommendation
Keep it concise:
- count of active ports
- count above 70%
- list only top 2–3 most utilized ports

Do not try to make this card a secondary table.

### UX refinements
Add:
- clearer empty-state handling when no recent samples exist
- clearer stale-data handling
- optional utilization sort in the metrics table if easy and consistent with existing table architecture

### Visual tuning
Use this phase to tune:
- gradient stop interpolation
- text contrast on hot tiles
- progress bar readability
- warning badge language

## 8.3 Acceptance criteria for Phase 3
- summary card appears only when meaningful
- warning thresholds render correctly
- the page stays readable under very low and very high utilization cases
- no new visual regressions are introduced

---

# 9. Phase 4 — Router Surface Extension

## 9.1 Goal
Extend the same utilization model to the router surface, but only if the current router telemetry path supports it cleanly.

This phase is intentionally isolated because the router portion is the least certain part of the original spec.

## 9.2 Decision gate
Before implementation, determine which of the following is true:

### Case A — Router time-series data already exists
If router interfaces already have timestamped counters in a queryable metrics store:
- implement the same delta-based computation
- add the same heat treatment to the router interface list/grid

### Case B — Only live current counters exist
If router counters are only returned live and there is no reliable two-sample source already stored:
- do not introduce a new polling mechanism
- do not add ad hoc in-memory pseudo-persistence unless there is already an AppState cache designed for this purpose
- defer router heat overlay and leave a documented extension point

## 9.3 Strong recommendation
Treat router support as **conditional optional scope**.

Do not block the switch feature waiting on router uncertainty.

## 9.4 Acceptance criteria for Phase 4
- if router telemetry supports it, router view gains consistent utilization rendering
- if not, switch feature remains complete and stable without router parity
- no new polling path is introduced solely for this feature

---

# 10. Shared Backend Data Contract by Phase

## Phase 1
- `PortUtilizationResponse`

## Phase 2
- same response reused by switch page
- no new backend contract required

## Phase 3
- same response reused by summary card
- no new backend contract required

## Phase 4
- reuse same response shape if router support is implemented
- otherwise no change

---

# 11. Shared Performance Guidance

## Query behavior
This endpoint should remain light, but validate that it is actually light.

Recommended checks:
- verify indexing on `device_id, port_name, timestamp`
- inspect query plan
- test on higher-port-count switches

## Refresh behavior
- poll every 10 seconds on the frontend
- accept that the values may be unchanged between underlying switch polls
- do not increase polling rate

## Failure behavior
If one port cannot be computed:
- omit or mark that port gracefully
- do not fail the entire endpoint

---

# 12. Shared UX Rules

1. utilization heat is supplemental, not destructive to existing information density
2. down ports always look down
3. hot links should be obvious at a glance
4. tooltip details should explain the math enough to build operator trust
5. the page should remain readable in dark mode even at full red saturation
6. rates are primary for live interpretation; totals remain secondary

---

# 13. What Not to Build in Any Phase

- historical utilization charts
- threshold alerting logic
- separate RX and TX heat channels
- utilization persistence tables
- topology-map utilization overlays
- custom polling loops for this feature
- router-specific telemetry collectors created only for this feature

---

# 14. Recommended Implementation Order

## Phase 1
- inspect existing indexes and metrics access path
- backend helper for speed resolution
- backend helper for delta/rate computation
- `/api/devices/{id}/port-utilization`
- frontend `utils/utilization.ts`
- `usePortUtilization(deviceId)`

## Phase 2
- merge utilization data into existing switch detail view
- port grid heat overlay
- bottom utilization bar
- tooltip enhancement
- metrics table utilization column
- RX/TX rate presentation

## Phase 3
- Saturated Links summary card
- stale/idle state polish
- visual tuning
- optional utilization sort if appropriate

## Phase 4
- confirm router telemetry support
- implement router utilization view only if cleanly supported
- otherwise document and defer

---

# 15. Risk Register

## Risk: bad rate math from counter reset / wrap
Mitigation:
- clamp invalid negative deltas to zero
- skip stale or invalid intervals
- never fail endpoint globally because of one bad port

## Risk: endpoint implemented with one query per port
Mitigation:
- fetch recent rows in batch and group in Rust

## Risk: VLAN color visibility regresses on the port grid
Mitigation:
- validate readability before moving VLAN color to top stripe
- treat that move as a design fallback, not a fixed assumption

## Risk: router scope balloons
Mitigation:
- isolate router work into Phase 4
- require telemetry-path confirmation before implementation

## Risk: operators lose cumulative byte visibility
Mitigation:
- keep cumulative totals in secondary line or tooltip

---

# 16. Build and Validation Checklist by Phase

## Phase 1
- `cargo build` passes
- `npm run build` passes
- utilization endpoint returns stable data
- utility functions behave correctly
- hook fetches and joins successfully

## Phase 2
- switch port grid heat overlay renders
- metrics table shows utilization and rates
- down ports remain dark/inactive
- tooltip values match endpoint data
- page behavior remains intact

## Phase 3
- summary card appears only when meaningful
- thresholds style correctly
- low/high utilization scenarios remain readable

## Phase 4
- router support either works correctly or is intentionally deferred
- no new polling or schema changes were introduced

---

# 17. Final Recommendation

This feature should be built.

But it should be built in **four disciplined phases**, not one broad pass.

The most important strategic move is:
- first prove the utilization math and data contract
- then add the switch visual layer
- then add operational summary polish
- then handle router parity only if the telemetry path is already clean

This maximizes the chance that the feature ships quickly, remains low-risk, and actually improves the operator experience without pulling the backend into unnecessary complexity.

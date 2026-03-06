# Response & Implementation Plan
## Topology Inference Engine for Ion Drift

> **Author:** svc-claude
> **Date:** 2026-03-06
> **In response to:** Initial analysis (chat), `ndr_attachment_algorithm.md`, `topology_inference_engine.md`, `topology_inference_pseudocode.md`

---

## Part 1: Response to the Analysis

### 1.1 Agreement on the Core Diagnosis

The three root causes identified are accurate and map directly to specific code in the current correlation engine.

**Root Cause #1 — FDB data treated as ground truth.**

The MAC processing loop (`correlation_engine.rs` lines 315-371) is a single pass over `all_macs`. Each entry gets one priority evaluation. There is no weighting on the quality of the observation itself — a MAC seen on a 10G trunk carrying 200 other MACs is treated with the same observational weight as a MAC alone on a 1G access port. The only differentiation is the priority formula based on port *classification*, which leads directly to Root Cause #2.

**Root Cause #2 — Port role classification is brittle.**

`classify_port_role()` is a 14-line if/else chain:

```
vlan_count > 1    → trunk
has_lldp          → uplink
mac_count > 10    → uplink
mac_count == 0    → unused
else              → access
```

The `>10 MAC` threshold for uplink is arbitrary. A real scenario in this network: the CRS326→CRS310 uplink carries only 3 downstream devices (cameras + WAP). That port classifies as `access` and gets the highest priority score (390), which is exactly backwards. The VLAN observation bias is also real — SwOS VLAN tables are unreliable.

**Root Cause #3 — Binding decisions are stateless.**

Mostly correct with one nuance. The code uses strict `>` (not `>=`) which prevents same-priority flapping between cycles. The `binding_last_seen` field exists in the `IdentityBuilder` struct but is stored and never used for tie-breaking — it's dead weight. The system is effectively stateless. A single poll cycle where CRS326's trunk happens to see a MAC before CRS310's access port reports it can flip a binding, and there's no memory of "this MAC has been on CRS310:ether7 for the last 30 minutes."

### 1.2 The Most Important Conceptual Shift

> "Upstream visibility is not competing evidence against downstream visibility — it is supporting evidence that the downstream branch is correct."

This reframes the entire binding problem. Currently every MAC observation is a competing claim:

```
CRS310:ether7  → priority 380
CRS326:sfp+1   → priority 210
RB4011:sfp+1   → priority 100
```

Three competitors. Best priority wins.

But physically, if the MAC is on CRS310:ether7, then it *must* appear on CRS326:sfp+1 and RB4011:sfp+1 — that's how L2 forwarding works. The upstream observations aren't competing evidence. They're *corroborating* evidence. Seeing the MAC on all three actually increases confidence in the deepest edge candidate.

The current system gets this right most of the time because the depth-priority formula suppresses upstream candidates with low scores. But it gets it right for the wrong reason. When port role classification fails, the suppression-by-priority trick breaks because the wrong port gets the "access" label and the highest priority.

### 1.3 Transit Filtering — Highest Single-Leverage Change

The NDR algorithm's candidate pruning step is deceptively simple:

> Remove candidates where `port_role = trunk AND downstream switch exists`

This changes the problem from "3 candidates, pick the best → sometimes wrong" to "1 candidate after filtering → almost always right." In the camera example, CRS326:sfp+1 and RB4011:sfp+1 are eliminated because both are trunk ports with known downstream switches. The only surviving candidate is CRS310:ether7. No scoring needed. No temporal smoothing needed. Just correct.

The current codebase already has everything needed for this — `trunk_ports` set, `trunk_peer` map, and switch depth. The filter is: "if this (device, port) is in `trunk_peer`, skip it as a candidate."

### 1.4 Role-Aware Persistence

Seeing a MAC on CRS326:sfp+1 in 12/12 polls tells you almost nothing — a trunk port sees everything downstream, always. That's 100% observation rate with near-zero informational value.

Seeing a MAC on CRS310:ether7 in 11/12 polls is strong evidence — an access port with a stable single device. The one missed poll is just FDB aging jitter.

Raw observation count is misleading. It must be weighted by how *surprising* the observation is given the port's role. This maps directly to the FDB credibility concept — the same signal, applied to temporal data.

### 1.5 The Belief Update Equation

```
posterior = 0.7 * previous_belief + 0.3 * new_evidence
```

This is an exponential moving average with a decay factor of 0.7. At 60-second correlation cycles:

- After 1 cycle: 30% new evidence
- After 3 cycles (~3 min): 66% new evidence
- After 7 cycles (~7 min): 92% new evidence
- After 10 cycles (~10 min): 97% new evidence

A legitimate device move takes about 3 minutes to reach Probable and 10 minutes to reach Stable. That's a reasonable time constant — fast enough to track real changes, slow enough to ignore polling artifacts. Computationally it's one multiplication and one addition per candidate per cycle.

### 1.6 MAC Range Detection — Agree on Exact Set

The current code computes `[min_mac..=max_mac]` which fills all values in the range. A switch with ports from two different ASICs could have a gap containing a real device's MAC. The 128-address cap is a safety net, but the memory cost of an exact `HashSet<u64>` with 24-48 entries per switch is negligible. This should change to exact set regardless of the inference engine work.

### 1.7 What the Current System Does Well

Three design choices are solid foundations:

1. **BFS depth model** — the infrastructure graph with depth-from-router is the correct backbone. The inference engine evolves it, not replaces it.
2. **Trunk redirection** — many topology engines fail at this entirely. The current single-hop downstream redirection is correct in concept.
3. **Identity builder pipeline** — the enrichment order (MAC → LLDP → ARP → DHCP → DNS → OUI) is well-designed and doesn't need to change.

---

## Part 2: Response to the Architecture Document

### 2.1 Module Structure

The 7-module split (`graph.rs`, `observations.rs`, `candidates.rs`, `scoring.rs`, `state.rs`, `resolver.rs`, `explain.rs`) maps 1:1 to the pseudocode stages. The current `correlation_engine.rs` is ~850 lines doing everything in one file. The new system will be substantially more code, so the separation is justified.

**Graph sharing between engines.** `graph.rs` duplicates work that `topology.rs` already does — BFS depth, adjacency, parent/child maps. Two options:

1. Build the graph in correlation, pass it to topology (reduces duplication, couples the engines)
2. Each engine builds its own (current approach — keeps them independent)

Recommendation: option 1. The correlation engine runs every 60s, topology every 120s. They need the same graph. Build once per correlation cycle, share via `Arc<RwLock<InfrastructureGraph>>` in the app state, same pattern as the existing topology cache. The topology engine can read the shared graph instead of rebuilding adjacency from scratch.

### 2.2 Schema Changes

**`port_role_probabilities`** replaces the binary `switch_port_roles` table with continuous values. Current code queries `switch_port_roles` in the topology engine, the identity manager API, and correlation itself.

Migration path: keep `switch_port_roles` populated during the transition (derive it from probabilities: `argmax(trunk_prob, uplink_prob, access_prob)` → role label). Add `port_role_probabilities` alongside it. Once the new engine is validated in shadow mode, deprecate the old table.

**`reasoning_json`** on `mac_attachment_state` and **`features_json`** on `mac_attachment_candidates` — JSON in SQLite is fine for this workload. Written once per cycle, read on demand via API. SQLite's `json_extract()` is available for queries if needed but mostly these will be opaque blobs deserialized in Rust.

**`switch_binding_source = 'inference'`** — good distinction from `'auto'` and `'human'`. Lets the UI differentiate between old binding and new probabilistic binding during migration. The `upsert_network_identity()` SQL needs a third CASE branch for this value.

### 2.3 Observation Table Growth

At current scale: 5 managed devices × 30s poll intervals × ~200 active MACs = ~2000 rows/minute. A 10-minute window = ~20K rows. A 15-minute window = ~30K rows. Manageable in SQLite.

Pruning strategy: delete everything older than `2 × observation_window` on every correlation cycle. This gives a safety margin for the temporal smoothing while preventing unbounded growth. At 20-minute retention and 2000 rows/minute, the table stays under 40K rows permanently.

### 2.4 Phased Rollout

The shadow mode recommendation (Phase 2) is the most operationally important aspect. Running both engines and logging divergence before changing real bindings is how you validate without risk. The shadow comparison should capture:

- How many MACs get different bindings
- Which direction the changes go (hopefully better, not worse)
- Whether the new engine converges faster after switch reboots
- Whether wireless roaming is handled better or worse
- Edge cases: newly discovered devices, devices going offline, port flaps

### 2.5 Performance

At SMB/SME scale, the full resolver pipeline is trivially fast. The O(n²) pairwise candidate comparison (typically 3-5 candidates per MAC) is negligible. The InfrastructureGraph is built once per cycle and cached. Port role probabilities are computed once per cycle. The scoring formula is arithmetic — no complex operations.

The only concern is SQLite contention with the observation table inserts happening on every poll cycle while the correlation engine reads. Using WAL mode (which the codebase already does) and batching inserts should handle this cleanly.

---

## Part 3: Response to the Pseudocode

### 3.1 Port Role Probability Computation

The additive model with normalization produces correct results for real scenarios in this network:

**CRS326:sfp+1** (backbone to CRS310, LLDP present, 3 VLANs, 10G, 45 MACs):

```
trunk_prob:  0.75 (backbone) + 0.25 (lldp) + 0.60 (>1 VLAN) + 0.20 (10G) = 1.80
uplink_prob: 0.60 (lldp) + 0.45 (>10 MACs) = 1.05
access_prob: 0.0
→ normalized: trunk=0.63, uplink=0.37, access=0.00
```

**CRS310:ether7** (no backbone, no LLDP, 1 VLAN, 1G, 1 MAC):

```
access_prob: 0.70
→ normalized: trunk=0.00, uplink=0.00, access=1.00
```

**CRS326:ether18** (backbone to CRS310, no LLDP, 1 VLAN, 1G, 3 MACs — the problem case):

```
trunk_prob:  0.75 (backbone)
→ normalized: trunk=1.00, uplink=0.00, access=0.00
```

The backbone link membership alone correctly classifies this port, even with only 3 MACs. Under the current binary system, this port classifies as `access` (mac_count < 10, no LLDP, single VLAN) and gets maximum priority. The probability model eliminates this failure mode entirely.

### 3.2 Observation Confidence

The multiplicative model applied to each MAC sighting:

```
Camera MAC on CRS310:ether7 (access_prob=1.0, 1 MAC, 1G):
  1.0 × 1.15 (access boost) = 1.0 (clamped)

Camera MAC on CRS326:sfp+1 (trunk_prob=0.63, 45 MACs, 10G):
  1.0 × 0.35 (trunk) × 0.60 (>20 MACs) × 0.75 (10G) = 0.157

Camera MAC on RB4011:sfp+1 (router trunk):
  1.0 × 0.35 (trunk) × 0.60 (many MACs) × 0.75 (10G) = 0.157
```

The edge observation is 6x more credible than the transit observations. Strong signal before scoring even begins.

### 3.3 Upstream Suppression

The pairwise comparison function is the algorithmic core of the transit filtering concept:

```
for each candidate_a:
  for each candidate_b:
    if is_descendant_of(B, A) and A is transit-like and B is edge-plausible:
      suppress A as final-winner eligible
```

After suppression, transit candidates are retained as evidence (their observations still feed persistence and frequency scores for the downstream winner) but can't win the binding. This implements the "upstream visibility supports downstream placement" insight algorithmically.

### 3.4 State Update Mechanics

The hysteresis logic is well-designed:

- **Same location wins** → smooth score via EMA, increment `consecutive_wins`, maybe promote state
- **Challenger beats current × 1.25** → increment `consecutive_losses`
- **Challenger doesn't beat threshold** → decay current score by 2% per cycle, reset `consecutive_losses`
- **After 2 consecutive losses** → switch binding, save previous location

The 2% decay is subtle but important. Even without a strong challenger, a wrong binding slowly weakens. Decay rate: `0.98^n` per cycle = ~50% after 35 cycles (~35 minutes). A truly wrong binding will self-correct within about 30 minutes. That's a reasonable time constant.

### 3.5 Confidence from Winner-to-Runner-Up Margin

`clamp(margin / 3.0, 0.0, 1.0)`:

| Margin | Confidence | Meaning |
|--------|------------|---------|
| 3.0+ | 1.0 | Certain |
| 1.5 | 0.5 | Moderate |
| 0.3 | 0.1 | Low |
| 0.0 | 0.0 | Conflicted |

Given scoring weights summing to ~10.2 (positive) and ~3.5 (negative), typical winning scores will be in the 3-7 range. A margin of 3.0 for full confidence means the winner needs to be about 50-100% ahead of the runner-up. Prevents false confidence when candidates are close.

### 3.6 Failure Handling

The **Conflicted** state for tied candidates is the most important addition. Currently, close-scoring candidates produce a silent, arbitrary choice. Surfacing the conflict is more honest — the operator can investigate and resolve with a human override, entering `HumanPinned` state.

The **Roaming** state with faster transitions for legitimate moves (laptop, phone) is also needed. Suggestion: devices on wireless VLANs should have a lower hysteresis threshold (e.g., 1.1x instead of 1.25x) and require only 1 consecutive loss instead of 2. Wireless roaming is expected behavior, not an anomaly.

### 3.7 Items Left Undefined

These will need decisions during implementation:

| Item | Recommendation |
|------|---------------|
| `smooth_score()` function | EMA with α=0.7, β=0.3 (from NDR doc) |
| `compute_downstream_preference()` | 1.0 if deepest edge-plausible candidate, 0.0 if deeper edge candidate exists, 0.5 if ambiguous |
| `compute_contradictions()` | Penalize when: MAC seen on mutually exclusive ports in same cycle, or MAC appears below its candidate in the graph |
| Observation window vs MAC table pruning | Separate tables, separate retention. `mac_observations` = 15 min, `switch_mac_table` = 1 hour (unchanged) |
| `next_state_after_move()` | Roaming if previous state was Stable/Probable, otherwise Candidate |
| WAP attribution integration | `infer_wireless_parent_candidate()` uses existing backbone link children lookup + wireless VLAN check. Round-robin for multi-WAP switches carries forward. |

---

## Part 4: Implementation Plan

### 4.0 Guiding Principles

1. **Evolve, don't replace.** The new inference engine lives inside the correlation phase. The topology engine remains a downstream consumer.
2. **Shadow mode first.** Run both old and new binding logic, log divergences, validate before switching.
3. **Incremental adoption.** Each phase delivers value independently. If phase N works, phase N+1 is not required.
4. **Operator trust.** Every binding must be explainable. The UI must show why a decision was made.

### 4.1 Phase 1 — Foundation: Observation History + Port Role Probabilities

**Goal:** Collect the temporal data needed for probabilistic scoring. No binding changes yet.

#### Schema additions

**`switch_store.rs` — add tables in `SwitchStore::new()` migrations:**

```sql
-- Time-series MAC sightings
CREATE TABLE IF NOT EXISTS mac_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL,
    device_id TEXT NOT NULL,
    port_name TEXT NOT NULL,
    vlan_id INTEGER,
    timestamp INTEGER NOT NULL,
    observation_confidence REAL NOT NULL DEFAULT 0.5,
    edge_likelihood REAL NOT NULL DEFAULT 0.5,
    transit_likelihood REAL NOT NULL DEFAULT 0.5
);
CREATE INDEX IF NOT EXISTS idx_mo_mac_time
    ON mac_observations(mac_address, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_mo_device_port
    ON mac_observations(device_id, port_name, timestamp DESC);

-- Probabilistic port roles
CREATE TABLE IF NOT EXISTS port_role_probabilities (
    device_id TEXT NOT NULL,
    port_name TEXT NOT NULL,
    trunk_prob REAL NOT NULL DEFAULT 0.0,
    uplink_prob REAL NOT NULL DEFAULT 0.0,
    access_prob REAL NOT NULL DEFAULT 0.0,
    wireless_prob REAL NOT NULL DEFAULT 0.0,
    computed_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, port_name)
);
```

#### Storage functions (`switch_store.rs`)

- `insert_mac_observation()` — batch insert observations per poll cycle
- `get_recent_observations(mac, window_secs)` — query observations within time window
- `get_observation_counts(mac, window_secs)` — grouped counts per (device, port)
- `prune_old_observations(max_age_secs)` — delete entries older than 2x observation window
- `set_port_role_probabilities(device_id, port_name, probs)` — upsert probabilities
- `get_port_role_probabilities(device_id)` — query all port probs for a device

#### Correlation engine changes

- After port role classification (Phase 1), compute port role probabilities using the additive model from the pseudocode and persist them
- After MAC table processing, create `mac_observations` entries with confidence scores computed from port role probabilities, MAC fanout, and port speed
- Add `prune_old_observations()` to the Phase 0 cleanup cycle
- Continue using the old binding logic — no behavior change yet

#### Fix: MAC range detection

- Change `build_switch_local_mac_set()` to always use exact set, remove the range expansion code

#### Files modified

| File | Change |
|------|--------|
| `crates/mikrotik-core/src/switch_store.rs` | Add tables, storage functions |
| `crates/ion-drift-web/src/correlation_engine.rs` | Add observation recording, port prob computation, prune call, fix MAC range |

#### Verification

```bash
cargo check --workspace
```

Observe: `mac_observations` table populating, `port_role_probabilities` table populating. Verify observation counts match expected poll rate. Verify port probs produce sane values for known ports.

---

### 4.2 Phase 2 — Infrastructure Graph Object

**Goal:** Build a persistent, shared graph with traversal helpers.

#### New module

`crates/ion-drift-web/src/topology_inference/mod.rs` (and `graph.rs`)

```rust
pub struct InfrastructureGraph {
    pub nodes: HashMap<String, GraphNode>,
    pub adjacency: HashMap<String, Vec<String>>,
    pub depth: HashMap<String, usize>,
    pub parent: HashMap<String, String>,
    pub children: HashMap<String, Vec<String>>,
    pub trunk_ports: HashSet<(String, String)>,
    pub trunk_peers: HashMap<(String, String), String>,
}

impl InfrastructureGraph {
    pub fn build(devices, neighbors, backbone_links, router_id) -> Self;
    pub fn depth_of(&self, device_id: &str) -> Option<usize>;
    pub fn parent_of(&self, device_id: &str) -> Option<&str>;
    pub fn children_of(&self, device_id: &str) -> &[String];
    pub fn is_descendant_of(&self, child: &str, ancestor: &str) -> bool;
    pub fn path_to_root(&self, device_id: &str) -> Vec<&str>;
}
```

#### Integration

- Build the graph at the start of each correlation cycle
- Cache it in `AppState` via `Arc<RwLock<InfrastructureGraph>>`
- Refactor the existing BFS depth computation, `trunk_ports`, and `trunk_peer` map out of correlation_engine.rs into `graph.rs`
- The topology engine can optionally consume the shared graph instead of rebuilding adjacency (but not required in this phase)

#### Files modified

| File | Change |
|------|--------|
| `crates/ion-drift-web/src/topology_inference/mod.rs` | New module root |
| `crates/ion-drift-web/src/topology_inference/graph.rs` | InfrastructureGraph |
| `crates/ion-drift-web/src/correlation_engine.rs` | Refactor graph-building code into new module |
| `crates/ion-drift-web/src/state.rs` | Add graph cache to AppState |

#### Verification

```bash
cargo check --workspace
```

Graph builds correctly. `depth_of()`, `is_descendant_of()`, `children_of()` produce correct results for the known network topology. Existing binding behavior unchanged.

---

### 4.3 Phase 3 — Candidate Generation + Scoring (Shadow Mode)

**Goal:** Implement the candidate generation, pruning, and scoring pipeline. Run in shadow mode alongside the existing binding logic. Log divergences.

#### New modules

- `topology_inference/candidates.rs` — candidate generation + transit pruning
- `topology_inference/scoring.rs` — weighted evidence scoring

#### Schema additions

```sql
CREATE TABLE IF NOT EXISTS mac_attachment_candidates (
    mac_address TEXT NOT NULL,
    device_id TEXT NOT NULL,
    port_name TEXT NOT NULL,
    vlan_id INTEGER,
    score REAL NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER,
    last_seen INTEGER,
    candidate_type TEXT NOT NULL DEFAULT 'WiredPort',
    features_json TEXT NOT NULL,
    PRIMARY KEY (mac_address, device_id, port_name)
);
```

#### Candidate generation

For each active MAC:
1. Collect all (device, port) pairs from recent observations
2. Add wireless parent candidate if VLAN is wireless
3. Add human override candidate if pinned (always wins)

#### Candidate pruning (transit suppression)

For each candidate pair (A, B):
- If B is a descendant of A in the graph, and A is transit-like (trunk_prob > 0.5), and B is edge-plausible (access_prob > 0.3): suppress A as final-winner eligible

#### Scoring formula

```
score =
  2.0 * edge_likelihood           // access_prob from port_role_probabilities
+ 1.5 * persistence               // polls_seen / polls_in_window, weighted by observation_confidence
+ 1.2 * vlan_consistency           // 1.0 if port carries the MAC's VLAN, 0.0 if not, 0.5 if unknown
+ 1.0 * downstream_preference     // 1.0 if deepest edge candidate, 0.0 if deeper exists
+ 0.8 * recency                   // age-weighted: most recent observation = 1.0, oldest in window = 0.0
+ 0.6 * graph_depth_score         // normalized depth: depth / max_depth, reduced for trunk ports
+ 0.6 * device_class_fit          // camera/printer → edge=1.0; phone → wireless=1.0; server → any=0.8
- 2.0 * transit_penalty            // max(trunk_prob, uplink_prob) from port_role_probabilities
- 1.5 * contradiction_penalty      // MAC seen on mutually exclusive ports in same cycle
```

#### Shadow mode

After computing the new winner, compare against the old priority-based binding:

```rust
if new_winner != old_binding {
    tracing::info!(
        mac = %mac,
        old_device = %old_device, old_port = %old_port,
        new_device = %new_device, new_port = %new_port,
        new_score = %score, new_confidence = %confidence,
        "inference divergence"
    );
}
```

Do NOT change real bindings. The existing priority-based binding continues to control `network_identities`.

#### Files modified

| File | Change |
|------|--------|
| `crates/ion-drift-web/src/topology_inference/candidates.rs` | New: candidate generation + pruning |
| `crates/ion-drift-web/src/topology_inference/scoring.rs` | New: weighted scoring |
| `crates/mikrotik-core/src/switch_store.rs` | Add candidates table, storage functions |
| `crates/ion-drift-web/src/correlation_engine.rs` | Call inference pipeline in shadow mode, log divergences |

#### Verification

```bash
cargo check --workspace
```

Run for several days. Review divergence logs. Key metrics:
- What % of MACs diverge?
- Are the new bindings more plausible? (manually verify a sample)
- Does the new engine handle switch reboots better?
- Does it handle wireless devices better or worse?
- Are there any cases where the old binding was correct and the new one is wrong?

---

### 4.4 Phase 4 — Attachment State Engine + Hysteresis

**Goal:** Add temporal stability. Bindings require sustained evidence to change.

#### New module

- `topology_inference/state.rs` — attachment state machine + hysteresis

#### Schema additions

```sql
CREATE TABLE IF NOT EXISTS mac_attachment_state (
    mac_address TEXT PRIMARY KEY,
    current_device_id TEXT,
    current_port_name TEXT,
    current_score REAL NOT NULL DEFAULT 0.0,
    confidence REAL NOT NULL DEFAULT 0.0,
    state TEXT NOT NULL DEFAULT 'Unknown',
    stable_since INTEGER,
    last_changed INTEGER,
    previous_device_id TEXT,
    previous_port_name TEXT,
    consecutive_wins INTEGER NOT NULL DEFAULT 0,
    consecutive_losses INTEGER NOT NULL DEFAULT 0,
    reasoning_json TEXT
);
```

#### State machine

```
Unknown   → Candidate    after 1 credible observation
Candidate → Probable     after 3 consecutive wins
Probable  → Stable       after 10 consecutive wins
Stable    → Roaming      when alternate candidate wins 2 consecutive cycles at >1.25x
Roaming   → Stable       after new location stabilizes (3 consecutive wins)
Any       → Conflicted   when top 2 candidates are within 10% score margin for 3+ cycles
Any       → HumanPinned  when switch_binding_source = 'human'
```

#### Hysteresis rules

```
Binding changes only when:
  new_score > current_score * 1.25
  for 2 consecutive cycles (consecutive_losses >= 2)

Exception: wireless VLAN devices use:
  new_score > current_score * 1.10
  for 1 consecutive cycle (consecutive_losses >= 1)
```

#### Score smoothing

```
smooth_score(current, new) = 0.7 * current + 0.3 * new
```

#### Score decay (no challenger)

```
current_score *= 0.98 per cycle when no challenger beats threshold
```

Full self-correction after ~35 minutes for wrong bindings.

#### Files modified

| File | Change |
|------|--------|
| `crates/ion-drift-web/src/topology_inference/state.rs` | New: state machine + hysteresis |
| `crates/mikrotik-core/src/switch_store.rs` | Add state table, CRUD functions |
| `crates/ion-drift-web/src/correlation_engine.rs` | Integrate state engine (still shadow mode) |

#### Verification

Extend shadow mode to include state tracking. Verify:
- State progression: Unknown → Candidate → Probable → Stable for stable devices
- Hysteresis: transient MAC table spikes don't cause binding changes
- Roaming: phones moving between WAPs transition within 1-2 minutes
- Conflicted: ambiguous devices are surfaced, not silently mis-bound
- Decay: deliberately wrong bindings self-correct within ~30 minutes

---

### 4.5 Phase 5 — Cut Over: Replace Priority Binding

**Goal:** Switch from old priority-based binding to inference-based binding for real `network_identities`.

#### Changes

- In `correlation_engine.rs`, replace the priority-based MAC processing loop with a call to the inference resolver
- The inference resolver output (`mac_attachment_state`) writes directly to `network_identities` via the existing `upsert_network_identity()` function
- Set `switch_binding_source = 'inference'` for inference-resolved bindings
- Human overrides (`switch_binding_source = 'human'`) are never touched
- Legacy `'auto'` bindings from pre-migration are treated as low-priority and overwritten by inference

#### Rollback plan

If the new engine produces worse results, revert to the old priority loop by:
1. Setting a feature flag (config toggle or environment variable)
2. The old binding code is preserved but gated behind the flag
3. If needed, `UPDATE network_identities SET switch_binding_source = 'auto'` to reset all inference bindings

#### Files modified

| File | Change |
|------|--------|
| `crates/ion-drift-web/src/correlation_engine.rs` | Replace priority binding with inference resolver call |
| `crates/ion-drift-web/src/topology_inference/resolver.rs` | New: orchestrates full resolution pipeline per MAC |

#### Verification

```bash
cargo check --workspace
cd web && npm run build
```

Deploy and observe:
- Topology map should show the same or better device placement
- No new flapping
- Conflicted devices surfaced with low confidence
- `switch_binding_source` column in identities shows `'inference'` for auto-resolved devices

---

### 4.6 Phase 6 — Explainability + UI

**Goal:** Show operators why each device is bound where it is.

#### New module

- `topology_inference/explain.rs` — generates human-readable reasoning

#### Explanation structure

```rust
pub struct AttachmentExplanation {
    pub winner_device: String,
    pub winner_port: String,
    pub confidence: f32,
    pub state: String,
    pub reasons: Vec<String>,
    pub supporting_observations: usize,
    pub suppressed_candidates: Vec<SuppressedCandidate>,
    pub score_breakdown: ScoreBreakdown,
}
```

#### Example explanation

```
Bound to CRS310:ether7
State: Stable (14 minutes)
Confidence: 0.91

Reasons:
- Seen on this port 9 of last 10 polls
- Port strongly resembles edge access (access_prob = 0.95)
- VLAN 99 consistent with port VLAN membership
- Upstream sightings on CRS326:sfp+1 and RB4011:sfp+1 suppressed as transit
- No contradicting evidence

Score breakdown:
  edge_likelihood:        2.0 × 0.95 = 1.90
  persistence:            1.5 × 0.90 = 1.35
  vlan_consistency:       1.2 × 1.00 = 1.20
  downstream_preference:  1.0 × 1.00 = 1.00
  recency:                0.8 × 0.95 = 0.76
  device_class_fit:       0.6 × 0.80 = 0.48
  transit_penalty:       -2.0 × 0.05 = -0.10
  contradiction_penalty: -1.5 × 0.00 =  0.00
  TOTAL:                              = 6.59

Suppressed candidates:
  CRS326:sfp+1 (transit, score 1.23)
  RB4011:sfp+1 (transit, score 0.87)
```

#### API endpoint

`GET /api/network/identities/{mac}/attachment` — returns the explanation JSON for a specific device.

#### Frontend

Add an expandable "Attachment Reasoning" section to the identity detail panel and/or the topology node detail sidebar. Show state badge (Stable/Probable/Conflicted/etc.), confidence bar, and collapsible reasoning text.

#### Files modified

| File | Change |
|------|--------|
| `crates/ion-drift-web/src/topology_inference/explain.rs` | New: explanation generation |
| `crates/ion-drift-web/src/routes/identity.rs` | New endpoint: GET attachment explanation |
| `crates/ion-drift-web/src/routes/mod.rs` | Register new route |
| `web/src/api/types.ts` | Add AttachmentExplanation type |
| `web/src/api/queries.ts` | Add useAttachmentExplanation query |
| `web/src/features/identity/identity-manager-page.tsx` | Add reasoning display |
| `web/src/features/topology/topology-page.tsx` | Add reasoning to node detail sidebar |

---

### 4.7 Summary: Files Touched Per Phase

| Phase | Description | Files | Risk |
|-------|-------------|-------|------|
| 1 | Observation history + port probs | 2 (switch_store, correlation_engine) | None — additive only |
| 2 | Infrastructure graph object | 4 (new module + refactor) | Low — refactor, no behavior change |
| 3 | Candidate scoring (shadow mode) | 4 (new modules + integration) | None — shadow mode, no real changes |
| 4 | Attachment state + hysteresis | 3 (new module + integration) | None — still shadow mode |
| 5 | Cut over to inference binding | 2 (correlation_engine + resolver) | **Medium** — changes real bindings |
| 6 | Explainability + UI | 7 (backend + frontend) | Low — read-only display |

### 4.8 Estimated Scope

| Phase | New Rust LOC | Modified Rust LOC | New Frontend LOC |
|-------|-------------|-------------------|-----------------|
| 1 | ~200 | ~150 | 0 |
| 2 | ~250 | ~100 | 0 |
| 3 | ~400 | ~100 | 0 |
| 4 | ~300 | ~50 | 0 |
| 5 | ~150 | ~200 | 0 |
| 6 | ~150 | ~50 | ~200 |
| **Total** | **~1450** | **~650** | **~200** |

### 4.9 What NOT to Do

- Do not implement HMM or Bayesian belief propagation in the first iteration
- Do not remove the old priority-based binding code until Phase 5 shadow mode has been validated for at least a week
- Do not change the topology engine — it remains a downstream consumer
- Do not change the identity enrichment pipeline (LLDP → ARP → DHCP → DNS → OUI) — it's correct
- Do not attempt traffic fingerprinting or deep packet inspection
- Do not add ML dependencies

---

## Part 5: Open Questions & Decisions Needed

These items are not fully specified in the source documents and will need decisions before or during implementation.

### 5.1 Architectural Decisions

**Q1: Observation storage model — time-series table vs. counter fields?**

The spec proposes a `mac_observations` time-series table (one row per sighting per poll). Alternative: add `observation_count` and `last_cycle_seen` columns to the existing `switch_mac_table`. The time-series approach is more powerful (preserves per-cycle timing) but grows faster (estimated ~2000 rows/minute at current scale).

Current recommendation: time-series table with aggressive pruning (delete > 2x window on each cycle). The granularity is needed for accurate persistence scoring.

Decision needed: **confirm observation window length (10 min vs 15 min)** and **pruning retention multiplier (2x vs 3x)**.

**Q2: Graph sharing between correlation and topology engines?**

The `InfrastructureGraph` struct duplicates BFS depth, adjacency, and parent/child computation that `topology.rs` already performs. Options:

- Option A: Build once in correlation, share via `Arc<RwLock<>>` in AppState. Topology reads the shared graph.
- Option B: Each engine builds its own graph independently. Simpler, but wastes work.

Current recommendation: Option A. The correlation engine runs more frequently (60s vs 120s), so it's the natural owner.

Decision needed: **confirm graph sharing approach**.

**Q3: Should `switch_port_roles` be kept alongside `port_role_probabilities`?**

Current consumers of `switch_port_roles`: topology engine, identity manager API, correlation engine. Options:

- Keep both tables during transition, derive old roles from argmax of probabilities
- Drop old table immediately and update all consumers to use probabilities

Current recommendation: keep both during Phase 1-4, deprecate old table in Phase 5.

Decision needed: **confirm backward-compatibility strategy**.

### 5.2 Scoring & Tuning Decisions

**Q4: Exact weight values for the scoring formula.**

The spec proposes:

```
2.0 * edge_likelihood
1.5 * persistence
1.2 * vlan_consistency
1.0 * downstream_preference
0.8 * recency
0.6 * graph_depth_score
0.6 * device_class_fit
-2.0 * transit_penalty
-1.5 * contradiction_penalty
```

These are starting points. Should these be hardcoded constants or configurable (via settings table or config file)?

Current recommendation: hardcoded constants initially, with a plan to move to config if tuning is needed. Premature configurability adds complexity.

Decision needed: **confirm hardcoded vs. configurable weights**.

**Q5: How is `compute_downstream_preference()` calculated?**

Not specified in the pseudocode. Proposed definition:

- 1.0 if this candidate is the deepest edge-plausible candidate (no deeper edge candidate exists)
- 0.0 if there exists a deeper edge-plausible candidate for the same MAC
- 0.5 if depth comparison is ambiguous (candidate and a peer at the same depth)

Decision needed: **confirm downstream preference scoring**.

**Q6: What constitutes a "contradiction"?**

The `contradiction_penalty` feature is mentioned but not defined. Proposed triggers:

- MAC observed on two mutually exclusive access ports on the same switch in the same cycle
- MAC appears on a switch that is a descendant of the current best candidate's switch (violates the tree constraint)
- MAC alternates between two candidates in successive cycles (flap detection)

Decision needed: **confirm contradiction definition**.

**Q7: How should `device_class_fit` interact with unknown device types?**

Many devices have `device_type = NULL` or low-confidence OUI-inferred types. When device class is unknown:

- Option A: `device_class_fit = 0.5` (neutral — neither helps nor hurts)
- Option B: `device_class_fit = 0.0` (conservative — don't credit unknown types)

Current recommendation: Option A. Unknown type shouldn't penalize; it just doesn't contribute.

Decision needed: **confirm handling of unknown device classes**.

### 5.3 State Machine Decisions

**Q8: Wireless roaming hysteresis threshold.**

The spec defines `1.25x` threshold for wired devices. Wireless devices roam legitimately and need faster transitions. Proposed:

- Wireless VLANs: `1.10x` threshold, 1 consecutive loss required
- Wired VLANs: `1.25x` threshold, 2 consecutive losses required

Decision needed: **confirm per-VLAN-type hysteresis parameters**.

**Q9: How to handle the Conflicted state?**

When top 2 candidates are within 10% score margin for 3+ cycles, the MAC enters Conflicted state. What happens to the binding?

- Option A: Retain previous binding until conflict resolves (conservative)
- Option B: Bind to the higher scorer but flag as low confidence (aggressive)
- Option C: Unbind entirely — set `switch_device_id = NULL` and show as orphan (honest but disruptive)

Current recommendation: Option A. Retain the last known-good binding, but surface the conflict in the UI and set confidence to 0.1.

Decision needed: **confirm Conflicted state behavior**.

**Q10: State progression timing — should it be cycle-count or wall-clock?**

The spec uses cycle counts (3 cycles for Probable, 10 for Stable). Alternative: use wall-clock time (3 minutes, 10 minutes). Wall-clock is more predictable if poll intervals vary.

Current recommendation: cycle count. At a consistent 60s cycle interval, the difference is minimal. Cycle count is simpler to implement.

Decision needed: **confirm cycle-count vs. wall-clock state progression**.

### 5.4 Integration & Migration Decisions

**Q11: How long should shadow mode run before cut-over?**

The spec recommends "several days" including device movement events and switch reboots.

Proposed minimum: **7 days** of shadow mode with daily divergence review. Ideally includes at least one switch reboot event and one device movement to validate those scenarios.

Decision needed: **confirm shadow mode duration**.

**Q12: What happens to existing `switch_binding_source = 'auto'` identities at cut-over?**

Options:

- Option A: Immediately re-evaluate all `'auto'` bindings with the inference engine on first cycle after cut-over
- Option B: Gradually transition — only re-evaluate MACs that are observed in the current cycle
- Option C: Batch migration — run inference on all known MACs once, then switch to incremental

Current recommendation: Option B. Natural migration as MACs are observed. Avoids a thundering herd of binding changes on the first cycle after cut-over.

Decision needed: **confirm migration strategy**.

**Q13: Should the explanation JSON be stored on every cycle or only on state changes?**

Writing `reasoning_json` on every cycle means 200+ JSON serializations per minute. Storing only on state changes reduces this to a handful per cycle.

Current recommendation: store on state changes only (binding change, state promotion, new conflict). Stale reasoning for Stable devices is acceptable — the reasoning was captured when the binding was established.

Decision needed: **confirm explanation persistence frequency**.

### 5.5 Multi-Homed Device Question

**Q14: How to handle devices with multiple NICs?**

A server with two NICs on two different switches is legitimately attached to both. The current model assumes one MAC = one attachment point. Options:

- Option A: Ignore for now — treat each MAC independently (each NIC gets its own binding). This is already how the system works.
- Option B: Add a concept of "device groups" where multiple MACs can be linked to a single logical device.

Current recommendation: Option A. Each MAC is an independent entity. Device grouping is a future feature and orthogonal to the inference engine.

Decision needed: **confirm single-MAC-per-attachment model**.

### 5.6 Performance Boundary Questions

**Q15: At what scale does this design need optimization?**

Current: 5 switches, ~200 MACs, 60s cycle. The full pipeline (graph build + observation + candidate + scoring + state update) should complete in <5 seconds.

At what point does the O(MACs × candidates²) scoring become a concern?

- 500 MACs × 5 candidates² = 12,500 score computations → trivial
- 2000 MACs × 5 candidates² = 50,000 score computations → still trivial
- 10,000 MACs × 10 candidates² = 1,000,000 → might need optimization

Current recommendation: no optimization needed for SMB/SME scale. Cross that bridge at ~5000 MACs.

Decision needed: **none — informational only**.

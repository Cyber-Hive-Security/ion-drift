
# Ion Drift Topology Inference Engine
## Rust-Oriented Architecture for Deterministic, Analyst-Grade Attachment Resolution

---

# 1. Purpose

This document defines a concrete implementation architecture for adding a **graph-aware, probabilistic, temporally-stable topology inference engine** to Ion Drift.

The goal is to improve:

- device → switch attribution
- device → port attribution
- switch confidence
- attachment stability over time

without requiring an LLM or external inference service.

This architecture is intended to evolve the existing correlation engine rather than replace it.

---

# 2. Design Goals

## Functional goals

- Resolve the most probable attachment point for each MAC
- Prefer true edge attachment over transit visibility
- Use topology graph constraints to suppress impossible candidates
- Minimize flapping
- Preserve explainability for operators

## Non-functional goals

- Deterministic
- Debuggable
- Fast enough for 60-second correlation cycles
- Compatible with SQLite-first architecture
- Incrementally adoptable
- Future-proof for multi-vendor support

---

# 3. High-Level Position in Ion Drift

Current shape:

```text
Pollers
  ↓
Raw tables
  ↓
Correlation Engine
  ↓
network_identities
  ↓
Topology Engine
```

Proposed evolved shape:

```text
Pollers
  ↓
Raw tables
  ↓
Observation Normalizer
  ↓
Infrastructure Graph Builder
  ↓
Candidate Generator
  ↓
Scoring Engine
  ↓
Attachment State Engine
  ↓
network_identities
  ↓
Topology Engine
```

The topology engine remains a consumer.

The new logic lives inside the correlation phase as a richer attachment-resolution subsystem.

---

# 4. Recommended Internal Modules

Recommended Rust modules:

```text
crates/ion-drift-web/src/
  topology_inference/
    mod.rs
    graph.rs
    observations.rs
    candidates.rs
    scoring.rs
    state.rs
    resolver.rs
    explain.rs
```

## Module responsibilities

### `graph.rs`
Builds the infrastructure graph from:
- device registry
- LLDP/MNDP neighbor data
- backbone links
- inferred infrastructure relationships

Provides:
- adjacency
- parent/child relationships
- depth
- descendant queries
- path queries

### `observations.rs`
Normalizes raw MAC sightings into a canonical observation model.

### `candidates.rs`
Generates plausible attachment candidates from recent observations.

### `scoring.rs`
Computes weighted evidence scores for each candidate.

### `state.rs`
Maintains attachment state, hysteresis, and temporal belief.

### `resolver.rs`
Coordinates the full resolution process for each MAC.

### `explain.rs`
Produces human-readable reasons for why a candidate won.

---

# 5. Core Data Model

## 5.1 Observation model

```rust
pub struct MacObservation {
    pub mac: String,
    pub device_id: String,
    pub port_name: String,
    pub vlan_id: Option<i64>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: ObservationSource,
    pub raw_port_role: Option<PortRole>,
    pub port_role_confidence: f32,
    pub edge_likelihood: f32,
    pub transit_likelihood: f32,
    pub observation_confidence: f32,
}
```

### Notes
- `observation_confidence` is the normalized credibility of the sighting
- `edge_likelihood` and `transit_likelihood` are probabilities, not exclusive labels

---

## 5.2 Candidate model

```rust
pub struct AttachmentCandidate {
    pub mac: String,
    pub device_id: String,
    pub port_name: String,
    pub vlan_id: Option<i64>,
    pub candidate_type: CandidateType,
    pub features: CandidateFeatures,
    pub score: f32,
}
```

```rust
pub enum CandidateType {
    WiredPort,
    WirelessParent,
    HumanOverride,
}
```

```rust
pub struct CandidateFeatures {
    pub observation_frequency: f32,
    pub persistence: f32,
    pub edge_likelihood: f32,
    pub transit_penalty: f32,
    pub vlan_consistency: f32,
    pub downstream_preference: f32,
    pub graph_depth_score: f32,
    pub recency: f32,
    pub device_class_fit: f32,
    pub contradiction_penalty: f32,
}
```

---

## 5.3 Attachment state model

```rust
pub struct AttachmentState {
    pub mac: String,
    pub current_device_id: Option<String>,
    pub current_port_name: Option<String>,
    pub current_score: f32,
    pub confidence: f32,
    pub state: AttachmentStateKind,
    pub stable_since: Option<chrono::DateTime<chrono::Utc>>,
    pub last_changed: Option<chrono::DateTime<chrono::Utc>>,
    pub previous_device_id: Option<String>,
    pub previous_port_name: Option<String>,
    pub consecutive_wins: u32,
    pub consecutive_losses: u32,
}
```

```rust
pub enum AttachmentStateKind {
    Unknown,
    Candidate,
    Probable,
    Stable,
    Roaming,
    Conflicted,
    HumanPinned,
}
```

---

# 6. Database Additions

## 6.1 `mac_observations`

```sql
CREATE TABLE IF NOT EXISTS mac_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL,
    device_id TEXT NOT NULL,
    port_name TEXT NOT NULL,
    vlan_id INTEGER,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    observation_confidence REAL NOT NULL DEFAULT 0.5,
    edge_likelihood REAL NOT NULL DEFAULT 0.5,
    transit_likelihood REAL NOT NULL DEFAULT 0.5
);
CREATE INDEX IF NOT EXISTS idx_mac_observations_mac_time
    ON mac_observations(mac_address, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_mac_observations_dev_port_time
    ON mac_observations(device_id, port_name, timestamp DESC);
```

## 6.2 `port_role_probabilities`

```sql
CREATE TABLE IF NOT EXISTS port_role_probabilities (
    device_id TEXT NOT NULL,
    port_name TEXT NOT NULL,
    trunk_prob REAL NOT NULL DEFAULT 0.0,
    uplink_prob REAL NOT NULL DEFAULT 0.0,
    access_prob REAL NOT NULL DEFAULT 0.0,
    wireless_prob REAL NOT NULL DEFAULT 0.0,
    computed_at TEXT NOT NULL,
    PRIMARY KEY (device_id, port_name)
);
```

## 6.3 `mac_attachment_state`

```sql
CREATE TABLE IF NOT EXISTS mac_attachment_state (
    mac_address TEXT PRIMARY KEY,
    current_device_id TEXT,
    current_port_name TEXT,
    current_score REAL NOT NULL DEFAULT 0.0,
    confidence REAL NOT NULL DEFAULT 0.0,
    state TEXT NOT NULL DEFAULT 'Unknown',
    stable_since TEXT,
    last_changed TEXT,
    previous_device_id TEXT,
    previous_port_name TEXT,
    consecutive_wins INTEGER NOT NULL DEFAULT 0,
    consecutive_losses INTEGER NOT NULL DEFAULT 0,
    reasoning_json TEXT
);
```

## 6.4 `mac_attachment_candidates`

```sql
CREATE TABLE IF NOT EXISTS mac_attachment_candidates (
    mac_address TEXT NOT NULL,
    device_id TEXT NOT NULL,
    port_name TEXT NOT NULL,
    vlan_id INTEGER,
    score REAL NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    candidate_type TEXT NOT NULL DEFAULT 'WiredPort',
    features_json TEXT NOT NULL,
    PRIMARY KEY (mac_address, device_id, port_name)
);
```

---

# 7. Graph Layer

## 7.1 Requirements

The graph builder should produce a cached object per correlation cycle:

```rust
pub struct InfrastructureGraph {
    pub nodes: HashMap<String, GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub adjacency: HashMap<String, Vec<String>>,
    pub depth: HashMap<String, usize>,
    pub parent: HashMap<String, String>,
    pub children: HashMap<String, Vec<String>>,
}
```

## 7.2 Required graph helpers

```rust
impl InfrastructureGraph {
    pub fn depth_of(&self, device_id: &str) -> Option<usize>;
    pub fn parent_of(&self, device_id: &str) -> Option<&str>;
    pub fn children_of(&self, device_id: &str) -> &[String];
    pub fn is_descendant_of(&self, child: &str, ancestor: &str) -> bool;
    pub fn path_to_root(&self, device_id: &str) -> Vec<&str>;
}
```

These helpers are necessary for downstream suppression and transit classification.

---

# 8. Observation Normalization

## 8.1 Input sources

Sources already available in Ion Drift:
- `switch_mac_table`
- `switch_port_roles`
- `neighbor_discovery`
- `switch_vlan_membership`
- `backbone_links`
- `switch_port_metrics`
- wireless VLAN definitions

## 8.2 Responsibility

Convert each MAC sighting into a single normalized observation.

## 8.3 Observation confidence

Suggested first-pass computation:

```text
base = 1.0
if local_mac => discard
if trunk_prob > 0.7 => base *= 0.35
if uplink_prob > 0.7 => base *= 0.50
if access_prob > 0.7 => base *= 1.15
if port speed >= 10000 => base *= 0.75
if many_macs_on_port => base *= 0.60
if single_stable_mac_on_port => base *= 1.20
clamp to [0.05, 1.0]
```

---

# 9. Candidate Generation

## 9.1 Candidate sources

For a given MAC:
- every observed `(device, port)` in the observation window
- wireless parent candidate when VLAN is wireless
- human override candidate if pinned

## 9.2 Candidate pruning

Drop candidates when:
- port is known local-only
- candidate is upstream transit and a stronger downstream candidate exists
- VLAN is inconsistent
- candidate port is impossible by graph constraints

## 9.3 Downstream suppression rule

If:
- candidate A is ancestor of candidate B
- A is transit-like
- B is edge-plausible

then A should be retained only as supporting evidence, not as final winner material.

This is one of the highest-value rules in the engine.

---

# 10. Scoring Engine

## 10.1 Scoring philosophy

Use an additive weighted model first.
It is:
- deterministic
- debuggable
- easy to tune

## 10.2 Suggested formula

```text
score =
  2.0 * edge_likelihood
+ 1.5 * persistence
+ 1.2 * vlan_consistency
+ 1.0 * downstream_preference
+ 0.8 * recency
+ 0.6 * graph_depth_score
+ 0.6 * device_class_fit
- 2.0 * transit_penalty
- 1.5 * contradiction_penalty
```

## 10.3 Feature definitions

### `edge_likelihood`
Derived from port role probabilities.

### `persistence`
Fraction of recent polls in which the MAC was seen on this candidate.

### `vlan_consistency`
Higher if the candidate regularly carries the inferred VLAN.

### `downstream_preference`
Higher if the candidate is lower in the graph and edge-plausible.

### `recency`
Recent observations weighted higher.

### `graph_depth_score`
Useful only when paired with edge plausibility.

### `device_class_fit`
Matches endpoint type to likely attachment mode.

### `transit_penalty`
Penalty for trunk/upstream fanout ports.

### `contradiction_penalty`
Applied when observations strongly suggest the candidate is impossible or unstable.

---

# 11. Attachment State Engine

## 11.1 Why it exists

This is what prevents flapping.

Without this layer, a single noisy cycle can move the binding.

## 11.2 Hysteresis rules

Recommended initial behavior:

```text
Switch binding only if:
new_score > current_score * 1.25
for 2 consecutive cycles
```

## 11.3 State progression

```text
Unknown   -> Candidate   after 1 credible observation
Candidate -> Probable    after 3 consistent wins
Probable  -> Stable      after 10 consistent wins
Stable    -> Roaming     when alternate candidate strongly and repeatedly wins
Roaming   -> Stable      after new location stabilizes
```

## 11.4 Confidence

Confidence should be separate from raw score.

Suggested heuristic:
- based on score margin between winner and runner-up
- boosted by stability duration
- reduced by contradiction count

---

# 12. Resolver Flow

One full per-MAC resolution cycle should look like:

```text
1. Load recent observations for MAC
2. Build candidate set
3. Apply graph-aware pruning
4. Score each candidate
5. Rank candidates
6. Compare winner to existing attachment state
7. Apply hysteresis/state transitions
8. Persist state
9. Update network_identities with resolved binding
10. Persist explanation/reasoning
```

---

# 13. Explainability Layer

## 13.1 Why it matters

Operators need to trust the engine.
The system must explain its reasoning.

## 13.2 Suggested explanation object

```rust
pub struct AttachmentExplanation {
    pub winner: String,
    pub confidence: f32,
    pub reasons: Vec<String>,
    pub supporting_observations: usize,
    pub suppressed_candidates: Vec<String>,
}
```

## 13.3 Example explanation

```text
Bound to CRS310:ether7
Confidence: 0.91
Reasons:
- Seen on this port 9 of last 10 polls
- Port strongly resembles edge access
- VLAN 35 consistent
- Upstream sightings on CRS326 and RB4011 treated as transit evidence
- Binding stable for 14 minutes
```

Persist as JSON for UI use.

---

# 14. Integration with `network_identities`

The final resolved binding should populate:

- `switch_device_id`
- `switch_port`
- `switch_binding_source = 'inference'`
- `confidence`

Preserve existing behavior:
- human overrides always win
- manually confirmed identities remain sticky

---

# 15. Recommended Rollout Plan

## Phase 1
Add observation history and port role probabilities.

## Phase 2
Run scoring engine in shadow mode.
Do not change real bindings yet.
Compare inferred winner vs current system.

## Phase 3
Enable attachment state engine for a subset of devices or VLANs.

## Phase 4
Replace existing hard priority binding.

## Phase 5
Expose reasoning in UI.

This lowers implementation risk and gives you measurement points.

---

# 16. Performance Notes

This design should still fit a 60-second cycle for SMB/SME-scale networks.

Optimization tactics:
- only evaluate MACs seen in the recent observation window
- cache graph once per cycle
- cache port role probabilities per cycle
- avoid recomputing VLAN consistency repeatedly
- batch SQLite reads

---

# 17. Final Recommendation

Do not jump straight to a formal HMM or Bayesian implementation.

Start with:

1. graph-aware candidate generation
2. weighted scoring
3. stateful hysteresis
4. explanation persistence

That gives you most of the enterprise-grade behavior with much lower complexity and much higher maintainability.

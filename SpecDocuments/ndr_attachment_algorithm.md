
# Enterprise NDR Device Attachment Inference
## (Darktrace / Vectra–Style Algorithm Reconstruction)

> **Note:** Vendors like Darktrace and Vectra AI do not publish their full internal algorithms.  
> The model described here is a technically accurate reconstruction based on patents, research papers,
> conference talks, and observed behavior of enterprise NDR systems.

---

# 1. Executive Summary

Enterprise Network Detection & Response (NDR) platforms determine where devices are connected in a network using a **probabilistic graph inference approach with temporal smoothing**.

Instead of asking:

> “Which switch saw this MAC most recently?”

They ask:

> “Given the topology and all recent observations, what is the most probable attachment point for this device?”

The system operates in six stages:

1. Build the infrastructure graph
2. Collect MAC observations
3. Generate candidate attachment points
4. Score each candidate using evidence weights
5. Update belief state with temporal smoothing
6. Emit the most probable attachment

This process is deterministic and does **not require machine learning** in most implementations.

---

# 2. Infrastructure Graph Construction

First the system builds a graph representing network infrastructure.

### Nodes
- Routers
- Switches
- Access points

### Edges
- Trunk links
- Backbone links
- Wireless uplinks

Example:

```
RB4011
 ├─ CRS326
 │   ├─ CRS310
 │   │   ├─ camera
 │   │   └─ printer
 │   └─ WAP-1
 └─ MS510
```

From this graph the system computes:

```
depth(node)
parent(node)
children(node)
```

The topology graph constrains which attachment points are possible.

---

# 3. Observation Collection

Every polling cycle produces observations:

```
(mac, device, port, vlan, timestamp)
```

Example:

```
MAC A seen on CRS326:sfp+1
MAC A seen on CRS310:ether7
MAC A seen on RB4011:sfp+1
```

These observations are appended to an **observation window**.

Typical window:

```
5–15 minutes
```

The window preserves temporal context needed for accurate inference.

---

# 4. Candidate Attachment Generation

For each MAC address, the system generates candidate attachment points.

Candidates typically include:

```
(device, port)
```

Example:

```
CRS310:ether7
CRS326:sfp+1
RB4011:sfp+1
```

However enterprise systems apply **transit filtering**:

Remove candidates where:

```
port_role = trunk
AND downstream switch exists
```

Because transit links will naturally observe downstream MACs.

After filtering, candidates might become:

```
CRS310:ether7
```

This drastically reduces mis-attribution.

---

# 5. Evidence Scoring

Each candidate is assigned a score.

General scoring model:

```
Score =
  w1 * observation_frequency
+ w2 * port_edge_probability
+ w3 * vlan_consistency
+ w4 * graph_depth_score
+ w5 * device_class_match
+ w6 * temporal_stability
- w7 * transit_penalty
```

Weights are tuned empirically.

---

# 6. Evidence Features

## Observation Frequency

```
observations(candidate) / total_observations
```

Example:

```
CRS310:ether7 = 12 sightings
CRS326:sfp+1  = 12 sightings
RB4011:sfp+1  = 12 sightings
```

Frequency alone is insufficient — other features must differentiate candidates.

---

## Port Edge Probability

Computed using:

- MAC fanout
- LLDP neighbors
- VLAN count
- port speed
- historical role

Example:

```
CRS310 ether7 → 0.90 edge probability
CRS326 sfp+1  → 0.10
RB4011 sfp+1  → 0.05
```

---

## VLAN Consistency

If device is inferred to belong to VLAN 35:

```
candidate_port_carries_vlan_35 → positive score
candidate_port_never_carries_vlan_35 → penalty
```

---

## Graph Depth Score

Endpoints typically appear near leaf nodes.

```
depth_score = normalized(depth)
```

However depth influence is reduced for trunk ports.

---

## Device Class Match

Device classification may come from:

- OUI database
- traffic fingerprinting
- DHCP metadata

Examples:

```
camera → wired edge port preferred
phone  → wireless attachment preferred
server → trunk attachment possible
```

---

## Temporal Stability

Measures persistence of attachment evidence.

```
stability = time_seen / observation_window
```

Example:

```
CRS310 ether7 seen for 9 minutes
CRS326 sfp+1 seen for 3 minutes
```

Edge candidate becomes more credible.

---

# 7. Belief State Update

Instead of switching attachments instantly, NDR systems maintain a belief state.

Variables:

```
current_attachment
current_confidence
previous_attachment
```

Belief update equation:

```
posterior =
   α * previous_belief
 + β * new_evidence
```

Typical parameters:

```
α = 0.7
β = 0.3
```

This creates **temporal smoothing**.

Short spikes of incorrect observations do not cause flapping.

---

# 8. Attachment State Machine

Attachment confidence progresses through states:

```
UNKNOWN
   ↓
CANDIDATE
   ↓
PROBABLE
   ↓
STABLE
```

Example transition rules:

```
CANDIDATE → PROBABLE  : 3 consistent cycles
PROBABLE → STABLE     : 10 consistent cycles
```

This prevents unstable attachment changes.

---

# 9. Roaming Detection

When a device legitimately moves:

```
new_candidate_score >> current_score
```

The system enters a roaming state:

```
ROAMING
```

The old attachment gradually decays while the new attachment gains confidence.

---

# 10. Why This Works

The algorithm relies on three fundamental properties of Ethernet networks.

### Transit links see everything
Upstream devices observe downstream MACs but are not the attachment point.

### Edge ports observe persistence
True attachment ports repeatedly see the same MAC.

### Network topology constrains possible locations
A MAC cannot appear below its true attachment point in the graph.

---

# 11. Implementation Guidance

A practical implementation requires three additional data structures.

## Observation History

```
mac_observations
----------------
mac_address
device_id
port_name
vlan_id
timestamp
confidence
```

## Candidate Attachments

```
mac_attachment_candidates
-------------------------
mac_address
device_id
port_name
score
observation_count
first_seen
last_seen
```

## Attachment State

```
mac_attachment_state
--------------------
mac_address
device_id
port_name
confidence
state
stable_since
last_changed
previous_device_id
previous_port_name
```

---

# 12. Simplified Scoring Formula

A practical first-pass scoring model:

```
score =
  2.0 * edge_likelihood
+ 1.5 * persistence
+ 1.2 * vlan_consistency
+ 1.0 * downstream_preference
+ 0.8 * recency
+ 0.6 * device_class_fit
- 2.0 * transit_penalty
- 1.5 * contradiction_penalty
```

Attachment changes occur only when:

```
new_score > current_score * 1.25
for 2 consecutive cycles
```

This introduces **binding hysteresis**.

---

# 13. Key Insight

Most enterprise NDR systems do **not** use deep learning for topology inference.

Instead they rely on:

```
network graph constraints
+ probabilistic scoring
+ temporal smoothing
```

This approach is deterministic, explainable, and performs extremely well at scale.

---

# 14. Final Takeaway

A system implementing:

- infrastructure graph modeling
- candidate scoring
- observation history
- belief state smoothing

will behave very similarly to enterprise NDR topology inference engines without requiring machine learning.


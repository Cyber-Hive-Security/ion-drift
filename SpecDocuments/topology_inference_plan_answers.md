
# Response to `RESPONSE_N_PLAN.md`
## Decisions and Answers for the Topology Inference Engine Plan

> This document answers the open questions in `RESPONSE_N_PLAN.md` and turns the proposed plan into concrete implementation decisions.

---

## Executive Summary

The overall direction is approved.

The right implementation strategy for Ion Drift is:

- keep the existing topology engine as a downstream consumer
- evolve the correlation engine into a graph-aware inference resolver
- run the new resolver in shadow mode first
- cut over only after measured validation
- keep the system deterministic, explainable, and SQLite-friendly

The recommendations below are intentionally opinionated. They optimize for correctness, maintainability, and low operational risk over theoretical elegance.

---

# Part 1 — Direct Answers to the Open Questions

## Q1: Observation storage model — time-series table vs. counter fields?

**Decision:** Use a **time-series `mac_observations` table**.

**Answer:**  
Do not overload `switch_mac_table` with counters. The inference engine needs true temporal evidence, not just aggregate counts. Persistence scoring, recency weighting, contradiction detection, and roaming analysis all benefit from retaining individual observations within a bounded recent window.

**Chosen parameters:**
- **Observation window:** `10 minutes`
- **Retention:** `2x window` = `20 minutes`
- **Pruning cadence:** once per correlation cycle

**Why 10 minutes instead of 15?**
- 10 minutes is enough to distinguish noise from persistence at a 60-second cycle
- it keeps the table smaller and reasoning tighter
- it reduces delayed self-correction after legitimate moves
- you can always expand to 15 later if field testing shows too much churn

**Final call:**  
Use the time-series table with aggressive pruning.

---

## Q2: Graph sharing between correlation and topology engines?

**Decision:** **Share the graph** from correlation to topology via `Arc<RwLock<InfrastructureGraph>>`.

**Answer:**  
The graph should have a single owner: the correlation engine. It already runs more frequently and uses the graph for the harder logic. The topology engine should read the shared graph instead of rebuilding it independently.

**Why this is the right choice:**
- eliminates duplicated BFS/depth/adjacency work
- guarantees correlation and topology are using the same graph interpretation
- reduces subtle drift between engines
- makes debugging easier because there is one authoritative graph object

**Constraint:**  
Keep a fallback path so topology can rebuild its own graph if the shared graph is unavailable during startup or error recovery.

**Final call:**  
Primary path is shared graph; topology rebuild only as fallback.

---

## Q3: Should `switch_port_roles` be kept alongside `port_role_probabilities`?

**Decision:** **Yes, keep both during transition.**

**Answer:**  
Maintain backward compatibility through Phase 5. Derive the legacy role label from the probability table using argmax.

**Implementation rule:**
- `switch_port_roles` remains populated
- `port_role_probabilities` becomes the new authoritative source
- legacy role = max(`trunk_prob`, `uplink_prob`, `access_prob`, `wireless_prob`)

**Why:**
- reduces migration risk
- avoids refactoring multiple consumers at once
- supports phased rollout and easier rollback

**Deprecation point:**  
After the inference engine is live and stable, mark `switch_port_roles` as compatibility-only and remove consumers gradually.

**Final call:**  
Keep both during rollout; probability table is the source of truth.

---

## Q4: Hardcoded vs configurable scoring weights?

**Decision:** **Hardcode the weights initially.**

**Answer:**  
Do not introduce configuration knobs for scoring in the first implementation. The system needs a stable baseline before it needs tunability.

**Why:**
- configuration surfaces encourage premature tuning
- too many knobs make debugging harder
- hardcoded constants are easier to reason about during shadow validation

**Implementation pattern:**
- define the weights as Rust constants in `scoring.rs`
- centralize them in one `Weights` struct
- make them easy to move into config later

**Final call:**  
Hardcoded first, configurable later only if field evidence justifies it.

---

## Q5: How should `compute_downstream_preference()` work?

**Decision:** Use the proposed **three-tier scoring** with one refinement.

**Answer:**  
`compute_downstream_preference()` should be:

- **1.0** if candidate is the deepest **edge-plausible** candidate
- **0.0** if a deeper edge-plausible candidate exists
- **0.5** if ambiguous among same-depth peers
- **0.25** if candidate is transit-like but not suppressible

That added `0.25` case is useful. It distinguishes weak-but-possible transit candidates from impossible ones.

**Why this works:**
- encodes the physical reality of downstream attachment
- preserves ambiguity honestly
- prevents transit candidates from collapsing all the way to zero unless they truly should

**Final call:**  
Adopt the 1.0 / 0.5 / 0.25 / 0.0 model.

---

## Q6: What counts as a contradiction?

**Decision:** Use a **narrow, high-signal contradiction definition**.

**Answer:**  
A contradiction should only be something that strongly undermines a candidate. Use these rules:

### Contradiction triggers
1. **Same-cycle mutually exclusive access observations**
   - same MAC on two different edge-plausible access ports in the same cycle
2. **Graph impossibility**
   - MAC observed on a descendant branch that would be impossible if the current candidate were true
3. **Rapid alternating winner pattern**
   - A/B/A/B winner oscillation across consecutive cycles with similar scores
4. **VLAN impossibility**
   - candidate port consistently does not carry the inferred VLAN while another candidate consistently does

### Not contradictions
- seeing the same MAC upstream on trunk ports
- brief absence from one poll
- stale router visibility
- weak OUI/device-type mismatch by itself

**Why narrow is better:**
- contradiction penalties should be rare and meaningful
- overusing contradictions makes the score model noisy and brittle

**Final call:**  
Use only strong structural contradictions.

---

## Q7: How should unknown device classes affect `device_class_fit`?

**Decision:** **Neutral default = `0.5`.**

**Answer:**  
Unknown device class should neither help nor hurt much.

**Why:**
- OUI/type inference is imperfect
- many endpoints will remain unclassified or low-confidence
- the engine should not punish uncertainty in a weak signal

**Refinement:**
- if device type is human-confirmed, allow strong contribution
- if type is auto-inferred with low confidence, compress toward neutral

Example:
- human-confirmed camera → `1.0` on wired edge candidate
- high-confidence phone on wireless VLAN → `1.0` on wireless candidate
- unknown type → `0.5`
- weak OUI guess → maybe `0.55` or `0.45`, not extreme

**Final call:**  
Unknown = neutral.

---

## Q8: Wireless roaming hysteresis threshold?

**Decision:** **Yes, use different hysteresis for wireless-capable attachments.**

**Answer:**  
Wireless movement is normal behavior. The engine should adapt faster.

### Chosen thresholds
#### Wired
- challenger must exceed current by **1.25x**
- require **2 consecutive losses**

#### Wireless
- challenger must exceed current by **1.10x**
- require **1 consecutive loss**

**Additional rule:**  
Only apply wireless hysteresis when the device is on a wireless VLAN or being resolved to a WAP candidate. Do not globally treat all devices with a wireless-capable OUI as roaming devices.

**Final call:**  
Use lower hysteresis for wireless attachments.

---

## Q9: How should the `Conflicted` state behave?

**Decision:** **Retain the previous binding and surface the conflict.**

**Answer:**  
Use conservative behavior.

When a MAC enters `Conflicted`:
- keep the last known-good binding
- reduce confidence sharply
- expose the conflict in reasoning/UI
- do not unbind unless there is no previous binding

### Confidence behavior
- set confidence floor around **0.10–0.20**
- include runner-up and margin in explanation

### If there is no previous binding
- leave unresolved and render as orphan/unknown attachment

**Why:**
- avoids disruptive map churn
- preserves operator continuity
- makes conflict visible without pretending certainty

**Final call:**  
Retain last known-good binding; if none exists, leave unbound.

---

## Q10: State progression — cycle count or wall-clock?

**Decision:** Use **cycle count**.

**Answer:**  
At your current architecture, cycle count is simpler and sufficiently predictable.

**Chosen progression:**
- `Candidate` after 1 credible win
- `Probable` after 3 consecutive wins
- `Stable` after 10 consecutive wins

**Why cycle count wins:**
- cheaper and simpler to implement
- aligns with the actual evaluation loop
- good enough as long as the correlation cadence is stable

**Caveat:**  
If you later allow variable or adaptive correlation intervals, revisit this and move to elapsed time.

**Final call:**  
Use cycle-count progression.

---

## Q11: How long should shadow mode run before cut-over?

**Decision:** Minimum **7 days**, target **10–14 days** if practical.

**Answer:**  
Seven days is the minimum acceptable validation window. That gives you:
- normal weekday traffic patterns
- overnight idleness
- at least one likely reboot/maintenance event
- enough time to inspect divergences

**Cut-over criteria should be explicit:**
1. divergence rate understood, not just observed
2. sampled divergences are mostly improvements
3. no recurring severe misbindings
4. no pathological flapping cases
5. roaming behavior acceptable

**Final call:**  
Run shadow mode for at least 7 days; prefer 10–14 if schedule allows.

---

## Q12: Migration strategy for existing `switch_binding_source = 'auto'` rows?

**Decision:** Use **Option B — gradual transition based on observed MACs**.

**Answer:**  
Do not batch-rebind the entire environment on first cut-over. Let bindings migrate naturally as devices are observed.

**Why:**
- avoids a thundering herd of changes
- keeps rollout incremental
- reduces operator shock
- naturally prioritizes live devices over stale identities

**Implementation:**
- only update attachments for MACs seen in the active observation window
- leave stale inactive identities untouched until re-observed
- optionally add a maintenance task later to revisit long-lived inactive entries

**Final call:**  
Gradual migration by active observation.

---

## Q13: When should explanation JSON be persisted?

**Decision:** Persist explanations **on state changes and binding changes only**.

**Answer:**  
Do not write explanation JSON every cycle.

### Persist when:
- binding changes
- state changes (`Candidate` → `Probable`, etc.)
- `Conflicted` begins or resolves
- a human override is applied or removed

### Do not persist when:
- same stable binding receives another confirming cycle
- score changes slightly with no semantic effect

**Why:**
- reduces write amplification
- keeps storage cleaner
- preserves the most meaningful reasoning snapshots

**Final call:**  
Persist reasoning only on meaningful state transitions.

---

## Q14: How should multi-homed devices be handled?

**Decision:** **Treat each MAC independently for now.**

**Answer:**  
Do not add device grouping in this project phase.

**Why:**
- the current system is MAC-centric
- multi-NIC grouping is a separate identity problem, not an attachment inference problem
- forcing grouping now adds complexity without helping the current objective

**Operational interpretation:**
- a server with 2 NICs = 2 attachments
- later, you may introduce a higher-level logical device abstraction that groups MACs

**Final call:**  
One MAC = one attachment decision.

---

## Q15: Performance boundary — any special optimization now?

**Decision:** **No special optimization needed now.**

**Answer:**  
The current design is comfortably within SQLite/Rust limits for the expected network scale.

**Recommendation:**
- optimize for clarity first
- use batching and WAL mode
- add indices exactly as planned
- measure before optimizing further

**When to revisit:**
- roughly **5,000+ active MACs**
- or when correlation cycle latency begins approaching the cycle interval

**Final call:**  
No extra optimization work in the first implementation.

---

# Part 2 — Additional Clarifications and Refinements

## 1. Transit filtering should happen in two layers

The document correctly identifies transit suppression as high leverage. I recommend formalizing it in two layers:

### Layer A — hard suppression
Suppress a candidate from final-winner eligibility when:
- it is transit-like
- it has a deeper edge-plausible descendant candidate

### Layer B — soft penalty
Keep the candidate in evidence scoring as supporting context with a transit penalty

This preserves the informational value of upstream visibility without allowing it to win incorrectly.

---

## 2. The graph cache should be authoritative but disposable

The shared graph should be treated as:
- authoritative for the current cycle
- disposable across cycles

Do not over-engineer long-lived graph mutation logic. Rebuild it cleanly once per cycle from source tables, then publish it to both engines.

That keeps graph correctness tied to source truth.

---

## 3. Keep the identity enrichment pipeline unchanged

This remains the right call.

The new inference engine should decide:
- **where** the MAC is attached

The existing identity builder still decides:
- **what** the MAC is
- **what metadata** is associated with it

Do not intermingle those responsibilities.

---

## 4. Add explicit metrics during shadow mode

Shadow mode should produce measurable outputs, not just logs.

Recommended counters:
- total active MACs evaluated
- total divergences
- divergence rate %
- divergences where new candidate deeper than old
- divergences where new candidate less transit-like than old
- number of conflicted MACs
- number of stable vs probable vs candidate states
- number of wireless roaming transitions
- average score margin of winners

This will make go/no-go cut-over decisions much easier.

---

## 5. Use a feature flag for the cut-over

At cut-over, gate the inference resolver behind a feature flag.

Suggested pattern:
- `TOPOLOGY_INFERENCE_MODE=shadow`
- `TOPOLOGY_INFERENCE_MODE=active`
- `TOPOLOGY_INFERENCE_MODE=legacy`

That gives you:
- reversible rollout
- easier testing
- lower operational risk

---

# Part 3 — Recommended Final Decisions Table

| Question | Decision |
|---|---|
| Q1 | Use `mac_observations` time-series table; 10-minute window, 20-minute retention |
| Q2 | Share graph from correlation to topology via `Arc<RwLock<InfrastructureGraph>>`; topology rebuild only as fallback |
| Q3 | Keep `switch_port_roles` during rollout; `port_role_probabilities` is authoritative |
| Q4 | Hardcode weights initially |
| Q5 | Use downstream preference values `1.0 / 0.5 / 0.25 / 0.0` |
| Q6 | Use narrow contradiction rules only for strong structural conflicts |
| Q7 | Unknown device class = neutral (`0.5`) |
| Q8 | Wireless hysteresis = `1.10x` and 1 loss; wired = `1.25x` and 2 losses |
| Q9 | Conflicted state retains previous binding; if none exists, remain unbound |
| Q10 | Use cycle-count state progression |
| Q11 | Minimum 7 days shadow mode; prefer 10–14 days |
| Q12 | Gradual migration based on observed MACs |
| Q13 | Persist explanation JSON only on state/binding changes |
| Q14 | Treat each MAC independently |
| Q15 | No special optimization now |

---

# Part 4 — Final Recommendation

The proposed plan is strong and should move forward.

The **highest-value sequence** is:

1. add time-series observations
2. add probabilistic port roles
3. build and share the infrastructure graph
4. implement candidate generation and transit suppression
5. run weighted scoring in shadow mode
6. add state/hysteresis
7. cut over behind a feature flag
8. expose reasoning in the UI

That path gives Ion Drift the behavior of an analyst-grade inference engine without overcomplicating the architecture.

---

# Part 5 — Immediate Next-Step Checklist

## Implement now
- Phase 1 schema additions
- exact-set local MAC handling
- port role probabilities
- observation recording
- pruning job

## Implement next
- shared graph object
- candidate generation
- transit suppression
- shadow scoring

## Only after validation
- state machine
- active cut-over
- explainability UI

---

## Closing Position

The right answer is **not** to chase a more exotic algorithm.

The right answer is to make the current system:
- graph-aware
- probabilistic
- temporal
- conservative under ambiguity
- explainable to operators

That is the correct architecture for Ion Drift at this stage.

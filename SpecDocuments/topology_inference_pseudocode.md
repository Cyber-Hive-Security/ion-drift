
# Ion Drift Topology Inference Pseudocode
## End-to-End Resolver Flow for MAC Attachment Attribution

---

# 1. Purpose

This document describes the step-by-step pseudocode for a deterministic topology inference engine that resolves the most probable attachment point for each MAC address.

This algorithm is intended to plug into Ion Drift's correlation engine and evolve the current priority-based binding logic into a graph-aware, temporally-stable resolver.

---

# 2. Inputs

The resolver assumes the following are available each correlation cycle:

- device registry
- LLDP/MNDP neighbor records
- backbone links
- `switch_mac_table`
- `switch_port_roles`
- `switch_vlan_membership`
- `switch_port_metrics`
- `network_identities`
- wireless VLAN definitions
- human overrides
- previous attachment state

---

# 3. High-Level Algorithm

```text
build_infrastructure_graph()
compute_port_role_probabilities()
normalize_recent_mac_observations()

for each mac in active_macs:
    if human_override_exists(mac):
        apply_human_override(mac)
        continue

    candidates = generate_candidates(mac)
    candidates = prune_candidates(mac, candidates)

    scored = score_candidates(mac, candidates)
    winner = choose_winner(scored)

    updated_state = update_attachment_state(mac, winner, scored)
    persist_attachment_state(updated_state)

    apply_resolved_binding_to_identity(mac, updated_state)
```

---

# 4. Build Infrastructure Graph

```text
function build_infrastructure_graph():
    graph = new Graph()

    devices = load_registered_devices()
    neighbors = load_neighbor_discovery()
    backbone_links = load_backbone_links()

    for each device in devices:
        graph.add_node(device.id, device.type)

    for each neighbor in neighbors:
        local = neighbor.device_id
        remote = resolve_neighbor_to_device(neighbor)

        if remote exists:
            graph.add_edge(local, remote, edge_type="trunk", source="lldp")

    for each link in backbone_links:
        graph.add_edge(link.device_a, link.device_b, edge_type="trunk", source="backbone")

    graph.compute_bfs_depth(root_router_id)
    graph.compute_parent_child_maps()

    return graph
```

---

# 5. Compute Port Role Probabilities

```text
function compute_port_role_probabilities():
    for each device:
        for each port on device:
            lldp_present = has_neighbor_on_port(device, port)
            mac_count = count_non_local_macs(device, port)
            vlan_count = count_vlans_on_port(device, port)
            speed = get_latest_port_speed(device, port)
            backbone = port_is_backbone_link(device, port)

            trunk_prob = 0.0
            uplink_prob = 0.0
            access_prob = 0.0
            wireless_prob = 0.0

            if backbone:
                trunk_prob += 0.75

            if lldp_present:
                uplink_prob += 0.60
                trunk_prob += 0.25

            if vlan_count > 1:
                trunk_prob += 0.60

            if mac_count > 10:
                uplink_prob += 0.45

            if mac_count == 1 and not lldp_present and vlan_count <= 1:
                access_prob += 0.70

            if speed >= 10000:
                trunk_prob += 0.20

            normalize probabilities to 0.0 .. 1.0
            persist port_role_probabilities(device, port)
```

---

# 6. Normalize Recent MAC Observations

Observation window recommendation:
- 5 to 15 minutes

```text
function normalize_recent_mac_observations():
    raw_entries = load_switch_mac_table_entries(window=10_minutes)

    for each entry in raw_entries:
        if entry.is_local:
            continue

        role_probs = load_port_role_probabilities(entry.device_id, entry.port_name)
        fanout = count_non_local_macs(entry.device_id, entry.port_name)
        speed = get_latest_port_speed(entry.device_id, entry.port_name)

        confidence = 1.0

        if role_probs.trunk_prob > 0.7:
            confidence *= 0.35

        if role_probs.uplink_prob > 0.7:
            confidence *= 0.50

        if role_probs.access_prob > 0.7:
            confidence *= 1.15

        if fanout > 20:
            confidence *= 0.60

        if speed >= 10000:
            confidence *= 0.75

        confidence = clamp(confidence, 0.05, 1.0)

        persist mac_observation(
            mac=entry.mac_address,
            device=entry.device_id,
            port=entry.port_name,
            vlan=entry.vlan_id,
            timestamp=entry.last_seen,
            observation_confidence=confidence,
            edge_likelihood=role_probs.access_prob,
            transit_likelihood=max(role_probs.trunk_prob, role_probs.uplink_prob)
        )
```

---

# 7. Generate Candidates

```text
function generate_candidates(mac):
    observations = load_recent_observations(mac, window=10_minutes)
    identity = load_identity(mac)

    candidates = empty set

    for each observation in observations:
        candidates.add(
            candidate(
                device_id=observation.device_id,
                port_name=observation.port_name,
                vlan_id=observation.vlan_id,
                type="WiredPort"
            )
        )

    if identity.vlan_id is wireless_vlan:
        wap_candidate = infer_wireless_parent_candidate(identity, observations)
        if wap_candidate exists:
            candidates.add(wap_candidate)

    if identity has human override:
        candidates.add(
            candidate(
                device_id=identity.switch_device_id,
                port_name=identity.switch_port,
                vlan_id=identity.vlan_id,
                type="HumanOverride"
            )
        )

    return deduplicated candidates
```

---

# 8. Candidate Pruning

```text
function prune_candidates(mac, candidates):
    graph = cached_graph
    identity = load_identity(mac)

    winner_set = []

    for each candidate in candidates:
        role_probs = load_port_role_probabilities(candidate.device_id, candidate.port_name)

        if candidate.type == "HumanOverride":
            winner_set.append(candidate)
            continue

        if candidate.vlan_id exists and identity.vlan_id exists:
            if candidate.vlan_id != identity.vlan_id:
                mark penalty but do not always discard

        if candidate is impossible by graph constraints:
            continue

        winner_set.append(candidate)

    winner_set = suppress_upstream_transit_candidates(mac, winner_set, graph)

    return winner_set
```

## Upstream suppression

```text
function suppress_upstream_transit_candidates(mac, candidates, graph):
    for each candidate_a in candidates:
        for each candidate_b in candidates:
            if candidate_a == candidate_b:
                continue

            if graph.is_descendant_of(candidate_b.device_id, candidate_a.device_id):
                if candidate_a is transit-like and candidate_b is edge-plausible:
                    mark candidate_a as suppressed

    return candidates not suppressed as final-winner eligible
```

---

# 9. Score Candidates

```text
function score_candidates(mac, candidates):
    observations = load_recent_observations(mac, window=10_minutes)
    identity = load_identity(mac)
    graph = cached_graph

    scored = []

    for each candidate in candidates:
        candidate_obs = observations matching candidate.device_id and candidate.port_name
        role_probs = load_port_role_probabilities(candidate.device_id, candidate.port_name)

        observation_frequency = count(candidate_obs) / count(observations)
        persistence = polls_seen(candidate_obs) / polls_in_window()
        edge_likelihood = role_probs.access_prob
        transit_penalty = max(role_probs.trunk_prob, role_probs.uplink_prob)
        vlan_consistency = compute_vlan_consistency(identity, candidate)
        downstream_preference = compute_downstream_preference(candidate, candidates, graph)
        graph_depth_score = normalized_depth(candidate.device_id, graph)
        recency = compute_recency(candidate_obs)
        device_class_fit = compute_device_class_fit(identity.device_type, candidate, role_probs)
        contradiction_penalty = compute_contradictions(mac, candidate)

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

        scored.append(candidate with feature breakdown and score)

    sort scored descending by score

    return scored
```

---

# 10. Choose Winner

```text
function choose_winner(scored_candidates):
    if scored_candidates is empty:
        return no_winner

    return scored_candidates[0]
```

Optionally retain:
- top winner
- runner-up
- score margin

---

# 11. Update Attachment State

```text
function update_attachment_state(mac, winner, scored):
    current = load_attachment_state(mac)

    if current does not exist:
        return create_initial_state_from_winner(mac, winner)

    if current.state == "HumanPinned":
        return current

    current_score = current.current_score
    winner_score = winner.score
    same_location = (
        current.current_device_id == winner.device_id
        and current.current_port_name == winner.port_name
    )

    if same_location:
        current.current_score = smooth_score(current_score, winner_score)
        current.confidence = recompute_confidence(scored)
        current.consecutive_wins += 1
        current.consecutive_losses = 0
        current = maybe_promote_state(current)
        return current

    if winner_score > current_score * 1.25:
        current.consecutive_losses += 1
    else:
        current.consecutive_losses = 0
        current.current_score = smooth_score(current_score, current_score * 0.98)
        return current

    if current.consecutive_losses >= 2:
        previous_device = current.current_device_id
        previous_port = current.current_port_name

        current.previous_device_id = previous_device
        current.previous_port_name = previous_port
        current.current_device_id = winner.device_id
        current.current_port_name = winner.port_name
        current.current_score = winner_score
        current.confidence = recompute_confidence(scored)
        current.last_changed = now()
        current.consecutive_wins = 1
        current.consecutive_losses = 0
        current.state = next_state_after_move(current)

        return current

    return current
```

---

# 12. Confidence Computation

```text
function recompute_confidence(scored):
    if scored is empty:
        return 0.0

    winner = scored[0]
    runner_up = scored[1] if exists else none

    margin = winner.score - runner_up.score if runner_up exists else winner.score
    normalized_margin = clamp(margin / 3.0, 0.0, 1.0)

    return normalized_margin
```

Optional boosts:
- stable for >10 minutes
- seen on same port >80% of polls

Optional penalties:
- multiple conflicting candidates
- port recently changed role

---

# 13. State Promotion

```text
function maybe_promote_state(state):
    if state.consecutive_wins >= 10:
        state.state = "Stable"
        if state.stable_since is null:
            state.stable_since = now()
    else if state.consecutive_wins >= 3:
        state.state = "Probable"
    else if state.consecutive_wins >= 1:
        state.state = "Candidate"

    return state
```

---

# 14. Apply Binding to Identity

```text
function apply_resolved_binding_to_identity(mac, state):
    identity = load_identity(mac)

    if identity.switch_binding_source == "human":
        return

    identity.switch_device_id = state.current_device_id
    identity.switch_port = state.current_port_name
    identity.switch_binding_source = "inference"
    identity.confidence = merge_identity_confidence(identity.confidence, state.confidence)

    save identity
```

---

# 15. Explanation Generation

```text
function build_explanation(mac, winner, scored):
    reasons = []

    if winner.features.persistence > 0.75:
        reasons.append("Seen consistently on this port over the recent observation window")

    if winner.features.edge_likelihood > 0.7:
        reasons.append("Port strongly resembles an edge/access attachment")

    if winner.features.vlan_consistency > 0.7:
        reasons.append("Candidate matches inferred VLAN")

    if winner.features.downstream_preference > 0.7:
        reasons.append("Downstream graph position preferred over upstream transit sightings")

    if winner.features.transit_penalty < 0.3:
        reasons.append("Port is not strongly transit-like")

    persist explanation JSON on attachment state
```

---

# 16. Shadow Mode Recommendation

Before replacing the current resolver:

```text
for each mac:
    old_binding = current priority resolver output
    new_binding = inference resolver output

    if old_binding != new_binding:
        log divergence
        persist comparison
```

Review divergence over:
- several days
- normal operation
- device movement events
- switch reboot events

This is the safest upgrade path.

---

# 17. Failure Handling

## If no winner exists
Set:
- state = `Unknown`
- confidence = 0.0
- do not force a bad binding

## If candidates are tied
Set:
- state = `Conflicted`
- retain previous binding if present

## If device is clearly roaming
Set:
- state = `Roaming`
- allow transition faster than normal hysteresis

---

# 18. Final Implementation Advice

Start with:
1. observation history
2. graph-aware candidate pruning
3. weighted scoring
4. hysteresis

Only after that should you consider:
- formal HMM modeling
- Bayesian belief propagation
- traffic fingerprinting expansion
- vendor-specific heuristics

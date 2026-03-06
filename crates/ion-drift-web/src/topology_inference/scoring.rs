//! Weighted scoring engine for MAC attachment candidates.

use std::collections::HashMap;

use mikrotik_core::switch_store::{MacObservation, PortRoleProbability};
use serde::Serialize;

use super::candidates::AttachmentCandidate;
use super::graph::InfrastructureGraph;

/// Breakdown of all feature scores for a candidate.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateFeatures {
    pub edge_likelihood: f64,
    pub persistence: f64,
    pub vlan_consistency: f64,
    pub downstream_preference: f64,
    pub recency: f64,
    pub graph_depth_score: f64,
    pub device_class_fit: f64,
    pub transit_penalty: f64,
    pub contradiction_penalty: f64,
}

/// A scored candidate with feature breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct ScoredCandidate {
    pub mac: String,
    pub device_id: String,
    pub port_name: String,
    pub vlan_id: Option<u32>,
    pub candidate_type: String,
    pub observation_count: u32,
    pub suppressed: bool,
    pub features: CandidateFeatures,
    pub score: f64,
}

// ── Scoring weights (hardcoded per spec) ─────────────────────────
const W_EDGE_LIKELIHOOD: f64 = 2.0;
const W_PERSISTENCE: f64 = 1.5;
const W_VLAN_CONSISTENCY: f64 = 1.2;
const W_DOWNSTREAM_PREFERENCE: f64 = 1.0;
const W_RECENCY: f64 = 0.8;
const W_GRAPH_DEPTH: f64 = 0.6;
const W_DEVICE_CLASS_FIT: f64 = 0.6;
const W_TRANSIT_PENALTY: f64 = -2.0;
const W_CONTRADICTION_PENALTY: f64 = -1.5;

/// Score all candidates for a MAC address.
///
/// Returns candidates sorted by score descending. Suppressed candidates
/// are scored but their scores are ignored for winner selection.
pub fn score_candidates(
    candidates: &[AttachmentCandidate],
    observations: &[MacObservation],
    role_probs: &HashMap<(String, String), PortRoleProbability>,
    graph: &InfrastructureGraph,
    identity_vlan: Option<u32>,
    device_type: Option<&str>,
    now_ts: i64,
    window_secs: i64,
) -> Vec<ScoredCandidate> {
    let _total_obs = observations.len() as f64;
    let window_start = now_ts - window_secs;

    // Count polls in window (unique timestamps = unique poll cycles)
    let unique_timestamps: std::collections::HashSet<i64> = observations
        .iter()
        .map(|o| o.timestamp)
        .collect();
    let polls_in_window = unique_timestamps.len().max(1) as f64;

    let mut scored: Vec<ScoredCandidate> = candidates
        .iter()
        .map(|c| {
            let key = (c.device_id.clone(), c.port_name.clone());
            let probs = role_probs.get(&key);

            // Filter observations for this candidate
            let candidate_obs: Vec<&MacObservation> = observations
                .iter()
                .filter(|o| o.device_id == c.device_id && o.port_name == c.port_name)
                .collect();
            let _candidate_obs_count = candidate_obs.len() as f64;

            // ── Feature computation ──────────────────────────────

            // Edge likelihood: from port role probabilities
            let edge_likelihood = probs
                .map(|p| p.access_prob + p.wireless_prob * 0.8)
                .unwrap_or(0.5)
                .clamp(0.0, 1.0);

            // Persistence: fraction of polls where this candidate was seen
            let candidate_timestamps: std::collections::HashSet<i64> = candidate_obs
                .iter()
                .map(|o| o.timestamp)
                .collect();
            let persistence = candidate_timestamps.len() as f64 / polls_in_window;

            // VLAN consistency: 1.0 if match, 0.0 if mismatch, 0.5 if unknown
            let vlan_consistency = match (identity_vlan, c.vlan_id) {
                (Some(iv), Some(cv)) => if iv == cv { 1.0 } else { 0.0 },
                _ => 0.5,
            };

            // Downstream preference: 1.0 if deepest edge-plausible, 0.0 if
            // a deeper edge candidate exists, 0.5 if ambiguous
            let downstream_preference = compute_downstream_preference(
                c, candidates, graph, role_probs,
            );

            // Recency: most recent observation = 1.0, oldest = 0.0
            let recency = if window_secs > 0 {
                candidate_obs
                    .iter()
                    .map(|o| (o.timestamp - window_start) as f64 / window_secs as f64)
                    .fold(0.0_f64, f64::max)
                    .clamp(0.0, 1.0)
            } else {
                0.5
            };

            // Graph depth score: normalized depth (deeper = higher)
            let graph_depth_score = graph.normalized_depth(&c.device_id);

            // Device class fit
            let device_class_fit = compute_device_class_fit(device_type, probs);

            // Transit penalty: max(trunk_prob, uplink_prob)
            let transit_penalty = probs
                .map(|p| p.trunk_prob.max(p.uplink_prob))
                .unwrap_or(0.0);

            // Contradiction penalty: currently 0 (Phase 3 state machine
            // will feed back contradictions from previous cycles)
            let contradiction_penalty = 0.0;

            let features = CandidateFeatures {
                edge_likelihood,
                persistence,
                vlan_consistency,
                downstream_preference,
                recency,
                graph_depth_score,
                device_class_fit,
                transit_penalty,
                contradiction_penalty,
            };

            let score = W_EDGE_LIKELIHOOD * edge_likelihood
                + W_PERSISTENCE * persistence
                + W_VLAN_CONSISTENCY * vlan_consistency
                + W_DOWNSTREAM_PREFERENCE * downstream_preference
                + W_RECENCY * recency
                + W_GRAPH_DEPTH * graph_depth_score
                + W_DEVICE_CLASS_FIT * device_class_fit
                + W_TRANSIT_PENALTY * transit_penalty
                + W_CONTRADICTION_PENALTY * contradiction_penalty;

            ScoredCandidate {
                mac: c.mac.clone(),
                device_id: c.device_id.clone(),
                port_name: c.port_name.clone(),
                vlan_id: c.vlan_id,
                candidate_type: format!("{:?}", c.candidate_type),
                observation_count: c.observation_count,
                suppressed: c.suppressed,
                features,
                score,
            }
        })
        .collect();

    // Sort by score descending
    scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    scored
}

/// Select the winner from scored candidates.
///
/// Suppressed candidates cannot win. Returns (winner, runner_up_score).
pub fn choose_winner(scored: &[ScoredCandidate]) -> Option<(&ScoredCandidate, f64)> {
    let eligible: Vec<&ScoredCandidate> = scored
        .iter()
        .filter(|c| !c.suppressed)
        .collect();

    if eligible.is_empty() {
        return None;
    }

    let winner = eligible[0];
    let runner_up_score = eligible.get(1).map(|c| c.score).unwrap_or(0.0);

    Some((winner, runner_up_score))
}

/// Compute confidence from the margin between winner and runner-up.
/// `clamp((winner_score - runner_up_score) / 3.0, 0.0, 1.0)`
pub fn confidence_from_margin(winner_score: f64, runner_up_score: f64) -> f64 {
    ((winner_score - runner_up_score) / 3.0).clamp(0.0, 1.0)
}

/// Downstream preference: 1.0 if this candidate is the deepest edge-plausible,
/// 0.25 if the deepest but not clearly edge, 0.5 if ambiguous, 0.0 if a deeper
/// edge candidate exists.
fn compute_downstream_preference(
    candidate: &AttachmentCandidate,
    all_candidates: &[AttachmentCandidate],
    graph: &InfrastructureGraph,
    role_probs: &HashMap<(String, String), PortRoleProbability>,
) -> f64 {
    let my_depth = graph.depth_of(&candidate.device_id).unwrap_or(0);
    let my_key = (candidate.device_id.clone(), candidate.port_name.clone());
    let my_access = role_probs.get(&my_key)
        .map(|p| p.access_prob + p.wireless_prob)
        .unwrap_or(0.5);

    let mut deeper_edge_exists = false;
    let mut same_depth_edge_exists = false;

    for other in all_candidates {
        if other.device_id == candidate.device_id && other.port_name == candidate.port_name {
            continue;
        }
        if other.suppressed {
            continue;
        }

        let other_depth = graph.depth_of(&other.device_id).unwrap_or(0);
        let other_key = (other.device_id.clone(), other.port_name.clone());
        let other_access = role_probs.get(&other_key)
            .map(|p| p.access_prob + p.wireless_prob)
            .unwrap_or(0.5);

        if other_depth > my_depth && other_access > 0.3 {
            deeper_edge_exists = true;
        } else if other_depth == my_depth && other_access > 0.3 {
            same_depth_edge_exists = true;
        }
    }

    if deeper_edge_exists {
        0.0
    } else if my_access > 0.5 {
        1.0
    } else if same_depth_edge_exists {
        0.5
    } else {
        0.25
    }
}

/// Device class fit: matches endpoint type to likely attachment mode.
fn compute_device_class_fit(
    device_type: Option<&str>,
    role_probs: Option<&PortRoleProbability>,
) -> f64 {
    let access = role_probs.map(|p| p.access_prob).unwrap_or(0.5);
    let wireless = role_probs.map(|p| p.wireless_prob).unwrap_or(0.0);

    match device_type {
        Some("camera") | Some("printer") | Some("iot") => {
            // These devices are always wired to access ports
            access * 1.0 + wireless * 0.2
        }
        Some("phone") | Some("tablet") | Some("laptop") => {
            // These are typically wireless
            wireless * 1.0 + access * 0.5
        }
        Some("server") | Some("workstation") => {
            // Typically wired but can be anywhere
            access * 0.8 + wireless * 0.3
        }
        Some("switch") | Some("router") | Some("ap") => {
            // Infrastructure should never be an endpoint candidate
            0.1
        }
        _ => 0.5, // Unknown — neutral
    }
    .clamp(0.0, 1.0)
}

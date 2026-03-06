//! Candidate generation and pruning for MAC attachment inference.

use std::collections::{HashMap, HashSet};

use mikrotik_core::switch_store::{MacObservation, PortRoleProbability};
use serde::Serialize;

use super::graph::InfrastructureGraph;

/// The type of candidate attachment.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum CandidateType {
    WiredPort,
    WirelessParent,
    HumanOverride,
}

/// A candidate attachment point for a MAC address.
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentCandidate {
    pub mac: String,
    pub device_id: String,
    pub port_name: String,
    pub vlan_id: Option<u32>,
    pub candidate_type: CandidateType,
    pub observation_count: u32,
    pub suppressed: bool,
}

/// Generate candidates from recent observations for a MAC address.
///
/// Each unique (device_id, port_name) pair in the observation window
/// becomes a candidate. Additionally, wireless parent and human override
/// candidates may be added.
pub fn generate_candidates(
    mac: &str,
    observations: &[MacObservation],
    identity_vlan: Option<u32>,
    identity_device: Option<&str>,
    identity_port: Option<&str>,
    human_confirmed: bool,
    wireless_vlans: &HashSet<u32>,
) -> Vec<AttachmentCandidate> {
    let mut seen: HashMap<(String, String), (Option<u32>, u32)> = HashMap::new();

    for obs in observations {
        let key = (obs.device_id.clone(), obs.port_name.clone());
        let entry = seen.entry(key).or_insert((obs.vlan_id, 0));
        entry.1 += 1;
    }

    let mut candidates: Vec<AttachmentCandidate> = seen
        .into_iter()
        .map(|((device_id, port_name), (vlan_id, count))| AttachmentCandidate {
            mac: mac.to_string(),
            device_id,
            port_name,
            vlan_id,
            candidate_type: CandidateType::WiredPort,
            observation_count: count,
            suppressed: false,
        })
        .collect();

    // If identity VLAN is wireless, the actual attachment point might be
    // upstream of the WAP (which may not be a managed switch). Candidate
    // generation handles this by inheriting from the identity binding.
    if let Some(vlan) = identity_vlan {
        if wireless_vlans.contains(&vlan) {
            // Check if we already have a candidate matching the identity binding
            let already_present = identity_device
                .zip(identity_port)
                .map(|(dev, port)| {
                    candidates.iter().any(|c| c.device_id == dev && c.port_name == port)
                })
                .unwrap_or(true);

            if !already_present {
                if let (Some(dev), Some(port)) = (identity_device, identity_port) {
                    candidates.push(AttachmentCandidate {
                        mac: mac.to_string(),
                        device_id: dev.to_string(),
                        port_name: port.to_string(),
                        vlan_id: Some(vlan),
                        candidate_type: CandidateType::WirelessParent,
                        observation_count: 0,
                        suppressed: false,
                    });
                }
            }
        }
    }

    // Human override: always a candidate if confirmed
    if human_confirmed {
        if let (Some(dev), Some(port)) = (identity_device, identity_port) {
            let already_present = candidates.iter().any(|c| c.device_id == dev && c.port_name == port);
            if !already_present {
                candidates.push(AttachmentCandidate {
                    mac: mac.to_string(),
                    device_id: dev.to_string(),
                    port_name: port.to_string(),
                    vlan_id: identity_vlan,
                    candidate_type: CandidateType::HumanOverride,
                    observation_count: 0,
                    suppressed: false,
                });
            }
        }
    }

    candidates
}

/// Prune candidates using graph constraints and upstream suppression.
///
/// Two-layer filtering:
/// 1. Remove candidates that violate basic constraints (unknown devices).
/// 2. Upstream suppression: when a downstream edge-plausible candidate exists,
///    suppress ancestor transit candidates from winning.
pub fn prune_candidates(
    candidates: &mut Vec<AttachmentCandidate>,
    graph: &InfrastructureGraph,
    role_probs: &HashMap<(String, String), PortRoleProbability>,
) {
    // Layer 1: Remove candidates for unknown devices (not in graph)
    candidates.retain(|c| {
        c.candidate_type == CandidateType::HumanOverride || graph.nodes.contains_key(&c.device_id)
    });

    // Layer 2: Upstream suppression
    // For each pair (A, B): if B is descendant of A, and A is transit-like,
    // and B is edge-plausible, mark A as suppressed.
    let suppress_indices: Vec<usize> = (0..candidates.len())
        .filter(|&i| {
            if candidates[i].candidate_type == CandidateType::HumanOverride {
                return false;
            }
            let a_dev = &candidates[i].device_id;
            candidates.iter().enumerate().any(|(j, b)| {
                if i == j { return false; }
                let b_dev = &b.device_id;
                if !graph.is_descendant_of(b_dev, a_dev) { return false; }

                let a_key = (candidates[i].device_id.clone(), candidates[i].port_name.clone());
                let b_key = (b.device_id.clone(), b.port_name.clone());

                let a_transit = role_probs.get(&a_key)
                    .map(|p| p.trunk_prob > 0.4 || p.uplink_prob > 0.4)
                    .unwrap_or(false)
                    || graph.is_trunk_port(&candidates[i].device_id, &candidates[i].port_name);

                let b_edge = role_probs.get(&b_key)
                    .map(|p| p.access_prob > 0.3 || p.wireless_prob > 0.3)
                    .unwrap_or(false);

                a_transit && b_edge
            })
        })
        .collect();

    for idx in suppress_indices {
        candidates[idx].suppressed = true;
    }
}

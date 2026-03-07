//! Candidate generation and pruning for MAC attachment inference.

use std::collections::{HashMap, HashSet};

use mikrotik_core::switch_store::{MacObservation, PortRoleProbability};
use serde::Serialize;

use super::ApFeederMap;
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
    /// Why this candidate was suppressed (populated by `prune_candidates`).
    pub suppression_reason: Option<String>,
}

/// Device types that are clearly wired — never generate WAP candidates for these.
const WIRED_DEVICE_TYPES: &[&str] = &["camera", "printer", "server", "switch", "router"];

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
    ap_feeder_map: &ApFeederMap,
    device_type: Option<&str>,
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
            suppression_reason: None,
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
                        suppression_reason: None,
                    });
                }
            }
        }
    }

    // ── AP feeder → WirelessParent candidate generation ──────────────
    // For each WiredPort candidate on an AP feeder port, generate
    // WirelessParent candidates for the downstream WAPs — unless the
    // endpoint is clearly a wired device type.
    let is_clearly_wired = device_type
        .map(|dt| WIRED_DEVICE_TYPES.contains(&dt))
        .unwrap_or(false);

    if !is_clearly_wired {
        let mut wap_candidates: Vec<AttachmentCandidate> = Vec::new();
        for c in &candidates {
            if c.candidate_type != CandidateType::WiredPort {
                continue;
            }
            let fed = super::fed_waps(ap_feeder_map, &c.device_id, &c.port_name);
            for wap_id in fed {
                // Don't add if this WAP is already a candidate
                let already = candidates.iter().any(|existing| existing.device_id == *wap_id)
                    || wap_candidates.iter().any(|existing| existing.device_id == *wap_id);
                if !already {
                    wap_candidates.push(AttachmentCandidate {
                        mac: mac.to_string(),
                        device_id: wap_id.clone(),
                        port_name: String::new(), // WAPs don't have port-level resolution
                        vlan_id: c.vlan_id,
                        candidate_type: CandidateType::WirelessParent,
                        observation_count: c.observation_count,
                        suppressed: false,
                        suppression_reason: None,
                    });
                }
            }
        }
        candidates.extend(wap_candidates);
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
                    suppression_reason: None,
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
///
/// Each suppressed candidate records a `suppression_reason`.
pub fn prune_candidates(
    candidates: &mut Vec<AttachmentCandidate>,
    graph: &InfrastructureGraph,
    role_probs: &HashMap<(String, String), PortRoleProbability>,
) {
    // Layer 1: Remove candidates for unknown devices (not in graph)
    // WirelessParent candidates may reference WAPs not in the managed graph —
    // keep them since they're downstream by definition.
    let mut removed_devices: Vec<String> = Vec::new();
    candidates.retain(|c| {
        if c.candidate_type == CandidateType::HumanOverride
            || c.candidate_type == CandidateType::WirelessParent
            || graph.nodes.contains_key(&c.device_id)
        {
            true
        } else {
            removed_devices.push(c.device_id.clone());
            false
        }
    });

    // Layer 2: Upstream suppression
    // For each pair (A, B): if B is descendant of A, and A is transit-like,
    // and B is edge-plausible, mark A as suppressed.
    // WirelessParent candidates are downstream by definition — don't suppress them.
    let suppress_info: Vec<(usize, String)> = (0..candidates.len())
        .filter_map(|i| {
            if candidates[i].candidate_type == CandidateType::HumanOverride
                || candidates[i].candidate_type == CandidateType::WirelessParent
            {
                return None;
            }
            let a_dev = &candidates[i].device_id;
            for (j, b) in candidates.iter().enumerate() {
                if i == j { continue; }
                let b_dev = &b.device_id;
                if !graph.is_descendant_of(b_dev, a_dev) { continue; }

                let a_key = (candidates[i].device_id.clone(), candidates[i].port_name.clone());
                let b_key = (b.device_id.clone(), b.port_name.clone());

                let a_transit = role_probs.get(&a_key)
                    .map(|p| p.trunk_prob > 0.4 || p.uplink_prob > 0.4)
                    .unwrap_or(false)
                    || graph.is_trunk_port(&candidates[i].device_id, &candidates[i].port_name);

                let b_edge = role_probs.get(&b_key)
                    .map(|p| p.access_prob > 0.3 || p.wireless_prob > 0.3)
                    .unwrap_or(false)
                    || b.candidate_type == CandidateType::WirelessParent;

                if a_transit && b_edge {
                    let reason = format!(
                        "upstream_of_edge: {} has edge-plausible port",
                        b.device_id,
                    );
                    return Some((i, reason));
                }
            }
            None
        })
        .collect();

    for (idx, reason) in suppress_info {
        candidates[idx].suppressed = true;
        candidates[idx].suppression_reason = Some(reason);
    }
}

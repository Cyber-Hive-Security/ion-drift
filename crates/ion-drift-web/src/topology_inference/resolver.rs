//! Resolver — orchestrates the full inference pipeline per MAC address.
//!
//! For each active MAC: generate candidates → prune → score → update state.

use std::collections::{HashMap, HashSet};

use mikrotik_core::SwitchStore;
use mikrotik_core::switch_store::{AttachmentStateRow, MacObservation, PortRoleProbability};

use super::candidates;
use super::graph::InfrastructureGraph;
use super::scoring::{self, ScoredCandidate};
use super::state::{AttachmentState, AttachmentStateKind};

/// Result of resolving a single MAC's attachment.
#[derive(Debug)]
pub struct ResolvedAttachment {
    pub mac: String,
    pub winner: Option<ScoredCandidate>,
    pub confidence: f64,
    pub state: AttachmentState,
    pub binding_changed: bool,
    #[allow(dead_code)]
    pub all_candidates: Vec<ScoredCandidate>,
}

/// The inference mode (controlled by TOPOLOGY_INFERENCE_MODE env var).
#[derive(Debug, Clone, PartialEq)]
pub enum InferenceMode {
    /// Old binding logic only. New inference is completely disabled.
    Legacy,
    /// Both old and new run. New results are logged but not applied.
    Shadow,
    /// New inference replaces old binding logic.
    Active,
}

impl InferenceMode {
    pub fn from_env() -> Self {
        match std::env::var("TOPOLOGY_INFERENCE_MODE")
            .unwrap_or_else(|_| "legacy".to_string())
            .to_lowercase()
            .as_str()
        {
            "shadow" => Self::Shadow,
            "active" => Self::Active,
            _ => Self::Legacy,
        }
    }

    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Shadow => "shadow",
            Self::Active => "active",
        }
    }
}

/// Observation window (10 minutes).
const OBSERVATION_WINDOW_SECS: i64 = 600;

// ── Conversion between state machine and storage types ───────────

fn state_from_row(row: &AttachmentStateRow) -> AttachmentState {
    AttachmentState {
        mac_address: row.mac_address.clone(),
        state: AttachmentStateKind::from_str(&row.state),
        current_device_id: row.current_device_id.clone(),
        current_port_name: row.current_port_name.clone(),
        current_score: row.current_score,
        confidence: row.confidence,
        consecutive_wins: row.consecutive_wins,
        consecutive_losses: row.consecutive_losses,
        updated_at: row.updated_at,
    }
}

fn state_to_row(s: &AttachmentState) -> AttachmentStateRow {
    AttachmentStateRow {
        mac_address: s.mac_address.clone(),
        state: s.state.as_str().to_string(),
        current_device_id: s.current_device_id.clone(),
        current_port_name: s.current_port_name.clone(),
        current_score: s.current_score,
        confidence: s.confidence,
        consecutive_wins: s.consecutive_wins,
        consecutive_losses: s.consecutive_losses,
        updated_at: s.updated_at,
    }
}

/// Resolve attachment for a single MAC address.
///
/// This is the core pipeline: generate → prune → score → update state.
pub fn resolve_mac(
    mac: &str,
    observations: &[MacObservation],
    graph: &InfrastructureGraph,
    role_probs: &HashMap<(String, String), PortRoleProbability>,
    wireless_vlans: &HashSet<u32>,
    existing_state: Option<AttachmentState>,
    // Identity data from current binding
    identity_vlan: Option<u32>,
    identity_device: Option<&str>,
    identity_port: Option<&str>,
    human_confirmed: bool,
    device_type: Option<&str>,
    now_ts: i64,
) -> ResolvedAttachment {
    let mut state = existing_state.unwrap_or_else(|| AttachmentState::new(mac));

    // 1. Generate candidates
    let mut cands = candidates::generate_candidates(
        mac,
        observations,
        identity_vlan,
        identity_device,
        identity_port,
        human_confirmed,
        wireless_vlans,
    );

    if cands.is_empty() {
        return ResolvedAttachment {
            mac: mac.to_string(),
            winner: None,
            confidence: 0.0,
            state,
            binding_changed: false,
            all_candidates: Vec::new(),
        };
    }

    // 2. Prune candidates (upstream suppression)
    candidates::prune_candidates(&mut cands, graph, role_probs);

    // 3. Score candidates
    let scored = scoring::score_candidates(
        &cands,
        observations,
        role_probs,
        graph,
        identity_vlan,
        device_type,
        now_ts,
        OBSERVATION_WINDOW_SECS,
    );

    // 4. Choose winner
    let (winner, confidence) = match scoring::choose_winner(&scored) {
        Some((w, runner_up)) => {
            let conf = scoring::confidence_from_margin(w.score, runner_up);
            (Some(w.clone()), conf)
        }
        None => (None, 0.0),
    };

    // 5. Update state
    let binding_changed = if let Some(ref w) = winner {
        let is_wireless = identity_vlan
            .map(|v| wireless_vlans.contains(&v))
            .unwrap_or(false);

        state.update(
            &w.device_id,
            &w.port_name,
            w.score,
            confidence,
            is_wireless,
            now_ts,
        )
    } else {
        false
    };

    ResolvedAttachment {
        mac: mac.to_string(),
        winner,
        confidence,
        state,
        binding_changed,
        all_candidates: scored,
    }
}

/// Run the full inference pipeline for all active MACs.
///
/// Returns a vec of resolved attachments. In shadow mode, these are
/// logged but not applied to the identity store.
pub async fn run_inference_cycle(
    store: &SwitchStore,
    graph: &InfrastructureGraph,
    wireless_vlans: &HashSet<u32>,
    now_ts: i64,
) -> Vec<ResolvedAttachment> {
    let window_start = now_ts - OBSERVATION_WINDOW_SECS;

    // Load all recent observations
    let all_obs = match store.get_all_recent_observations(window_start).await {
        Ok(obs) => obs,
        Err(e) => {
            tracing::warn!("inference: failed to load observations: {e}");
            return Vec::new();
        }
    };

    if all_obs.is_empty() {
        return Vec::new();
    }

    // Group observations by MAC
    let mut obs_by_mac: HashMap<String, Vec<MacObservation>> = HashMap::new();
    for obs in all_obs {
        obs_by_mac.entry(obs.mac_address.clone()).or_default().push(obs);
    }

    // Load role probabilities
    let role_prob_vec = store.get_port_role_probabilities(None).await.unwrap_or_default();
    let role_probs: HashMap<(String, String), PortRoleProbability> = role_prob_vec
        .into_iter()
        .map(|p| ((p.device_id.clone(), p.port_name.clone()), p))
        .collect();

    // Load existing states (convert from storage rows to state machine objects)
    let existing_rows = store.get_all_attachment_states().await.unwrap_or_default();
    let state_map: HashMap<String, AttachmentState> = existing_rows
        .iter()
        .map(|r| (r.mac_address.clone(), state_from_row(r)))
        .collect();

    // Load identities for context
    let identities = store.get_network_identities().await.unwrap_or_default();
    let identity_map: HashMap<String, _> = identities
        .iter()
        .map(|i| (i.mac_address.to_uppercase(), i))
        .collect();

    let mut results = Vec::new();

    for (mac, observations) in &obs_by_mac {
        let identity = identity_map.get(mac.as_str());
        let identity_vlan = identity.and_then(|i| i.vlan_id);
        let identity_device = identity.and_then(|i| i.switch_device_id.as_deref());
        let identity_port = identity.and_then(|i| i.switch_port.as_deref());
        let human_confirmed = identity.map(|i| i.human_confirmed).unwrap_or(false);
        let device_type = identity.and_then(|i| i.device_type.as_deref());

        let existing_state = state_map.get(mac).cloned();

        let result = resolve_mac(
            mac,
            observations,
            graph,
            &role_probs,
            wireless_vlans,
            existing_state,
            identity_vlan,
            identity_device,
            identity_port,
            human_confirmed,
            device_type,
            now_ts,
        );

        results.push(result);
    }

    // Persist updated states (convert back to storage rows)
    for result in &results {
        let row = state_to_row(&result.state);
        if let Err(e) = store.upsert_attachment_state_row(&row).await {
            tracing::warn!(mac = %result.mac, "persist attachment state: {e}");
        }
    }

    results
}

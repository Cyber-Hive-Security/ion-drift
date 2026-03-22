//! Topology inference diagnostic API endpoints.

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, State};
use axum::response::{Json, Response};
use serde::Serialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;
use crate::topology_inference::canonicalize_port_name;
use crate::topology_inference::resolver::{
    self, InferenceMode, OBSERVATION_WINDOW_SECS,
};
use crate::topology_inference::scoring;

use super::internal_error;

// ── Response types ──────────────────────────────────────────────

#[derive(Serialize)]
pub struct InferenceStatus {
    mode: String,
    total_macs: usize,
    state_distribution: HashMap<String, usize>,
    avg_confidence: f64,
    divergence_count: usize,
    divergence_categories: HashMap<String, usize>,
    last_cycle_ts: i64,
}

#[derive(Serialize)]
struct CurrentBinding {
    device_id: String,
    port: String,
    source: String,
}

#[derive(Serialize)]
pub struct InferenceMacDetail {
    mac: String,
    state: ion_drift_storage::switch::AttachmentStateRow,
    current_binding: Option<CurrentBinding>,
    candidates: Vec<crate::topology_inference::scoring::ScoredCandidate>,
    explanation: Vec<String>,
}

#[derive(Serialize)]
pub struct ObservationStats {
    total_observations: usize,
    unique_macs: usize,
    observations_per_device: HashMap<String, usize>,
}

// ── Handlers ────────────────────────────────────────────────────

/// GET /api/network/inference/status — aggregate overview.
pub async fn inference_status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<InferenceStatus>, Response> {
    let store = &state.switch_store;

    let all_states = store
        .get_all_attachment_states()
        .await
        .map_err(|e| internal_error("inference status: attachment states", e))?;

    let total_macs = all_states.len();

    // State distribution
    let mut state_distribution: HashMap<String, usize> = HashMap::new();
    for s in &all_states {
        *state_distribution.entry(s.state.clone()).or_default() += 1;
    }

    // Average confidence
    let avg_confidence = if total_macs > 0 {
        all_states.iter().map(|s| s.confidence).sum::<f64>() / total_macs as f64
    } else {
        0.0
    };

    // Last cycle timestamp (most recent updated_at)
    let last_cycle_ts = all_states.iter().map(|s| s.updated_at).max().unwrap_or(0);

    // Divergence count: MACs where inference binding differs from identity binding
    let identities = store.get_network_identities().await.unwrap_or_else(|e| {
        tracing::warn!("inference: failed to load network identities: {e}");
        Vec::new()
    });
    let identity_map: HashMap<String, _> = identities
        .iter()
        .map(|i| (i.mac_address.to_uppercase(), i))
        .collect();

    // Determine router ID for divergence categorization
    let dm = state.device_manager.read().await;
    let router_id = dm
        .all_devices()
        .into_iter()
        .find(|d| d.record.is_primary)
        .map(|d| d.record.id.clone())
        .unwrap_or_default();
    drop(dm);

    // Build WAP identifier set for divergence categorization
    let infra_identities = store.get_infrastructure_identities().await.unwrap_or_else(|e| {
        tracing::warn!("inference: failed to load infrastructure identities: {e}");
        Vec::new()
    });
    let wap_identifiers = crate::topology_inference::build_wap_identifier_set(&infra_identities);

    let mut divergence_count = 0usize;
    let mut divergence_categories: HashMap<String, usize> = HashMap::new();
    for s in &all_states {
        if let (Some(inf_dev), Some(inf_port)) =
            (&s.current_device_id, &s.current_port_name)
        {
            if let Some(ident) = identity_map.get(&s.mac_address.to_uppercase()) {
                let old_dev = ident.switch_device_id.as_deref().unwrap_or("");
                let old_port = ident.switch_port.as_deref().unwrap_or("");
                if old_dev != inf_dev || old_port != inf_port {
                    divergence_count += 1;
                    let category = categorize_divergence(
                        inf_dev, inf_port,
                        old_dev, old_port,
                        &router_id,
                        &wap_identifiers,
                    );
                    *divergence_categories.entry(category.to_string()).or_default() += 1;
                }
            }
        }
    }

    let mode = InferenceMode::from_env();

    Ok(Json(InferenceStatus {
        mode: mode.as_str().to_string(),
        total_macs,
        state_distribution,
        avg_confidence,
        divergence_count,
        divergence_categories,
        last_cycle_ts,
    }))
}

/// GET /api/network/inference/mac/{mac} — per-MAC detail.
pub async fn inference_mac_detail(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> Result<Json<InferenceMacDetail>, Response> {
    let store = &state.switch_store;
    let mac_upper = mac.to_uppercase();

    // Load attachment state
    let att_state = store
        .get_attachment_state(&mac_upper)
        .await
        .map_err(|e| internal_error("inference mac: attachment state", e))?;

    let att_state = match att_state {
        Some(s) => s,
        None => {
            // Return empty detail for unknown MAC
            return Ok(Json(InferenceMacDetail {
                mac: mac_upper,
                state: ion_drift_storage::switch::AttachmentStateRow {
                    mac_address: mac.to_uppercase(),
                    state: "unknown".to_string(),
                    current_device_id: None,
                    current_port_name: None,
                    previous_device_id: None,
                    previous_port_name: None,
                    current_score: 0.0,
                    confidence: 0.0,
                    consecutive_wins: 0,
                    consecutive_losses: 0,
                    updated_at: 0,
                },
                current_binding: None,
                candidates: Vec::new(),
                explanation: Vec::new(),
            }));
        }
    };

    // Load current identity binding for comparison
    let identities = store.get_network_identities().await.unwrap_or_else(|e| {
        tracing::warn!("inference detail: failed to load network identities: {e}");
        Vec::new()
    });
    let current_binding = identities
        .iter()
        .find(|i| i.mac_address.eq_ignore_ascii_case(&mac_upper))
        .and_then(|i| {
            Some(CurrentBinding {
                device_id: i.switch_device_id.as_ref()?.clone(),
                port: i.switch_port.as_ref()?.clone(),
                source: i.switch_binding_source.clone(),
            })
        });

    let identity = identities
        .iter()
        .find(|i| i.mac_address.eq_ignore_ascii_case(&mac_upper));
    let identity_vlan = identity.and_then(|i| i.vlan_id);
    let identity_device = identity.and_then(|i| i.switch_device_id.as_deref());
    let identity_port = identity.and_then(|i| i.switch_port.as_deref());
    let human_confirmed = identity.map(|i| i.human_confirmed).unwrap_or(false);
    let device_type = identity.and_then(|i| i.device_type.as_deref());

    // Load recent observations for this MAC
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let window_start = now_ts - OBSERVATION_WINDOW_SECS;

    let all_obs = store
        .get_all_recent_observations(window_start)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("inference detail: failed to load observations: {e}");
            Vec::new()
        });
    let mac_obs: Vec<_> = all_obs
        .into_iter()
        .filter(|o| o.mac_address.eq_ignore_ascii_case(&mac_upper))
        .collect();

    // Build graph and role probs for scoring
    let role_prob_vec = store.get_port_role_probabilities(None).await.unwrap_or_else(|e| {
        tracing::warn!("inference detail: failed to load port role probabilities: {e}");
        Vec::new()
    });
    let role_probs: HashMap<_, _> = role_prob_vec
        .into_iter()
        .map(|p| ((p.device_id.clone(), p.port_name.clone()), p))
        .collect();

    // Build infrastructure graph
    let vlan_configs = store.get_vlan_configs().await.unwrap_or_else(|e| {
        tracing::warn!("inference detail: failed to load vlan configs: {e}");
        Vec::new()
    });
    let wireless_vlans: std::collections::HashSet<u32> = vlan_configs
        .iter()
        .filter(|v| v.media_type == "wireless" || v.media_type == "mixed")
        .map(|v| v.vlan_id)
        .collect();

    let dm = state.device_manager.read().await;
    let device_ids: Vec<String> = dm.all_devices().into_iter().map(|d| d.record.id.clone()).collect();
    let router_id = dm
        .all_devices()
        .into_iter()
        .find(|d| d.record.is_primary)
        .map(|d| d.record.id.clone())
        .unwrap_or_default();

    let all_devs = dm.all_devices();
    let resolution = crate::topology_inference::graph::DeviceResolutionMaps {
        identity_to_device: {
            let mut m = HashMap::new();
            for entry in &all_devs {
                m.insert(entry.record.name.to_lowercase(), entry.record.id.clone());
                m.insert(entry.record.id.to_lowercase(), entry.record.id.clone());
            }
            m
        },
        ip_to_device: {
            let mut m = HashMap::new();
            for entry in &all_devs {
                m.insert(entry.record.host.clone(), entry.record.id.clone());
            }
            m
        },
    };
    drop(dm);

    let neighbors = store.get_neighbors(None).await.unwrap_or_else(|e| {
        tracing::warn!("inference detail: failed to load neighbors: {e}");
        Vec::new()
    });
    let backbone_links = store.get_backbone_links().await.unwrap_or_else(|e| {
        tracing::warn!("inference detail: failed to load backbone links: {e}");
        Vec::new()
    });
    let port_roles = store.get_port_roles(None).await.unwrap_or_else(|e| {
        tracing::warn!("inference detail: failed to load port roles: {e}");
        Vec::new()
    });
    let port_role_tuples: Vec<(String, String, String)> = port_roles
        .iter()
        .map(|r| (r.device_id.clone(), r.port_name.clone(), r.role.clone()))
        .collect();

    let graph = crate::topology_inference::graph::InfrastructureGraph::build(
        &device_ids,
        &router_id,
        &neighbors,
        &backbone_links,
        &port_role_tuples,
        &resolution,
    );

    // Build AP feeder map for wireless attribution
    let infra_identities = store.get_infrastructure_identities().await.unwrap_or_default();
    let wap_ids = crate::topology_inference::build_wap_identifier_set(&infra_identities);
    let ap_feeder_map = crate::topology_inference::build_ap_feeder_map(&backbone_links, &wap_ids);

    // Run scoring pipeline (read-only)
    let candidates = resolver::score_mac_candidates(
        &mac_upper,
        &mac_obs,
        &graph,
        &role_probs,
        &wireless_vlans,
        &ap_feeder_map,
        identity_vlan,
        identity_device,
        identity_port,
        human_confirmed,
        device_type,
        now_ts,
    );

    // Generate explanation from winner
    let explanation = if let Some(winner) = scoring::choose_winner(&candidates) {
        let (w, runner_up) = winner;
        resolver::build_explanation(w, runner_up)
    } else {
        Vec::new()
    };

    Ok(Json(InferenceMacDetail {
        mac: mac_upper,
        state: att_state,
        current_binding,
        candidates,
        explanation,
    }))
}

/// GET /api/network/inference/observations — recent observation stats.
pub async fn observation_stats(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<ObservationStats>, Response> {
    let store = &state.switch_store;

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let window_start = now_ts - OBSERVATION_WINDOW_SECS;

    let all_obs = store
        .get_all_recent_observations(window_start)
        .await
        .map_err(|e| internal_error("inference observations", e))?;

    let total_observations = all_obs.len();

    let mut unique_macs = std::collections::HashSet::new();
    let mut per_device: HashMap<String, usize> = HashMap::new();

    for obs in &all_obs {
        unique_macs.insert(obs.mac_address.to_uppercase());
        *per_device.entry(obs.device_id.clone()).or_default() += 1;
    }

    Ok(Json(ObservationStats {
        total_observations,
        unique_macs: unique_macs.len(),
        observations_per_device: per_device,
    }))
}

/// GET /api/network/inference/states — all attachment state rows.
pub async fn all_attachment_states(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<ion_drift_storage::switch::AttachmentStateRow>>, Response> {
    let states = state
        .switch_store
        .get_all_attachment_states()
        .await
        .map_err(|e| internal_error("inference states", e))?;
    Ok(Json(states))
}

// ── Divergence categorization ───────────────────────────────────

/// Categorize a divergence between inference and legacy bindings.
fn categorize_divergence(
    inf_dev: &str,
    inf_port: &str,
    legacy_dev: &str,
    legacy_port: &str,
    router_id: &str,
    wap_identifiers: &HashSet<String>,
) -> &'static str {
    // Port alias only: same device, canonical ports match
    if inf_dev == legacy_dev && canonicalize_port_name(inf_port) == canonicalize_port_name(legacy_port) {
        return "port_alias_only";
    }

    // Router fallback: legacy is bound to router
    if legacy_dev == router_id {
        return "router_fallback";
    }

    // Wireless parent preferred: inference resolved to a WAP
    if wap_identifiers.contains(inf_dev) {
        return "wireless_parent_preferred";
    }

    // Same device, different port — inference found a better access port
    if inf_dev == legacy_dev {
        return "better_downstream_access";
    }

    // Different device entirely
    if inf_dev != legacy_dev {
        return "different_switch";
    }

    "other"
}

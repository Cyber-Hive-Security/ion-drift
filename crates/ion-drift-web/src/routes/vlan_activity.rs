use std::collections::HashMap;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Json, IntoResponse, Response};
use serde::Serialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

#[derive(Serialize)]
pub struct VlanActivityEntry {
    pub name: String,
    /// Router-authoritative VLAN ID resolved from vlan_config.interface_name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u32>,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

/// GET /api/traffic/vlan-activity
///
/// Returns the most recent VLAN throughput from the MetricsStore (populated
/// by the background poller every 60s). VLAN IDs are resolved from the
/// vlan_config table (synced from router), not parsed from interface names.
pub async fn vlan_activity(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<VlanActivityEntry>>, Response> {
    let latest = state
        .metrics_store
        .latest_vlan_metrics()
        .await
        .map_err(|e| {
            tracing::error!("vlan metrics query error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "failed to query VLAN metrics" })),
            )
                .into_response()
        })?;

    // Build interface_name → vlan_id map from vlan_config table
    let iface_to_vlan: HashMap<String, u32> = state
        .switch_store
        .get_vlan_configs()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|cfg| cfg.interface_name.map(|iface| (iface, cfg.vlan_id)))
        .collect();

    let entries: Vec<VlanActivityEntry> = latest
        .into_iter()
        .map(|(name, rx_bps, tx_bps)| {
            let vlan_id = iface_to_vlan.get(&name).copied();
            VlanActivityEntry {
                name,
                vlan_id,
                rx_bps,
                tx_bps,
            }
        })
        .collect();

    Ok(Json(entries))
}

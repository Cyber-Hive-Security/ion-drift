use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Json, IntoResponse, Response};
use serde::Serialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

#[derive(Serialize)]
pub struct VlanActivityEntry {
    pub name: String,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

/// GET /api/traffic/vlan-activity
///
/// Returns the most recent VLAN throughput from the MetricsStore (populated
/// by the background poller every 60s). No live router calls.
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

    let entries: Vec<VlanActivityEntry> = latest
        .into_iter()
        .map(|(name, rx_bps, tx_bps)| VlanActivityEntry {
            name,
            rx_bps,
            tx_bps,
        })
        .collect();

    Ok(Json(entries))
}

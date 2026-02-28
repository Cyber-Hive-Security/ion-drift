//! Network topology API routes.

use axum::extract::{Path, State};
use axum::response::{Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

use super::internal_error;

/// GET /api/network/topology — return cached topology.
pub async fn get_topology(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let cache = state.topology_cache.read().await;
    match &*cache {
        Some(topo) => Json(serde_json::to_value(topo).unwrap()),
        None => Json(serde_json::json!({
            "nodes": [],
            "edges": [],
            "vlan_groups": [],
            "computed_at": 0,
            "node_count": 0,
            "edge_count": 0,
            "infrastructure_count": 0,
            "endpoint_count": 0,
        })),
    }
}

/// POST /api/network/topology/refresh — force recompute.
pub async fn refresh_topology(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    match crate::topology::compute_topology(&state.switch_store, &state.device_manager).await {
        Ok(topo) => {
            let count = topo.node_count;
            let mut cache = state.topology_cache.write().await;
            *cache = Some(topo);
            Ok(Json(serde_json::json!({ "status": "ok", "nodes": count })))
        }
        Err(e) => Err(internal_error("topology refresh", e)),
    }
}

/// GET /api/network/topology/positions — all position records.
pub async fn get_positions(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let positions = state
        .switch_store
        .get_topology_positions()
        .await
        .map_err(|e| internal_error("topology positions", e))?;
    Ok(Json(serde_json::to_value(positions).unwrap()))
}

#[derive(Deserialize)]
pub struct PositionUpdate {
    pub x: f64,
    pub y: f64,
}

/// PUT /api/network/topology/positions/{nodeId} — human position override.
pub async fn update_position(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(body): Json<PositionUpdate>,
) -> Result<Json<serde_json::Value>, Response> {
    state
        .switch_store
        .set_topology_position(&node_id, body.x, body.y, "human")
        .await
        .map_err(|e| internal_error("set position", e))?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

/// DELETE /api/network/topology/positions/{nodeId} — reset to auto.
pub async fn reset_position(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let removed = state
        .switch_store
        .delete_topology_position(&node_id)
        .await
        .map_err(|e| internal_error("reset position", e))?;
    Ok(Json(serde_json::json!({ "removed": removed })))
}

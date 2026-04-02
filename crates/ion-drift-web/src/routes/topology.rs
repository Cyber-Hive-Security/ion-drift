//! Network topology API routes.

use axum::extract::{Path, State};
use axum::response::{Json, Response};
use serde::Deserialize;

use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

use super::internal_error;

/// GET /api/network/topology — return cached topology.
pub async fn get_topology(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let cache = state.topology_cache.read().await;
    match &*cache {
        Some(topo) => Json(serde_json::to_value(topo).unwrap_or_default()),
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
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let snapshot = {
        let snap_state = state.infrastructure_snapshot.read().await;
        match snap_state.best_available() {
            Some(s) => s.clone(),
            None => return Err(internal_error(
                "topology refresh",
                anyhow::anyhow!("no infrastructure snapshot available yet — wait for first correlation cycle"),
            )),
        }
    };
    match crate::topology::compute_topology(&state.switch_store, &state.behavior_store, &snapshot, &state.config.router.wan_interface).await {
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
    let json = serde_json::to_value(positions).map_err(|e| internal_error("serialize topology positions", e))?;
    Ok(Json(json))
}

#[derive(Deserialize)]
pub struct PositionUpdate {
    pub x: f64,
    pub y: f64,
}

/// PUT /api/network/topology/positions/{nodeId} — human position override.
pub async fn update_position(
    RequireAdmin(_session): RequireAdmin,
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

/// PUT /api/network/topology/positions — batch position update (e.g. sector drag).
#[derive(Deserialize)]
pub struct BatchPositionUpdate {
    pub positions: Vec<NodePositionEntry>,
}

#[derive(Deserialize)]
pub struct NodePositionEntry {
    pub node_id: String,
    pub x: f64,
    pub y: f64,
}

pub async fn batch_update_positions(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<BatchPositionUpdate>,
) -> Result<Json<serde_json::Value>, Response> {
    let entries: Vec<(String, f64, f64)> = body
        .positions
        .into_iter()
        .map(|p| (p.node_id, p.x, p.y))
        .collect();
    state
        .switch_store
        .set_topology_positions_batch(&entries, "human")
        .await
        .map_err(|e| internal_error("batch set positions", e))?;
    Ok(Json(serde_json::json!({ "status": "ok", "count": entries.len() })))
}

/// DELETE /api/network/topology/positions/{nodeId} — reset to auto.
pub async fn reset_position(
    RequireAdmin(_session): RequireAdmin,
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

/// DELETE /api/network/topology/reset-layout — clear ALL positions and sectors, recompute layout.
pub async fn reset_layout(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let positions = state
        .switch_store
        .delete_all_topology_positions()
        .await
        .map_err(|e| internal_error("reset all positions", e))?;
    let sectors = state
        .switch_store
        .delete_all_sector_positions()
        .await
        .map_err(|e| internal_error("reset all sectors", e))?;
    // Trigger recompute
    let snapshot = {
        let snap_state = state.infrastructure_snapshot.read().await;
        match snap_state.best_available() {
            Some(s) => s.clone(),
            None => return Err(internal_error(
                "topology reset",
                anyhow::anyhow!("no infrastructure snapshot available yet"),
            )),
        }
    };
    match crate::topology::compute_topology(&state.switch_store, &state.behavior_store, &snapshot, &state.config.router.wan_interface).await {
        Ok(topo) => {
            let mut cache = state.topology_cache.write().await;
            *cache = Some(topo);
        }
        Err(e) => tracing::error!("topology recompute after reset failed: {e}"),
    }
    Ok(Json(serde_json::json!({ "positions_cleared": positions, "sectors_cleared": sectors })))
}

// ── Sector positions ──────────────────────────────────────────

/// GET /api/network/topology/sectors — all sector position records.
pub async fn get_sectors(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let sectors = state
        .switch_store
        .get_sector_positions()
        .await
        .map_err(|e| internal_error("sector positions", e))?;
    Ok(Json(serde_json::to_value(sectors).unwrap_or_default()))
}

#[derive(Deserialize)]
pub struct SectorUpdate {
    pub x: f64,
    pub y: f64,
    pub width: Option<f64>,
    pub height: Option<f64>,
}

/// PUT /api/network/topology/sectors/{vlanId} — human sector position override.
pub async fn update_sector(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(vlan_id): Path<u32>,
    Json(body): Json<SectorUpdate>,
) -> Result<Json<serde_json::Value>, Response> {
    state
        .switch_store
        .set_sector_position(vlan_id, body.x, body.y, body.width, body.height, "human")
        .await
        .map_err(|e| internal_error("set sector position", e))?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

/// DELETE /api/network/topology/sectors/{vlanId} — reset sector to auto.
pub async fn reset_sector(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(vlan_id): Path<u32>,
) -> Result<Json<serde_json::Value>, Response> {
    let removed = state
        .switch_store
        .delete_sector_position(vlan_id)
        .await
        .map_err(|e| internal_error("reset sector", e))?;
    Ok(Json(serde_json::json!({ "removed": removed })))
}

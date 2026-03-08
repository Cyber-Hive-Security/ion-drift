//! Neighbor alias API routes — map or hide unregistered topology neighbors.

use axum::extract::{Path, State};
use axum::response::{Json, Response};
use serde::Deserialize;

use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

use super::internal_error;

/// GET /api/network/neighbor-aliases — list all neighbor aliases.
pub async fn list_neighbor_aliases(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let aliases = state
        .switch_store
        .get_neighbor_aliases()
        .await
        .map_err(|e| internal_error("neighbor aliases", e))?;
    Ok(Json(serde_json::to_value(aliases).unwrap()))
}

#[derive(Deserialize)]
pub struct CreateNeighborAliasRequest {
    pub match_type: String,
    pub match_value: String,
    pub action: String,
    pub target_device_id: Option<String>,
}

/// POST /api/network/neighbor-aliases — create a neighbor alias.
pub async fn create_neighbor_alias(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<CreateNeighborAliasRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    // Validate match_type
    if body.match_type != "mac" && body.match_type != "identity" {
        return Ok(Json(serde_json::json!({
            "error": "match_type must be 'mac' or 'identity'"
        })));
    }
    // Validate action
    if body.action != "alias" && body.action != "hide" {
        return Ok(Json(serde_json::json!({
            "error": "action must be 'alias' or 'hide'"
        })));
    }
    // alias action requires target_device_id
    if body.action == "alias" && body.target_device_id.is_none() {
        return Ok(Json(serde_json::json!({
            "error": "target_device_id is required when action is 'alias'"
        })));
    }

    let id = state
        .switch_store
        .create_neighbor_alias(
            &body.match_type,
            &body.match_value,
            &body.action,
            body.target_device_id.as_deref(),
        )
        .await
        .map_err(|e| internal_error("create neighbor alias", e))?;
    Ok(Json(serde_json::json!({ "id": id })))
}

/// DELETE /api/network/neighbor-aliases/{id} — delete a neighbor alias.
pub async fn delete_neighbor_alias(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, Response> {
    let removed = state
        .switch_store
        .delete_neighbor_alias(id)
        .await
        .map_err(|e| internal_error("delete neighbor alias", e))?;
    Ok(Json(serde_json::json!({ "removed": removed })))
}

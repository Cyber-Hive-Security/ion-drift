//! Backbone link API routes — manual switch-to-switch interconnects.

use axum::extract::{Path, State};
use axum::response::{Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

use super::internal_error;

/// GET /api/network/backbone-links — list all backbone links.
pub async fn list_backbone_links(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let links = state
        .switch_store
        .get_backbone_links()
        .await
        .map_err(|e| internal_error("backbone links", e))?;
    Ok(Json(serde_json::to_value(links).unwrap()))
}

#[derive(Deserialize)]
pub struct CreateBackboneLinkRequest {
    pub device_a: String,
    pub port_a: Option<String>,
    pub device_b: String,
    pub port_b: Option<String>,
    pub label: Option<String>,
    pub link_type: Option<String>,
    pub speed_mbps: Option<u32>,
}

/// POST /api/network/backbone-links — create a backbone link.
pub async fn create_backbone_link(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<CreateBackboneLinkRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    let id = state
        .switch_store
        .create_backbone_link(
            &body.device_a,
            body.port_a.as_deref(),
            &body.device_b,
            body.port_b.as_deref(),
            body.label.as_deref(),
            body.link_type.as_deref(),
            body.speed_mbps,
        )
        .await
        .map_err(|e| internal_error("create backbone link", e))?;
    Ok(Json(serde_json::json!({ "id": id })))
}

/// DELETE /api/network/backbone-links/{id} — delete a backbone link.
pub async fn delete_backbone_link(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, Response> {
    let removed = state
        .switch_store
        .delete_backbone_link(id)
        .await
        .map_err(|e| internal_error("delete backbone link", e))?;
    Ok(Json(serde_json::json!({ "removed": removed })))
}

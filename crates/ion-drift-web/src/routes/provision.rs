use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAdmin;
use crate::provision::{self, ProvisionConfig};
use crate::state::AppState;

use super::internal_error;

/// Helper: get a MikrotikClient for a device ID, requiring it to be a router.
async fn get_router_client(
    state: &AppState,
    id: &str,
) -> Result<mikrotik_core::MikrotikClient, Response> {
    let dm = state.device_manager.read().await;
    let entry = dm.get_device(id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "device not found" })),
        )
            .into_response()
    })?;

    if entry.record.device_type != "router" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "only router devices can be provisioned" })),
        )
            .into_response());
    }

    let client = entry.client.as_routeros().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "device is not a RouterOS client" })),
        )
            .into_response()
    })?;

    Ok(client.clone())
}

// ── POST /api/devices/{id}/provision/plan ──────────────────────────

pub async fn plan(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(config): Json<ProvisionConfig>,
) -> Result<Json<provision::ProvisionPlan>, Response> {
    let client = get_router_client(&state, &id).await?;

    let plan = provision::generate_plan(&client, &config)
        .await
        .map_err(|e| internal_error("generate provision plan", e))?;

    Ok(Json(plan))
}

// ── POST /api/devices/{id}/provision/apply ─────────────────────────

#[derive(Deserialize)]
pub struct ApplyRequest {
    pub config: ProvisionConfig,
    pub item_ids: Vec<String>,
}

pub async fn apply(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ApplyRequest>,
) -> Result<Json<provision::ApplyResult>, Response> {
    let client = get_router_client(&state, &id).await?;

    let result = provision::apply_plan(&client, &req.config, &req.item_ids)
        .await
        .map_err(|e| internal_error("apply provision plan", e))?;

    Ok(Json(result))
}

// ── GET /api/devices/{id}/provision/interfaces ─────────────────────

pub async fn interfaces(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let client = get_router_client(&state, &id).await?;

    let ifaces = client
        .interfaces()
        .await
        .map_err(|e| {
            tracing::error!("router API error: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "upstream router communication error" })),
            )
                .into_response()
        })?;

    let result: Vec<serde_json::Value> = ifaces
        .iter()
        .map(|iface| {
            serde_json::json!({
                "name": iface.name,
                "type": iface.iface_type,
                "running": iface.running,
                "comment": iface.comment,
            })
        })
        .collect();

    Ok(Json(serde_json::json!(result)))
}

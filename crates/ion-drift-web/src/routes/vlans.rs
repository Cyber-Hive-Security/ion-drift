//! VLAN configuration API routes.

use axum::extract::{Path, State};
use axum::response::{Json, Response};
use axum::http::StatusCode;
use ion_drift_storage::switch::VlanConfig;

use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

use super::internal_error;

/// GET /api/network/vlan-config — list all VLAN configs.
pub async fn list_vlan_configs(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let configs = state
        .switch_store
        .get_vlan_configs()
        .await
        .map_err(|e| internal_error("vlan configs", e))?;
    Ok(Json(serde_json::to_value(configs).unwrap_or_default()))
}

/// PUT /api/network/vlan-config/{vlan_id} — upsert a VLAN config.
pub async fn upsert_vlan_config(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(vlan_id): Path<u32>,
    Json(mut body): Json<VlanConfig>,
) -> Result<Json<serde_json::Value>, Response> {
    // Validate media_type
    if !["wired", "wireless", "mixed"].contains(&body.media_type.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "media_type must be one of: wired, wireless, mixed"
            })),
        )
            .into_response());
    }

    body.vlan_id = vlan_id;
    state
        .switch_store
        .upsert_vlan_config(&body)
        .await
        .map_err(|e| internal_error("upsert vlan config", e))?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Helper to convert (StatusCode, Json) into a Response.
trait IntoResponseHelper {
    fn into_response(self) -> Response;
}

impl IntoResponseHelper for (StatusCode, Json<serde_json::Value>) {
    fn into_response(self) -> Response {
        axum::response::IntoResponse::into_response(self)
    }
}

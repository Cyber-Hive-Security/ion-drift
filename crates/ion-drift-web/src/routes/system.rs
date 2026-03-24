use axum::extract::State;
use axum::response::{Json, Response};

use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;
use super::{api_error, internal_error};

pub async fn resources(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let res = state.mikrotik.system_resources().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(res).map_err(|e| internal_error("serialize system resources", e))?))
}

pub async fn identity(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let id = state.mikrotik.system_identity().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(id).map_err(|e| internal_error("serialize system identity", e))?))
}

pub async fn tasks(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let statuses = state.task_supervisor.status().await;
    Json(serde_json::json!({ "tasks": statuses }))
}

/// POST /api/system/restart — gracefully restart the server process.
/// Docker's restart policy will bring it back automatically.
pub async fn restart(
    RequireAdmin(_session): RequireAdmin,
) -> Json<serde_json::Value> {
    tracing::info!("admin-initiated restart requested");
    tokio::spawn(async {
        // Brief delay so the HTTP response reaches the client
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        tracing::info!("restarting process");
        std::process::exit(0);
    });
    Json(serde_json::json!({ "message": "restarting" }))
}

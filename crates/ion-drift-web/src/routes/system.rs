use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};

use crate::middleware::RequireAuth;
use crate::state::AppState;

pub async fn resources(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let res = state.mikrotik.system_resources().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(res).unwrap()))
}

pub async fn identity(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let id = state.mikrotik.system_identity().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(id).unwrap()))
}

fn api_error(e: mikrotik_core::MikrotikError) -> Response {
    tracing::error!("router API error: {e}");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}

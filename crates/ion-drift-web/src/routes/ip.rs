use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};

use crate::middleware::RequireAuth;
use crate::state::AppState;

pub async fn addresses(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let addrs = state.mikrotik.ip_addresses().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(addrs).unwrap()))
}

pub async fn routes(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let routes = state.mikrotik.ip_routes().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(routes).unwrap()))
}

pub async fn dhcp_leases(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let leases = state.mikrotik.dhcp_leases().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(leases).unwrap()))
}

fn api_error(e: mikrotik_core::MikrotikError) -> Response {
    tracing::error!("router API error: {e}");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}

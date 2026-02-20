use axum::extract::State;
use axum::response::{Json, Response};

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::api_error;

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

pub async fn pools(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let pools = state.mikrotik.ip_pools().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(pools).unwrap()))
}

pub async fn dhcp_servers(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let servers = state.mikrotik.dhcp_servers().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(servers).unwrap()))
}

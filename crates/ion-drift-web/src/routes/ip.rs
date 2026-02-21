use axum::extract::State;
use axum::response::{Json, Response};

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::{api_error, internal_error};

pub async fn addresses(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let addrs = state.mikrotik.ip_addresses().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(addrs).map_err(|e| internal_error("serialize ip addresses", e))?))
}

pub async fn routes(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let routes = state.mikrotik.ip_routes().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(routes).map_err(|e| internal_error("serialize ip routes", e))?))
}

pub async fn dhcp_leases(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let leases = state.mikrotik.dhcp_leases().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(leases).map_err(|e| internal_error("serialize dhcp leases", e))?))
}

pub async fn pools(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let pools = state.mikrotik.ip_pools().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(pools).map_err(|e| internal_error("serialize ip pools", e))?))
}

pub async fn dhcp_servers(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let servers = state.mikrotik.dhcp_servers().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(servers).map_err(|e| internal_error("serialize dhcp servers", e))?))
}

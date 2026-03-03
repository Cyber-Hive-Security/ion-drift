use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use mikrotik_core::resources::system::SystemResource;
use mikrotik_core::resources::interface::Interface;

use crate::device_manager::DeviceClient;
use crate::middleware::RequireAuth;
use crate::state::AppState;

use super::{api_error, internal_error};

// ── Query params ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SinceQuery {
    /// Unix timestamp — return data since this time. Defaults to 1 hour ago.
    pub since: Option<i64>,
}

fn default_since(since: Option<i64>) -> i64 {
    since.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 3600
    })
}

// ── GET /api/devices/{id}/resources ──────────────────────────────

pub async fn device_resources(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let dm = state.device_manager.read().await;
    let entry = dm.get_device(&id).ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "device not found" })),
        )
            .into_response()
    })?;
    let client = match &entry.client {
        DeviceClient::RouterOs(c) => c.clone(),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "system resources not available for this device type" })),
            )
                .into_response());
        }
    };
    drop(dm);

    let res: SystemResource = client.system_resources().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(res).unwrap()))
}

// ── GET /api/devices/{id}/interfaces ─────────────────────────────

pub async fn device_interfaces(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let dm = state.device_manager.read().await;
    let entry = dm.get_device(&id).ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "device not found" })),
        )
            .into_response()
    })?;
    let client = match &entry.client {
        DeviceClient::RouterOs(c) => c.clone(),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "interfaces not available for this device type" })),
            )
                .into_response());
        }
    };
    drop(dm);

    let interfaces: Vec<Interface> = client.interfaces().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(interfaces).unwrap()))
}

// ── GET /api/devices/{id}/ports ──────────────────────────────────

pub async fn device_ports(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<SinceQuery>,
) -> Result<Json<serde_json::Value>, Response> {
    let since = default_since(q.since);
    let data = state
        .switch_store
        .get_port_metrics(&id, since)
        .await
        .map_err(|e| internal_error("port metrics", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// ── GET /api/devices/{id}/mac-table ──────────────────────────────

pub async fn device_mac_table(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_mac_table(Some(&id))
        .await
        .map_err(|e| internal_error("mac table", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// ── GET /api/devices/{id}/neighbors ──────────────────────────────

pub async fn device_neighbors(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_neighbors(Some(&id))
        .await
        .map_err(|e| internal_error("neighbors", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// ── GET /api/devices/{id}/vlans ──────────────────────────────────

pub async fn device_vlans(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_vlan_membership(&id)
        .await
        .map_err(|e| internal_error("vlan membership", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// ── GET /api/devices/{id}/port-roles ─────────────────────────────

pub async fn device_port_roles(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_port_roles(Some(&id))
        .await
        .map_err(|e| internal_error("port roles", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// ── Correlation data (cross-device) ──────────────────────────────

// GET /api/network/identities

pub async fn network_identities(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_network_identities()
        .await
        .map_err(|e| internal_error("network identities", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// GET /api/network/mac-table

pub async fn network_mac_table(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_mac_table(None)
        .await
        .map_err(|e| internal_error("mac table", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// GET /api/network/neighbors

pub async fn network_neighbors(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_neighbors(None)
        .await
        .map_err(|e| internal_error("neighbors", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// GET /api/network/port-roles

pub async fn network_port_roles(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_port_roles(None)
        .await
        .map_err(|e| internal_error("port roles", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

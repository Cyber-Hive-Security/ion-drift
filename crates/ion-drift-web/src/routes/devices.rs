use std::path::PathBuf;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use mikrotik_core::{MikrotikClient, MikrotikConfig, SnmpClient, SwosClient};

use crate::device_manager::{DeviceClient, DeviceStatus, DeviceInfo};
use crate::middleware::{RequireAuth, RequireAdmin};
use crate::secrets::{NewDevice, UpdateDevice};
use crate::state::AppState;

use super::internal_error;

fn is_blocked_host(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (host, 0u16).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip();
            match ip {
                std::net::IpAddr::V4(v4) => {
                    if v4.is_loopback() || v4.is_link_local() || v4.is_broadcast()
                        || v4.octets()[0] == 0
                        || (v4.octets()[0] == 169 && v4.octets()[1] == 254) {
                        return true;
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    if v6.is_loopback() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn validate_ca_cert_path(path: &str) -> Result<(), Response> {
    if path.contains("..") || (!path.starts_with("/app/data/certs/") && !path.starts_with("/app/certs/")) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "ca_cert_path must be within /app/data/certs/ or /app/certs/" })),
        )
            .into_response());
    }
    Ok(())
}

// ── GET /api/devices ─────────────────────────────────────────────

pub async fn list_devices(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<DeviceInfo>>, Response> {
    let dm = state.device_manager.read().await;
    Ok(Json(dm.device_list()))
}

// ── GET /api/devices/{id} ────────────────────────────────────────

pub async fn get_device(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<DeviceInfo>, Response> {
    let dm = state.device_manager.read().await;
    let entry = dm.get_device(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "device not found" })),
        )
            .into_response()
    })?;
    Ok(Json(DeviceInfo {
        record: entry.record.clone(),
        status: entry.status.clone(),
    }))
}

// ── POST /api/devices ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateDeviceRequest {
    #[serde(flatten)]
    pub device: NewDevice,
    pub username: String,
    pub password: String,
    // SNMPv3 extras
    pub snmp_auth_protocol: Option<String>,
    pub snmp_priv_password: Option<String>,
    pub snmp_priv_protocol: Option<String>,
}

pub async fn create_device(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(req): Json<CreateDeviceRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "secrets manager not enabled" })),
        )
            .into_response()
    })?;

    // Input validation
    const VALID_DEVICE_TYPES: &[&str] = &["router", "switch", "snmp_switch", "swos_switch"];
    if !VALID_DEVICE_TYPES.contains(&req.device.device_type.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("invalid device_type: must be one of {:?}", VALID_DEVICE_TYPES) })),
        )
            .into_response());
    }
    if req.device.id.is_empty()
        || req.device.id.len() > 64
        || !req.device.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid id: 1-64 chars, alphanumeric/hyphen/underscore only" })),
        )
            .into_response());
    }
    if req.device.host.is_empty()
        || req.device.host.len() > 253
        || req.device.host.contains(char::is_whitespace)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid host: 1-253 chars, no whitespace" })),
        )
            .into_response());
    }
    if req.device.name.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid name: max 128 chars" })),
        )
            .into_response());
    }

    // SSRF protection: block connections to loopback, link-local, metadata IPs
    if is_blocked_host(&req.device.host) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "host resolves to a blocked address" })),
        )
            .into_response());
    }

    // Validate ca_cert_path if provided
    if let Some(ref path) = req.device.ca_cert_path {
        validate_ca_cert_path(path)?;
    }

    // Build client based on device type and test connection
    let (client, identity) = if req.device.device_type == "snmp_switch" {
        let snmp = if req.snmp_priv_password.is_some() || req.snmp_auth_protocol.is_some() {
            SnmpClient::new_v3(
                req.device.host.clone(),
                req.device.port,
                req.username.clone(),
                req.password.clone(),
                req.snmp_auth_protocol.clone().unwrap_or_else(|| "SHA".into()),
                req.snmp_priv_password.clone().unwrap_or_default(),
                req.snmp_priv_protocol.clone().unwrap_or_else(|| "AES128".into()),
            )
        } else {
            SnmpClient::new_v2c(
                req.device.host.clone(),
                req.device.port,
                req.password.clone(),
            )
        };
        let identity = snmp.test_connection().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("connection test failed: {e}") })),
            )
                .into_response()
        })?;
        (DeviceClient::Snmp(snmp), identity)
    } else if req.device.device_type == "swos_switch" {
        let swos = SwosClient::new(
            req.device.host.clone(),
            req.device.port,
            req.username.clone(),
            req.password.clone(),
        );
        let identity = swos.test_connection().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("connection test failed: {e}") })),
            )
                .into_response()
        })?;
        (DeviceClient::SwOs(swos), identity)
    } else {
        let ca_cert_path = req
            .device
            .ca_cert_path
            .as_deref()
            .or(state.config.router.ca_cert_path.as_deref())
            .map(PathBuf::from);

        let config = MikrotikConfig {
            host: req.device.host.clone(),
            port: req.device.port,
            tls: req.device.tls,
            ca_cert_path,
            username: req.username.clone(),
            password: req.password.clone(),
        };

        let routeros = MikrotikClient::new(config).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("failed to create client: {e}") })),
            )
                .into_response()
        })?;

        let identity = routeros.test_connection().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("connection test failed: {e}") })),
            )
                .into_response()
        })?;
        (DeviceClient::RouterOs(routeros), identity)
    };

    // Store in database
    let sm_read = sm.read().await;
    sm_read
        .add_device(&req.device, &req.username, &req.password)
        .await
        .map_err(|e| internal_error("add device", e))?;

    // Store SNMPv3 extras if provided
    sm_read
        .store_snmp_v3_secrets(
            &req.device.id,
            req.snmp_priv_password.as_deref(),
            req.snmp_auth_protocol.as_deref(),
            req.snmp_priv_protocol.as_deref(),
        )
        .await
        .map_err(|e| internal_error("store snmp v3 secrets", e))?;

    // Get the stored record back
    let record = sm_read
        .get_device(&req.device.id)
        .await
        .map_err(|e| internal_error("get device", e))?
        .ok_or_else(|| internal_error("get device", "device not found after insert"))?;
    drop(sm_read);

    // Add to device manager
    let mut dm = state.device_manager.write().await;
    dm.add_device(record, client);
    dm.set_status(
        &req.device.id,
        DeviceStatus::Online { identity: identity.clone() },
    );

    Ok(Json(serde_json::json!({
        "id": req.device.id,
        "identity": identity,
        "message": "device added successfully"
    })))
}

// ── PUT /api/devices/{id} ────────────────────────────────────────

pub async fn update_device(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(update): Json<UpdateDevice>,
) -> Result<Json<serde_json::Value>, Response> {
    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "secrets manager not enabled" })),
        )
            .into_response()
    })?;

    let sm_read = sm.read().await;
    sm_read
        .update_device(&id, &update)
        .await
        .map_err(|e| internal_error("update device", e))?;

    // Reload the record and update device manager
    let record = sm_read
        .get_device(&id)
        .await
        .map_err(|e| internal_error("get device", e))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "device not found" })),
            )
                .into_response()
        })?;
    drop(sm_read);

    let mut dm = state.device_manager.write().await;
    dm.update_record(&id, record);

    Ok(Json(serde_json::json!({
        "message": "device updated",
        "note": "restart server to apply client changes"
    })))
}

// ── DELETE /api/devices/{id} ─────────────────────────────────────

pub async fn delete_device(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    // Prevent deleting the primary router
    {
        let dm = state.device_manager.read().await;
        if let Some(entry) = dm.get_device(&id) {
            if entry.record.is_primary {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "error": "cannot delete primary router" })),
                )
                    .into_response());
            }
        } else {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "device not found" })),
            )
                .into_response());
        }
    }

    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "secrets manager not enabled" })),
        )
            .into_response()
    })?;

    // Remove from database
    let sm_read = sm.read().await;
    sm_read
        .remove_device(&id)
        .await
        .map_err(|e| internal_error("remove device", e))?;
    drop(sm_read);

    // Remove from device manager
    let mut dm = state.device_manager.write().await;
    dm.remove_device(&id);
    drop(dm);

    // Clean up switch store data
    if let Err(e) = state.switch_store.remove_device_data(&id).await {
        tracing::warn!(device = %id, "failed to clean up switch data: {e}");
    }

    Ok(Json(serde_json::json!({ "message": "device removed" })))
}

// ── POST /api/devices/{id}/test ──────────────────────────────────

pub async fn test_device(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let dm = state.device_manager.read().await;
    let entry = dm.get_device(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "device not found" })),
        )
            .into_response()
    })?;
    let client = entry.client.clone();
    drop(dm);

    match client.test_connection().await {
        Ok(identity) => {
            let mut dm = state.device_manager.write().await;
            dm.set_status(&id, DeviceStatus::Online { identity: identity.clone() });
            Ok(Json(serde_json::json!({
                "status": "online",
                "identity": identity
            })))
        }
        Err(e) => {
            let mut dm = state.device_manager.write().await;
            dm.set_status(&id, DeviceStatus::Offline { error: e.to_string() });
            Ok(Json(serde_json::json!({
                "status": "offline",
                "error": e.to_string()
            })))
        }
    }
}

// ── POST /api/devices/test ───────────────────────────────────────
// Test connectivity to an arbitrary host (before adding to registry)

#[derive(Deserialize)]
pub struct TestConnectionRequest {
    pub host: String,
    pub port: Option<u16>,
    pub tls: Option<bool>,
    pub ca_cert_path: Option<String>,
    pub device_type: Option<String>,
    pub username: String,
    pub password: String,
    // SNMPv3 extras
    pub snmp_auth_protocol: Option<String>,
    pub snmp_priv_password: Option<String>,
    pub snmp_priv_protocol: Option<String>,
}

pub async fn test_connection(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Json(req): Json<TestConnectionRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    // Input validation
    if req.host.is_empty() || req.host.len() > 253 || req.host.contains(char::is_whitespace) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid host: 1-253 chars, no whitespace" })),
        )
            .into_response());
    }

    // SSRF protection: block connections to loopback, link-local, metadata IPs
    if is_blocked_host(&req.host) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "host resolves to a blocked address" })),
        )
            .into_response());
    }

    // Validate ca_cert_path if provided
    if let Some(ref path) = req.ca_cert_path {
        validate_ca_cert_path(path)?;
    }

    let device_type = req.device_type.as_deref().unwrap_or("switch");

    if device_type == "snmp_switch" {
        let port = req.port.unwrap_or(161);
        let client = if req.snmp_priv_password.is_some() || req.snmp_auth_protocol.is_some() {
            SnmpClient::new_v3(
                req.host,
                port,
                req.username,
                req.password,
                req.snmp_auth_protocol.unwrap_or_else(|| "SHA".into()),
                req.snmp_priv_password.unwrap_or_default(),
                req.snmp_priv_protocol.unwrap_or_else(|| "AES128".into()),
            )
        } else {
            SnmpClient::new_v2c(req.host, port, req.password)
        };
        match client.test_connection().await {
            Ok(identity) => Ok(Json(serde_json::json!({
                "status": "online",
                "identity": identity
            }))),
            Err(e) => Ok(Json(serde_json::json!({
                "status": "offline",
                "error": e.to_string()
            }))),
        }
    } else if device_type == "swos_switch" {
        let client = SwosClient::new(
            req.host,
            req.port.unwrap_or(80),
            req.username,
            req.password,
        );
        match client.test_connection().await {
            Ok(identity) => Ok(Json(serde_json::json!({
                "status": "online",
                "identity": identity
            }))),
            Err(e) => Ok(Json(serde_json::json!({
                "status": "offline",
                "error": e.to_string()
            }))),
        }
    } else {
        let ca_cert_path = req
            .ca_cert_path
            .as_deref()
            .or(state.config.router.ca_cert_path.as_deref())
            .map(PathBuf::from);

        let config = MikrotikConfig {
            host: req.host,
            port: req.port.unwrap_or(443),
            tls: req.tls.unwrap_or(true),
            ca_cert_path,
            username: req.username,
            password: req.password,
        };

        let client = MikrotikClient::new(config).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("failed to create client: {e}") })),
            )
                .into_response()
        })?;

        match client.test_connection().await {
            Ok(identity) => Ok(Json(serde_json::json!({
                "status": "online",
                "identity": identity
            }))),
            Err(e) => Ok(Json(serde_json::json!({
                "status": "offline",
                "error": e.to_string()
            }))),
        }
    }
}

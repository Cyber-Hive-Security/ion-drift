use std::path::PathBuf;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use secrecy::ExposeSecret;
use serde::Deserialize;

use mikrotik_core::{MikrotikClient, MikrotikConfig, SecretString, SnmpClient, SwosClient};

use crate::device_manager::{DeviceClient, DeviceInfo, DeviceStatus};
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::secrets::{NewDevice, SecretsManager, UpdateDevice};
use crate::state::AppState;

use super::internal_error;

fn is_blocked_host(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (host, 0u16).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip();
            match ip {
                std::net::IpAddr::V4(v4) => {
                    if v4.is_loopback()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.octets()[0] == 0
                        || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
                    {
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

fn bad_request(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

fn validate_ca_cert_path(path: &str) -> Result<(), Response> {
    if path.contains("..")
        || (!path.starts_with("/app/data/certs/") && !path.starts_with("/app/certs/"))
    {
        return Err(bad_request(
            "ca_cert_path must be within /app/data/certs/ or /app/certs/",
        ));
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<(), Response> {
    if host.is_empty() || host.len() > 253 || host.contains(char::is_whitespace) {
        return Err(bad_request("invalid host: 1-253 chars, no whitespace"));
    }
    if is_blocked_host(host) {
        return Err(bad_request("host resolves to a blocked address"));
    }
    Ok(())
}

/// Validate optional host and ca_cert_path fields on an update request.
fn validate_device_update(update: &UpdateDevice) -> Result<(), Response> {
    if let Some(ref host) = update.host {
        validate_host(host)?;
    }
    if let Some(ref path) = update.ca_cert_path {
        validate_ca_cert_path(path)?;
    }
    Ok(())
}

fn requires_primary_restart(update: &UpdateDevice) -> bool {
    update.host.is_some()
        || update.port.is_some()
        || update.tls.is_some()
        || update.ca_cert_path.is_some()
        || update.username.is_some()
        || update.password.is_some()
}

async fn build_runtime_client(
    state: &AppState,
    secrets: &SecretsManager,
    record: &crate::secrets::DeviceRecord,
) -> Result<DeviceClient, Response> {
    let creds = secrets
        .get_device_credentials(&record.id)
        .await
        .map_err(|e| internal_error("get device credentials", e))?
        .ok_or_else(|| bad_request("device credentials are missing"))?;
    let (username, password) = creds;

    if record.device_type == "snmp_switch" {
        let (priv_pw, auth_proto, priv_proto) = secrets
            .get_snmp_v3_params(&record.id)
            .await
            .map_err(|e| internal_error("get snmp v3 params", e))?;
        let client = if priv_pw.is_some() || auth_proto.is_some() {
            SnmpClient::new_v3(
                record.host.clone(),
                record.port,
                username,
                password.expose_secret().to_string(),
                auth_proto.unwrap_or_else(|| "SHA".into()),
                priv_pw.unwrap_or_default(),
                priv_proto.unwrap_or_else(|| "AES128".into()),
            )
        } else {
            SnmpClient::new_v2c(
                record.host.clone(),
                record.port,
                password.expose_secret().to_string(),
            )
        };
        return Ok(DeviceClient::Snmp(client));
    }

    if record.device_type == "swos_switch" {
        let client = SwosClient::new(
            record.host.clone(),
            record.port,
            username,
            password.expose_secret().to_string(),
        )
        .map_err(|e| bad_request(&format!("failed to create SwOS client: {e}")))?;
        return Ok(DeviceClient::SwOs(client));
    }

    let ca_cert_path = record
        .ca_cert_path
        .as_deref()
        .or(state.config.router.ca_cert_path.as_deref())
        .map(PathBuf::from);

    let config = MikrotikConfig {
        host: record.host.clone(),
        port: record.port,
        tls: record.tls,
        ca_cert_path,
        username,
        password,
    };

    let client = MikrotikClient::new(config)
        .map_err(|e| bad_request(&format!("failed to create client: {e}")))?;
    Ok(DeviceClient::RouterOs(client))
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
    if let Some(entry) = dm.get_device(&id) {
        return Ok(Json(DeviceInfo {
            record: entry.record.clone(),
            status: entry.status.clone(),
            limitations: entry.limitations.clone(),
        }));
    }
    if let Some(record) = dm.get_disabled_device(&id) {
        return Ok(Json(DeviceInfo {
            record: record.clone(),
            status: DeviceStatus::Offline {
                error: "device disabled".into(),
            },
            limitations: Vec::new(),
        }));
    }
    Err((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "device not found" })),
    )
        .into_response())
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

    // Enforce single primary router
    if req.device.device_type == "router" && req.device.is_primary {
        let dm = state.device_manager.read().await;
        let primary_exists = dm
            .all_devices()
            .iter()
            .any(|d| d.record.is_primary && d.record.device_type == "router");
        drop(dm);
        if primary_exists {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "a primary router is already configured",
                    "code": "primary_exists"
                })),
            )
                .into_response());
        }
    }

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
        || !req
            .device
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid id: 1-64 chars, alphanumeric/hyphen/underscore only" })),
        )
            .into_response());
    }
    validate_host(&req.device.host)?;
    if req.device.name.len() > 128 {
        return Err(bad_request("invalid name: max 128 chars"));
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
                req.snmp_auth_protocol
                    .clone()
                    .unwrap_or_else(|| "SHA".into()),
                req.snmp_priv_password.clone().unwrap_or_default(),
                req.snmp_priv_protocol
                    .clone()
                    .unwrap_or_else(|| "AES128".into()),
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
        )
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("failed to create SwOS client: {e}") })),
            )
                .into_response()
        })?;
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
            password: SecretString::from(req.password.clone()),
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

    // Store SNMPv3 extras if provided, resolving defaults so they are persisted
    let resolved_priv_proto = if req.snmp_priv_password.is_some() || req.snmp_auth_protocol.is_some() {
        Some(req.snmp_priv_protocol.as_deref().unwrap_or("AES128").to_string())
    } else {
        req.snmp_priv_protocol.clone()
    };
    sm_read
        .store_snmp_v3_secrets(
            &req.device.id,
            req.snmp_priv_password.as_deref(),
            req.snmp_auth_protocol.as_deref(),
            resolved_priv_proto.as_deref(),
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
        DeviceStatus::Online {
            identity: identity.clone(),
        },
    );

    // Start the poller for this device immediately (no server restart needed)
    if let Some(entry) = dm.get_device(&req.device.id) {
        if entry.record.enabled {
            let mut registry = state.poller_registry.write().await;
            registry.start_poller(
                entry,
                state.device_manager.clone(),
                state.switch_store.clone(),
            );
        }
    }

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

    // Validate host (SSRF) and ca_cert_path (path traversal) before persisting
    validate_device_update(&update)?;

    let needs_restart = {
        let dm = state.device_manager.read().await;
        dm.get_device(&id)
            .map(|entry| entry.record.is_primary && requires_primary_restart(&update))
            .unwrap_or(false)
    };

    // Always save — even if a restart is needed, persist the new credentials
    // so they take effect on next startup.
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
    let client = build_runtime_client(&state, &sm_read, &record).await?;
    drop(sm_read);

    if !needs_restart {
        let mut dm = state.device_manager.write().await;
        dm.update_runtime_device(&id, record, client);
    }

    // Restart the poller with updated configuration, handling enabled/disabled transitions
    {
        let dm = state.device_manager.read().await;
        let mut registry = state.poller_registry.write().await;
        if let Some(entry) = dm.get_device(&id) {
            if !entry.record.enabled {
                registry.stop_poller(&id);
            } else {
                // Always (re)start poller for enabled devices — handles disabled→enabled transition
                registry.start_poller(
                    entry,
                    state.device_manager.clone(),
                    state.switch_store.clone(),
                );
            }
        } else {
            // Device moved to disabled map — stop any existing poller
            registry.stop_poller(&id);
        }
    }

    if needs_restart {
        Ok(Json(serde_json::json!({
            "message": "device updated — restart the container to apply primary router changes",
            "restart_required": true
        })))
    } else {
        Ok(Json(serde_json::json!({
            "message": "device updated"
        })))
    }
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

    // Stop the poller for this device
    {
        let mut registry = state.poller_registry.write().await;
        registry.stop_poller(&id);
    }

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
    RequireAdmin(_session): RequireAdmin,
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
            dm.set_status(
                &id,
                DeviceStatus::Online {
                    identity: identity.clone(),
                },
            );
            Ok(Json(serde_json::json!({
                "status": "online",
                "identity": identity
            })))
        }
        Err(e) => {
            let mut dm = state.device_manager.write().await;
            dm.set_status(
                &id,
                DeviceStatus::Offline {
                    error: e.to_string(),
                },
            );
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
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(req): Json<TestConnectionRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    // Input validation
    validate_host(&req.host)?;

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
        let client = SwosClient::new(req.host, req.port.unwrap_or(80), req.username, req.password)
            .map_err(|e| {
                (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("failed to create SwOS client: {e}") })),
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
            password: SecretString::from(req.password),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_blocks_loopback() {
        assert!(is_blocked_host("127.0.0.1"));
        assert!(is_blocked_host("127.0.0.2"));
    }

    #[test]
    fn ssrf_blocks_link_local() {
        assert!(is_blocked_host("169.254.169.254")); // AWS metadata
        assert!(is_blocked_host("169.254.1.1"));
    }

    #[test]
    fn ssrf_blocks_zero_prefix() {
        assert!(is_blocked_host("0.0.0.0"));
    }

    #[test]
    fn ssrf_allows_private_rfc1918() {
        // Private IPs are allowed — this tool is for managing LAN devices
        assert!(!is_blocked_host("10.0.0.1"));
        assert!(!is_blocked_host("192.168.1.1"));
        assert!(!is_blocked_host("172.16.0.1"));
    }

    #[test]
    fn ssrf_allows_public_ip() {
        assert!(!is_blocked_host("8.8.8.8"));
    }

    #[test]
    fn ssrf_blocks_ipv6_loopback() {
        assert!(is_blocked_host("::1"));
    }

    #[test]
    fn ca_cert_path_rejects_traversal() {
        assert!(validate_ca_cert_path("../../etc/passwd").is_err());
        assert!(validate_ca_cert_path("/etc/shadow").is_err());
        assert!(validate_ca_cert_path("/app/data/certs/../../../etc/passwd").is_err());
    }

    #[test]
    fn ca_cert_path_accepts_valid() {
        assert!(validate_ca_cert_path("/app/data/certs/ca.pem").is_ok());
        assert!(validate_ca_cert_path("/app/certs/custom-ca.crt").is_ok());
    }
}

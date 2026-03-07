use std::path::PathBuf;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use secrecy::ExposeSecret;
use serde::Deserialize;

use mikrotik_core::{MikrotikClient, MikrotikConfig};

use crate::device_manager::{DeviceStatus, DeviceInfo};
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::secrets::{NewDevice, UpdateDevice};
use crate::state::AppState;

use super::internal_error;

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

    // Build client and test connection
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

    let client = MikrotikClient::new(config).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("failed to create client: {e}") })),
        )
            .into_response()
    })?;

    let identity = client.test_connection().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("connection test failed: {e}") })),
        )
            .into_response()
    })?;

    // Store in database
    let sm_read = sm.read().await;
    sm_read
        .add_device(&req.device, &req.username, &req.password)
        .await
        .map_err(|e| internal_error("add device", e))?;

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
    pub username: String,
    pub password: String,
}

pub async fn test_connection(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(req): Json<TestConnectionRequest>,
) -> Result<Json<serde_json::Value>, Response> {
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

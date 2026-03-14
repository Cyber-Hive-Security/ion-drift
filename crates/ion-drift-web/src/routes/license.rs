use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use crate::license;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

use super::internal_error;

/// GET /api/license — Returns current license status.
pub async fn get_license(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Json<license::LicenseMode> {
    let mode = license::determine_license_mode(
        state
            .secrets_manager
            .as_ref()
            .map(|sm| sm.as_ref() as &tokio::sync::RwLock<_>),
    )
    .await;
    Json(mode)
}

#[derive(Deserialize)]
pub struct SubmitKeyRequest {
    pub key: String,
}

/// POST /api/license/key — Submit a commercial license key.
pub async fn submit_license_key(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(req): Json<SubmitKeyRequest>,
) -> Result<Json<license::LicenseMode>, Response> {
    // Validate the key first
    let payload = license::validate_license_key(&req.key).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response()
    })?;

    // Store the valid key
    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "secrets manager not available" })),
        )
            .into_response()
    })?;

    let sm = sm.read().await;
    sm.encrypt_secret("license_key", &req.key)
        .await
        .map_err(|e| internal_error("store license key", e))?;

    tracing::info!(
        licensee = %payload.licensee,
        tier = %payload.tier,
        expires = %payload.expires,
        "commercial license key activated"
    );

    Ok(Json(license::LicenseMode::Licensed {
        licensee: payload.licensee,
        tier: payload.tier,
        expires: payload.expires,
        device_limit: payload.device_limit,
    }))
}

/// POST /api/license/acknowledge — Acknowledge personal home use.
pub async fn acknowledge_license(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<license::LicenseMode>, Response> {
    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "secrets manager not available" })),
        )
            .into_response()
    })?;

    let sm = sm.read().await;
    sm.encrypt_secret("license_acknowledged", "true")
        .await
        .map_err(|e| internal_error("store license acknowledgment", e))?;

    tracing::info!("license acknowledged as personal home use");

    Ok(Json(license::LicenseMode::Community {
        acknowledged: true,
    }))
}

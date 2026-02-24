use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use crate::secrets;
use crate::state::AppState;

use super::internal_error;

// ── GET /api/settings/secrets ────────────────────────────────────

#[derive(Serialize)]
pub struct SecretsStatusResponse {
    secrets: Vec<secrets::SecretStatus>,
    key_fingerprint: String,
}

pub async fn secrets_status(State(state): State<AppState>) -> Result<Json<SecretsStatusResponse>, Response> {
    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "secrets manager not enabled (no bootstrap configured)" })),
        )
            .into_response()
    })?;

    let sm = sm.read().await;
    let statuses = sm
        .secret_status()
        .await
        .map_err(|e| internal_error("secrets status", e))?;
    let fingerprint = sm.fingerprint().to_string();

    Ok(Json(SecretsStatusResponse {
        secrets: statuses,
        key_fingerprint: fingerprint,
    }))
}

// ── PUT /api/settings/secrets ────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateSecretsRequest {
    pub router_username: Option<String>,
    pub router_password: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub certwarden_cert_api_key: Option<String>,
    pub certwarden_key_api_key: Option<String>,
}

#[derive(Serialize)]
pub struct UpdateSecretsResponse {
    updated: Vec<String>,
}

pub async fn update_secrets(
    State(state): State<AppState>,
    Json(req): Json<UpdateSecretsRequest>,
) -> Result<Json<UpdateSecretsResponse>, Response> {
    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "secrets manager not enabled" })),
        )
            .into_response()
    })?;

    let sm = sm.read().await;
    let mut updated = Vec::new();

    if let Some(ref username) = req.router_username {
        if !username.trim().is_empty() {
            sm.encrypt_secret(secrets::SECRET_ROUTER_USERNAME, username.trim())
                .await
                .map_err(|e| internal_error("encrypt router_username", e))?;
            updated.push(secrets::SECRET_ROUTER_USERNAME.to_string());
        }
    }

    if let Some(ref password) = req.router_password {
        if !password.is_empty() {
            sm.encrypt_secret(secrets::SECRET_ROUTER_PASSWORD, password)
                .await
                .map_err(|e| internal_error("encrypt router_password", e))?;
            updated.push(secrets::SECRET_ROUTER_PASSWORD.to_string());
        }
    }

    if let Some(ref secret) = req.oidc_client_secret {
        if !secret.is_empty() {
            sm.encrypt_secret(secrets::SECRET_OIDC_CLIENT_SECRET, secret)
                .await
                .map_err(|e| internal_error("encrypt oidc_client_secret", e))?;
            updated.push(secrets::SECRET_OIDC_CLIENT_SECRET.to_string());
        }
    }

    if let Some(ref key) = req.certwarden_cert_api_key {
        if !key.is_empty() {
            sm.encrypt_secret(secrets::SECRET_CW_CERT_API_KEY, key)
                .await
                .map_err(|e| internal_error("encrypt certwarden_cert_api_key", e))?;
            updated.push(secrets::SECRET_CW_CERT_API_KEY.to_string());
        }
    }

    if let Some(ref key) = req.certwarden_key_api_key {
        if !key.is_empty() {
            sm.encrypt_secret(secrets::SECRET_CW_KEY_API_KEY, key)
                .await
                .map_err(|e| internal_error("encrypt certwarden_key_api_key", e))?;
            updated.push(secrets::SECRET_CW_KEY_API_KEY.to_string());
        }
    }

    if !updated.is_empty() {
        tracing::info!(secrets = ?updated, "secrets updated via settings API");
    }

    Ok(Json(UpdateSecretsResponse { updated }))
}

// ── POST /api/settings/secrets/session/regenerate ────────────────

#[derive(Serialize)]
pub struct RegenerateSessionResponse {
    status: String,
}

pub async fn regenerate_session(
    State(state): State<AppState>,
) -> Result<Json<RegenerateSessionResponse>, Response> {
    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "secrets manager not enabled" })),
        )
            .into_response()
    })?;

    // Generate new session secret
    let session_bytes: [u8; 32] = rand::random();
    let new_secret = hex::encode(session_bytes);

    let sm = sm.read().await;
    sm.encrypt_secret(secrets::SECRET_SESSION_SECRET, &new_secret)
        .await
        .map_err(|e| internal_error("regenerate session secret", e))?;

    // Clear all existing sessions to force re-authentication
    state.sessions.clear_all();

    tracing::info!("session secret regenerated, all sessions invalidated");

    Ok(Json(RegenerateSessionResponse {
        status: "regenerated".to_string(),
    }))
}

// ── GET /api/settings/encryption ────────────────────────────────

#[derive(Serialize)]
pub struct EncryptionStatusResponse {
    key_fingerprint: String,
    source: String,
    all_secrets_current: bool,
}

pub async fn encryption_status(State(state): State<AppState>) -> Result<Json<EncryptionStatusResponse>, Response> {
    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "secrets manager not enabled" })),
        )
            .into_response()
    })?;

    let sm = sm.read().await;
    let statuses = sm
        .secret_status()
        .await
        .map_err(|e| internal_error("encryption status", e))?;

    let all_current = statuses.iter().all(|s| s.key_current);
    let fingerprint = sm.fingerprint().to_string();

    Ok(Json(EncryptionStatusResponse {
        key_fingerprint: fingerprint,
        source: "keycloak_mtls".to_string(),
        all_secrets_current: all_current,
    }))
}

// ── GET /api/settings/cert ──────────────────────────────────────

#[derive(Serialize)]
pub struct CertStatusResponse {
    subject_cn: String,
    issuer_cn: String,
    not_before: i64,
    not_after: i64,
    seconds_until_expiry: i64,
    serial: String,
    auto_renewal_enabled: bool,
    renewal_threshold_days: u32,
    check_interval_hours: u32,
}

pub async fn cert_status(State(state): State<AppState>) -> Result<Json<CertStatusResponse>, Response> {
    let cert_path = &state.config.tls.client_cert;

    let status = crate::certwarden::check_cert_status(cert_path)
        .map_err(|e| internal_error("cert status", e))?;

    let cw = state.config.certwarden.resolve();
    let (auto_renewal, threshold, interval) = match cw {
        Some(ref c) => (true, c.renewal_threshold_days, c.check_interval_hours),
        None => (false, 0, 0),
    };

    Ok(Json(CertStatusResponse {
        subject_cn: status.subject_cn,
        issuer_cn: status.issuer_cn,
        not_before: status.not_before,
        not_after: status.not_after,
        seconds_until_expiry: status.seconds_until_expiry,
        serial: status.serial,
        auto_renewal_enabled: auto_renewal,
        renewal_threshold_days: threshold,
        check_interval_hours: interval,
    }))
}

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
            Json(serde_json::json!({ "error": "secrets manager not enabled (no tls.key_path configured)" })),
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

// ── GET /api/settings/tls ────────────────────────────────────────

#[derive(Serialize)]
pub struct TlsStatusResponse {
    key_fingerprint: String,
    key_path: String,
    all_secrets_current: bool,
    previous_key_path: Option<String>,
}

pub async fn tls_status(State(state): State<AppState>) -> Result<Json<TlsStatusResponse>, Response> {
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
        .map_err(|e| internal_error("tls status", e))?;

    let all_current = statuses.iter().all(|s| s.key_current);
    let fingerprint = sm.fingerprint().to_string();

    let key_path = state
        .config
        .tls
        .key_path
        .clone()
        .unwrap_or_default();
    let previous_key_path = state.config.tls.previous_key_path.clone();

    Ok(Json(TlsStatusResponse {
        key_fingerprint: fingerprint,
        key_path,
        all_secrets_current: all_current,
        previous_key_path,
    }))
}

use std::path::PathBuf;

use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use secrecy::ExposeSecret;

use crate::middleware::{RequireAdmin, RequireAuth};
use crate::secrets;
use crate::state::AppState;

use super::internal_error;

// ── GET /api/settings/map-config ────────────────────────────────

#[derive(Serialize)]
pub struct MapConfigResponse {
    /// Home longitude, if configured.
    pub home_lon: Option<f64>,
    /// Home latitude, if configured.
    pub home_lat: Option<f64>,
    /// Home country ISO 3166-1 alpha-2 code, if configured.
    pub home_country: Option<String>,
    /// Country codes highlighted for monitoring (ISO 3166-1 alpha-2 codes).
    pub monitored_regions: Vec<String>,
}

pub async fn map_config(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Json<MapConfigResponse> {
    Json(MapConfigResponse {
        home_lon: state.config.server.home_lon,
        home_lat: state.config.server.home_lat,
        home_country: state.config.server.home_country.clone(),
        monitored_regions: state.geo_cache.get_monitored_regions(),
    })
}

// ── GET/PUT /api/settings/monitored-regions ──────────────────────

#[derive(Deserialize)]
pub struct MonitoredRegionsRequest {
    pub regions: Vec<String>,
}

pub async fn get_monitored_regions(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Json<Vec<String>> {
    Json(state.geo_cache.get_monitored_regions())
}

pub async fn update_monitored_regions(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<MonitoredRegionsRequest>,
) -> Result<Json<Vec<String>>, Response> {
    // Normalize to uppercase
    let codes: Vec<String> = body
        .regions
        .iter()
        .map(|c| c.trim().to_uppercase())
        .filter(|c| c.len() == 2)
        .collect();

    // Persist to database
    let json = serde_json::to_string(&codes)
        .map_err(|e| internal_error("serialize monitored regions", e))?;
    state
        .switch_store
        .set_setting("monitored_regions", &json)
        .await
        .map_err(|e| internal_error("save monitored regions", e))?;

    // Update in-memory cache
    state.geo_cache.set_monitored_regions(codes.clone());

    Ok(Json(codes))
}

// ── GET /api/settings/secrets ────────────────────────────────────

#[derive(Serialize)]
pub struct SecretsStatusResponse {
    secrets: Vec<secrets::SecretStatus>,
    key_fingerprint: String,
}

pub async fn secrets_status(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<SecretsStatusResponse>, Response> {
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
    pub maxmind_account_id: Option<String>,
    pub maxmind_license_key: Option<String>,
}

#[derive(Serialize)]
pub struct UpdateSecretsResponse {
    updated: Vec<String>,
    restart_required: bool,
    deferred: Vec<String>,
}

pub async fn update_secrets(
    RequireAdmin(_session): RequireAdmin,
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

    let mut updated = Vec::new();
    let mut deferred = Vec::new();
    let mut restart_required = false;

    if let Some(ref username) = req.router_username {
        if !username.trim().is_empty() {
            deferred.push(secrets::SECRET_ROUTER_USERNAME.to_string());
            restart_required = true;
        }
    }

    if let Some(ref password) = req.router_password {
        if !password.is_empty() {
            deferred.push(secrets::SECRET_ROUTER_PASSWORD.to_string());
            restart_required = true;
        }
    }

    if let Some(ref secret) = req.oidc_client_secret {
        if !secret.is_empty() {
            deferred.push(secrets::SECRET_OIDC_CLIENT_SECRET.to_string());
            restart_required = true;
        }
    }

    let sm = sm.read().await;

    // Router and OIDC secrets are intentionally deferred until restart so the
    // running clients do not claim to have picked up credentials they still
    // have cached in memory.
    if let Some(ref username) = req.router_username {
        if !username.trim().is_empty() {
            sm.encrypt_secret(secrets::SECRET_ROUTER_USERNAME, username.trim())
                .await
                .map_err(|e| internal_error("encrypt router_username", e))?;
        }
    }

    if let Some(ref password) = req.router_password {
        if !password.is_empty() {
            sm.encrypt_secret(secrets::SECRET_ROUTER_PASSWORD, password)
                .await
                .map_err(|e| internal_error("encrypt router_password", e))?;
        }
    }

    if let Some(ref secret) = req.oidc_client_secret {
        if !secret.is_empty() {
            sm.encrypt_secret(secrets::SECRET_OIDC_CLIENT_SECRET, secret)
                .await
                .map_err(|e| internal_error("encrypt oidc_client_secret", e))?;
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

    if let Some(ref id) = req.maxmind_account_id {
        if !id.trim().is_empty() {
            sm.encrypt_secret(secrets::SECRET_MAXMIND_ACCOUNT_ID, id.trim())
                .await
                .map_err(|e| internal_error("encrypt maxmind_account_id", e))?;
            updated.push(secrets::SECRET_MAXMIND_ACCOUNT_ID.to_string());
        }
    }

    if let Some(ref key) = req.maxmind_license_key {
        if !key.is_empty() {
            sm.encrypt_secret(secrets::SECRET_MAXMIND_LICENSE_KEY, key)
                .await
                .map_err(|e| internal_error("encrypt maxmind_license_key", e))?;
            updated.push(secrets::SECRET_MAXMIND_LICENSE_KEY.to_string());
        }
    }

    if !updated.is_empty() {
        tracing::info!(count = updated.len(), "secrets updated via settings API");
    }

    Ok(Json(UpdateSecretsResponse {
        updated,
        restart_required,
        deferred,
    }))
}

// ── POST /api/settings/secrets/session/regenerate ────────────────

#[derive(Serialize)]
pub struct RegenerateSessionResponse {
    status: String,
}

pub async fn regenerate_session(
    RequireAdmin(_session): RequireAdmin,
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
    state.sessions.rotate_signing_secret(&new_secret).await;

    // Clear all existing sessions to force re-authentication
    state.sessions.clear_all();

    tracing::info!("session secret regenerated, all sessions invalidated");

    Ok(Json(RegenerateSessionResponse {
        status: "regenerated".to_string(),
    }))
}

// â”€â”€ GET /api/settings/sessions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Serialize)]
pub struct SessionsResponse {
    sessions: Vec<crate::auth::SessionListEntry>,
}

pub async fn list_sessions(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Json<SessionsResponse> {
    let current = jar
        .get(&state.config.session.cookie_name)
        .map(|c| c.value().to_string());
    let sessions = state.sessions.list_sessions(current.as_deref());
    Json(SessionsResponse { sessions })
}

// â”€â”€ DELETE /api/settings/sessions/{session_id} â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Serialize)]
pub struct RevokeSessionResponse {
    revoked: bool,
}

pub async fn revoke_session(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Json<RevokeSessionResponse> {
    let revoked = state.sessions.revoke_session(&session_id);
    Json(RevokeSessionResponse { revoked })
}

// ── GET /api/settings/encryption ────────────────────────────────

#[derive(Serialize)]
pub struct EncryptionStatusResponse {
    key_fingerprint: String,
    source: String,
    all_secrets_current: bool,
}

pub async fn encryption_status(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<EncryptionStatusResponse>, Response> {
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

pub async fn cert_status(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<CertStatusResponse>, Response> {
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

// ── POST /api/settings/geoip/update ─────────────────────────────

#[derive(Serialize)]
pub struct UpdateGeoipResponse {
    downloaded: Vec<String>,
}

pub async fn update_geoip_databases(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<UpdateGeoipResponse>, Response> {
    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "secrets manager not enabled" })),
        )
            .into_response()
    })?;

    let sm = sm.read().await;
    let account_id = sm
        .decrypt_secret(secrets::SECRET_MAXMIND_ACCOUNT_ID)
        .await
        .map_err(|e| internal_error("decrypt maxmind account_id", e))?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "MaxMind account ID not configured" })),
            )
                .into_response()
        })?;
    let license_key = sm
        .decrypt_secret(secrets::SECRET_MAXMIND_LICENSE_KEY)
        .await
        .map_err(|e| internal_error("decrypt maxmind license_key", e))?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "MaxMind license key not configured" })),
            )
                .into_response()
        })?;
    drop(sm);

    let geoip_dir = geoip_data_dir();

    // Remove existing files so download_maxmind_databases will re-fetch them
    for filename in &["GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"] {
        let path = geoip_dir.join(filename);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }

    let downloaded = crate::geo::download_maxmind_databases(
        &geoip_dir,
        account_id.expose_secret(),
        license_key.expose_secret(),
    )
    .await
    .map_err(|e| internal_error("download MaxMind databases", e))?;

    if !downloaded.is_empty() {
        state.geo_cache.hot_swap_maxmind(&geoip_dir);
        tracing::info!(
            count = downloaded.len(),
            "MaxMind databases updated via settings API"
        );
    }

    Ok(Json(UpdateGeoipResponse { downloaded }))
}

/// Resolve the geoip data directory (same logic as main.rs).
fn geoip_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ion-drift")
        .join("geoip")
}

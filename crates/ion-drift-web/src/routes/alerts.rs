use axum::extract::{Query, State};
use axum::response::{IntoResponse, Json, Response};
use axum::http::StatusCode;
use serde::Deserialize;

use crate::alerting;
use crate::middleware::RequireAuth;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Deserialize)]
pub struct UpdateChannelBody {
    pub enabled: Option<bool>,
    #[serde(flatten)]
    pub config: serde_json::Map<String, serde_json::Value>,
}

/// GET /api/alerts/rules — list all alert rules.
pub async fn list_rules(
    _auth: RequireAuth,
    State(state): State<AppState>,
) -> Response {
    match alerting::get_alert_rules(&state.switch_store).await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => super::internal_error("alert rules", e).into_response(),
    }
}

/// GET /api/alerts/status — alert engine summary.
pub async fn status(
    _auth: RequireAuth,
    State(state): State<AppState>,
) -> Response {
    match alerting::get_alert_status(&state.switch_store).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => super::internal_error("alert status", e).into_response(),
    }
}

/// GET /api/alerts/history — recent alert history (paginated).
pub async fn history(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);
    match alerting::get_alert_history(&state.switch_store, limit, offset).await {
        Ok(h) => Json(h).into_response(),
        Err(e) => super::internal_error("alert history", e).into_response(),
    }
}

/// DELETE /api/alerts/history — clear all alert history.
pub async fn clear_history(
    _auth: RequireAuth,
    State(state): State<AppState>,
) -> Response {
    match alerting::clear_alert_history(&state.switch_store).await {
        Ok(n) => Json(serde_json::json!({ "deleted": n })).into_response(),
        Err(e) => super::internal_error("clear alert history", e).into_response(),
    }
}

/// GET /api/alerts/channels — delivery channel configs (passwords never returned).
pub async fn list_channels(
    _auth: RequireAuth,
    State(state): State<AppState>,
) -> Response {
    match alerting::get_delivery_channels(&state.switch_store).await {
        Ok(mut channels) => {
            // Strip sensitive fields from config_json before returning
            for ch in &mut channels {
                if let Some(obj) = ch.config_json.as_object_mut() {
                    obj.remove("token");
                    obj.remove("secret");
                    // For SMTP, indicate password is set without revealing it
                    if ch.channel == "smtp" {
                        // Don't return password field at all
                    }
                }
            }
            Json(channels).into_response()
        }
        Err(e) => super::internal_error("alert channels", e).into_response(),
    }
}

/// PUT /api/alerts/channels/{channel} — update channel config.
pub async fn update_channel(
    _auth: RequireAuth,
    State(state): State<AppState>,
    axum::extract::Path(channel): axum::extract::Path<String>,
    Json(body): Json<UpdateChannelBody>,
) -> Response {
    // Extract password for SMTP and store via encrypted secrets
    if channel == "smtp" {
        if let Some(password) = body.config.get("password").and_then(|v| v.as_str()) {
            if !password.is_empty() {
                if let Some(ref sm) = state.secrets_manager {
                    let sm_guard = sm.read().await;
                    if let Err(e) = sm_guard.encrypt_secret("smtp_password", password).await {
                        return super::internal_error("store smtp password", e).into_response();
                    }
                } else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "bootstrap mode required for SMTP password storage" })),
                    ).into_response();
                }
            }
        }
    }

    // Build config_json without sensitive fields (password is stored separately)
    let mut config_json = serde_json::Value::Object(body.config);
    if let Some(obj) = config_json.as_object_mut() {
        obj.remove("password");
        obj.remove("enabled"); // enabled is handled separately
    }

    let config_update = if config_json.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        None
    } else {
        // Merge with existing config so partial updates work
        match alerting::get_delivery_channels(&state.switch_store).await {
            Ok(channels) => {
                if let Some(existing) = channels.iter().find(|c| c.channel == channel) {
                    let mut merged = existing.config_json.clone();
                    if let (Some(base), Some(update)) = (merged.as_object_mut(), config_json.as_object()) {
                        for (k, v) in update {
                            base.insert(k.clone(), v.clone());
                        }
                    }
                    Some(merged)
                } else {
                    Some(config_json)
                }
            }
            Err(_) => Some(config_json),
        }
    };

    match alerting::update_channel_config(&state.switch_store, &channel, body.enabled, config_update).await {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => super::internal_error("update channel", e).into_response(),
    }
}

/// POST /api/alerts/rules — create a new alert rule.
pub async fn create_rule(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<alerting::CreateRuleRequest>,
) -> Response {
    match alerting::create_rule(&state.switch_store, body).await {
        Ok(rule) => (StatusCode::CREATED, Json(rule)).into_response(),
        Err(e) => super::internal_error("create rule", e).into_response(),
    }
}

/// PUT /api/alerts/rules/{id} — update an alert rule.
pub async fn update_rule(
    _auth: RequireAuth,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(body): Json<alerting::UpdateRuleRequest>,
) -> Response {
    match alerting::update_rule(&state.switch_store, id, body).await {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => super::internal_error("update rule", e).into_response(),
    }
}

/// DELETE /api/alerts/rules/{id} — delete a custom alert rule.
pub async fn delete_rule(
    _auth: RequireAuth,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    match alerting::delete_rule(&state.switch_store, id).await {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

/// POST /api/alerts/channels/{channel}/test — send a test notification.
pub async fn test_channel(
    _auth: RequireAuth,
    State(state): State<AppState>,
    axum::extract::Path(channel): axum::extract::Path<String>,
) -> Response {
    // Resolve SMTP password if needed
    let smtp_pw = if channel == "smtp" {
        if let Some(ref sm) = state.secrets_manager {
            let sm_guard = sm.read().await;
            match sm_guard.decrypt_secret("smtp_password").await {
                Ok(Some(secret)) => {
                    use secrecy::ExposeSecret;
                    Some(secret.expose_secret().to_string())
                }
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    match alerting::test_channel(&state.http_client, &state.switch_store, &channel, smtp_pw.as_deref()).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Json, Response};
use axum::http::StatusCode;
use serde::Deserialize;

use crate::alerting;
use crate::middleware::RequireAdmin;
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
    _auth: RequireAdmin,
    State(state): State<AppState>,
) -> Response {
    match alerting::get_alert_rules(&state.switch_store).await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => super::internal_error("alert rules", e).into_response(),
    }
}

/// GET /api/alerts/status — alert engine summary.
pub async fn status(
    _auth: RequireAdmin,
    State(state): State<AppState>,
) -> Response {
    match alerting::get_alert_status(&state.switch_store).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => super::internal_error("alert status", e).into_response(),
    }
}

/// GET /api/alerts/history — recent alert history (paginated).
pub async fn history(
    _auth: RequireAdmin,
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
    _auth: RequireAdmin,
    State(state): State<AppState>,
) -> Response {
    match alerting::clear_alert_history(&state.switch_store).await {
        Ok(n) => Json(serde_json::json!({ "deleted": n })).into_response(),
        Err(e) => super::internal_error("clear alert history", e).into_response(),
    }
}

/// GET /api/alerts/channels — delivery channel configs (passwords never returned).
pub async fn list_channels(
    _auth: RequireAdmin,
    State(state): State<AppState>,
) -> Response {
    match alerting::get_delivery_channels(&state.switch_store).await {
        Ok(mut channels) => {
            // Strip sensitive fields from config_json before returning.
            // Secrets are stored encrypted via SecretsManager, not in config_json,
            // but strip them defensively in case of legacy data.
            for ch in &mut channels {
                if let Some(obj) = ch.config_json.as_object_mut() {
                    obj.remove("password");
                    obj.remove("token");
                    obj.remove("secret");
                }
            }
            Json(channels).into_response()
        }
        Err(e) => super::internal_error("alert channels", e).into_response(),
    }
}

/// PUT /api/alerts/channels/{channel} — update channel config.
pub async fn update_channel(
    _auth: RequireAdmin,
    State(state): State<AppState>,
    axum::extract::Path(channel): axum::extract::Path<String>,
    Json(body): Json<UpdateChannelBody>,
) -> Response {
    // Extract secrets and store via encrypted SecretsManager
    {
        let secret_fields: &[(&str, &str)] = match channel.as_str() {
            "smtp" => &[("password", "smtp_password")],
            "ntfy" => &[("token", "alert_channel_ntfy_token")],
            "webhook" => &[("secret", "alert_channel_webhook_secret")],
            _ => &[],
        };

        for &(field, secret_key) in secret_fields {
            if let Some(value) = body.config.get(field).and_then(|v| v.as_str()) {
                if !value.is_empty() {
                    if let Some(ref sm) = state.secrets_manager {
                        let sm_guard = sm.read().await;
                        if let Err(e) = sm_guard.encrypt_secret(secret_key, value).await {
                            return super::internal_error("store channel secret", e).into_response();
                        }
                    } else {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": "bootstrap mode required for secret storage" })),
                        ).into_response();
                    }
                }
            }
        }
    }

    // Build config_json without sensitive fields (secrets are stored separately via SecretsManager)
    let mut config_json = serde_json::Value::Object(body.config);
    if let Some(obj) = config_json.as_object_mut() {
        obj.remove("password");
        obj.remove("token");
        obj.remove("secret");
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
    _auth: RequireAdmin,
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
    _auth: RequireAdmin,
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
    _auth: RequireAdmin,
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
    _auth: RequireAdmin,
    State(state): State<AppState>,
    axum::extract::Path(channel): axum::extract::Path<String>,
) -> Response {
    // Resolve the appropriate secret for this channel from encrypted storage
    let secret_key = match channel.as_str() {
        "smtp" => Some("smtp_password"),
        "ntfy" => Some("alert_channel_ntfy_token"),
        "webhook" => Some("alert_channel_webhook_secret"),
        _ => None,
    };

    let channel_secret = if let Some(key) = secret_key {
        if let Some(ref sm) = state.secrets_manager {
            let sm_guard = sm.read().await;
            match sm_guard.decrypt_secret(key).await {
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

    match alerting::test_channel(&state.http_client, &state.switch_store, &channel, channel_secret.as_deref()).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

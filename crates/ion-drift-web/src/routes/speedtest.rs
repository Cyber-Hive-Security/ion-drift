use std::sync::atomic::Ordering;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::internal_error;

/// Minimum seconds between speed test runs.
const SPEEDTEST_COOLDOWN_SECS: i64 = 300;

/// Maximum number of history entries a client can request.
const MAX_HISTORY_LIMIT: usize = 100;

pub async fn latest(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let result = state.speedtest_store.latest().await.map_err(|e| {
        internal_error("speedtest store", e)
    })?;

    match result {
        Some(r) => Ok(Json(serde_json::to_value(r).map_err(|e| internal_error("serialize speedtest", e))?)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "no speedtest results yet" })),
        ).into_response()),
    }
}

#[derive(Deserialize, Default)]
pub struct HistoryParams {
    pub limit: Option<usize>,
}

pub async fn history(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let limit = params.limit.unwrap_or(10).min(MAX_HISTORY_LIMIT);
    let results = state.speedtest_store.recent(limit).await.map_err(|e| {
        internal_error("speedtest store", e)
    })?;

    Ok(Json(serde_json::to_value(results).map_err(|e| internal_error("serialize speedtest history", e))?))
}

/// Trigger an on-demand speed test. Returns 409 if one is already running,
/// 429 if the cooldown period hasn't elapsed.
pub async fn run(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    // Enforce cooldown between tests
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let last = state.speedtest_last_completed.load(Ordering::Acquire);
    if last > 0 && (now - last) < SPEEDTEST_COOLDOWN_SECS {
        let remaining = SPEEDTEST_COOLDOWN_SECS - (now - last);
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "speed test cooldown active",
                "retry_after": remaining,
            })),
        )
            .into_response());
    }

    // Atomically try to claim the running flag
    if state
        .speedtest_running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "speed test already in progress" })),
        )
            .into_response());
    }

    let store = state.speedtest_store.clone();
    let running = state.speedtest_running.clone();
    let last_completed = state.speedtest_last_completed.clone();

    tokio::spawn(async move {
        let http_client = reqwest::Client::new();
        tracing::info!("starting on-demand speed test");
        let result = mikrotik_core::speedtest::run_speedtest(&http_client).await;
        tracing::info!(
            "on-demand speedtest complete: {:.1}/{:.1} Mbps (down/up)",
            result.median_download_mbps,
            result.median_upload_mbps,
        );
        if let Err(e) = store.save(&result).await {
            tracing::error!("failed to save speedtest result: {e}");
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        last_completed.store(now, Ordering::Release);
        running.store(false, Ordering::Release);
    });

    Ok(Json(serde_json::json!({ "status": "started" })))
}

/// Check if a speed test is currently running.
pub async fn status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "running": state.speedtest_running.load(Ordering::Acquire)
    }))
}

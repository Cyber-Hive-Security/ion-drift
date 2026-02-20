use std::sync::atomic::Ordering;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

pub async fn latest(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let result = state.speedtest_store.latest().await.map_err(|e| {
        tracing::error!("speedtest store error: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response()
    })?;

    match result {
        Some(r) => Ok(Json(serde_json::to_value(r).unwrap())),
        None => Ok(Json(serde_json::json!({ "message": "no speedtest results yet" }))),
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
    let limit = params.limit.unwrap_or(10);
    let results = state.speedtest_store.recent(limit).await.map_err(|e| {
        tracing::error!("speedtest store error: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response()
    })?;

    Ok(Json(serde_json::to_value(results).unwrap()))
}

/// Trigger an on-demand speed test. Returns 409 if one is already running.
pub async fn run(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    // Check if a test is already in progress
    if state.speedtest_running.load(Ordering::Relaxed) {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "speed test already in progress" })),
        )
            .into_response());
    }

    // Mark as running and spawn
    state.speedtest_running.store(true, Ordering::Relaxed);
    let store = state.speedtest_store.clone();
    let running = state.speedtest_running.clone();

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
        running.store(false, Ordering::Relaxed);
    });

    Ok(Json(serde_json::json!({ "status": "started" })))
}

/// Check if a speed test is currently running.
pub async fn status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "running": state.speedtest_running.load(Ordering::Relaxed)
    }))
}

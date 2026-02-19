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

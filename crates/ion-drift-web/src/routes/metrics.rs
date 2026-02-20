use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct HistoryParams {
    /// `"24h"` (default) or `"7d"`.
    #[serde(default = "default_range")]
    pub range: String,
}

fn default_range() -> String {
    "24h".to_string()
}

pub async fn history(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let since_secs_ago = match params.range.as_str() {
        "7d" => 7 * 86400,
        _ => 86400, // default to 24h
    };

    let points = state.metrics_store.query(since_secs_ago).await.map_err(|e| {
        tracing::error!("metrics query error: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response()
    })?;

    Ok(Json(serde_json::to_value(points).unwrap()))
}

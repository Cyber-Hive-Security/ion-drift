use axum::extract::{Query, State};
use axum::response::{Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::internal_error;

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
        internal_error("metrics query", e)
    })?;

    Ok(Json(serde_json::to_value(points).map_err(|e| internal_error("serialize metrics", e))?))
}

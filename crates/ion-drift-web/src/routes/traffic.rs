use axum::extract::State;
use axum::response::{Json, Response};

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::internal_error;

pub async fn current(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let totals = state.traffic_tracker.get_totals().await.map_err(|e| {
        internal_error("traffic tracker", e)
    })?;

    Ok(Json(serde_json::to_value(totals).map_err(|e| internal_error("serialize traffic", e))?))
}

pub async fn live(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let samples = state.live_traffic.snapshot().await;
    Ok(Json(serde_json::to_value(samples).map_err(|e| internal_error("serialize live traffic", e))?))
}

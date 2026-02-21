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

fn range_to_secs(range: &str) -> i64 {
    match range {
        "7d" => 7 * 86400,
        _ => 86400,
    }
}

/// GET /api/metrics/history — system CPU/memory history.
pub async fn history(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let points = state
        .metrics_store
        .query(range_to_secs(&params.range))
        .await
        .map_err(|e| internal_error("metrics query", e))?;

    Ok(Json(
        serde_json::to_value(points).map_err(|e| internal_error("serialize metrics", e))?,
    ))
}

/// GET /api/metrics/drops — firewall drop packet/byte history.
pub async fn drops_history(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let points = state
        .metrics_store
        .query_drops(range_to_secs(&params.range))
        .await
        .map_err(|e| internal_error("drop metrics query", e))?;

    Ok(Json(
        serde_json::to_value(points).map_err(|e| internal_error("serialize drop metrics", e))?,
    ))
}

/// GET /api/metrics/connections — connection tracking count history.
pub async fn connections_history(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let points = state
        .metrics_store
        .query_connections(range_to_secs(&params.range))
        .await
        .map_err(|e| internal_error("connection metrics query", e))?;

    Ok(Json(
        serde_json::to_value(points)
            .map_err(|e| internal_error("serialize connection metrics", e))?,
    ))
}

/// GET /api/metrics/vlans — VLAN throughput history.
pub async fn vlans_history(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let points = state
        .metrics_store
        .query_vlan_metrics(range_to_secs(&params.range))
        .await
        .map_err(|e| internal_error("VLAN metrics query", e))?;

    Ok(Json(
        serde_json::to_value(points).map_err(|e| internal_error("serialize VLAN metrics", e))?,
    ))
}

/// GET /api/metrics/log-trends — hourly log aggregate roll-ups.
pub async fn log_trends(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let since = match params.range.as_str() {
        "7d" => 7 * 86400,
        "30d" => 30 * 86400,
        _ => 86400,
    };

    let points = state
        .metrics_store
        .query_log_aggregates(since)
        .await
        .map_err(|e| internal_error("log trends query", e))?;

    Ok(Json(
        serde_json::to_value(points).map_err(|e| internal_error("serialize log trends", e))?,
    ))
}

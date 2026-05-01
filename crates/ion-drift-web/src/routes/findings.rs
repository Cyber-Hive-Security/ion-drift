//! Findings API endpoints — module-emitted findings, lifecycle operations.
//!
//! - `GET  /api/findings`                 — list (filterable).
//! - `GET  /api/findings/summary`         — counts by status + open severity.
//! - `GET  /api/findings/{id}`            — single finding by row id.
//! - `POST /api/findings/{id}/acknowledge` — admin: mark acknowledged.
//! - `POST /api/findings/{id}/resolve`    — admin: mark resolved with optional note.
//!
//! Reads require an authenticated session; writes additionally require
//! the admin role. State transitions live in `FindingsStore`; this module
//! only translates HTTP shape to/from store calls.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use ion_drift_module_api::FindingSeverity;
use ion_drift_storage::{Finding, FindingStatus, FindingsQuery, FindingsSummary};
use serde::Deserialize;

use super::internal_error;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ListParams {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub module: Option<String>,
    pub category: Option<String>,
    pub since: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Deserialize, Default)]
pub struct ResolveBody {
    pub note: Option<String>,
}

fn parse_status(s: &str) -> Option<FindingStatus> {
    match s {
        "open" => Some(FindingStatus::Open),
        "acknowledged" => Some(FindingStatus::Acknowledged),
        "resolved" => Some(FindingStatus::Resolved),
        _ => None,
    }
}

fn parse_severity(s: &str) -> Option<FindingSeverity> {
    match s {
        "critical" => Some(FindingSeverity::Critical),
        "high" => Some(FindingSeverity::High),
        "medium" => Some(FindingSeverity::Medium),
        "low" => Some(FindingSeverity::Low),
        "info" => Some(FindingSeverity::Info),
        _ => None,
    }
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// GET /api/findings
pub async fn list(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<Finding>>, Response> {
    let mut query = FindingsQuery::default();
    if let Some(s) = params.status.as_deref() {
        query.status =
            Some(parse_status(s).ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid status"))?);
    }
    if let Some(s) = params.severity.as_deref() {
        query.severity = Some(
            parse_severity(s).ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid severity"))?,
        );
    }
    query.module_name = params.module;
    query.category = params.category;
    query.since = params.since;
    query.limit = Some(params.limit.unwrap_or(50).clamp(1, 200));
    query.offset = params.offset;

    let rows = state
        .findings_store
        .list_findings(&query)
        .await
        .map_err(|e| internal_error("list findings", e))?;
    Ok(Json(rows))
}

/// GET /api/findings/summary
pub async fn summary(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<FindingsSummary>, Response> {
    let s = state
        .findings_store
        .summary()
        .await
        .map_err(|e| internal_error("findings summary", e))?;
    Ok(Json(s))
}

/// GET /api/findings/{id}
pub async fn detail(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Finding>, Response> {
    let f = state
        .findings_store
        .get_finding(id)
        .await
        .map_err(|e| internal_error("get finding", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "finding not found"))?;
    Ok(Json(f))
}

/// POST /api/findings/{id}/acknowledge
pub async fn acknowledge(
    RequireAdmin(session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, Response> {
    // Pre-check existence so we can return a clean 404 vs the
    // store's combined "not found or wrong state" error → 409.
    if state
        .findings_store
        .get_finding(id)
        .await
        .map_err(|e| internal_error("get finding", e))?
        .is_none()
    {
        return Err(err(StatusCode::NOT_FOUND, "finding not found"));
    }
    state
        .findings_store
        .acknowledge(id, &session.username)
        .await
        .map_err(|e| err(StatusCode::CONFLICT, &e))?;
    Ok(Json(serde_json::json!({ "id": id, "status": "acknowledged" })))
}

/// POST /api/findings/{id}/resolve
pub async fn resolve(
    RequireAdmin(session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    body: Option<Json<ResolveBody>>,
) -> Result<Json<serde_json::Value>, Response> {
    if state
        .findings_store
        .get_finding(id)
        .await
        .map_err(|e| internal_error("get finding", e))?
        .is_none()
    {
        return Err(err(StatusCode::NOT_FOUND, "finding not found"));
    }
    let note = body.and_then(|Json(b)| b.note);
    state
        .findings_store
        .resolve(id, &session.username, note)
        .await
        .map_err(|e| err(StatusCode::CONFLICT, &e))?;
    Ok(Json(serde_json::json!({ "id": id, "status": "resolved" })))
}

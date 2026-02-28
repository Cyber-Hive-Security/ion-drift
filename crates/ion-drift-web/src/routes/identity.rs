//! Identity management and observed services API routes.

use axum::extract::{Path, Query, State};
use axum::response::{Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

use super::internal_error;

// ── Identity endpoints ──────────────────────────────────────────

/// GET /api/network/identities/stats
pub async fn identity_stats(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let stats = state
        .switch_store
        .get_identity_stats()
        .await
        .map_err(|e| internal_error("identity stats", e))?;
    Ok(Json(serde_json::to_value(stats).unwrap()))
}

/// Query params for review queue.
#[derive(Deserialize)]
pub struct ReviewQueueParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// GET /api/network/identities/review-queue
pub async fn review_queue(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<ReviewQueueParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);
    let data = state
        .switch_store
        .get_review_queue(limit, offset)
        .await
        .map_err(|e| internal_error("review queue", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

/// Request body for updating an identity.
#[derive(Deserialize)]
pub struct UpdateIdentityRequest {
    pub device_type: Option<String>,
    pub human_label: Option<String>,
}

/// PUT /api/network/identities/{mac}
pub async fn update_identity(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Json(body): Json<UpdateIdentityRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    let updated = state
        .switch_store
        .update_identity_human_override(
            &mac,
            body.device_type.as_deref(),
            body.human_label.as_deref(),
        )
        .await
        .map_err(|e| internal_error("update identity", e))?;

    Ok(Json(serde_json::json!({ "updated": updated })))
}

/// Request body for bulk confirm.
#[derive(Deserialize)]
pub struct BulkConfirmRequest {
    pub macs: Vec<String>,
}

/// POST /api/network/identities/bulk-confirm
pub async fn bulk_confirm(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<BulkConfirmRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    let mac_refs: Vec<&str> = body.macs.iter().map(|s| s.as_str()).collect();
    let count = state
        .switch_store
        .bulk_confirm_identities(&mac_refs)
        .await
        .map_err(|e| internal_error("bulk confirm", e))?;

    Ok(Json(serde_json::json!({ "confirmed": count })))
}

// ── Observed services (passive discovery) ───────────────────────

/// Query params for observed services.
#[derive(Deserialize)]
pub struct ObservedServicesParams {
    pub ip: Option<String>,
}

/// GET /api/network/services
pub async fn observed_services(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<ObservedServicesParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_observed_services(params.ip.as_deref())
        .await
        .map_err(|e| internal_error("observed services", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// Nmap scan endpoints removed — replaced by passive_discovery (connection tracking).

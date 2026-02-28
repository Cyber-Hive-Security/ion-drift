//! Identity management and nmap scan API routes.

use axum::extract::{Path, Query, State};
use axum::response::{Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::scanner::ScanProfile;
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

// ── Scan endpoints ──────────────────────────────────────────────

/// Request body for starting a scan.
#[derive(Deserialize)]
pub struct StartScanRequest {
    pub vlan_id: u32,
    pub profile: ScanProfile,
}

/// POST /api/scans
pub async fn start_scan(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<StartScanRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    match state.scanner.start_scan(body.vlan_id, body.profile).await {
        Ok(scan_id) => Ok(Json(serde_json::json!({
            "scan_id": scan_id,
            "status": "running",
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "error": e,
        }))),
    }
}

/// Query params for listing scans.
#[derive(Deserialize)]
pub struct ListScansParams {
    pub limit: Option<usize>,
}

/// GET /api/scans
pub async fn list_scans(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<ListScansParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let limit = params.limit.unwrap_or(20);
    let data = state
        .switch_store
        .get_nmap_scans(limit)
        .await
        .map_err(|e| internal_error("list scans", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

/// GET /api/scans/status
pub async fn scan_status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "scanning": state.scanner.is_scanning(),
        "nmap_available": crate::scanner::nmap_available(),
    }))
}

/// GET /api/scans/{id}
pub async fn get_scan(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let scan = state
        .switch_store
        .get_nmap_scan(&id)
        .await
        .map_err(|e| internal_error("get scan", e))?;
    Ok(Json(serde_json::to_value(scan).unwrap()))
}

/// GET /api/scans/{id}/results
pub async fn scan_results(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_nmap_results(&id)
        .await
        .map_err(|e| internal_error("scan results", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// ── Scan exclusions ─────────────────────────────────────────────

/// GET /api/scans/exclusions
pub async fn list_exclusions(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_scan_exclusions()
        .await
        .map_err(|e| internal_error("scan exclusions", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

/// Request body for adding an exclusion.
#[derive(Deserialize)]
pub struct AddExclusionRequest {
    pub ip: String,
    pub reason: String,
}

/// POST /api/scans/exclusions
pub async fn add_exclusion(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<AddExclusionRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    state
        .switch_store
        .add_scan_exclusion(&body.ip, &body.reason)
        .await
        .map_err(|e| internal_error("add exclusion", e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// DELETE /api/scans/exclusions/{ip}
pub async fn remove_exclusion(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let removed = state
        .switch_store
        .remove_scan_exclusion(&ip)
        .await
        .map_err(|e| internal_error("remove exclusion", e))?;
    Ok(Json(serde_json::json!({ "removed": removed })))
}

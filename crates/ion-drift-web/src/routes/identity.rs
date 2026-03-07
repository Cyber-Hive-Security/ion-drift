//! Identity management and observed services API routes.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

use super::internal_error;

// ── Identity endpoints ──────────────────────────────────────────

/// GET /api/network/identities/infrastructure — infrastructure-flagged identities.
pub async fn list_infrastructure_identities(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let identities = state
        .switch_store
        .get_infrastructure_identities()
        .await
        .map_err(|e| internal_error("infrastructure identities", e))?;
    Ok(Json(serde_json::to_value(identities).unwrap()))
}

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
    let json = serde_json::to_value(stats).map_err(|e| internal_error("serialize identity stats", e))?;
    Ok(Json(json))
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
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize review queue", e))?;
    Ok(Json(json))
}

/// Request body for updating an identity.
#[derive(Deserialize)]
pub struct UpdateIdentityRequest {
    pub device_type: Option<String>,
    pub human_label: Option<String>,
    pub switch_device_id: Option<String>,
    pub switch_port: Option<String>,
    /// Tri-state: omitted = don't change, null = auto-detect, true/false = human override.
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub is_infrastructure: Option<Option<bool>>,
}

/// Custom deserializer for Option<Option<bool>>:
///   field absent → None (don't change)
///   field: null  → Some(None) (set to auto)
///   field: true  → Some(Some(true))
///   field: false → Some(Some(false))
fn deserialize_optional_nullable<'de, D>(
    deserializer: D,
) -> Result<Option<Option<bool>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

/// PUT /api/network/identities/{mac}
pub async fn update_identity(
    RequireAdmin(_session): RequireAdmin,
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
            body.switch_device_id.as_deref(),
            body.switch_port.as_deref(),
            body.is_infrastructure,
        )
        .await
        .map_err(|e| internal_error("update identity", e))?;

    Ok(Json(serde_json::json!({ "updated": updated })))
}

// ── Per-field reset ───────────────────────────────────────────

const RESETTABLE_FIELDS: &[&str] = &["device_type", "human_label", "switch_binding", "is_infrastructure"];

/// DELETE /api/network/identities/{mac}/fields/{field}
pub async fn reset_identity_field(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path((mac, field)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, Response> {
    if !RESETTABLE_FIELDS.contains(&field.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("unknown field: {field}") })),
        )
            .into_response());
    }
    let updated = state
        .switch_store
        .reset_identity_field(&mac, &field)
        .await
        .map_err(|e| internal_error("reset identity field", e))?;
    if !updated {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "MAC not found" })),
        )
            .into_response());
    }
    Ok(Json(serde_json::json!({ "reset": true })))
}

/// Request body for bulk confirm.
#[derive(Deserialize)]
pub struct BulkConfirmRequest {
    pub macs: Vec<String>,
}

/// POST /api/network/identities/bulk-confirm
pub async fn bulk_confirm(
    RequireAdmin(_session): RequireAdmin,
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
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize observed services", e))?;
    Ok(Json(json))
}

// ── Disposition ──────────────────────────────────────────────────

const VALID_DISPOSITIONS: &[&str] = &["unknown", "my_device", "external", "ignored", "flagged"];

/// Request body for setting disposition.
#[derive(Deserialize)]
pub struct SetDispositionRequest {
    pub disposition: String,
}

/// PUT /api/network/identities/{mac}/disposition
pub async fn set_disposition(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Json(body): Json<SetDispositionRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    if !VALID_DISPOSITIONS.contains(&body.disposition.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid disposition" })),
        )
            .into_response());
    }
    let updated = state
        .switch_store
        .set_disposition(&mac, &body.disposition)
        .await
        .map_err(|e| internal_error("set disposition", e))?;
    Ok(Json(serde_json::json!({ "updated": updated })))
}

/// Request body for bulk disposition.
#[derive(Deserialize)]
pub struct BulkDispositionRequest {
    pub macs: Vec<String>,
    pub disposition: String,
}

/// POST /api/network/identities/bulk-disposition
pub async fn bulk_disposition(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<BulkDispositionRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    if !VALID_DISPOSITIONS.contains(&body.disposition.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid disposition" })),
        )
            .into_response());
    }
    let mac_refs: Vec<&str> = body.macs.iter().map(|s| s.as_str()).collect();
    let count = state
        .switch_store
        .bulk_set_disposition(&mac_refs, &body.disposition)
        .await
        .map_err(|e| internal_error("bulk disposition", e))?;
    Ok(Json(serde_json::json!({ "updated": count })))
}

// ── Port MAC bindings ───────────────────────────────────────────

/// GET /api/network/port-bindings (optionally ?device_id=...)
#[derive(Deserialize)]
pub struct PortBindingsParams {
    pub device_id: Option<String>,
}

pub async fn list_port_bindings(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<PortBindingsParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_port_bindings(params.device_id.as_deref())
        .await
        .map_err(|e| internal_error("list port bindings", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize port bindings", e))?;
    Ok(Json(json))
}

/// GET /api/network/port-bindings/{device_id}
pub async fn list_device_port_bindings(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_port_bindings(Some(&device_id))
        .await
        .map_err(|e| internal_error("device port bindings", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize device port bindings", e))?;
    Ok(Json(json))
}

/// Request body for creating a port binding.
#[derive(Deserialize)]
pub struct CreatePortBindingRequest {
    pub device_id: String,
    pub port_name: String,
    pub expected_mac: String,
}

/// POST /api/network/port-bindings
pub async fn create_port_binding(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<CreatePortBindingRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    state
        .switch_store
        .upsert_port_binding(&body.device_id, &body.port_name, &body.expected_mac)
        .await
        .map_err(|e| internal_error("create port binding", e))?;
    Ok(Json(serde_json::json!({ "created": true })))
}

/// Request body for updating a port binding.
#[derive(Deserialize)]
pub struct UpdatePortBindingRequest {
    pub expected_mac: String,
}

/// PUT /api/network/port-bindings/{device_id}/{port}
pub async fn update_port_binding(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path((device_id, port)): Path<(String, String)>,
    Json(body): Json<UpdatePortBindingRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    state
        .switch_store
        .upsert_port_binding(&device_id, &port, &body.expected_mac)
        .await
        .map_err(|e| internal_error("update port binding", e))?;
    Ok(Json(serde_json::json!({ "updated": true })))
}

/// DELETE /api/network/port-bindings/{device_id}/{port}
pub async fn delete_port_binding(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path((device_id, port)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, Response> {
    let deleted = state
        .switch_store
        .delete_port_binding(&device_id, &port)
        .await
        .map_err(|e| internal_error("delete port binding", e))?;
    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

// ── Port violations ─────────────────────────────────────────────

/// GET /api/network/port-violations (optionally ?device_id=...)
#[derive(Deserialize)]
pub struct PortViolationsParams {
    pub device_id: Option<String>,
}

pub async fn list_port_violations(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<PortViolationsParams>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_port_violations(params.device_id.as_deref())
        .await
        .map_err(|e| internal_error("list port violations", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize port violations", e))?;
    Ok(Json(json))
}

/// GET /api/network/port-violations/{device_id}
pub async fn list_device_port_violations(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_port_violations(Some(&device_id))
        .await
        .map_err(|e| internal_error("device port violations", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize device port violations", e))?;
    Ok(Json(json))
}

/// PUT /api/network/port-violations/{id}/resolve
pub async fn resolve_port_violation(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, Response> {
    let resolved = state
        .switch_store
        .resolve_port_violation(id)
        .await
        .map_err(|e| internal_error("resolve port violation", e))?;
    Ok(Json(serde_json::json!({ "resolved": resolved })))
}

// Nmap scan endpoints removed — replaced by passive_discovery (connection tracking).

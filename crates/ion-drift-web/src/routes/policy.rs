//! Policy API endpoints — infrastructure policy map, sync control, and admin policy CRUD.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use super::internal_error;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

#[derive(Serialize)]
pub struct PolicyEntry {
    pub id: i64,
    pub service: String,
    pub protocol: Option<String>,
    pub port: Option<i64>,
    pub authorized_targets: Vec<String>,
    pub vlan_scope: Option<Vec<i64>>,
    pub source: String,
    pub priority: String,
    pub last_synced: i64,
    pub user_created: bool,
}

#[derive(Serialize)]
pub struct IonTagEntry {
    pub rule_id: String,
    pub chain: String,
    pub action: String,
    pub tag: String,
    pub comment: String,
    pub rule_summary: String,
    pub last_synced: i64,
}

#[derive(Serialize)]
pub struct PolicyOverview {
    pub policies: Vec<PolicyEntry>,
    pub ion_tags: Vec<IonTagEntry>,
    pub policy_count: usize,
    pub tag_count: usize,
}

/// GET /api/policy
pub async fn policy_overview(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<PolicyOverview>, Response> {
    let policies = state
        .behavior_store
        .get_all_policies()
        .await
        .map_err(|e| internal_error("policy overview", e))?;

    let ion_tags = state
        .behavior_store
        .get_ion_tags()
        .await
        .map_err(|e| internal_error("policy ion tags", e))?;

    let policy_entries: Vec<PolicyEntry> = policies
        .into_iter()
        .map(|p| PolicyEntry {
            id: p.id,
            service: p.service,
            protocol: p.protocol,
            port: p.port,
            authorized_targets: p.authorized_targets,
            vlan_scope: p.vlan_scope,
            source: p.source,
            priority: p.priority,
            last_synced: p.last_synced,
            user_created: p.user_created,
        })
        .collect();

    let tag_entries: Vec<IonTagEntry> = ion_tags
        .into_iter()
        .map(|t| IonTagEntry {
            rule_id: t.rule_id,
            chain: t.chain,
            action: t.action,
            tag: t.tag,
            comment: t.comment,
            rule_summary: t.rule_summary,
            last_synced: t.last_synced,
        })
        .collect();

    let policy_count = policy_entries.len();
    let tag_count = tag_entries.len();

    Ok(Json(PolicyOverview {
        policies: policy_entries,
        ion_tags: tag_entries,
        policy_count,
        tag_count,
    }))
}

// ── Policy CRUD (admin policies only) ───────────────────────────

#[derive(Deserialize)]
pub struct CreatePolicyRequest {
    pub service: String,
    pub protocol: Option<String>,
    pub port: Option<i64>,
    pub authorized_targets: Vec<String>,
    pub vlan_scope: Option<Vec<i64>>,
    pub priority: String,
    #[serde(default)]
    pub force: bool,
}

fn validate_policy_request(req: &CreatePolicyRequest) -> Result<(), String> {
    // Service: required, lowercase alphanumeric + hyphens
    if req.service.is_empty() || !req.service.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("service must be non-empty alphanumeric (hyphens/underscores allowed)".into());
    }

    // Protocol
    if let Some(ref p) = req.protocol {
        if !matches!(p.as_str(), "tcp" | "udp" | "icmp") {
            return Err("protocol must be tcp, udp, or icmp".into());
        }
    }

    // Port: required if protocol is tcp/udp
    if let Some(ref p) = req.protocol {
        if matches!(p.as_str(), "tcp" | "udp") && req.port.is_none() {
            return Err("port is required when protocol is tcp or udp".into());
        }
    }
    if let Some(port) = req.port {
        if !(1..=65535).contains(&port) {
            return Err("port must be between 1 and 65535".into());
        }
    }

    // Priority
    if !matches!(req.priority.as_str(), "critical" | "high" | "medium" | "low") {
        return Err("priority must be critical, high, medium, or low".into());
    }

    // Authorized targets: each must be valid IP or CIDR
    for target in &req.authorized_targets {
        if target.contains('/') {
            // CIDR: validate IP part and prefix length
            let parts: Vec<&str> = target.splitn(2, '/').collect();
            if parts.len() != 2 {
                return Err(format!("invalid CIDR: {target}"));
            }
            parts[0].parse::<IpAddr>().map_err(|_| format!("invalid IP in CIDR: {target}"))?;
            let prefix: u8 = parts[1].parse().map_err(|_| format!("invalid prefix length in CIDR: {target}"))?;
            if (parts[0].contains(':') && prefix > 128) || (!parts[0].contains(':') && prefix > 32) {
                return Err(format!("prefix length out of range: {target}"));
            }
        } else {
            target.parse::<IpAddr>().map_err(|_| format!("invalid IP address: {target}"))?;
        }
    }

    Ok(())
}

/// POST /api/policy — create an admin policy.
pub async fn create_policy(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    validate_policy_request(&req)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response())?;

    // Hard conflict check: same tuple already exists
    let existing = state
        .behavior_store
        .get_policies_for_service(&req.service, req.protocol.as_deref(), req.port, None)
        .await
        .unwrap_or_default();

    let vlan_json = req.vlan_scope.as_ref().map(|v| {
        let mut sorted = v.clone();
        sorted.sort();
        sorted
    });

    for p in &existing {
        if p.vlan_scope == vlan_json {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "policy with same service/protocol/port/vlan already exists",
                    "existing_policy_id": p.id,
                    "existing_source": p.source,
                })),
            ).into_response());
        }
    }

    // Soft conflict check: overlapping CIDRs (skip if force=true)
    if !req.force && !req.authorized_targets.is_empty() {
        for p in &existing {
            // Only check policies for overlapping VLANs
            let vlan_overlap = match (&vlan_json, &p.vlan_scope) {
                (None, _) | (_, None) => true, // global overlaps everything
                (Some(a), Some(b)) => a.iter().any(|v| b.contains(v)),
            };
            if vlan_overlap {
                for target in &req.authorized_targets {
                    if p.authorized_targets.contains(target) {
                        return Err((
                            StatusCode::CONFLICT,
                            Json(serde_json::json!({
                                "error": format!("overlapping target {target} with existing policy (use force=true to override)"),
                                "existing_policy_id": p.id,
                            })),
                        ).into_response());
                    }
                }
            }
        }
    }

    let id = state
        .behavior_store
        .create_admin_policy(
            &req.service,
            req.protocol.as_deref(),
            req.port,
            &req.authorized_targets,
            req.vlan_scope.as_deref(),
            &req.priority,
        )
        .await
        .map_err(|e| {
            if e.contains("already exists") {
                (StatusCode::CONFLICT, Json(serde_json::json!({ "error": e }))).into_response()
            } else {
                internal_error("create policy", e)
            }
        })?;

    tracing::info!(
        id,
        service = %req.service,
        "admin policy created",
    );

    Ok(Json(serde_json::json!({ "ok": true, "id": id })))
}

#[derive(Deserialize)]
pub struct UpdatePolicyRequest {
    pub authorized_targets: Vec<String>,
    pub vlan_scope: Option<Vec<i64>>,
    pub priority: String,
}

/// PUT /api/policy/{id} — update an admin policy. Router-synced policies cannot be edited.
pub async fn update_policy(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    // Validate priority
    if !matches!(req.priority.as_str(), "critical" | "high" | "medium" | "low") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "priority must be critical, high, medium, or low" })),
        ).into_response());
    }

    // Validate targets
    for target in &req.authorized_targets {
        if target.contains('/') {
            let parts: Vec<&str> = target.splitn(2, '/').collect();
            if parts.len() != 2 || parts[0].parse::<IpAddr>().is_err() {
                return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("invalid CIDR: {target}") }))).into_response());
            }
        } else if target.parse::<IpAddr>().is_err() {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("invalid IP: {target}") }))).into_response());
        }
    }

    state
        .behavior_store
        .update_admin_policy(id, &req.authorized_targets, req.vlan_scope.as_deref(), &req.priority)
        .await
        .map_err(|e| {
            if e.contains("not editable") || e.contains("not found") {
                (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": e }))).into_response()
            } else {
                internal_error("update policy", e)
            }
        })?;

    tracing::info!(id, "admin policy updated");
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// DELETE /api/policy/{id} — delete an admin policy. Router-synced policies cannot be deleted.
pub async fn delete_policy(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, Response> {
    state
        .behavior_store
        .delete_admin_policy(id)
        .await
        .map_err(|e| {
            if e.contains("not deletable") || e.contains("not found") {
                (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": e }))).into_response()
            } else {
                internal_error("delete policy", e)
            }
        })?;

    tracing::info!(id, "admin policy deleted");
    Ok(Json(serde_json::json!({ "ok": true })))
}

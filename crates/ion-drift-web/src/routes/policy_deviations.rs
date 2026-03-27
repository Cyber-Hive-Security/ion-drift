//! Policy deviation API endpoints — DNS deviation detection with ATT&CK context.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use super::internal_error;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

use ion_drift_storage::behavior::{PolicyDeviation, PolicyDeviationCounts};

// ── GET /api/policy/deviations ────────────────────────────────────

#[derive(Deserialize)]
pub struct DeviationListQuery {
    pub status: Option<String>,
    pub mac: Option<String>,
    #[serde(rename = "type")]
    pub deviation_type: Option<String>,
    pub limit: Option<i64>,
}

pub async fn list_deviations(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(q): Query<DeviationListQuery>,
) -> Result<Json<Vec<PolicyDeviation>>, Response> {
    let deviations = state
        .behavior_store
        .get_policy_deviations(
            q.status.as_deref(),
            q.mac.as_deref(),
            q.deviation_type.as_deref(),
            q.limit.or(Some(500)),
        )
        .await
        .map_err(|e| internal_error("list deviations", e))?;

    Ok(Json(deviations))
}

// ── GET /api/policy/deviations/device/{mac} ───────────────────────

pub async fn device_deviations(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> Result<Json<Vec<PolicyDeviation>>, Response> {
    let deviations = state
        .behavior_store
        .get_device_policy_deviations(&mac)
        .await
        .map_err(|e| internal_error("device deviations", e))?;

    Ok(Json(deviations))
}

// ── POST /api/policy/deviations/{id}/resolve ──────────────────────

#[derive(Deserialize)]
pub struct ResolveRequest {
    pub action: String, // "deny_all", "authorize", "dismiss", "acknowledge"
}

pub async fn resolve_deviation(
    RequireAdmin(session): RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<ResolveRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    let resolver = session.username.clone();

    // Get the deviation to know what we're resolving
    let deviation = state
        .behavior_store
        .get_policy_deviation(id)
        .await
        .map_err(|e| internal_error("get deviation", e))?
        .ok_or_else(|| internal_error("get deviation", "not found"))?;

    let status = match body.action.as_str() {
        "deny_all" => {
            // Create a deny-all DNS policy for this VLAN
            if let Some(vlan) = deviation.vlan {
                state.behavior_store.upsert_policy(
                    "dns",
                    Some("udp"),
                    Some(53),
                    &[],
                    Some(&[vlan]),
                    "admin_policy",
                    "high",
                    None,
                ).await.map_err(|e| internal_error("create deny policy", e))?;
            }
            "resolved"
        }
        "authorize" => {
            // Merge the observed target into the existing VLAN-scoped DNS policy.
            // Only merge VLAN-specific policies — global policies are left separate
            // so future global changes propagate cleanly.
            if let Some(vlan) = deviation.vlan {
                let existing = state.behavior_store
                    .get_policies_for_service("dns", Some("udp"), Some(53), Some(vlan))
                    .await
                    .unwrap_or_default();

                // Only include targets from VLAN-scoped policies, not global ones
                let mut targets: Vec<String> = existing.iter()
                    .filter(|p| p.vlan_scope.is_some())
                    .flat_map(|p| p.authorized_targets.clone())
                    .collect();
                if !targets.contains(&deviation.actual) {
                    targets.push(deviation.actual.clone());
                }
                targets.sort();
                targets.dedup();

                state.behavior_store.upsert_policy(
                    "dns",
                    Some("udp"),
                    Some(53),
                    &targets,
                    Some(&[vlan]),
                    "admin_policy",
                    "medium",
                    None,
                ).await.map_err(|e| internal_error("create authorize policy", e))?;
            }
            "resolved"
        }
        "dismiss" => "dismissed",
        "acknowledge" => "acknowledged",
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid action — use acknowledge, authorize, deny_all, or dismiss" })),
            ).into_response());
        }
    };

    state
        .behavior_store
        .resolve_policy_deviation(id, status, Some(&resolver))
        .await
        .map_err(|e| internal_error("resolve deviation", e))?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "status": status,
        "action": body.action,
    })))
}

// ── GET /api/policy/deviations/counts ─────────────────────────────

pub async fn deviation_counts(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<PolicyDeviationCounts>, Response> {
    let counts = state
        .behavior_store
        .policy_deviation_counts()
        .await
        .map_err(|e| internal_error("deviation counts", e))?;

    Ok(Json(counts))
}

// ── GET /api/attack-techniques ────────────────────────────────────

pub async fn attack_techniques(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<crate::attack_techniques::AttackTechniqueDb>, Response> {
    Ok(Json((*state.attack_techniques).clone()))
}

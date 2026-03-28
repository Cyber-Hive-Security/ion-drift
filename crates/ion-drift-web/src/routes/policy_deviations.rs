//! Policy deviation API endpoints — DNS deviation detection with ATT&CK context.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use super::internal_error;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

use ion_drift_storage::behavior::{PolicyDeviation, PolicyDeviationCounts};

/// Enriched deviation with human-readable labels for device, expected, and actual IPs.
#[derive(Serialize)]
pub struct EnrichedDeviation {
    #[serde(flatten)]
    pub inner: PolicyDeviation,
    /// Hostname or friendly name of the device (from device profiles).
    pub device_hostname: Option<String>,
    /// Human-readable label for the expected value (hostname or org name).
    pub expected_label: Option<String>,
    /// Human-readable label for the actual value (hostname or org name).
    pub actual_label: Option<String>,
}

// ── GET /api/policy/deviations ────────────────────────────────────

#[derive(Deserialize)]
pub struct DeviationListQuery {
    pub status: Option<String>,
    pub mac: Option<String>,
    #[serde(rename = "type")]
    pub deviation_type: Option<String>,
    pub limit: Option<i64>,
}

/// Resolve an IP to a human-readable label.
/// Tries device profiles (internal), then GeoIP org/ISP (external).
fn resolve_ip_label(
    ip: &str,
    ip_to_hostname: &std::collections::HashMap<String, String>,
    geo_cache: &crate::geo::GeoCache,
) -> Option<String> {
    // Check internal device profiles first (IP → hostname)
    if let Some(name) = ip_to_hostname.get(ip) {
        return Some(name.clone());
    }
    // Fall back to GeoIP org for external IPs
    if let Some(geo) = geo_cache.lookup_cached(ip) {
        // Prefer org, fall back to ISP
        if let Some(org) = geo.org.as_ref().or(geo.isp.as_ref()) {
            return Some(org.clone());
        }
    }
    None
}

pub async fn list_deviations(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(q): Query<DeviationListQuery>,
) -> Result<Json<Vec<EnrichedDeviation>>, Response> {
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

    // Build MAC → hostname map from device profiles
    let macs: Vec<&str> = deviations.iter().map(|d| d.mac_address.as_str()).collect();
    let profiles = state
        .behavior_store
        .get_profiles_bulk(&macs)
        .await
        .unwrap_or_default();

    // Build IP → hostname map from all profiles (for resolving expected/actual IPs)
    let all_profiles = state
        .behavior_store
        .get_all_profiles()
        .await
        .unwrap_or_default();
    let mut ip_to_hostname = std::collections::HashMap::new();
    for p in &all_profiles {
        if let (Some(ip), Some(hostname)) = (&p.current_ip, &p.hostname) {
            if !hostname.is_empty() {
                ip_to_hostname.insert(ip.clone(), hostname.clone());
            }
        }
    }

    let enriched: Vec<EnrichedDeviation> = deviations
        .into_iter()
        .map(|d| {
            let device_hostname = profiles
                .get(&d.mac_address)
                .and_then(|p| p.hostname.clone())
                .filter(|h| !h.is_empty());

            let expected_label = resolve_ip_label(&d.expected, &ip_to_hostname, &state.geo_cache);
            let actual_label = resolve_ip_label(&d.actual, &ip_to_hostname, &state.geo_cache);

            EnrichedDeviation {
                inner: d,
                device_hostname,
                expected_label,
                actual_label,
            }
        })
        .collect();

    Ok(Json(enriched))
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

    // Derive service metadata from deviation_type prefix.
    // Temporary shim — Phase 3 adds service/protocol/port columns to the deviation table.
    let (service, protocol, port): (&str, Option<&str>, Option<i64>) =
        if deviation.deviation_type.starts_with("dns") {
            ("dns", Some("udp"), Some(53))
        } else if deviation.deviation_type.starts_with("ntp") {
            ("ntp", Some("udp"), Some(123))
        } else {
            ("unknown", None, None)
        };

    let status = match body.action.as_str() {
        "deny_all" => {
            // Create a deny-all policy for this service/VLAN
            if let Some(vlan) = deviation.vlan {
                state.behavior_store.upsert_policy(
                    service,
                    protocol,
                    port,
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
            // Merge the observed target into the existing VLAN-scoped policy.
            // Only merge VLAN-specific policies — global policies are left separate
            // so future global changes propagate cleanly.
            if let Some(vlan) = deviation.vlan {
                let existing = state.behavior_store
                    .get_policies_for_service(service, protocol, port, Some(vlan))
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
                    service,
                    protocol,
                    port,
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

// ── DELETE /api/policy/deviations ─────────────────────────────────

pub async fn delete_all_deviations(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let count = state
        .behavior_store
        .delete_all_policy_deviations()
        .await
        .map_err(|e| internal_error("delete all deviations", e))?;

    tracing::info!("deleted all policy deviations: {count} rows (admin action)");
    Ok(Json(serde_json::json!({ "ok": true, "deleted": count })))
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

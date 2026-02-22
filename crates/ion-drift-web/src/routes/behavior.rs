//! Behavior API endpoints — device fingerprinting, baselines, anomalies.

use axum::extract::{Path, Query, State};
use axum::response::{Json, Response};
use serde::{Deserialize, Serialize};

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::internal_error;

// ── Request / Response types ─────────────────────────────────

#[derive(Deserialize)]
pub struct AnomalyQueryParams {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub vlan: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct ResolveRequest {
    pub action: String,
}

#[derive(Serialize)]
pub struct VlanBehaviorDetail {
    pub vlan: i64,
    pub devices: Vec<mikrotik_core::behavior::DeviceProfile>,
    pub anomalies: Vec<mikrotik_core::behavior::DeviceAnomaly>,
}

#[derive(Serialize)]
pub struct DeviceDetailResponse {
    pub profile: mikrotik_core::behavior::DeviceProfile,
    pub baselines: Vec<mikrotik_core::behavior::DeviceBaseline>,
    pub anomalies: Vec<mikrotik_core::behavior::DeviceAnomaly>,
}

// ── Handlers ─────────────────────────────────────────────────

/// GET /api/behavior/overview
pub async fn overview(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<mikrotik_core::behavior::BehaviorOverview>, Response> {
    let stats = state
        .behavior_store
        .overview_stats()
        .await
        .map_err(|e| internal_error("behavior overview", e))?;
    Ok(Json(stats))
}

/// GET /api/behavior/vlan/:vlan_id
pub async fn vlan_detail(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(vlan_id): Path<i64>,
) -> Result<Json<VlanBehaviorDetail>, Response> {
    let devices = state
        .behavior_store
        .get_profiles_by_vlan(vlan_id)
        .await
        .map_err(|e| internal_error("behavior vlan devices", e))?;

    let anomalies = state
        .behavior_store
        .get_anomalies(Some("pending"), None, Some(vlan_id), Some(100))
        .await
        .map_err(|e| internal_error("behavior vlan anomalies", e))?;

    Ok(Json(VlanBehaviorDetail {
        vlan: vlan_id,
        devices,
        anomalies,
    }))
}

/// GET /api/behavior/device/:mac
pub async fn device_detail(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> Result<Json<DeviceDetailResponse>, Response> {
    let profile = state
        .behavior_store
        .get_profile(&mac)
        .await
        .map_err(|e| internal_error("behavior device profile", e))?;

    let profile = match profile {
        Some(p) => p,
        None => {
            return Err(internal_error("behavior device", "device not found"));
        }
    };

    let baselines = state
        .behavior_store
        .get_baselines(&mac)
        .await
        .map_err(|e| internal_error("behavior device baselines", e))?;

    let anomalies = state
        .behavior_store
        .get_anomalies_by_mac(&mac)
        .await
        .map_err(|e| internal_error("behavior device anomalies", e))?;

    Ok(Json(DeviceDetailResponse {
        profile,
        baselines,
        anomalies,
    }))
}

/// GET /api/behavior/anomalies
pub async fn anomalies(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<AnomalyQueryParams>,
) -> Result<Json<Vec<mikrotik_core::behavior::DeviceAnomaly>>, Response> {
    let results = state
        .behavior_store
        .get_anomalies(
            params.status.as_deref(),
            params.severity.as_deref(),
            params.vlan,
            params.limit.or(Some(100)),
        )
        .await
        .map_err(|e| internal_error("behavior anomalies", e))?;
    Ok(Json(results))
}

/// POST /api/behavior/anomalies/:id/resolve
pub async fn resolve_anomaly(
    RequireAuth(session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<ResolveRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    let valid_actions = ["accepted", "flagged", "dismissed"];
    if !valid_actions.contains(&body.action.as_str()) {
        return Err(internal_error(
            "resolve anomaly",
            format!("invalid action '{}', must be one of: accepted, flagged, dismissed", body.action),
        ));
    }

    let resolved_by = &session.username;
    let updated = state
        .behavior_store
        .resolve_anomaly(id, &body.action, resolved_by)
        .await
        .map_err(|e| internal_error("resolve anomaly", e))?;

    Ok(Json(serde_json::json!({
        "success": updated,
        "id": id,
        "action": body.action,
    })))
}

/// GET /api/behavior/alerts
pub async fn alerts(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<mikrotik_core::behavior::AlertCount>, Response> {
    let counts = state
        .behavior_store
        .get_pending_anomaly_counts()
        .await
        .map_err(|e| internal_error("behavior alerts", e))?;
    Ok(Json(counts))
}

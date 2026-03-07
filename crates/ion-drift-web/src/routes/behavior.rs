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
    pub devices: Vec<ion_drift_storage::behavior::DeviceProfile>,
    pub anomalies: Vec<ion_drift_storage::behavior::DeviceAnomaly>,
}

// ── Handlers ─────────────────────────────────────────────────

/// GET /api/behavior/overview
pub async fn overview(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<ion_drift_storage::behavior::BehaviorOverview>, Response> {
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
) -> Result<Json<EnhancedDeviceDetailResponse>, Response> {
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

    // Build port flow contexts for relevant anomalies
    let mut port_flow_contexts = Vec::new();
    for anomaly in &anomalies {
        if anomaly.anomaly_type != "new_port" && anomaly.anomaly_type != "volume_spike" {
            continue;
        }
        if let Some(ref details) = anomaly.details {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(details) {
                let protocol = json.get("protocol").and_then(|v| v.as_str());
                let dst_port = json.get("dst_port").and_then(|v| v.as_i64());
                if let (Some(proto), Some(port)) = (protocol, dst_port) {
                    if let Ok(Some(ctx)) = state.connection_store.get_port_flow_context(proto, port) {
                        port_flow_contexts.push(ctx);
                    }
                }
            }
        }
    }

    Ok(Json(EnhancedDeviceDetailResponse {
        profile,
        baselines,
        anomalies,
        port_flow_contexts,
    }))
}

/// GET /api/behavior/anomalies
pub async fn anomalies(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(params): Query<AnomalyQueryParams>,
) -> Result<Json<Vec<ion_drift_storage::behavior::DeviceAnomaly>>, Response> {
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
) -> Result<Json<ion_drift_storage::behavior::AlertCount>, Response> {
    let counts = state
        .behavior_store
        .get_pending_anomaly_counts()
        .await
        .map_err(|e| internal_error("behavior alerts", e))?;
    Ok(Json(counts))
}

// ── Anomaly Link Endpoints ──────────────────────────────────

/// GET /api/behavior/anomaly-links — all unresolved anomaly links.
pub async fn anomaly_links(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::connection_store::AnomalyLink>>, Response> {
    let links = state
        .connection_store
        .get_unresolved_links()
        .map_err(|e| internal_error("anomaly links", e))?;
    Ok(Json(links))
}

#[derive(Deserialize)]
pub struct PortLinkPath {
    pub protocol: String,
    pub port: i64,
}

#[derive(Deserialize)]
pub struct PortLinkQuery {
    pub direction: Option<String>,
}

/// GET /api/behavior/anomaly-links/port/:protocol/:port — links for a specific port.
pub async fn anomaly_links_by_port(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(path): Path<PortLinkPath>,
    Query(query): Query<PortLinkQuery>,
) -> Result<Json<Vec<crate::connection_store::AnomalyLink>>, Response> {
    let direction = query.direction.as_deref().unwrap_or("outbound");
    let links = state
        .connection_store
        .get_links_for_port(&path.protocol, path.port, direction)
        .map_err(|e| internal_error("anomaly links by port", e))?;
    Ok(Json(links))
}

/// GET /api/behavior/anomaly-links/device/:mac — links for a specific device.
pub async fn anomaly_links_by_device(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> Result<Json<Vec<crate::connection_store::AnomalyLink>>, Response> {
    let links = state
        .connection_store
        .get_links_for_device(&mac)
        .map_err(|e| internal_error("anomaly links by device", e))?;
    Ok(Json(links))
}

/// POST /api/behavior/anomaly-links/:id/resolve — resolve an anomaly link.
pub async fn resolve_anomaly_link(
    RequireAuth(session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, Response> {
    let updated = state
        .connection_store
        .resolve_link(id, &session.username)
        .map_err(|e| internal_error("resolve anomaly link", e))?;

    Ok(Json(serde_json::json!({
        "success": updated,
        "id": id,
    })))
}

/// Enhanced device detail with port flow context.
#[derive(Serialize)]
pub struct EnhancedDeviceDetailResponse {
    pub profile: ion_drift_storage::behavior::DeviceProfile,
    pub baselines: Vec<ion_drift_storage::behavior::DeviceBaseline>,
    pub anomalies: Vec<ion_drift_storage::behavior::DeviceAnomaly>,
    pub port_flow_contexts: Vec<crate::connection_store::PortFlowContext>,
}

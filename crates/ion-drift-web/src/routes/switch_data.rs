use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use chrono::{Datelike, Timelike};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use mikrotik_core::resources::system::SystemResource;
use mikrotik_core::resources::interface::Interface;

use crate::device_manager::DeviceClient;
use crate::middleware::RequireAuth;
use crate::state::AppState;

use super::{api_error, internal_error};

// ── Query params ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SinceQuery {
    /// Unix timestamp — return data since this time. Defaults to 1 hour ago.
    pub since: Option<i64>,
}

fn default_since(since: Option<i64>) -> i64 {
    since.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            - 3600
    })
}

// ── GET /api/devices/{id}/resources ──────────────────────────────

pub async fn device_resources(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let dm = state.device_manager.read().await;
    let entry = dm.get_device(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "device not found" })),
        )
            .into_response()
    })?;

    match &entry.client {
        DeviceClient::RouterOs(c) => {
            let client = c.clone();
            drop(dm);
            let res: SystemResource = client.system_resources().await.map_err(api_error)?;
            Ok(Json(serde_json::to_value(res).unwrap()))
        }
        DeviceClient::SwOs(c) => {
            let client = c.clone();
            drop(dm);
            let sys = client.get_system().await.map_err(api_error)?;
            // Map SwOS system info into a SystemResource-shaped JSON so the
            // frontend switch detail page can render it without a separate type.
            let uptime_str = format_uptime_secs(sys.uptime_secs);
            Ok(Json(serde_json::json!({
                "uptime": uptime_str,
                "version": sys.firmware_version,
                "board-name": sys.board_name,
                "platform": "SwOS",
                "cpu": "SwOS",
                "cpu-count": 0,
                "cpu-frequency": 0,
                "cpu-load": 0,
                "total-memory": 0,
                "free-memory": 0,
                "free-hdd-space": 0,
                "total-hdd-space": 0,
                "mac-address": sys.mac_address,
            })))
        }
        DeviceClient::Snmp(c) => {
            let client = c.clone();
            drop(dm);
            let sys = client.get_system_info().await.map_err(api_error)?;
            let uptime_str = format_uptime_secs(sys.uptime_secs);
            Ok(Json(serde_json::json!({
                "uptime": uptime_str,
                "version": sys.sys_descr,
                "board-name": sys.sys_name,
                "platform": "SNMP",
                "cpu": "SNMP",
                "cpu-count": 0,
                "cpu-frequency": 0,
                "cpu-load": 0,
                "total-memory": 0,
                "free-memory": 0,
                "free-hdd-space": 0,
                "total-hdd-space": 0,
            })))
        }
    }
}

/// Format seconds into a human-readable uptime string like "3d 12h 5m".
fn format_uptime_secs(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

// ── GET /api/devices/{id}/interfaces ─────────────────────────────

pub async fn device_interfaces(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let dm = state.device_manager.read().await;
    let entry = dm.get_device(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "device not found" })),
        )
            .into_response()
    })?;
    let client = match &entry.client {
        DeviceClient::RouterOs(c) => c.clone(),
        // SwOS / SNMP have no interface concept — return empty array
        DeviceClient::SwOs(_) | DeviceClient::Snmp(_) => {
            drop(dm);
            return Ok(Json(serde_json::json!([])));
        }
    };
    drop(dm);

    let interfaces: Vec<Interface> = client.interfaces().await.map_err(api_error)?;
    let json = serde_json::to_value(interfaces).map_err(|e| internal_error("serialize interfaces", e))?;
    Ok(Json(json))
}

// ── GET /api/devices/{id}/ports ──────────────────────────────────

pub async fn device_ports(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<SinceQuery>,
) -> Result<Json<serde_json::Value>, Response> {
    let since = default_since(q.since);
    let data = state
        .switch_store
        .get_port_metrics(&id, since)
        .await
        .map_err(|e| internal_error("port metrics", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize port metrics", e))?;
    Ok(Json(json))
}

// ── GET /api/devices/{id}/port-list ──────────────────────────────

pub async fn device_port_list(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_device_port_list(&id)
        .await
        .map_err(|e| internal_error("port list", e))?;
    Ok(Json(serde_json::to_value(data).unwrap()))
}

// ── GET /api/devices/{id}/mac-table ──────────────────────────────

pub async fn device_mac_table(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_mac_table(Some(&id))
        .await
        .map_err(|e| internal_error("mac table", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize mac table", e))?;
    Ok(Json(json))
}

// ── GET /api/devices/{id}/neighbors ──────────────────────────────

pub async fn device_neighbors(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_neighbors(Some(&id))
        .await
        .map_err(|e| internal_error("neighbors", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize neighbors", e))?;
    Ok(Json(json))
}

// ── GET /api/devices/{id}/vlans ──────────────────────────────────

pub async fn device_vlans(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_vlan_membership(&id)
        .await
        .map_err(|e| internal_error("vlan membership", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize vlan membership", e))?;
    Ok(Json(json))
}

// ── GET /api/devices/{id}/port-roles ─────────────────────────────

pub async fn device_port_roles(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_port_roles(Some(&id))
        .await
        .map_err(|e| internal_error("port roles", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize port roles", e))?;
    Ok(Json(json))
}

// ── Correlation data (cross-device) ──────────────────────────────

// GET /api/network/identities

pub async fn network_identities(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_network_identities()
        .await
        .map_err(|e| internal_error("network identities", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize network identities", e))?;
    Ok(Json(json))
}

// GET /api/network/mac-table

pub async fn network_mac_table(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_mac_table(None)
        .await
        .map_err(|e| internal_error("mac table", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize network mac table", e))?;
    Ok(Json(json))
}

// GET /api/network/neighbors

pub async fn network_neighbors(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_neighbors(None)
        .await
        .map_err(|e| internal_error("neighbors", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize network neighbors", e))?;
    Ok(Json(json))
}

// GET /api/network/port-roles

pub async fn network_port_roles(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let data = state
        .switch_store
        .get_port_roles(None)
        .await
        .map_err(|e| internal_error("port roles", e))?;
    let json = serde_json::to_value(data).map_err(|e| internal_error("serialize network port roles", e))?;
    Ok(Json(json))
}

// ── GET /api/devices/{id}/port-utilization ──────────────────────

#[derive(Serialize)]
pub struct PortUtilization {
    pub port_name: String,
    pub running: bool,
    pub rx_rate_bps: f64,
    pub tx_rate_bps: f64,
    pub rx_utilization: f64,
    pub tx_utilization: f64,
    pub utilization: f64,
    pub rated_speed_mbps: f64,
    pub speed_source: String,
    pub sample_age_secs: i64,
    /// Baseline average bps for the current hour-of-week (None if learning)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_avg_bps: Option<f64>,
    /// Baseline peak bps for the current hour-of-week (None if learning)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_peak_bps: Option<f64>,
    /// Current rate / baseline average (1.0 = normal, 2.0 = 2x normal)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_ratio: Option<f64>,
    /// How many samples contributed to the baseline (maturity indicator)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_sample_count: Option<u32>,
}

pub async fn device_port_utilization(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<PortUtilization>>, Response> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let since = now - 300; // last 5 minutes

    let rows = state
        .switch_store
        .get_port_metrics(&id, since)
        .await
        .map_err(|e| internal_error("port metrics", e))?;

    // Query baselines for the current hour-of-week
    let local = chrono::Local::now();
    let hour_of_week = local.weekday().num_days_from_monday() * 24 + local.hour();
    let baselines = state
        .switch_store
        .get_port_baselines(&id, hour_of_week)
        .await
        .unwrap_or_default();
    let baseline_map: HashMap<String, _> = baselines
        .into_iter()
        .map(|b| (b.port_name.clone(), b))
        .collect();

    // Group by port_name, keep only 2 most recent samples per port
    // Rows are already ordered timestamp DESC
    let mut by_port: HashMap<String, Vec<(i64, i64, i64, Option<String>, bool)>> = HashMap::new();
    for (port_name, rx_bytes, tx_bytes, ts, speed, running, _port_index) in rows {
        let samples = by_port.entry(port_name).or_default();
        if samples.len() < 2 {
            samples.push((ts, rx_bytes, tx_bytes, speed, running));
        }
    }

    let mut result = Vec::new();
    for (port_name, samples) in &by_port {
        if samples.len() < 2 {
            continue;
        }
        let (ts_new, rx_new, tx_new, speed_str, running) = &samples[0];
        let (ts_old, rx_old, tx_old, _, _) = &samples[1];

        let elapsed = ts_new - ts_old;
        if elapsed <= 0 || elapsed > 120 {
            continue;
        }

        let rx_delta = (rx_new - rx_old).max(0) as f64;
        let tx_delta = (tx_new - tx_old).max(0) as f64;
        let elapsed_f = elapsed as f64;

        let rx_rate_bps = (rx_delta * 8.0) / elapsed_f;
        let tx_rate_bps = (tx_delta * 8.0) / elapsed_f;

        // Speed resolution: polled speed → default 1 Gbps
        let (rated_speed_mbps, speed_source) = resolve_speed(speed_str.as_deref());
        let rated_speed_bps = rated_speed_mbps * 1_000_000.0;

        let rx_util = if rated_speed_bps > 0.0 { (rx_rate_bps / rated_speed_bps).clamp(0.0, 1.0) } else { 0.0 };
        let tx_util = if rated_speed_bps > 0.0 { (tx_rate_bps / rated_speed_bps).clamp(0.0, 1.0) } else { 0.0 };
        let utilization = rx_util.max(tx_util);

        // Baseline comparison: current max rate vs baseline average
        let current_max_bps = rx_rate_bps.max(tx_rate_bps);
        let baseline = baseline_map.get(port_name);
        let (baseline_avg_bps, baseline_peak_bps, baseline_ratio, baseline_sample_count) =
            match baseline {
                Some(b) if b.sample_count >= 3 => {
                    let avg = b.avg_rx_bps.max(b.avg_tx_bps);
                    let peak = b.peak_rx_bps.max(b.peak_tx_bps);
                    let ratio = if avg > 0.0 {
                        Some(current_max_bps / avg)
                    } else {
                        None
                    };
                    (Some(avg), Some(peak), ratio, Some(b.sample_count))
                }
                _ => (None, None, None, baseline.map(|b| b.sample_count)),
            };

        result.push(PortUtilization {
            port_name: port_name.clone(),
            running: *running,
            rx_rate_bps,
            tx_rate_bps,
            rx_utilization: rx_util,
            tx_utilization: tx_util,
            utilization,
            rated_speed_mbps,
            speed_source,
            sample_age_secs: now - ts_new,
            baseline_avg_bps,
            baseline_peak_bps,
            baseline_ratio,
            baseline_sample_count,
        });
    }

    result.sort_by(|a, b| a.port_name.cmp(&b.port_name));
    Ok(Json(result))
}

fn resolve_speed(speed_str: Option<&str>) -> (f64, String) {
    if let Some(s) = speed_str {
        if let Some(mbps) = parse_speed_mbps(s) {
            return (mbps, "polled".into());
        }
    }
    (1000.0, "default".into())
}

fn parse_speed_mbps(s: &str) -> Option<f64> {
    let s = s.trim().to_lowercase();
    if let Some(rest) = s.strip_suffix("gbps") {
        rest.trim().parse::<f64>().ok().map(|v| v * 1000.0)
    } else if let Some(rest) = s.strip_suffix("mbps") {
        rest.trim().parse::<f64>().ok()
    } else if let Some(rest) = s.strip_suffix("g") {
        rest.trim().parse::<f64>().ok().map(|v| v * 1000.0)
    } else if let Some(rest) = s.strip_suffix("m") {
        rest.trim().parse::<f64>().ok()
    } else {
        // Try parsing as raw number (assume Mbps)
        s.parse::<f64>().ok()
    }
}

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::response::{Json, Response};
use serde::{Deserialize, Serialize};

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::{api_error, internal_error};

#[derive(Deserialize, Default)]
pub struct InterfaceFilter {
    #[serde(rename = "type")]
    pub iface_type: Option<String>,
    pub running: Option<bool>,
}

pub async fn list(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(filter): Query<InterfaceFilter>,
) -> Result<Json<serde_json::Value>, Response> {
    let mut interfaces = state.mikrotik.interfaces().await.map_err(api_error)?;

    if let Some(ref t) = filter.iface_type {
        interfaces.retain(|i| i.iface_type == *t);
    }
    if let Some(running) = filter.running {
        interfaces.retain(|i| i.running == running);
    }

    Ok(Json(serde_json::to_value(interfaces).map_err(|e| internal_error("serialize interfaces", e))?))
}

pub async fn vlans(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let vlans = state.mikrotik.vlan_interfaces().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(vlans).map_err(|e| internal_error("serialize vlans", e))?))
}

// ── GET /api/interfaces/utilization ──────────────────────────

#[derive(Serialize)]
pub struct InterfaceUtilization {
    pub name: String,
    pub running: bool,
    pub rx_rate_bps: f64,
    pub tx_rate_bps: f64,
    pub rx_utilization: f64,
    pub tx_utilization: f64,
    pub utilization: f64,
    pub rated_speed_mbps: f64,
    pub speed_source: String,
}

pub async fn interface_utilization(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<InterfaceUtilization>>, Response> {
    let interfaces = state.mikrotik.interfaces().await.map_err(api_error)?;
    let ethernets = state.mikrotik.ethernet_interfaces().await.unwrap_or_default();

    // Build speed lookup from ethernet interfaces
    let speed_map: HashMap<String, f64> = ethernets
        .iter()
        .filter_map(|e| {
            let speed = parse_speed_mbps(e.speed.as_deref().unwrap_or(""))?;
            Some((e.name.clone(), speed))
        })
        .collect();

    let mut results = Vec::new();
    for iface in &interfaces {
        if !iface.running || iface.disabled {
            continue;
        }

        // Get live rates from monitor-traffic
        let entries = match state.mikrotik.monitor_traffic(&iface.name).await {
            Ok(e) => e,
            Err(_) => continue, // skip interfaces that can't be monitored
        };
        let entry = match entries.first() {
            Some(e) => e,
            None => continue,
        };

        let rx_bps = entry.rx_bits_per_second.unwrap_or(0) as f64;
        let tx_bps = entry.tx_bits_per_second.unwrap_or(0) as f64;

        let (rated_speed_mbps, speed_source) = speed_map
            .get(&iface.name)
            .or_else(|| {
                iface
                    .default_name
                    .as_ref()
                    .and_then(|dn| speed_map.get(dn))
            })
            .map(|&mbps| (mbps, "polled".to_string()))
            .unwrap_or((1000.0, "default".to_string()));

        let rated_speed_bps = rated_speed_mbps * 1_000_000.0;
        let rx_util = if rated_speed_bps > 0.0 {
            (rx_bps / rated_speed_bps).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let tx_util = if rated_speed_bps > 0.0 {
            (tx_bps / rated_speed_bps).clamp(0.0, 1.0)
        } else {
            0.0
        };

        results.push(InterfaceUtilization {
            name: iface.name.clone(),
            running: iface.running,
            rx_rate_bps: rx_bps,
            tx_rate_bps: tx_bps,
            rx_utilization: rx_util,
            tx_utilization: tx_util,
            utilization: rx_util.max(tx_util),
            rated_speed_mbps,
            speed_source,
        });
    }

    results.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Json(results))
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
        s.parse::<f64>().ok()
    }
}

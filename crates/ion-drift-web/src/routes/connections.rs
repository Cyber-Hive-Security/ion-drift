use axum::extract::State;
use axum::response::{Json, Response};
use serde::Serialize;
use std::collections::HashMap;

use crate::geo::{CountryInfo, GeoDb};
use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::api_error;

#[derive(Serialize)]
pub struct ConnectionSummary {
    pub total_connections: usize,
    pub tcp_count: usize,
    pub udp_count: usize,
    pub other_count: usize,
    pub max_entries: Option<u64>,
    pub flagged_count: usize,
}

/// Normalize protocol name — RouterOS may return either the name ("tcp")
/// or the IANA protocol number ("6").
fn normalize_protocol(proto: &str) -> &'static str {
    match proto {
        "6" | "tcp" => "tcp",
        "17" | "udp" => "udp",
        "1" | "icmp" => "icmp",
        _ => "other",
    }
}

/// GET /api/connections/summary
pub async fn summary(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<ConnectionSummary>, Response> {
    let connections = state
        .mikrotik
        .firewall_connections(".id,protocol")
        .await
        .map_err(api_error)?;

    let tracking = state
        .mikrotik
        .connection_tracking()
        .await
        .map_err(api_error)?;

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for c in &connections {
        let key = c.protocol.as_deref().map(normalize_protocol).unwrap_or("other");
        *counts.entry(key).or_default() += 1;
    }

    // For flagged count, we need geo data — if available, do a quick scan
    // (expensive, so only count if geo is available)
    let flagged_count = if state.geo_db.is_available() {
        // Fetch full connections for geo
        let full = state.mikrotik.firewall_connections_full().await.map_err(api_error)?;
        full.iter()
            .filter(|c| {
                let src_ip = c.src_address.as_deref().and_then(|a| a.split(':').next());
                let dst_ip = c.dst_address.as_deref().and_then(|a| a.split(':').next());
                let src_flagged = src_ip
                    .and_then(|ip| state.geo_db.lookup(ip))
                    .map(|c| GeoDb::is_flagged(&c.code))
                    .unwrap_or(false);
                let dst_flagged = dst_ip
                    .and_then(|ip| state.geo_db.lookup(ip))
                    .map(|c| GeoDb::is_flagged(&c.code))
                    .unwrap_or(false);
                src_flagged || dst_flagged
            })
            .count()
    } else {
        0
    };

    Ok(Json(ConnectionSummary {
        total_connections: connections.len(),
        tcp_count: counts.get("tcp").copied().unwrap_or(0),
        udp_count: counts.get("udp").copied().unwrap_or(0),
        other_count: connections.len()
            - counts.get("tcp").copied().unwrap_or(0)
            - counts.get("udp").copied().unwrap_or(0),
        max_entries: tracking.max_entries,
        flagged_count,
    }))
}

// ── Full connections page endpoint ───────────────────────────────

#[derive(Serialize)]
pub struct ConnectionResponse {
    pub id: String,
    pub protocol: String,
    pub src_address: String,
    pub src_port: String,
    pub dst_address: String,
    pub dst_port: String,
    pub tcp_state: Option<String>,
    pub timeout: Option<String>,
    pub orig_bytes: u64,
    pub repl_bytes: u64,
    pub connection_mark: Option<String>,
    pub src_country: Option<CountryInfo>,
    pub dst_country: Option<CountryInfo>,
    pub flagged: bool,
}

#[derive(Serialize)]
pub struct ConnectionsPageResponse {
    pub connections: Vec<ConnectionResponse>,
    pub summary: ConnectionsPageSummary,
}

#[derive(Serialize)]
pub struct ConnectionsPageSummary {
    pub total: usize,
    pub by_protocol: HashMap<String, usize>,
    pub by_state: HashMap<String, usize>,
    pub flagged_count: usize,
    pub max_entries: Option<u64>,
}

/// Split "IP:port" into (IP, port). RouterOS uses this format for src/dst-address.
fn split_addr_port(addr: &str) -> (&str, &str) {
    // Handle IPv6 [addr]:port
    if addr.starts_with('[') {
        if let Some(bracket_end) = addr.find(']') {
            let ip = &addr[1..bracket_end];
            let port = if addr.len() > bracket_end + 2 {
                &addr[bracket_end + 2..]
            } else {
                ""
            };
            return (ip, port);
        }
    }
    // IPv4 IP:port
    if let Some(colon) = addr.rfind(':') {
        (&addr[..colon], &addr[colon + 1..])
    } else {
        (addr, "")
    }
}

/// GET /api/connections/page
pub async fn page(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<ConnectionsPageResponse>, Response> {
    let (full_conns, tracking) = tokio::try_join!(
        async { state.mikrotik.firewall_connections_full().await.map_err(api_error) },
        async { state.mikrotik.connection_tracking().await.map_err(api_error) },
    )?;

    let mut by_protocol: HashMap<String, usize> = HashMap::new();
    let mut by_state: HashMap<String, usize> = HashMap::new();
    let mut flagged_count = 0usize;

    let connections: Vec<ConnectionResponse> = full_conns
        .into_iter()
        .map(|c| {
            let protocol = c
                .protocol
                .as_deref()
                .map(normalize_protocol)
                .unwrap_or("other")
                .to_string();

            *by_protocol.entry(protocol.clone()).or_default() += 1;

            // Count by state (tcp_state for TCP, connection_state for others)
            let state_key = c
                .tcp_state
                .as_deref()
                .or(c.connection_state.as_deref())
                .unwrap_or("unknown")
                .to_string();
            *by_state.entry(state_key).or_default() += 1;

            let (src_ip, src_port) = c
                .src_address
                .as_deref()
                .map(split_addr_port)
                .unwrap_or(("", ""));
            let (dst_ip, dst_port) = c
                .dst_address
                .as_deref()
                .map(split_addr_port)
                .unwrap_or(("", ""));

            let src_country = state.geo_db.lookup(src_ip);
            let dst_country = state.geo_db.lookup(dst_ip);

            let flagged = src_country
                .as_ref()
                .map(|c| GeoDb::is_flagged(&c.code))
                .unwrap_or(false)
                || dst_country
                    .as_ref()
                    .map(|c| GeoDb::is_flagged(&c.code))
                    .unwrap_or(false);

            if flagged {
                flagged_count += 1;
            }

            ConnectionResponse {
                id: c.id,
                protocol,
                src_address: src_ip.to_string(),
                src_port: src_port.to_string(),
                dst_address: dst_ip.to_string(),
                dst_port: dst_port.to_string(),
                tcp_state: c.tcp_state,
                timeout: c.timeout,
                orig_bytes: c.orig_bytes.unwrap_or(0),
                repl_bytes: c.repl_bytes.unwrap_or(0),
                connection_mark: c.connection_mark,
                src_country,
                dst_country,
                flagged,
            }
        })
        .collect();

    let total = connections.len();

    Ok(Json(ConnectionsPageResponse {
        connections,
        summary: ConnectionsPageSummary {
            total,
            by_protocol,
            by_state,
            flagged_count,
            max_entries: tracking.max_entries,
        },
    }))
}

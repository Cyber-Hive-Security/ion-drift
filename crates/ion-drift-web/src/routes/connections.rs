use axum::extract::{Query, State};
use axum::response::{Json, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::connection_store::{
    CitySummaryEntry, ConnectionHistoryStats, GeoSummaryEntry, HistoryFilters, PaginatedHistory,
    PortSummaryEntry,
};
use crate::geo::{GeoCache, GeoInfo};
use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::{api_error, internal_error};

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

    // Count flagged using cached geo data only (no HTTP calls in summary).
    // The cache is warmed by the /api/connections/page endpoint.
    let flagged_count = {
        let full = state.mikrotik.firewall_connections_full().await.map_err(api_error)?;
        full.iter()
            .filter(|c| {
                let src_ip = c.src_address.as_deref();
                let dst_ip = c.dst_address.as_deref();
                let src_flagged = src_ip
                    .and_then(|ip| state.geo_cache.lookup_cached(ip))
                    .map(|g| GeoCache::is_flagged(&g.country_code))
                    .unwrap_or(false);
                let dst_flagged = dst_ip
                    .and_then(|ip| state.geo_cache.lookup_cached(ip))
                    .map(|g| GeoCache::is_flagged(&g.country_code))
                    .unwrap_or(false);
                src_flagged || dst_flagged
            })
            .count()
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
    pub src_geo: Option<GeoInfo>,
    pub dst_geo: Option<GeoInfo>,
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


/// GET /api/connections/page
pub async fn page(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<ConnectionsPageResponse>, Response> {
    let (full_conns, tracking) = tokio::try_join!(
        async { state.mikrotik.firewall_connections_full().await.map_err(api_error) },
        async { state.mikrotik.connection_tracking().await.map_err(api_error) },
    )?;

    // Collect unique IPs for batch geo resolution
    let mut all_ips: Vec<String> = Vec::new();
    for c in &full_conns {
        if let Some(ref src) = c.src_address {
            all_ips.push(src.clone());
        }
        if let Some(ref dst) = c.dst_address {
            all_ips.push(dst.clone());
        }
    }

    // Warm the geo cache for all external IPs (non-fatal on failure)
    if let Err(e) = state.geo_cache.resolve_batch(&all_ips).await {
        tracing::warn!("geo batch resolve failed: {e}");
    }

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

            let src_ip = c.src_address.as_deref().unwrap_or("");
            let dst_ip = c.dst_address.as_deref().unwrap_or("");
            let src_port = c.src_port.as_deref().unwrap_or("");
            let dst_port = c.dst_port.as_deref().unwrap_or("");

            let src_geo = state.geo_cache.lookup_cached(src_ip);
            let dst_geo = state.geo_cache.lookup_cached(dst_ip);

            let flagged = src_geo
                .as_ref()
                .map(|g| GeoCache::is_flagged(&g.country_code))
                .unwrap_or(false)
                || dst_geo
                    .as_ref()
                    .map(|g| GeoCache::is_flagged(&g.country_code))
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
                src_geo,
                dst_geo,
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

// ── Connection history endpoints ─────────────────────────────

/// GET /api/connections/history — paginated connection history with filters.
pub async fn history(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(filters): Query<HistoryFilters>,
) -> Result<Json<PaginatedHistory>, Response> {
    let result = state
        .connection_store
        .query_history(&filters)
        .map_err(|e| internal_error("connection history query", e))?;
    Ok(Json(result))
}

/// Query params for geo-summary.
#[derive(Deserialize)]
pub struct GeoSummaryQuery {
    #[serde(default = "default_30")]
    pub days: i64,
}

fn default_30() -> i64 {
    30
}

/// GET /api/connections/geo-summary — aggregated per-country data for the world map.
pub async fn geo_summary(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(query): Query<GeoSummaryQuery>,
) -> Result<Json<Vec<GeoSummaryEntry>>, Response> {
    let result = state
        .connection_store
        .geo_summary(query.days)
        .map_err(|e| internal_error("geo summary", e))?;
    Ok(Json(result))
}

/// Query params for port-summary.
#[derive(Deserialize)]
pub struct PortSummaryQuery {
    #[serde(default = "default_7")]
    pub days: i64,
    #[serde(default)]
    pub direction: Option<String>,
}

fn default_7() -> i64 {
    7
}

/// GET /api/connections/port-summary — aggregated per-port data for Sankey diagram.
pub async fn port_summary(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(query): Query<PortSummaryQuery>,
) -> Result<Json<Vec<PortSummaryEntry>>, Response> {
    let direction = query.direction.as_deref().unwrap_or("");
    let result = state
        .connection_store
        .port_summary(query.days, direction)
        .map_err(|e| internal_error("port summary", e))?;
    Ok(Json(result))
}

/// Query params for city-summary.
#[derive(Deserialize)]
pub struct CitySummaryQuery {
    #[serde(default = "default_7")]
    pub days: i64,
    #[serde(default = "default_50")]
    pub min_connections: i64,
}

fn default_50() -> i64 {
    50
}

/// GET /api/connections/city-summary — aggregated per-city data for city dots on world map.
pub async fn city_summary(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(query): Query<CitySummaryQuery>,
) -> Result<Json<Vec<CitySummaryEntry>>, Response> {
    let result = state
        .connection_store
        .city_summary(query.days, query.min_connections)
        .map_err(|e| internal_error("city summary", e))?;
    Ok(Json(result))
}

/// GET /api/connections/stats — connection history stats for settings page.
pub async fn history_stats(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<ConnectionHistoryStats>, Response> {
    let result = state
        .connection_store
        .stats()
        .map_err(|e| internal_error("connection stats", e))?;
    Ok(Json(result))
}

// ── Syslog status endpoint ───────────────────────────────────

/// Syslog listener status.
#[derive(Serialize)]
pub struct SyslogStatus {
    pub port: u16,
    pub enabled: bool,
    pub events_today: i64,
    pub events_week: i64,
    pub listening: bool,
}

/// GET /api/settings/syslog — syslog listener status.
pub async fn syslog_status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<SyslogStatus>, Response> {
    let (today, week) = state
        .connection_store
        .syslog_event_counts()
        .map_err(|e| internal_error("syslog counts", e))?;

    Ok(Json(SyslogStatus {
        port: 5514,
        enabled: true,
        events_today: today,
        events_week: week,
        listening: true,
    }))
}

// ── GeoIP status endpoint ────────────────────────────────────

/// GeoIP database status.
#[derive(Serialize)]
pub struct GeoIpStatus {
    pub has_maxmind: bool,
    pub has_credentials: bool,
}

/// GET /api/settings/geoip — GeoIP database status.
pub async fn geoip_status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<GeoIpStatus>, Response> {
    let has_credentials = if let Some(ref sm) = state.secrets_manager {
        let sm = sm.read().await;
        sm.decrypt_secret(crate::secrets::SECRET_MAXMIND_ACCOUNT_ID)
            .await
            .ok()
            .flatten()
            .is_some()
    } else {
        false
    };

    Ok(Json(GeoIpStatus {
        has_maxmind: state.geo_cache.has_maxmind(),
        has_credentials,
    }))
}

use axum::extract::{Query, State};
use axum::response::{Json, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::connection_store::{
    CitySummaryEntry, ClassifiedPortSummary, ConnectionHistoryRow, ConnectionHistoryStats,
    CountrySummary, GeoSummaryEntry, HistoryFilters, PaginatedHistory, PortBaselineStatus,
    PortSummaryEntry,
};
use crate::geo::GeoInfo;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;
use super::{internal_error, live_or_degrade, LiveOr};

#[derive(Serialize)]
pub struct ConnectionSummary {
    pub total_connections: usize,
    pub tcp_count: usize,
    pub udp_count: usize,
    pub other_count: usize,
    pub max_entries: Option<u64>,
    pub flagged_count: usize,
    /// `false` when the router is unreachable and these figures were derived
    /// from stored last-known history rather than live conntrack (DRIFT P3).
    pub live_available: bool,
    /// `last_seen` of the most recent stored connection when degraded; `None`
    /// on the live path or when no history exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
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
    // Fetch everything the live summary needs; if the router is unreachable,
    // degrade to a summary computed from stored history instead of 502ing.
    let live = tokio::try_join!(
        async { state.mikrotik.firewall_connections(".id,protocol").await },
        async { state.mikrotik.connection_tracking().await },
        async { state.mikrotik.firewall_connections_full().await },
    );

    let (connections, tracking, full) = match live_or_degrade(live) {
        LiveOr::Live(tuple) => tuple,
        LiveOr::Degraded => {
            let store = state.connection_store.clone();
            let rows = tokio::task::spawn_blocking(move || {
                store.query_history(&fallback_history_filters())
            })
            .await
            .map_err(|e| internal_error("spawn_blocking", e))?
            .map_err(|e| internal_error("connection history query", e))?;
            return Ok(Json(connection_summary_from_history(rows.items)));
        }
    };

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for c in &connections {
        let key = c.protocol.as_deref().map(normalize_protocol).unwrap_or("other");
        *counts.entry(key).or_default() += 1;
    }

    // Count flagged using cached geo data only (no HTTP calls in summary).
    // The cache is warmed by the /api/connections/page endpoint.
    let flagged_count = full
        .iter()
        .filter(|c| {
            let src_ip = c.src_address.as_deref();
            let dst_ip = c.dst_address.as_deref();
            let src_flagged = src_ip
                .and_then(|ip| state.geo_cache.lookup_cached(ip))
                .map(|g| state.geo_cache.is_flagged(&g.country_code))
                .unwrap_or(false);
            let dst_flagged = dst_ip
                .and_then(|ip| state.geo_cache.lookup_cached(ip))
                .map(|g| state.geo_cache.is_flagged(&g.country_code))
                .unwrap_or(false);
            src_flagged || dst_flagged
        })
        .count();

    Ok(Json(ConnectionSummary {
        total_connections: connections.len(),
        tcp_count: counts.get("tcp").copied().unwrap_or(0),
        udp_count: counts.get("udp").copied().unwrap_or(0),
        other_count: connections.len()
            - counts.get("tcp").copied().unwrap_or(0)
            - counts.get("udp").copied().unwrap_or(0),
        max_entries: tracking.max_entries,
        flagged_count,
        live_available: true,
        as_of: None,
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
    /// `false` when the router is unreachable and `connections` were derived
    /// from stored last-known history rather than live conntrack (DRIFT P3).
    pub live_available: bool,
    /// `last_seen` of the most recent stored connection when degraded; `None`
    /// on the live path or when no history exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
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
    // Degrade to stored last-known connections when the router is unreachable
    // instead of 502ing (DRIFT P3).
    let live = tokio::try_join!(
        async { state.mikrotik.firewall_connections_full().await },
        async { state.mikrotik.connection_tracking().await },
    );

    let (full_conns, tracking) = match live_or_degrade(live) {
        LiveOr::Live(tuple) => tuple,
        LiveOr::Degraded => {
            let store = state.connection_store.clone();
            let rows = tokio::task::spawn_blocking(move || {
                store.query_history(&fallback_history_filters())
            })
            .await
            .map_err(|e| internal_error("spawn_blocking", e))?
            .map_err(|e| internal_error("connection history query", e))?;
            return Ok(Json(connections_page_from_history(rows.items)));
        }
    };

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
                .map(|g| state.geo_cache.is_flagged(&g.country_code))
                .unwrap_or(false)
                || dst_geo
                    .as_ref()
                    .map(|g| state.geo_cache.is_flagged(&g.country_code))
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
        live_available: true,
        as_of: None,
    }))
}

// ── Connection history endpoints ─────────────────────────────

/// GET /api/connections/history — paginated connection history with filters.
pub async fn history(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(filters): Query<HistoryFilters>,
) -> Result<Json<PaginatedHistory>, Response> {
    let store = state.connection_store.clone();
    let filters = filters.clone();
    let result = tokio::task::spawn_blocking(move || {
        store.query_history(&filters)
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
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
    let days = query.days.clamp(1, 365);
    let store = state.connection_store.clone();
    let mut result = tokio::task::spawn_blocking(move || {
        store.geo_summary(days)
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("geo summary", e))?;

    // Recompute flagged_count dynamically from current monitored regions
    // rather than relying on the historical flagged column in the database.
    let monitored = state.geo_cache.get_monitored_regions();
    for entry in &mut result {
        if monitored.is_empty() {
            entry.flagged_count = 0;
        } else if monitored.contains(&entry.country_code) {
            entry.flagged_count = entry.connection_count;
        } else {
            entry.flagged_count = 0;
        }
    }

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
    let days = query.days.clamp(1, 365);
    let direction = query.direction.as_deref().unwrap_or("").to_string();
    let store = state.connection_store.clone();
    let result = tokio::task::spawn_blocking(move || {
        store.port_summary(days, &direction)
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("port summary", e))?;
    Ok(Json(result))
}

/// GET /api/connections/port-summary-classified — port flows with anomaly classification.
pub async fn port_summary_classified(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(query): Query<PortSummaryQuery>,
) -> Result<Json<ClassifiedPortSummary>, Response> {
    let days = query.days.clamp(1, 365);
    let direction = query.direction.as_deref().unwrap_or("").to_string();
    let store = state.connection_store.clone();
    let result = tokio::task::spawn_blocking(move || {
        store.classified_port_summary(days, &direction)
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("classified port summary", e))?;
    Ok(Json(result))
}

/// GET /api/behavior/port-baseline — port flow baseline status.
pub async fn port_baseline_status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<PortBaselineStatus>, Response> {
    let store = state.connection_store.clone();
    let result = tokio::task::spawn_blocking(move || {
        store.port_baseline_status()
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("port baseline status", e))?;
    Ok(Json(result))
}

/// POST /api/behavior/port-baseline/compute — trigger baseline computation.
pub async fn compute_port_baselines(
    RequireAdmin(_session): RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let store = state.connection_store.clone();
    let count = tokio::task::spawn_blocking(move || {
        store.compute_port_flow_baselines()
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("compute port baselines", e))?;
    Ok(Json(serde_json::json!({ "baselines_computed": count })))
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
    let days = query.days.clamp(1, 365);
    let min_connections = query.min_connections;
    let store = state.connection_store.clone();
    let mut result = tokio::task::spawn_blocking(move || {
        store.city_summary(days, min_connections)
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("city summary", e))?;

    // Recompute flagged_count dynamically from current monitored regions.
    let monitored = state.geo_cache.get_monitored_regions();
    for entry in &mut result {
        if monitored.is_empty() {
            entry.flagged_count = 0;
        } else if monitored.contains(&entry.country_code) {
            entry.flagged_count = entry.connection_count;
        } else {
            entry.flagged_count = 0;
        }
    }

    Ok(Json(result))
}

/// Query params for country-summary.
#[derive(Deserialize)]
pub struct CountrySummaryQuery {
    #[serde(default = "default_30")]
    pub days: i64,
}

/// GET /api/connections/country/{code}/summary — per-country drill-down.
pub async fn country_summary(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    axum::extract::Path(code): axum::extract::Path<String>,
    Query(query): Query<CountrySummaryQuery>,
) -> Result<Json<CountrySummary>, Response> {
    let days = query.days.clamp(1, 365);
    let store = state.connection_store.clone();
    let result = tokio::task::spawn_blocking(move || {
        store.country_summary(&code, days)
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("country summary", e))?;
    Ok(Json(result))
}

/// GET /api/connections/stats — connection history stats for settings page.
pub async fn history_stats(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<ConnectionHistoryStats>, Response> {
    let store = state.connection_store.clone();
    let result = tokio::task::spawn_blocking(move || {
        store.stats()
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
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
    let store = state.connection_store.clone();
    let (today, week) = tokio::task::spawn_blocking(move || {
        store.syslog_event_counts()
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("syslog counts", e))?;

    Ok(Json(SyslogStatus {
        port: state.config.syslog.port,
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
    pub loaded: bool,
    /// "maxmind", "dbip", or "none"
    pub source: String,
    pub has_credentials: bool,
    /// Attribution text for the active database source.
    pub attribution: Option<String>,
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

    let source = state.geo_cache.source_name();
    let attribution = match source.as_str() {
        "dbip" => Some("IP Geolocation by DB-IP (https://db-ip.com) — CC BY 4.0".to_string()),
        "maxmind" => Some("This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com)".to_string()),
        _ => None,
    };

    Ok(Json(GeoIpStatus {
        loaded: state.geo_cache.has_maxmind(),
        source,
        has_credentials,
        attribution,
    }))
}

// ── Graceful-degradation fallbacks (DRIFT P3) ────────────────────

/// Filters used to pull the last-known connections from the store when the
/// router is offline: most-recent first (the store orders by `last_seen DESC`),
/// capped at the store's per-page maximum (500).
fn fallback_history_filters() -> HistoryFilters {
    HistoryFilters {
        per_page: Some(500),
        ..Default::default()
    }
}

/// Build a [`GeoInfo`] from the geo columns stored on a history row, or `None`
/// when the row has no resolved country.
fn geo_from_row(
    country_code: Option<String>,
    country: Option<String>,
    city: Option<String>,
    asn: Option<i64>,
    org: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
) -> Option<GeoInfo> {
    let country_code = country_code?;
    Some(GeoInfo {
        country: country.unwrap_or_default(),
        country_code,
        city,
        isp: None,
        asn: asn.map(|a| a.to_string()),
        org,
        lat,
        lon,
    })
}

/// Compute a degraded [`ConnectionSummary`] from stored connection history.
/// `max_entries` is unknown while the router is offline, and `live_available`
/// is `false` so the UI can surface a "showing last-known data" banner.
fn connection_summary_from_history(rows: Vec<ConnectionHistoryRow>) -> ConnectionSummary {
    let as_of = rows.first().map(|r| r.last_seen.clone());
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut flagged_count = 0usize;
    for r in &rows {
        *counts.entry(normalize_protocol(&r.protocol)).or_default() += 1;
        if r.flagged {
            flagged_count += 1;
        }
    }
    let total = rows.len();
    let tcp = counts.get("tcp").copied().unwrap_or(0);
    let udp = counts.get("udp").copied().unwrap_or(0);
    ConnectionSummary {
        total_connections: total,
        tcp_count: tcp,
        udp_count: udp,
        other_count: total - tcp - udp,
        max_entries: None,
        flagged_count,
        live_available: false,
        as_of,
    }
}

/// Compute a degraded [`ConnectionsPageResponse`] from stored connection
/// history. Live-only fields absent from history (`src_port`, `timeout`,
/// `connection_mark`, `src_geo`) are left empty/`None`.
fn connections_page_from_history(rows: Vec<ConnectionHistoryRow>) -> ConnectionsPageResponse {
    let as_of = rows.first().map(|r| r.last_seen.clone());
    let mut by_protocol: HashMap<String, usize> = HashMap::new();
    let mut by_state: HashMap<String, usize> = HashMap::new();
    let mut flagged_count = 0usize;

    let connections: Vec<ConnectionResponse> = rows
        .into_iter()
        .map(|r| {
            let protocol = normalize_protocol(&r.protocol).to_string();
            *by_protocol.entry(protocol.clone()).or_default() += 1;

            let state_key = r.last_state.clone().unwrap_or_else(|| "unknown".to_string());
            *by_state.entry(state_key).or_default() += 1;

            if r.flagged {
                flagged_count += 1;
            }

            let dst_geo = geo_from_row(
                r.geo_country_code,
                r.geo_country,
                r.geo_city,
                r.geo_asn,
                r.geo_org,
                r.geo_lat,
                r.geo_lon,
            );

            ConnectionResponse {
                id: r.conntrack_id.unwrap_or_else(|| r.id.to_string()),
                protocol,
                src_address: r.src_ip,
                src_port: String::new(),
                dst_address: r.dst_ip,
                dst_port: r.dst_port.map(|p| p.to_string()).unwrap_or_default(),
                tcp_state: r.last_state,
                timeout: None,
                orig_bytes: r.bytes_tx.max(0) as u64,
                repl_bytes: r.bytes_rx.max(0) as u64,
                connection_mark: None,
                src_geo: None,
                dst_geo,
                flagged: r.flagged,
            }
        })
        .collect();

    let total = connections.len();
    ConnectionsPageResponse {
        connections,
        summary: ConnectionsPageSummary {
            total,
            by_protocol,
            by_state,
            flagged_count,
            max_entries: None,
        },
        live_available: false,
        as_of,
    }
}

#[cfg(test)]
mod degradation_tests {
    use super::*;
    use mikrotik_core::{MikrotikClient, MikrotikConfig, MikrotikError, SecretString};

    fn row(
        protocol: &str,
        flagged: bool,
        cc: Option<&str>,
        last_seen: &str,
    ) -> ConnectionHistoryRow {
        ConnectionHistoryRow {
            id: 1,
            conntrack_id: Some("*ABC".into()),
            protocol: protocol.into(),
            src_ip: "10.0.0.5".into(),
            dst_ip: "1.2.3.4".into(),
            dst_port: Some(443),
            src_mac: None,
            src_vlan: None,
            src_hostname: None,
            dst_vlan: None,
            dst_hostname: None,
            first_seen: last_seen.into(),
            last_seen: last_seen.into(),
            closed: false,
            last_state: Some("established".into()),
            duration_seconds: Some(10),
            bytes_tx: 100,
            bytes_rx: 200,
            data_source: "poll".into(),
            poll_count: 1,
            dst_is_external: true,
            geo_country_code: cc.map(|s| s.to_string()),
            geo_country: cc.map(|_| "Testland".to_string()),
            geo_city: None,
            geo_asn: Some(64500),
            geo_org: Some("TestOrg".into()),
            geo_lat: Some(1.0),
            geo_lon: Some(2.0),
            flagged,
            anomaly_id: None,
        }
    }

    #[test]
    fn summary_from_history_marks_unavailable_and_counts() {
        let rows = vec![
            row("tcp", true, Some("CN"), "2026-09-24T00:00:02Z"),
            row("udp", false, None, "2026-09-24T00:00:01Z"),
            row("6", false, None, "2026-09-24T00:00:00Z"),
        ];
        let s = connection_summary_from_history(rows);
        assert!(!s.live_available);
        assert_eq!(s.total_connections, 3);
        assert_eq!(s.tcp_count, 2); // "tcp" and IANA "6" both normalize to tcp
        assert_eq!(s.udp_count, 1);
        assert_eq!(s.flagged_count, 1);
        assert_eq!(s.max_entries, None);
        assert_eq!(s.as_of.as_deref(), Some("2026-09-24T00:00:02Z"));
    }

    #[test]
    fn page_from_history_maps_rows_and_geo() {
        let rows = vec![row("tcp", true, Some("RU"), "2026-09-24T00:00:00Z")];
        let p = connections_page_from_history(rows);
        assert!(!p.live_available);
        assert_eq!(p.connections.len(), 1);
        let c = &p.connections[0];
        assert_eq!(c.protocol, "tcp");
        assert_eq!(c.dst_port, "443");
        assert_eq!(c.orig_bytes, 100);
        assert_eq!(c.repl_bytes, 200);
        assert!(c.flagged);
        assert_eq!(
            c.dst_geo.as_ref().map(|g| g.country_code.as_str()),
            Some("RU")
        );
        assert!(c.src_geo.is_none());
        assert_eq!(p.summary.total, 1);
        assert_eq!(p.summary.max_entries, None);
        assert_eq!(p.as_of.as_deref(), Some("2026-09-24T00:00:00Z"));
    }

    #[test]
    fn empty_history_degrades_without_as_of() {
        let s = connection_summary_from_history(vec![]);
        assert!(!s.live_available);
        assert_eq!(s.total_connections, 0);
        assert!(s.as_of.is_none());
        let p = connections_page_from_history(vec![]);
        assert!(!p.live_available);
        assert!(p.connections.is_empty());
        assert!(p.as_of.is_none());
    }

    #[test]
    fn live_or_degrade_maps_ok_and_err() {
        match live_or_degrade::<u8>(Ok(7)) {
            LiveOr::Live(v) => assert_eq!(v, 7),
            LiveOr::Degraded => panic!("expected Live on Ok"),
        }
        match live_or_degrade::<u8>(Err(MikrotikError::AuthFailed)) {
            LiveOr::Degraded => {}
            LiveOr::Live(_) => panic!("expected Degraded on Err"),
        }
    }

    #[test]
    fn success_shape_serializes_live_available_and_omits_none_as_of() {
        let s = ConnectionSummary {
            total_connections: 0,
            tcp_count: 0,
            udp_count: 0,
            other_count: 0,
            max_entries: Some(1000),
            flagged_count: 0,
            live_available: true,
            as_of: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["live_available"], serde_json::json!(true));
        // as_of is skipped when None -> additive, backward-compatible shape.
        assert!(v.get("as_of").is_none());
    }

    // A real MikrotikClient pointed at an unreachable port errors, and that
    // error must degrade (not 502). 127.0.0.1:1 refuses the connection
    // immediately, so this is deterministic and fast.
    #[tokio::test]
    async fn erroring_router_client_degrades() {
        let client = MikrotikClient::new(MikrotikConfig {
            host: "127.0.0.1".into(),
            port: 1,
            tls: false,
            ca_cert_path: None,
            username: "x".into(),
            password: SecretString::from("y".to_string()),
        })
        .expect("client builds without network I/O");
        let result = client.firewall_connections_full().await;
        assert!(result.is_err(), "unreachable router should error");
        assert!(matches!(live_or_degrade(result), LiveOr::Degraded));
    }
}

use std::collections::HashSet;

use axum::extract::{Path, Query, State};
use axum::response::{Json, Response};
use serde::{Deserialize, Serialize};

use crate::middleware::RequireAuth;
use crate::state::AppState;

use super::internal_error;

// ── Shared types ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RangeQuery {
    pub range: Option<String>,
}

/// Strip "VLAN " prefix from DB format ("VLAN 25" → "25"), pass through "WAN".
fn strip_vlan_prefix(s: &str) -> String {
    s.strip_prefix("VLAN ").unwrap_or(s).to_string()
}

fn range_to_sqlite_offset(range: &str) -> String {
    let hours = match range {
        "1h" => 1,
        "6h" => 6,
        "24h" => 24,
        "7d" => 24 * 7,
        "30d" => 24 * 30,
        _ => 24,
    };
    format!("-{hours} hours")
}

// ── GET /api/sankey/network ─────────────────────────────────────

#[derive(Serialize)]
pub struct SankeyNetworkFlow {
    pub src_vlan: String,
    pub dst_vlan: String,
    pub bytes: i64,
    pub connections: i64,
    pub anomaly_count: i64,
}

#[derive(Serialize)]
pub struct SankeyNetworkVlan {
    pub vlan_id: String,
    pub device_count: i64,
    pub total_bytes: i64,
    pub total_connections: i64,
}

#[derive(Serialize)]
pub struct SankeyNetworkResponse {
    pub flows: Vec<SankeyNetworkFlow>,
    pub vlans: Vec<SankeyNetworkVlan>,
    pub range: String,
}

pub async fn network_overview(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<SankeyNetworkResponse>, Response> {
    let range = q.range.as_deref().unwrap_or("24h");
    let offset = range_to_sqlite_offset(range);

    let store = state.connection_store.clone();
    let (flows, vlans) = tokio::task::spawn_blocking(move || {
        let db = store.lock_db()
            .map_err(|e| format!("sankey db lock: {e}"))?;

        let mut stmt = db.prepare(
            "SELECT
                COALESCE(src_vlan, 'WAN') as sv,
                COALESCE(dst_vlan, CASE WHEN dst_is_external = 1 THEN 'WAN' ELSE 'WAN' END) as dv,
                SUM(bytes_tx + bytes_rx) as total_bytes,
                COUNT(*) as conn_count,
                SUM(CASE WHEN flagged = 1 THEN 1 ELSE 0 END) as anomaly_count
             FROM connection_history
             WHERE first_seen >= datetime('now', ?1)
             GROUP BY sv, dv
             ORDER BY total_bytes DESC",
        ).map_err(|e| format!("sankey query: {e}"))?;

        let flows: Vec<SankeyNetworkFlow> = stmt
            .query_map(rusqlite::params![offset], |row| {
                Ok(SankeyNetworkFlow {
                    src_vlan: strip_vlan_prefix(&row.get::<_, String>(0)?),
                    dst_vlan: strip_vlan_prefix(&row.get::<_, String>(1)?),
                    bytes: row.get(2)?,
                    connections: row.get(3)?,
                    anomaly_count: row.get(4)?,
                })
            })
            .map_err(|e| format!("sankey flow query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        let mut stmt2 = db.prepare(
            "SELECT
                COALESCE(src_vlan, 'WAN') as vlan_id,
                COUNT(DISTINCT src_mac) as device_count,
                SUM(bytes_tx + bytes_rx) as total_bytes,
                COUNT(*) as conn_count
             FROM connection_history
             WHERE first_seen >= datetime('now', ?1)
             GROUP BY vlan_id
             ORDER BY total_bytes DESC",
        ).map_err(|e| format!("sankey vlan query: {e}"))?;

        let vlans: Vec<SankeyNetworkVlan> = stmt2
            .query_map(rusqlite::params![offset], |row| {
                Ok(SankeyNetworkVlan {
                    vlan_id: strip_vlan_prefix(&row.get::<_, String>(0)?),
                    device_count: row.get(1)?,
                    total_bytes: row.get(2)?,
                    total_connections: row.get(3)?,
                })
            })
            .map_err(|e| format!("sankey vlan query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();

        Ok::<_, String>((flows, vlans))
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("sankey network_overview", e))?;

    Ok(Json(SankeyNetworkResponse {
        flows,
        vlans,
        range: range.to_string(),
    }))
}

// ── GET /api/sankey/vlan/{vlan_id} ──────────────────────────────

#[derive(Deserialize)]
pub struct VlanDetailQuery {
    pub range: Option<String>,
    pub dest_vlan: Option<String>,
}

#[derive(Serialize)]
pub struct SankeyVlanDevice {
    pub mac: String,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub total_bytes: i64,
    pub total_connections: i64,
    pub baseline_status: Option<String>,
}

#[derive(Serialize)]
pub struct SankeyVlanFlow {
    pub src_mac: String,
    pub dst_group: String,
    pub bytes: i64,
    pub connections: i64,
    pub flow_state: String,
}

#[derive(Serialize)]
pub struct SankeyVlanResponse {
    pub vlan_id: String,
    pub devices: Vec<SankeyVlanDevice>,
    pub flows: Vec<SankeyVlanFlow>,
    pub range: String,
}

pub async fn vlan_detail(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(vlan_id): Path<String>,
    Query(q): Query<VlanDetailQuery>,
) -> Result<Json<SankeyVlanResponse>, Response> {
    let range = q.range.as_deref().unwrap_or("24h");
    let offset = range_to_sqlite_offset(range);
    let dest_filter = q.dest_vlan.clone().unwrap_or_default();

    // Convert VLAN ID to DB format: "90" → "VLAN 90"
    // "WAN" means src_vlan IS NULL in the DB (traffic with no matching VLAN subnet)
    let src_is_wan = vlan_id.eq_ignore_ascii_case("wan");
    let db_vlan = if src_is_wan {
        String::new() // unused — we use IS NULL instead
    } else {
        format!("VLAN {vlan_id}")
    };
    let dest_is_wan = dest_filter.eq_ignore_ascii_case("wan");
    let db_dest = if dest_is_wan {
        "WAN".to_string()
    } else if dest_filter.is_empty() {
        String::new()
    } else {
        format!("VLAN {dest_filter}")
    };

    // Run all DB access on a blocking thread
    let store = state.connection_store.clone();
    let vlan_id_clone = db_vlan;
    let (devices, flows) = tokio::task::spawn_blocking(move || {
        let db = store.lock_db()
            .map_err(|e| format!("sankey db lock: {e}"))?;

        let device_sql = if src_is_wan {
            "SELECT
                COALESCE(src_mac, src_ip) as mac,
                src_hostname,
                src_ip,
                SUM(bytes_tx + bytes_rx) as total_bytes,
                COUNT(*) as conn_count
             FROM connection_history
             WHERE src_vlan IS NULL AND first_seen >= datetime('now', ?1)
             GROUP BY mac
             ORDER BY total_bytes DESC
             LIMIT 100"
        } else {
            "SELECT
                COALESCE(src_mac, src_ip) as mac,
                src_hostname,
                src_ip,
                SUM(bytes_tx + bytes_rx) as total_bytes,
                COUNT(*) as conn_count
             FROM connection_history
             WHERE src_vlan = ?1 AND first_seen >= datetime('now', ?2)
             GROUP BY mac
             ORDER BY total_bytes DESC
             LIMIT 100"
        };
        let mut device_stmt = db.prepare(device_sql)
            .map_err(|e| format!("sankey device query: {e}"))?;

        let map_device = |row: &rusqlite::Row| -> rusqlite::Result<SankeyVlanDevice> {
            Ok(SankeyVlanDevice {
                mac: row.get(0)?,
                hostname: row.get(1)?,
                ip: row.get(2)?,
                total_bytes: row.get(3)?,
                total_connections: row.get(4)?,
                baseline_status: None,
            })
        };
        let devices: Vec<SankeyVlanDevice> = if src_is_wan {
            device_stmt.query_map(rusqlite::params![offset], map_device)
                .map_err(|e| format!("sankey device query: {e}"))?
                .filter_map(|r| r.ok())
                .collect()
        } else {
            device_stmt.query_map(rusqlite::params![vlan_id_clone, offset], map_device)
                .map_err(|e| format!("sankey device query: {e}"))?
                .filter_map(|r| r.ok())
                .collect()
        };
        drop(device_stmt);

        // Build flow query dynamically based on WAN vs named VLAN
        let (flow_sql, flow_params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = {
            let src_clause = if src_is_wan { "src_vlan IS NULL" } else { "src_vlan = ?" };
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            if !src_is_wan {
                params.push(Box::new(vlan_id_clone.clone()));
            }
            params.push(Box::new(offset.clone()));

            let dest_clause = if db_dest.is_empty() {
                String::new()
            } else {
                params.push(Box::new(db_dest.clone()));
                let dp = params.len();
                format!(" AND (dst_vlan = ?{dp} OR (dst_is_external = 1 AND ?{dp} = 'WAN'))")
            };

            let sql = format!(
                "SELECT
                    COALESCE(src_mac, src_ip) as mac,
                    COALESCE(dst_vlan, 'WAN') as dst_group,
                    SUM(bytes_tx + bytes_rx) as total_bytes,
                    COUNT(*) as conn_count
                 FROM connection_history
                 WHERE {src_clause} AND first_seen >= datetime('now', ?{time_param}){dest_clause}
                 GROUP BY mac, dst_group
                 ORDER BY total_bytes DESC
                 LIMIT 500",
                time_param = if src_is_wan { 1 } else { 2 },
            );
            (sql, params)
        };
        let mut flow_stmt = db.prepare(&flow_sql)
            .map_err(|e| format!("sankey flow query: {e}"))?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = flow_params.iter().map(|p| p.as_ref()).collect();
        let flows: Vec<SankeyVlanFlow> = flow_stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(SankeyVlanFlow {
                    src_mac: row.get(0)?,
                    dst_group: row.get(1)?,
                    bytes: row.get(2)?,
                    connections: row.get(3)?,
                    flow_state: "unknown".into(),
                })
            })
            .map_err(|e| format!("sankey flow query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();

        Ok::<_, String>((devices, flows))
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("sankey vlan_detail", e))?;

    // Bulk profile lookup — collect all unique MACs from devices and flows
    let mut all_macs: HashSet<String> = HashSet::new();
    for dev in &devices {
        all_macs.insert(dev.mac.clone());
    }
    for flow in &flows {
        all_macs.insert(flow.src_mac.clone());
    }
    let mac_refs: Vec<&str> = all_macs.iter().map(|s| s.as_str()).collect();
    let profiles = state.behavior_store.get_profiles_bulk(&mac_refs).await.unwrap_or_default();

    // Enrich devices with baseline status
    let mut enriched_devices = devices;
    for dev in &mut enriched_devices {
        if let Some(profile) = profiles.get(&dev.mac) {
            dev.baseline_status = Some(profile.baseline_status.clone());
        }
    }

    // Enrich flows with flow state
    let mut enriched_flows = flows;
    for flow in &mut enriched_flows {
        if let Some(profile) = profiles.get(&flow.src_mac) {
            flow.flow_state = match profile.baseline_status.as_str() {
                "baselined" => "baselined".into(),
                "sparse" => "unbaselined".into(),
                "learning" => "learning".into(),
                _ => "unknown".into(),
            };
        }
    }

    Ok(Json(SankeyVlanResponse {
        vlan_id,
        devices: enriched_devices,
        flows: enriched_flows,
        range: range.to_string(),
    }))
}

// ── GET /api/sankey/device/{mac} ──────────────────────────────

#[derive(Serialize)]
pub struct SankeyDeviceProtocol {
    pub protocol: String,
    pub dst_port: i64,
    pub service_name: String,
    pub bytes: i64,
    pub connections: i64,
}

#[derive(Serialize)]
pub struct SankeyDeviceDestination {
    pub dst_ip: String,
    pub dst_hostname: Option<String>,
    pub is_external: bool,
    pub bytes: i64,
    pub connections: i64,
}

#[derive(Serialize)]
pub struct SankeyDeviceFlow {
    pub protocol: String,
    pub dst_port: i64,
    pub dst_ip: String,
    pub bytes: i64,
    pub connections: i64,
    pub flagged: bool,
}

#[derive(Serialize)]
pub struct SankeyDeviceResponse {
    pub mac: String,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub baseline_status: Option<String>,
    pub protocols: Vec<SankeyDeviceProtocol>,
    pub destinations: Vec<SankeyDeviceDestination>,
    pub flows: Vec<SankeyDeviceFlow>,
    pub range: String,
}

fn port_to_service(protocol: &str, port: i64) -> String {
    match (protocol, port) {
        ("tcp", 22) => "SSH".into(),
        ("tcp", 25) | ("tcp", 587) | ("tcp", 465) => "SMTP".into(),
        ("tcp", 53) | ("udp", 53) => "DNS".into(),
        ("tcp", 80) => "HTTP".into(),
        ("tcp", 443) => "HTTPS".into(),
        ("tcp", 993) => "IMAP".into(),
        ("tcp", 3306) => "MySQL".into(),
        ("tcp", 5432) => "PostgreSQL".into(),
        ("tcp", 8080) | ("tcp", 8443) => "HTTP-Alt".into(),
        ("udp", 123) => "NTP".into(),
        ("udp", 443) => "QUIC".into(),
        ("udp", 500) | ("udp", 4500) => "IPsec".into(),
        ("udp", 51820) => "WireGuard".into(),
        (_, p) if p >= 1024 => format!("{protocol}/{port}").to_uppercase(),
        _ => format!("{protocol}/{port}"),
    }
}

pub async fn device_trace(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<SankeyDeviceResponse>, Response> {
    let range = q.range.as_deref().unwrap_or("24h");
    let offset = range_to_sqlite_offset(range);

    let store = state.connection_store.clone();
    let mac_clone = mac.clone();
    let (protocols, destinations, flows, hostname, ip) = tokio::task::spawn_blocking(move || {
        let db = store.lock_db()
            .map_err(|e| format!("sankey db lock: {e}"))?;

        // Protocols aggregated by (protocol, dst_port)
        let mut stmt_p = db.prepare(
            "SELECT protocol, dst_port, SUM(bytes_tx + bytes_rx) as total_bytes, COUNT(*) as conn_count
             FROM connection_history
             WHERE src_mac = ?1 AND first_seen >= datetime('now', ?2) AND dst_port IS NOT NULL
             GROUP BY protocol, dst_port
             ORDER BY total_bytes DESC
             LIMIT 100",
        ).map_err(|e| format!("sankey device protocol query: {e}"))?;

        let protocols: Vec<SankeyDeviceProtocol> = stmt_p
            .query_map(rusqlite::params![mac_clone, offset], |row| {
                let proto: String = row.get(0)?;
                let port: i64 = row.get(1)?;
                Ok(SankeyDeviceProtocol {
                    service_name: port_to_service(&proto, port),
                    protocol: proto,
                    dst_port: port,
                    bytes: row.get(2)?,
                    connections: row.get(3)?,
                })
            })
            .map_err(|e| format!("sankey device protocol query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt_p);

        // Destinations aggregated by dst_ip
        let mut stmt_d = db.prepare(
            "SELECT dst_ip, dst_hostname, dst_is_external,
                    SUM(bytes_tx + bytes_rx) as total_bytes, COUNT(*) as conn_count
             FROM connection_history
             WHERE src_mac = ?1 AND first_seen >= datetime('now', ?2)
             GROUP BY dst_ip
             ORDER BY total_bytes DESC
             LIMIT 100",
        ).map_err(|e| format!("sankey device dest query: {e}"))?;

        let destinations: Vec<SankeyDeviceDestination> = stmt_d
            .query_map(rusqlite::params![mac_clone, offset], |row| {
                Ok(SankeyDeviceDestination {
                    dst_ip: row.get(0)?,
                    dst_hostname: row.get(1)?,
                    is_external: row.get::<_, i32>(2)? != 0,
                    bytes: row.get(3)?,
                    connections: row.get(4)?,
                })
            })
            .map_err(|e| format!("sankey device dest query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt_d);

        // Individual flows: protocol+port+destination
        let mut stmt_f = db.prepare(
            "SELECT protocol, dst_port, dst_ip,
                    SUM(bytes_tx + bytes_rx) as total_bytes, COUNT(*) as conn_count,
                    SUM(CASE WHEN flagged = 1 THEN 1 ELSE 0 END) as flag_count
             FROM connection_history
             WHERE src_mac = ?1 AND first_seen >= datetime('now', ?2) AND dst_port IS NOT NULL
             GROUP BY protocol, dst_port, dst_ip
             ORDER BY total_bytes DESC
             LIMIT 500",
        ).map_err(|e| format!("sankey device flow query: {e}"))?;

        let flows: Vec<SankeyDeviceFlow> = stmt_f
            .query_map(rusqlite::params![mac_clone, offset], |row| {
                Ok(SankeyDeviceFlow {
                    protocol: row.get(0)?,
                    dst_port: row.get(1)?,
                    dst_ip: row.get(2)?,
                    bytes: row.get(3)?,
                    connections: row.get(4)?,
                    flagged: row.get::<_, i64>(5)? > 0,
                })
            })
            .map_err(|e| format!("sankey device flow query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt_f);

        // Get device hostname/IP from most recent connection
        let meta: (Option<String>, Option<String>) = db.query_row(
            "SELECT src_hostname, src_ip FROM connection_history
             WHERE src_mac = ?1 ORDER BY first_seen DESC LIMIT 1",
            rusqlite::params![mac_clone],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap_or((None, None));

        Ok::<_, String>((protocols, destinations, flows, meta.0, meta.1))
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("sankey device_trace", e))?;

    // Baseline enrichment
    let baseline_status = match state.behavior_store.get_profile(&mac).await {
        Ok(Some(profile)) => Some(profile.baseline_status.clone()),
        _ => None,
    };

    Ok(Json(SankeyDeviceResponse {
        mac,
        hostname,
        ip,
        baseline_status,
        protocols,
        destinations,
        flows,
        range: range.to_string(),
    }))
}

// ── GET /api/sankey/device/{mac}/destination/{ip} ─────────────

#[derive(Deserialize)]
pub struct ConversationQuery {
    pub range: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Serialize)]
pub struct ConversationSummary {
    pub total_bytes: i64,
    pub total_connections: i64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub protocols: Vec<String>,
    pub flagged_count: i64,
    pub blocked_count: i64,
}

#[derive(Serialize)]
pub struct ConversationTimelineBucket {
    pub bucket: String,
    pub bytes: i64,
    pub connections: i64,
}

#[derive(Serialize)]
pub struct ConversationConnection {
    pub id: i64,
    pub protocol: String,
    pub src_port: Option<i64>,
    pub dst_port: Option<i64>,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub flagged: bool,
}

#[derive(Serialize)]
pub struct ConversationDetailResponse {
    pub src_mac: String,
    pub dst_ip: String,
    pub src_hostname: Option<String>,
    pub dst_hostname: Option<String>,
    pub baseline_status: Option<String>,
    pub summary: ConversationSummary,
    pub timeline: Vec<ConversationTimelineBucket>,
    pub connections: Vec<ConversationConnection>,
    pub total_pages: i64,
    pub current_page: i64,
    pub range: String,
}

pub async fn conversation_detail(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path((mac, dst_ip)): Path<(String, String)>,
    Query(q): Query<ConversationQuery>,
) -> Result<Json<ConversationDetailResponse>, Response> {
    let range = q.range.as_deref().unwrap_or("24h");
    let offset = range_to_sqlite_offset(range);
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(100).clamp(1, 500);
    let db_offset = (page - 1) * per_page;

    let bucket_format = match range {
        "1h" => "%Y-%m-%dT%H:", // 5-min buckets: use minute truncation below
        "6h" | "24h" => "%Y-%m-%dT%H:00:00",
        "7d" => "will_be_replaced",
        "30d" => "%Y-%m-%d",
        _ => "%Y-%m-%dT%H:00:00",
    };

    // Build the strftime expression for timeline bucketing
    let bucket_expr = match range {
        "1h" => "strftime('%Y-%m-%dT%H:', first_seen) || printf('%02d', (CAST(strftime('%M', first_seen) AS INTEGER) / 5) * 5) || ':00'".to_string(),
        "7d" => "strftime('%Y-%m-%dT', first_seen) || printf('%02d', (CAST(strftime('%H', first_seen) AS INTEGER) / 6) * 6) || ':00:00'".to_string(),
        _ => format!("strftime('{bucket_format}', first_seen)"),
    };

    let store = state.connection_store.clone();
    let mac_clone = mac.clone();
    let dst_ip_clone = dst_ip.clone();
    let (summary, timeline, connections, total_count, src_hostname, dst_hostname) =
        tokio::task::spawn_blocking(move || {
            let db = store.lock_db()
                .map_err(|e| format!("sankey db lock: {e}"))?;

            // Summary stats
            let summary: ConversationSummary = db.query_row(
                &format!(
                    "SELECT
                        COALESCE(SUM(bytes_tx + bytes_rx), 0),
                        COUNT(*),
                        MIN(first_seen),
                        MAX(last_seen),
                        COALESCE(SUM(CASE WHEN flagged = 1 THEN 1 ELSE 0 END), 0)
                     FROM connection_history
                     WHERE src_mac = ?1 AND dst_ip = ?2 AND first_seen >= datetime('now', ?3)"
                ),
                rusqlite::params![mac_clone, dst_ip_clone, offset],
                |row| {
                    Ok(ConversationSummary {
                        total_bytes: row.get(0)?,
                        total_connections: row.get(1)?,
                        first_seen: row.get(2)?,
                        last_seen: row.get(3)?,
                        protocols: Vec::new(), // filled below
                        flagged_count: row.get(4)?,
                        blocked_count: 0, // no blocked column; derive from flagged
                    })
                },
            ).map_err(|e| format!("sankey conversation summary: {e}"))?;

            // Distinct protocols
            let mut proto_stmt = db.prepare(
                "SELECT DISTINCT protocol FROM connection_history
                 WHERE src_mac = ?1 AND dst_ip = ?2 AND first_seen >= datetime('now', ?3)
                 ORDER BY protocol",
            ).map_err(|e| format!("sankey conversation protocols: {e}"))?;

            let protocols: Vec<String> = proto_stmt
                .query_map(rusqlite::params![mac_clone, dst_ip_clone, offset], |row| row.get(0))
                .map_err(|e| format!("sankey conversation protocols: {e}"))?
                .filter_map(|r| r.ok())
                .collect();
            drop(proto_stmt);

            let summary = ConversationSummary { protocols, ..summary };

            // Timeline buckets
            let timeline_sql = format!(
                "SELECT {bucket_expr} as bucket,
                        SUM(bytes_tx + bytes_rx) as total_bytes,
                        COUNT(*) as conn_count
                 FROM connection_history
                 WHERE src_mac = ?1 AND dst_ip = ?2 AND first_seen >= datetime('now', ?3)
                 GROUP BY bucket
                 ORDER BY bucket"
            );

            let mut tl_stmt = db.prepare(&timeline_sql)
                .map_err(|e| format!("sankey conversation timeline: {e}"))?;

            let timeline: Vec<ConversationTimelineBucket> = tl_stmt
                .query_map(rusqlite::params![mac_clone, dst_ip_clone, offset], |row| {
                    Ok(ConversationTimelineBucket {
                        bucket: row.get(0)?,
                        bytes: row.get(1)?,
                        connections: row.get(2)?,
                    })
                })
                .map_err(|e| format!("sankey conversation timeline: {e}"))?
                .filter_map(|r| r.ok())
                .collect();
            drop(tl_stmt);

            // Total count for pagination
            let total_count: i64 = db.query_row(
                "SELECT COUNT(*) FROM connection_history
                 WHERE src_mac = ?1 AND dst_ip = ?2 AND first_seen >= datetime('now', ?3)",
                rusqlite::params![mac_clone, dst_ip_clone, offset],
                |row| row.get(0),
            ).map_err(|e| format!("sankey conversation count: {e}"))?;

            // Paginated connections
            let mut conn_stmt = db.prepare(
                "SELECT rowid, protocol, src_port, dst_port, bytes_tx, bytes_rx,
                        first_seen, last_seen, COALESCE(flagged, 0)
                 FROM connection_history
                 WHERE src_mac = ?1 AND dst_ip = ?2 AND first_seen >= datetime('now', ?3)
                 ORDER BY first_seen DESC
                 LIMIT ?4 OFFSET ?5",
            ).map_err(|e| format!("sankey conversation connections: {e}"))?;

            let connections: Vec<ConversationConnection> = conn_stmt
                .query_map(rusqlite::params![mac_clone, dst_ip_clone, offset, per_page, db_offset], |row| {
                    Ok(ConversationConnection {
                        id: row.get(0)?,
                        protocol: row.get(1)?,
                        src_port: row.get(2)?,
                        dst_port: row.get(3)?,
                        bytes_tx: row.get(4)?,
                        bytes_rx: row.get(5)?,
                        first_seen: row.get(6)?,
                        last_seen: row.get(7)?,
                        flagged: row.get::<_, i64>(8)? != 0,
                    })
                })
                .map_err(|e| format!("sankey conversation connections: {e}"))?
                .filter_map(|r| r.ok())
                .collect();
            drop(conn_stmt);

            // Get hostnames from most recent connection
            let (src_hostname, dst_hostname): (Option<String>, Option<String>) = db.query_row(
                "SELECT src_hostname, dst_hostname FROM connection_history
                 WHERE src_mac = ?1 AND dst_ip = ?2 ORDER BY first_seen DESC LIMIT 1",
                rusqlite::params![mac_clone, dst_ip_clone],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap_or((None, None));

            Ok::<_, String>((summary, timeline, connections, total_count, src_hostname, dst_hostname))
        })
        .await
        .map_err(|e| internal_error("spawn_blocking", e))?
        .map_err(|e| internal_error("sankey conversation_detail", e))?;

    // Async enrichment — baseline status from behavior store
    let baseline_status = match state.behavior_store.get_profile(&mac).await {
        Ok(Some(profile)) => Some(profile.baseline_status.clone()),
        _ => None,
    };

    let total_pages = (total_count + per_page - 1) / per_page;

    Ok(Json(ConversationDetailResponse {
        src_mac: mac,
        dst_ip,
        src_hostname,
        dst_hostname,
        baseline_status,
        summary,
        timeline,
        connections,
        total_pages,
        current_page: page,
        range: range.to_string(),
    }))
}

// ── GET /api/sankey/destination/{ip}/devices ──────────────────

#[derive(Serialize)]
pub struct SankeyDestinationPeer {
    pub mac: String,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub bytes: i64,
    pub connections: i64,
}

#[derive(Serialize)]
pub struct SankeyDestinationPeersResponse {
    pub dst_ip: String,
    pub peers: Vec<SankeyDestinationPeer>,
    pub range: String,
}

pub async fn destination_peers(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(dst_ip): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<SankeyDestinationPeersResponse>, Response> {
    let range = q.range.as_deref().unwrap_or("24h");
    let offset = range_to_sqlite_offset(range);

    let store = state.connection_store.clone();
    let dst_ip_clone = dst_ip.clone();
    let peers = tokio::task::spawn_blocking(move || {
        let db = store.lock_db()
            .map_err(|e| format!("sankey db lock: {e}"))?;

        let mut stmt = db.prepare(
            "SELECT COALESCE(src_mac, src_ip) as mac, src_hostname, src_ip,
                    SUM(bytes_tx + bytes_rx) as total_bytes, COUNT(*) as conn_count
             FROM connection_history
             WHERE dst_ip = ?1 AND first_seen >= datetime('now', ?2)
             GROUP BY mac
             ORDER BY total_bytes DESC
             LIMIT 100",
        ).map_err(|e| format!("sankey dest peers query: {e}"))?;

        let peers: Vec<SankeyDestinationPeer> = stmt
            .query_map(rusqlite::params![dst_ip_clone, offset], |row| {
                Ok(SankeyDestinationPeer {
                    mac: row.get(0)?,
                    hostname: row.get(1)?,
                    ip: row.get(2)?,
                    bytes: row.get(3)?,
                    connections: row.get(4)?,
                })
            })
            .map_err(|e| format!("sankey dest peers query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();

        Ok::<_, String>(peers)
    })
    .await
    .map_err(|e| internal_error("spawn_blocking", e))?
    .map_err(|e| internal_error("sankey destination_peers", e))?;

    Ok(Json(SankeyDestinationPeersResponse {
        dst_ip,
        peers,
        range: range.to_string(),
    }))
}

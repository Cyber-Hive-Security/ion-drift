//! Persistent connection history store backed by SQLite.
//!
//! Stores every observed connection (from polling or syslog) with GeoIP enrichment,
//! deduplication by conntrack ID, and configurable retention.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::geo::{self, GeoCache, GeoInfo};

/// Default retention for closed connections.
const DEFAULT_RETENTION_DAYS: i64 = 30;

/// Connection history store.
pub struct ConnectionStore {
    db: Mutex<rusqlite::Connection>,
}

/// A row in the connection_history table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionHistoryRow {
    pub id: i64,
    pub conntrack_id: Option<String>,
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: Option<i64>,
    pub src_mac: Option<String>,
    pub src_vlan: Option<String>,
    pub src_hostname: Option<String>,
    pub dst_vlan: Option<String>,
    pub dst_hostname: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub closed: bool,
    pub last_state: Option<String>,
    pub duration_seconds: Option<i64>,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
    pub data_source: String,
    pub poll_count: i64,
    pub dst_is_external: bool,
    pub geo_country_code: Option<String>,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_asn: Option<i64>,
    pub geo_org: Option<String>,
    pub geo_lat: Option<f64>,
    pub geo_lon: Option<f64>,
    pub flagged: bool,
    pub anomaly_id: Option<i64>,
}

/// Data needed to insert/update from a poll cycle.
pub struct PollConnection {
    pub conntrack_id: String,
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: Option<i64>,
    pub src_mac: Option<String>,
    pub tcp_state: Option<String>,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
}

/// Data from a syslog event.
pub struct SyslogEvent {
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<i64>,
    pub dst_port: Option<i64>,
    pub src_mac: Option<String>,
    pub action: Option<String>,
    pub in_interface: Option<String>,
    pub timestamp: String,
}

/// Aggregated per-country data for the world map.
#[derive(Debug, Clone, Serialize)]
pub struct GeoSummaryEntry {
    pub country_code: String,
    pub country: String,
    pub lat: f64,
    pub lon: f64,
    pub connection_count: i64,
    pub unique_sources: i64,
    pub unique_destinations: i64,
    pub total_tx: i64,
    pub total_rx: i64,
    pub top_orgs: Vec<String>,
    pub flagged_count: i64,
}

/// Aggregated per-city data for city-level dots on the world map.
#[derive(Debug, Clone, Serialize)]
pub struct CitySummaryEntry {
    pub city: String,
    pub country_code: String,
    pub lat: f64,
    pub lon: f64,
    pub connection_count: i64,
    pub unique_ips: i64,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
    pub top_orgs: Vec<String>,
    pub flagged_count: i64,
}

/// Aggregated per-port data for Sankey diagram.
#[derive(Debug, Clone, Serialize)]
pub struct PortSummaryEntry {
    pub dst_port: i64,
    pub protocol: String,
    pub total_bytes: i64,
    pub flow_count: i64,
    pub unique_sources: i64,
    pub unique_destinations: i64,
}

/// A row in the port_flow_baseline table.
#[derive(Debug, Clone, Serialize)]
pub struct PortFlowBaseline {
    pub flow_direction: String,
    pub protocol: String,
    pub dst_port: i64,
    pub service_name: Option<String>,
    pub avg_bytes_per_day: i64,
    pub max_bytes_per_day: i64,
    pub avg_connections_per_day: i64,
    pub max_connections_per_day: i64,
    pub days_present: i64,
    pub typical_sources: Option<String>,
    pub typical_destinations: Option<String>,
    pub computed_at: String,
}

/// Anomaly classification for a port flow.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowClassification {
    Normal,
    NewPort,
    VolumeSpike,
    SourceAnomaly,
    Disappeared,
}

/// Enhanced port summary entry with anomaly classification.
#[derive(Debug, Clone, Serialize)]
pub struct ClassifiedPortFlow {
    pub dst_port: i64,
    pub protocol: String,
    pub total_bytes: i64,
    pub flow_count: i64,
    pub unique_sources: i64,
    pub unique_destinations: i64,
    pub classification: FlowClassification,
    pub baseline_avg_bytes: Option<i64>,
    pub volume_ratio: Option<f64>,
    pub days_in_baseline: i64,
    pub top_sources: Vec<String>,
    pub new_sources: Vec<String>,
    pub involved_devices: Vec<InvolvedDevice>,
}

/// Summary for a direction's classified flows.
#[derive(Debug, Clone, Serialize)]
pub struct ClassifiedPortSummary {
    pub anomaly_count: usize,
    pub has_baselines: bool,
    pub flows: Vec<ClassifiedPortFlow>,
    pub disappeared: Vec<ClassifiedPortFlow>,
}

/// Port flow baseline status for the settings/debug endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct PortBaselineStatus {
    pub total_baselines: i64,
    pub outbound_count: i64,
    pub internal_count: i64,
    pub last_computed: Option<String>,
}

/// A row in the anomaly_links table.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyLink {
    pub id: i64,
    pub port_anomaly_type: String,
    pub flow_direction: String,
    pub protocol: String,
    pub dst_port: i64,
    pub device_mac: String,
    pub device_ip: String,
    pub device_vlan: Option<String>,
    pub device_hostname: Option<String>,
    pub behavior_anomaly_id: Option<i64>,
    pub correlated: bool,
    pub source: String,
    pub severity: String,
    pub device_bytes: i64,
    pub device_connections: i64,
    pub port_is_baselined: bool,
    pub port_days_in_baseline: i64,
    pub created_at: String,
    pub resolved_at: Option<String>,
    pub resolved_by: Option<String>,
}

/// Data needed to insert a new anomaly link.
pub struct NewAnomalyLink {
    pub port_anomaly_type: String,
    pub flow_direction: String,
    pub protocol: String,
    pub dst_port: i64,
    pub device_mac: String,
    pub device_ip: String,
    pub device_vlan: Option<String>,
    pub device_hostname: Option<String>,
    pub behavior_anomaly_id: Option<i64>,
    pub correlated: bool,
    pub source: String,
    pub severity: String,
    pub device_bytes: i64,
    pub device_connections: i64,
    pub port_is_baselined: bool,
    pub port_days_in_baseline: i64,
}

/// A device involved in a port flow anomaly (for API enrichment).
#[derive(Debug, Clone, Serialize)]
pub struct InvolvedDevice {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub vlan: Option<String>,
    pub bytes: i64,
    pub connections: i64,
    pub has_behavior_anomaly: bool,
    pub behavior_anomaly_id: Option<i64>,
    pub correlated: bool,
}

/// Port flow context for a device anomaly.
#[derive(Debug, Clone, Serialize)]
pub struct PortFlowContext {
    pub port: i64,
    pub protocol: String,
    pub port_is_baselined: bool,
    pub port_days_in_baseline: i64,
    pub correlated: bool,
    pub other_devices_count: i64,
    pub network_level_classification: String,
    pub total_network_bytes_on_port: i64,
}

/// Well-known service ports that should never be treated as ephemeral.
const KNOWN_SERVICE_PORTS: &[i64] = &[
    20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 161,
    443, 465, 554, 587, 993, 995,
    1433, 1883, 3000, 3306, 3389, 5060, 5228, 5432, 5672, 6379,
    8080, 8443, 8554, 8883, 9001, 9090, 9443,
    27017, 32400,
];

fn is_ephemeral_port(port: i64) -> bool {
    port >= 10_000 && !KNOWN_SERVICE_PORTS.contains(&port)
}

/// Weekly snapshot record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklySnapshot {
    pub id: i64,
    pub snapshot_week: String,
    pub snapshot_type: String,
    pub period_start: String,
    pub period_end: String,
    pub data: String,
    pub summary: String,
    pub created_at: String,
}

/// Summary entry for listing snapshots.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotListEntry {
    pub week: String,
    pub types: Vec<String>,
    pub summary: String,
}

/// Pagination wrapper.
#[derive(Debug, Clone, Serialize)]
pub struct PaginatedHistory {
    pub items: Vec<ConnectionHistoryRow>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

/// Filters for history queries.
#[derive(Debug, Default, Deserialize)]
pub struct HistoryFilters {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i64>,
    pub protocol: Option<String>,
    pub country: Option<String>,
    pub closed: Option<bool>,
    pub flagged: Option<bool>,
    pub after: Option<String>,
    pub before: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

/// Connection history stats for the settings page.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionHistoryStats {
    pub retention_days: i64,
    pub row_count: i64,
    pub db_size_bytes: i64,
    pub oldest_record: Option<String>,
}

impl ConnectionStore {
    /// Acquire a lock on the underlying database connection.
    pub fn lock_db(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, String> {
        self.db.lock().map_err(|e| format!("db lock: {e}"))
    }

    /// Create a new ConnectionStore backed by SQLite at the given path.
    pub fn new(db_path: &Path) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;",
        )?;
        conn.execute_batch(include_str!("connection_store_schema.sql"))?;
        Ok(Self {
            db: Mutex::new(conn),
        })
    }

    /// Insert or update a connection from a poll cycle.
    /// Returns true if a new row was inserted.
    pub fn upsert_from_poll(
        &self,
        conn: &PollConnection,
        geo_cache: &GeoCache,
    ) -> anyhow::Result<bool> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let now = now_iso();

        // Try to find existing open row by conntrack ID
        let existing_id: Option<i64> = db
            .query_row(
                "SELECT id FROM connection_history WHERE conntrack_id = ?1 AND closed = 0",
                params![conn.conntrack_id],
                |row| row.get(0),
            )
            .ok();

        if let Some(id) = existing_id {
            // Update existing row
            db.execute(
                "UPDATE connection_history SET
                    last_seen = ?1,
                    bytes_tx = ?2,
                    bytes_rx = ?3,
                    last_state = ?4,
                    poll_count = poll_count + 1
                 WHERE id = ?5",
                params![now, conn.bytes_tx, conn.bytes_rx, conn.tcp_state, id],
            )?;
            Ok(false)
        } else {
            // Insert new row with GeoIP enrichment
            let dst_is_external = conn
                .dst_ip
                .parse::<std::net::IpAddr>()
                .map(|a| !geo::is_private(&a))
                .unwrap_or(false);

            let geo = if dst_is_external {
                geo_cache.lookup_cached(&conn.dst_ip)
            } else {
                None
            };

            let src_vlan = vlan_label(&conn.src_ip);
            let dst_vlan = if dst_is_external {
                None
            } else {
                vlan_label(&conn.dst_ip)
            };

            let flagged = geo
                .as_ref()
                .map(|g| GeoCache::is_flagged(&g.country_code))
                .unwrap_or(false);

            db.execute(
                "INSERT INTO connection_history (
                    conntrack_id, protocol, src_ip, dst_ip, dst_port,
                    src_mac, src_vlan, dst_vlan,
                    first_seen, last_seen, closed, last_state,
                    bytes_tx, bytes_rx, data_source, poll_count,
                    dst_is_external, geo_country_code, geo_country, geo_city,
                    geo_asn, geo_org, geo_lat, geo_lon, flagged
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5,
                    ?6, ?7, ?8,
                    ?9, ?10, 0, ?11,
                    ?12, ?13, 'poll', 1,
                    ?14, ?15, ?16, ?17,
                    ?18, ?19, ?20, ?21, ?22
                )",
                params![
                    conn.conntrack_id,
                    conn.protocol,
                    conn.src_ip,
                    conn.dst_ip,
                    conn.dst_port,
                    conn.src_mac,
                    src_vlan,
                    dst_vlan,
                    now,
                    now,
                    conn.tcp_state,
                    conn.bytes_tx,
                    conn.bytes_rx,
                    dst_is_external as i64,
                    geo.as_ref().map(|g| g.country_code.as_str()),
                    geo.as_ref().map(|g| g.country.as_str()),
                    geo.as_ref().and_then(|g| g.city.as_deref()),
                    geo.as_ref()
                        .and_then(|g| g.asn.as_deref())
                        .and_then(|s| s.strip_prefix("AS"))
                        .and_then(|s| s.parse::<i64>().ok()),
                    geo.as_ref().and_then(|g| g.org.as_deref()),
                    geo.as_ref().and_then(|g| g.lat),
                    geo.as_ref().and_then(|g| g.lon),
                    flagged as i64,
                ],
            )?;
            Ok(true)
        }
    }

    /// Mark connections as closed if their conntrack ID is not in the current poll set.
    /// Uses a 2-cycle grace period (>threshold_secs since last_seen).
    pub fn close_stale(&self, active_conntrack_ids: &[String], threshold_secs: i64) -> anyhow::Result<usize> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let cutoff = now_iso_minus_secs(threshold_secs);

        // Build a temp table of active IDs for efficient lookup
        db.execute("CREATE TEMP TABLE IF NOT EXISTS _active_ids (cid TEXT PRIMARY KEY)", [])?;
        db.execute("DELETE FROM _active_ids", [])?;
        {
            let mut stmt = db.prepare("INSERT OR IGNORE INTO _active_ids (cid) VALUES (?1)")?;
            for id in active_conntrack_ids {
                stmt.execute(params![id])?;
            }
        }

        let count = db.execute(
            "UPDATE connection_history SET
                closed = 1,
                duration_seconds = CAST(
                    (julianday(last_seen) - julianday(first_seen)) * 86400 AS INTEGER
                )
             WHERE closed = 0
               AND conntrack_id IS NOT NULL
               AND conntrack_id NOT IN (SELECT cid FROM _active_ids)
               AND last_seen < ?1",
            params![cutoff],
        )?;

        db.execute("DROP TABLE IF EXISTS _active_ids", [])?;
        Ok(count)
    }

    /// Insert or merge a syslog event into connection history.
    pub fn upsert_from_syslog(
        &self,
        event: &SyslogEvent,
        geo_cache: &GeoCache,
    ) -> anyhow::Result<bool> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;

        // Try to find matching open row by flow tuple
        let existing_id: Option<i64> = db
            .query_row(
                "SELECT id FROM connection_history
                 WHERE protocol = ?1 AND src_ip = ?2 AND dst_ip = ?3
                   AND (dst_port = ?4 OR (?4 IS NULL AND dst_port IS NULL))
                   AND closed = 0
                 ORDER BY last_seen DESC LIMIT 1",
                params![event.protocol, event.src_ip, event.dst_ip, event.dst_port],
                |row| row.get(0),
            )
            .ok();

        if let Some(id) = existing_id {
            // Merge: update data_source to 'both', optionally close
            let is_close = event
                .action
                .as_deref()
                .map(|a| a == "drop" || a == "reject")
                .unwrap_or(false);
            if is_close {
                db.execute(
                    "UPDATE connection_history SET
                        data_source = CASE WHEN data_source = 'poll' THEN 'both' ELSE data_source END,
                        closed = 1,
                        last_seen = ?1,
                        duration_seconds = CAST(
                            (julianday(?1) - julianday(first_seen)) * 86400 AS INTEGER
                        )
                     WHERE id = ?2",
                    params![event.timestamp, id],
                )?;
            } else {
                db.execute(
                    "UPDATE connection_history SET
                        data_source = CASE WHEN data_source = 'poll' THEN 'both' ELSE data_source END,
                        last_seen = ?1
                     WHERE id = ?2",
                    params![event.timestamp, id],
                )?;
            }
            Ok(false)
        } else {
            // New syslog-only entry
            let dst_is_external = event
                .dst_ip
                .parse::<std::net::IpAddr>()
                .map(|a| !geo::is_private(&a))
                .unwrap_or(false);

            let geo = if dst_is_external {
                geo_cache.lookup_cached(&event.dst_ip)
            } else {
                None
            };

            let src_vlan = vlan_label(&event.src_ip);
            let dst_vlan = if dst_is_external {
                None
            } else {
                vlan_label(&event.dst_ip)
            };

            let flagged = geo
                .as_ref()
                .map(|g| GeoCache::is_flagged(&g.country_code))
                .unwrap_or(false);

            db.execute(
                "INSERT INTO connection_history (
                    conntrack_id, protocol, src_ip, dst_ip, dst_port,
                    src_mac, src_vlan, dst_vlan,
                    first_seen, last_seen, closed, last_state,
                    bytes_tx, bytes_rx, data_source, poll_count,
                    dst_is_external, geo_country_code, geo_country, geo_city,
                    geo_asn, geo_org, geo_lat, geo_lon, flagged
                ) VALUES (
                    NULL, ?1, ?2, ?3, ?4,
                    ?5, ?6, ?7,
                    ?8, ?9, 0, NULL,
                    0, 0, 'syslog', 0,
                    ?10, ?11, ?12, ?13,
                    ?14, ?15, ?16, ?17, ?18
                )",
                params![
                    event.protocol,
                    event.src_ip,
                    event.dst_ip,
                    event.dst_port,
                    event.src_mac,
                    src_vlan,
                    dst_vlan,
                    event.timestamp,
                    event.timestamp,
                    dst_is_external as i64,
                    geo.as_ref().map(|g| g.country_code.as_str()),
                    geo.as_ref().map(|g| g.country.as_str()),
                    geo.as_ref().and_then(|g| g.city.as_deref()),
                    geo.as_ref()
                        .and_then(|g| g.asn.as_deref())
                        .and_then(|s| s.strip_prefix("AS"))
                        .and_then(|s| s.parse::<i64>().ok()),
                    geo.as_ref().and_then(|g| g.org.as_deref()),
                    geo.as_ref().and_then(|g| g.lat),
                    geo.as_ref().and_then(|g| g.lon),
                    flagged as i64,
                ],
            )?;
            Ok(true)
        }
    }

    /// Query connection history with filters and pagination.
    pub fn query_history(&self, filters: &HistoryFilters) -> anyhow::Result<PaginatedHistory> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;

        let page = filters.page.unwrap_or(1).max(1);
        let per_page = filters.per_page.unwrap_or(50).clamp(1, 500);
        let offset = (page - 1) * per_page;

        let (where_clause, bind_values) = build_filter_clause(filters);

        // Count total matching rows
        let count_sql = format!("SELECT COUNT(*) FROM connection_history {where_clause}");
        let total: i64 = {
            let mut stmt = db.prepare(&count_sql)?;
            bind_and_query_scalar(&mut stmt, &bind_values)?
        };

        // Fetch page
        let select_sql = format!(
            "SELECT id, conntrack_id, protocol, src_ip, dst_ip, dst_port,
                    src_mac, src_vlan, src_hostname, dst_vlan, dst_hostname,
                    first_seen, last_seen, closed, last_state, duration_seconds,
                    bytes_tx, bytes_rx, data_source, poll_count,
                    dst_is_external, geo_country_code, geo_country, geo_city,
                    geo_asn, geo_org, geo_lat, geo_lon, flagged, anomaly_id
             FROM connection_history {where_clause}
             ORDER BY last_seen DESC
             LIMIT {per_page} OFFSET {offset}"
        );

        let mut stmt = db.prepare(&select_sql)?;
        let items = bind_and_query_rows(&mut stmt, &bind_values)?;

        Ok(PaginatedHistory {
            items,
            total,
            page,
            per_page,
        })
    }

    /// Aggregated per-country GeoIP data for the world map.
    pub fn geo_summary(&self, days: i64) -> anyhow::Result<Vec<GeoSummaryEntry>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let cutoff = now_iso_minus_secs(days * 86400);

        let mut stmt = db.prepare(
            "SELECT geo_country_code, geo_country,
                    AVG(geo_lat) as lat, AVG(geo_lon) as lon,
                    COUNT(*) as connection_count,
                    COUNT(DISTINCT src_ip) as unique_sources,
                    COUNT(DISTINCT dst_ip) as unique_destinations,
                    SUM(bytes_tx) as total_tx,
                    SUM(bytes_rx) as total_rx,
                    GROUP_CONCAT(DISTINCT geo_org) as orgs,
                    SUM(CASE WHEN flagged = 1 THEN 1 ELSE 0 END) as flagged_count
             FROM connection_history
             WHERE dst_is_external = 1
               AND geo_country_code IS NOT NULL
               AND first_seen >= ?1
             GROUP BY geo_country_code
             ORDER BY connection_count DESC",
        )?;

        let rows = stmt
            .query_map(params![cutoff], |row| {
                let orgs_str: Option<String> = row.get(9)?;
                let top_orgs: Vec<String> = orgs_str
                    .unwrap_or_default()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .take(5)
                    .map(String::from)
                    .collect();

                Ok(GeoSummaryEntry {
                    country_code: row.get(0)?,
                    country: row.get(1)?,
                    lat: row.get::<_, f64>(2).unwrap_or(0.0),
                    lon: row.get::<_, f64>(3).unwrap_or(0.0),
                    connection_count: row.get(4)?,
                    unique_sources: row.get(5)?,
                    unique_destinations: row.get(6)?,
                    total_tx: row.get::<_, i64>(7).unwrap_or(0),
                    total_rx: row.get::<_, i64>(8).unwrap_or(0),
                    top_orgs,
                    flagged_count: row.get::<_, i64>(10).unwrap_or(0),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    /// Aggregated per-city GeoIP data for city-level dots on the world map.
    pub fn city_summary(&self, days: i64, min_connections: i64) -> anyhow::Result<Vec<CitySummaryEntry>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let cutoff = now_iso_minus_secs(days * 86400);

        let mut stmt = db.prepare(
            "SELECT geo_city, geo_country_code,
                    AVG(geo_lat) as lat, AVG(geo_lon) as lon,
                    COUNT(*) as connection_count,
                    COUNT(DISTINCT dst_ip) as unique_ips,
                    SUM(bytes_tx) as total_tx,
                    SUM(bytes_rx) as total_rx,
                    GROUP_CONCAT(DISTINCT geo_org) as orgs,
                    SUM(CASE WHEN flagged = 1 THEN 1 ELSE 0 END) as flagged_count
             FROM connection_history
             WHERE dst_is_external = 1
               AND geo_city IS NOT NULL
               AND geo_city != ''
               AND geo_lat IS NOT NULL
               AND geo_lon IS NOT NULL
               AND first_seen >= ?1
             GROUP BY geo_city, geo_country_code
             HAVING COUNT(*) >= ?2
             ORDER BY connection_count DESC",
        )?;

        let rows = stmt
            .query_map(params![cutoff, min_connections], |row| {
                let orgs_str: Option<String> = row.get(8)?;
                let top_orgs: Vec<String> = orgs_str
                    .unwrap_or_default()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .take(5)
                    .map(String::from)
                    .collect();

                Ok(CitySummaryEntry {
                    city: row.get(0)?,
                    country_code: row.get(1)?,
                    lat: row.get::<_, f64>(2).unwrap_or(0.0),
                    lon: row.get::<_, f64>(3).unwrap_or(0.0),
                    connection_count: row.get(4)?,
                    unique_ips: row.get(5)?,
                    bytes_tx: row.get::<_, i64>(6).unwrap_or(0),
                    bytes_rx: row.get::<_, i64>(7).unwrap_or(0),
                    top_orgs,
                    flagged_count: row.get::<_, i64>(9).unwrap_or(0),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    /// Aggregated per-port data for the Sankey diagram, filtered by direction.
    /// direction: "outbound" | "inbound" | "internal" | "" (all)
    pub fn port_summary(&self, days: i64, direction: &str) -> anyhow::Result<Vec<PortSummaryEntry>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let cutoff = now_iso_minus_secs(days * 86400);

        let direction_filter = match direction {
            "outbound" => "AND dst_is_external = 1",
            "inbound" => "AND dst_is_external = 0 AND src_vlan IS NULL",
            "internal" => "AND dst_is_external = 0 AND src_vlan IS NOT NULL",
            _ => "",
        };

        let sql = format!(
            "SELECT dst_port, protocol,
                    SUM(bytes_tx + bytes_rx) as total_bytes,
                    COUNT(*) as flow_count,
                    COUNT(DISTINCT src_ip) as unique_sources,
                    COUNT(DISTINCT dst_ip) as unique_destinations
             FROM connection_history
             WHERE first_seen >= ?1
               AND dst_port IS NOT NULL
               {direction_filter}
             GROUP BY dst_port, protocol
             HAVING SUM(bytes_tx + bytes_rx) >= 100000
             ORDER BY total_bytes DESC"
        );

        let mut stmt = db.prepare(&sql)?;
        let rows: Vec<PortSummaryEntry> = stmt
            .query_map(params![cutoff], |row| {
                Ok(PortSummaryEntry {
                    dst_port: row.get(0)?,
                    protocol: row.get(1)?,
                    total_bytes: row.get::<_, i64>(2).unwrap_or(0),
                    flow_count: row.get(3)?,
                    unique_sources: row.get(4)?,
                    unique_destinations: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Filter out ephemeral ports unless they have > 1GB traffic
        let filtered: Vec<PortSummaryEntry> = rows
            .into_iter()
            .filter(|e| !is_ephemeral_port(e.dst_port) || e.total_bytes >= 1_073_741_824)
            .collect();

        Ok(filtered)
    }

    /// Prune closed connections older than retention_days.
    pub fn prune(&self, retention_days: i64) -> anyhow::Result<usize> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let cutoff = now_iso_minus_secs(retention_days * 86400);

        // Delete old closed connections
        let deleted = db.execute(
            "DELETE FROM connection_history WHERE closed = 1 AND last_seen < ?1",
            params![cutoff],
        )?;

        // Force-close stale open connections (last_seen > 1 day ago)
        let stale_cutoff = now_iso_minus_secs(86400);
        db.execute(
            "UPDATE connection_history SET
                closed = 1,
                duration_seconds = CAST(
                    (julianday(last_seen) - julianday(first_seen)) * 86400 AS INTEGER
                )
             WHERE closed = 0 AND last_seen < ?1",
            params![stale_cutoff],
        )?;

        Ok(deleted)
    }

    /// Get connection history statistics for the settings page.
    pub fn stats(&self) -> anyhow::Result<ConnectionHistoryStats> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;

        let row_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM connection_history",
            [],
            |row| row.get(0),
        )?;

        let oldest_record: Option<String> = db
            .query_row(
                "SELECT MIN(first_seen) FROM connection_history",
                [],
                |row| row.get(0),
            )
            .ok()
            .flatten();

        let db_size_bytes: i64 = db.query_row(
            "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
            [],
            |row| row.get(0),
        ).unwrap_or(0);

        Ok(ConnectionHistoryStats {
            retention_days: DEFAULT_RETENTION_DAYS,
            row_count,
            db_size_bytes,
            oldest_record,
        })
    }

    // ── Snapshot methods ─────────────────────────────────────────

    /// Save a weekly snapshot.
    pub fn save_snapshot(
        &self,
        week: &str,
        snapshot_type: &str,
        data: &str,
        summary: &str,
    ) -> anyhow::Result<()> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let now = now_iso();

        // Compute period_start and period_end from the ISO week string
        let (period_start, period_end) = week_to_period(week);

        db.execute(
            "INSERT OR REPLACE INTO weekly_snapshots
                (snapshot_week, snapshot_type, period_start, period_end, data, summary, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![week, snapshot_type, period_start, period_end, data, summary, now],
        )?;
        Ok(())
    }

    /// List available weekly snapshots.
    pub fn list_snapshots(&self) -> anyhow::Result<Vec<SnapshotListEntry>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;

        let mut stmt = db.prepare(
            "SELECT snapshot_week, GROUP_CONCAT(snapshot_type), MAX(summary)
             FROM weekly_snapshots
             GROUP BY snapshot_week
             ORDER BY snapshot_week DESC",
        )?;

        let rows = stmt
            .query_map([], |row| {
                let types_str: String = row.get(1)?;
                let types: Vec<String> = types_str.split(',').map(String::from).collect();
                Ok(SnapshotListEntry {
                    week: row.get(0)?,
                    types,
                    summary: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    /// Get a specific snapshot by week and type.
    pub fn get_snapshot(&self, week: &str, snapshot_type: &str) -> anyhow::Result<Option<WeeklySnapshot>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;

        let result = db
            .query_row(
                "SELECT id, snapshot_week, snapshot_type, period_start, period_end,
                        data, summary, created_at
                 FROM weekly_snapshots
                 WHERE snapshot_week = ?1 AND snapshot_type = ?2",
                params![week, snapshot_type],
                |row| {
                    Ok(WeeklySnapshot {
                        id: row.get(0)?,
                        snapshot_week: row.get(1)?,
                        snapshot_type: row.get(2)?,
                        period_start: row.get(3)?,
                        period_end: row.get(4)?,
                        data: row.get(5)?,
                        summary: row.get(6)?,
                        created_at: row.get(7)?,
                    })
                },
            )
            .ok();

        Ok(result)
    }

    /// Look up a well-known service name for a port number.
    fn service_name(port: i64) -> Option<&'static str> {
        match port {
            20 => Some("FTP-Data"),
            21 => Some("FTP"),
            22 => Some("SSH"),
            25 => Some("SMTP"),
            53 => Some("DNS"),
            67 => Some("DHCP-S"),
            68 => Some("DHCP-C"),
            80 => Some("HTTP"),
            110 => Some("POP3"),
            123 => Some("NTP"),
            143 => Some("IMAP"),
            161 => Some("SNMP"),
            443 => Some("HTTPS"),
            445 => Some("SMB"),
            465 => Some("SMTPS"),
            554 => Some("RTSP"),
            587 => Some("Submission"),
            993 => Some("IMAPS"),
            995 => Some("POP3S"),
            1433 => Some("MSSQL"),
            1883 => Some("MQTT"),
            3000 => Some("Dev"),
            3306 => Some("MySQL"),
            3389 => Some("RDP"),
            4444 => Some("Metasploit"),
            5060 => Some("SIP"),
            5228 => Some("GCM"),
            5432 => Some("PostgreSQL"),
            5514 => Some("Syslog"),
            5672 => Some("AMQP"),
            6379 => Some("Redis"),
            8080 => Some("HTTP-Alt"),
            8443 => Some("HTTPS-Alt"),
            8554 => Some("RTSP-Alt"),
            8883 => Some("MQTT-TLS"),
            9001 => Some("Portainer"),
            9090 => Some("Prometheus"),
            9443 => Some("Alt-HTTPS"),
            27017 => Some("MongoDB"),
            32400 => Some("Plex"),
            _ => None,
        }
    }

    /// Compute and store port flow baselines from the last 7 days of connection history.
    /// Returns the number of baselines upserted.
    pub fn compute_port_flow_baselines(&self) -> anyhow::Result<usize> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let now = now_iso();
        let cutoff = now_iso_minus_secs(7 * 86400);

        // Query per-day aggregates for each (direction, protocol, dst_port) combination.
        // We use julianday to bucket by day.
        let mut stmt = db.prepare(
            "SELECT
                CASE
                    WHEN dst_is_external = 1 THEN 'outbound'
                    WHEN src_vlan IS NOT NULL THEN 'internal'
                    ELSE 'other'
                END AS flow_dir,
                protocol,
                dst_port,
                CAST(julianday(first_seen) - 0.5 AS INTEGER) AS day_bucket,
                SUM(bytes_tx + bytes_rx) AS day_bytes,
                COUNT(*) AS day_connections,
                GROUP_CONCAT(DISTINCT src_ip) AS sources,
                GROUP_CONCAT(DISTINCT dst_ip) AS destinations
             FROM connection_history
             WHERE first_seen >= ?1
               AND dst_port IS NOT NULL
             GROUP BY flow_dir, protocol, dst_port, day_bucket
             HAVING flow_dir IN ('outbound', 'internal')"
        )?;

        // Collect into a map: (direction, protocol, port) -> Vec<(day_bytes, day_conns, sources, dests)>
        struct DayData {
            bytes: i64,
            connections: i64,
            sources: Vec<String>,
            destinations: Vec<String>,
        }

        let mut baselines: std::collections::HashMap<(String, String, i64), Vec<DayData>> =
            std::collections::HashMap::new();

        let rows = stmt.query_map(params![cutoff], |row| {
            let dir: String = row.get(0)?;
            let proto: String = row.get(1)?;
            let port: i64 = row.get(2)?;
            let _day: i64 = row.get(3)?;
            let bytes: i64 = row.get::<_, i64>(4).unwrap_or(0);
            let conns: i64 = row.get(5)?;
            let srcs: Option<String> = row.get(6)?;
            let dsts: Option<String> = row.get(7)?;
            Ok((dir, proto, port, bytes, conns, srcs, dsts))
        })?;

        for row in rows {
            let (dir, proto, port, bytes, conns, srcs, dsts) = row?;
            let key = (dir, proto, port);
            let sources: Vec<String> = srcs
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            let destinations: Vec<String> = dsts
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            baselines.entry(key).or_default().push(DayData {
                bytes,
                connections: conns,
                sources,
                destinations,
            });
        }

        // Upsert baselines
        let mut upsert_stmt = db.prepare(
            "INSERT OR REPLACE INTO port_flow_baseline (
                flow_direction, protocol, dst_port, service_name,
                avg_bytes_per_day, max_bytes_per_day,
                avg_connections_per_day, max_connections_per_day,
                days_present, typical_sources, typical_destinations,
                computed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
        )?;

        let mut count = 0usize;
        for ((direction, protocol, port), days) in &baselines {
            let days_present = days.len() as i64;
            let total_bytes: i64 = days.iter().map(|d| d.bytes).sum();
            let max_bytes: i64 = days.iter().map(|d| d.bytes).max().unwrap_or(0);
            let avg_bytes = total_bytes / days_present.max(1);
            let total_conns: i64 = days.iter().map(|d| d.connections).sum();
            let max_conns: i64 = days.iter().map(|d| d.connections).max().unwrap_or(0);
            let avg_conns = total_conns / days_present.max(1);

            // Collect unique sources/destinations across all days
            let mut all_sources: Vec<String> = days
                .iter()
                .flat_map(|d| d.sources.iter().cloned())
                .collect();
            all_sources.sort();
            all_sources.dedup();
            let all_sources: Vec<&str> = all_sources.iter().take(50).map(|s| s.as_str()).collect();

            let mut all_dests: Vec<String> = days
                .iter()
                .flat_map(|d| d.destinations.iter().cloned())
                .collect();
            all_dests.sort();
            all_dests.dedup();
            let all_dests: Vec<&str> = all_dests.iter().take(50).map(|s| s.as_str()).collect();

            let sources_json = serde_json::to_string(&all_sources).unwrap_or_else(|_| "[]".into());
            let dests_json = serde_json::to_string(&all_dests).unwrap_or_else(|_| "[]".into());
            let svc_name = Self::service_name(*port);

            upsert_stmt.execute(params![
                direction,
                protocol,
                port,
                svc_name,
                avg_bytes,
                max_bytes,
                avg_conns,
                max_conns,
                days_present,
                sources_json,
                dests_json,
                now,
            ])?;
            count += 1;
        }

        // Prune stale baselines: remove rows not recomputed in 14 days
        let stale_cutoff = now_iso_minus_secs(14 * 86400);
        db.execute(
            "DELETE FROM port_flow_baseline WHERE computed_at < ?1",
            params![stale_cutoff],
        )?;

        Ok(count)
    }

    /// Get all port flow baselines for a specific direction.
    pub fn get_baselines_for_direction(&self, direction: &str) -> anyhow::Result<Vec<PortFlowBaseline>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let mut stmt = db.prepare(
            "SELECT flow_direction, protocol, dst_port, service_name,
                    avg_bytes_per_day, max_bytes_per_day,
                    avg_connections_per_day, max_connections_per_day,
                    days_present, typical_sources, typical_destinations, computed_at
             FROM port_flow_baseline
             WHERE flow_direction = ?1"
        )?;
        let rows = stmt.query_map(params![direction], |row| {
            Ok(PortFlowBaseline {
                flow_direction: row.get(0)?,
                protocol: row.get(1)?,
                dst_port: row.get(2)?,
                service_name: row.get(3)?,
                avg_bytes_per_day: row.get(4)?,
                max_bytes_per_day: row.get(5)?,
                avg_connections_per_day: row.get(6)?,
                max_connections_per_day: row.get(7)?,
                days_present: row.get(8)?,
                typical_sources: row.get(9)?,
                typical_destinations: row.get(10)?,
                computed_at: row.get(11)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get port flow baseline status summary.
    pub fn port_baseline_status(&self) -> anyhow::Result<PortBaselineStatus> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let total: i64 = db.query_row(
            "SELECT COUNT(*) FROM port_flow_baseline", [], |row| row.get(0),
        )?;
        let outbound: i64 = db.query_row(
            "SELECT COUNT(*) FROM port_flow_baseline WHERE flow_direction = 'outbound'",
            [], |row| row.get(0),
        )?;
        let internal: i64 = db.query_row(
            "SELECT COUNT(*) FROM port_flow_baseline WHERE flow_direction = 'internal'",
            [], |row| row.get(0),
        )?;
        let last_computed: Option<String> = db.query_row(
            "SELECT MAX(computed_at) FROM port_flow_baseline",
            [], |row| row.get(0),
        ).ok().flatten();

        Ok(PortBaselineStatus {
            total_baselines: total,
            outbound_count: outbound,
            internal_count: internal,
            last_computed,
        })
    }

    /// Enhanced port summary with anomaly classification.
    /// Compares current flows against the baseline and classifies each flow.
    pub fn classified_port_summary(&self, days: i64, direction: &str) -> anyhow::Result<ClassifiedPortSummary> {
        // Get current flows
        let current_flows = self.port_summary(days, direction)?;

        // Get baselines for this direction
        let baselines = self.get_baselines_for_direction(direction)?;

        // Build baseline lookup: (protocol, port) -> baseline
        let baseline_map: std::collections::HashMap<(String, i64), &PortFlowBaseline> =
            baselines.iter().map(|b| ((b.protocol.clone(), b.dst_port), b)).collect();

        // Get top sources per flow for source anomaly detection
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let cutoff = now_iso_minus_secs(days * 86400);

        let direction_filter = match direction {
            "outbound" => "AND dst_is_external = 1",
            "inbound" => "AND dst_is_external = 0 AND src_vlan IS NULL",
            "internal" => "AND dst_is_external = 0 AND src_vlan IS NOT NULL",
            _ => "",
        };

        let mut classified_flows = Vec::new();
        let mut anomaly_count = 0;

        for flow in &current_flows {
            let key = (flow.protocol.clone(), flow.dst_port);

            // Get current top sources for this flow
            let source_sql = format!(
                "SELECT src_ip, COUNT(*) as cnt FROM connection_history
                 WHERE first_seen >= ?1 AND dst_port = ?2 AND protocol = ?3
                   AND dst_port IS NOT NULL {direction_filter}
                 GROUP BY src_ip ORDER BY cnt DESC LIMIT 20"
            );
            let mut src_stmt = db.prepare(&source_sql)?;
            let top_sources: Vec<String> = src_stmt
                .query_map(params![cutoff, flow.dst_port, flow.protocol], |row| {
                    row.get::<_, String>(0)
                })?
                .filter_map(|r| r.ok())
                .collect();

            let (classification, baseline_avg, volume_ratio, days_in_baseline, new_sources) =
                if let Some(baseline) = baseline_map.get(&key) {
                    // Check volume spike: > 4x max_bytes_per_day
                    let ratio = if baseline.max_bytes_per_day > 0 {
                        flow.total_bytes as f64 / baseline.max_bytes_per_day as f64
                    } else {
                        1.0
                    };

                    if ratio > 4.0 {
                        (
                            FlowClassification::VolumeSpike,
                            Some(baseline.avg_bytes_per_day),
                            Some(ratio),
                            baseline.days_present,
                            Vec::new(),
                        )
                    } else {
                        // Check source anomaly
                        let typical: Vec<String> = baseline
                            .typical_sources
                            .as_deref()
                            .and_then(|s| serde_json::from_str(s).ok())
                            .unwrap_or_default();
                        let new_srcs: Vec<String> = top_sources
                            .iter()
                            .filter(|s| !typical.contains(s))
                            .cloned()
                            .collect();

                        if !new_srcs.is_empty() && !typical.is_empty() {
                            (
                                FlowClassification::SourceAnomaly,
                                Some(baseline.avg_bytes_per_day),
                                Some(ratio),
                                baseline.days_present,
                                new_srcs,
                            )
                        } else {
                            (
                                FlowClassification::Normal,
                                Some(baseline.avg_bytes_per_day),
                                Some(ratio),
                                baseline.days_present,
                                Vec::new(),
                            )
                        }
                    }
                } else {
                    // No baseline — this is a new port
                    (
                        FlowClassification::NewPort,
                        None,
                        None,
                        0,
                        top_sources.clone(),
                    )
                };

            if !matches!(classification, FlowClassification::Normal) {
                anomaly_count += 1;
            }

            // For anomalous flows, look up involved devices from anomaly_links
            let involved_devices = if !matches!(classification, FlowClassification::Normal) {
                Self::query_involved_devices_inner(
                    &db, &flow.protocol, flow.dst_port, direction, &cutoff,
                )?
            } else {
                Vec::new()
            };

            classified_flows.push(ClassifiedPortFlow {
                dst_port: flow.dst_port,
                protocol: flow.protocol.clone(),
                total_bytes: flow.total_bytes,
                flow_count: flow.flow_count,
                unique_sources: flow.unique_sources,
                unique_destinations: flow.unique_destinations,
                classification,
                baseline_avg_bytes: baseline_avg,
                volume_ratio,
                days_in_baseline,
                top_sources,
                new_sources,
                involved_devices,
            });
        }

        // Find disappeared ports: baselines with days_present >= 5 that aren't in current flows
        let current_keys: std::collections::HashSet<(String, i64)> =
            current_flows.iter().map(|f| (f.protocol.clone(), f.dst_port)).collect();

        let disappeared: Vec<ClassifiedPortFlow> = baselines
            .iter()
            .filter(|b| b.days_present >= 5 && !current_keys.contains(&(b.protocol.clone(), b.dst_port)))
            .map(|b| ClassifiedPortFlow {
                dst_port: b.dst_port,
                protocol: b.protocol.clone(),
                total_bytes: 0,
                flow_count: 0,
                unique_sources: 0,
                unique_destinations: 0,
                classification: FlowClassification::Disappeared,
                baseline_avg_bytes: Some(b.avg_bytes_per_day),
                volume_ratio: None,
                days_in_baseline: b.days_present,
                top_sources: Vec::new(),
                new_sources: Vec::new(),
                involved_devices: Vec::new(),
            })
            .collect();

        drop(db);

        let has_baselines = !baselines.is_empty();

        Ok(ClassifiedPortSummary {
            anomaly_count,
            has_baselines,
            flows: classified_flows,
            disappeared,
        })
    }

    // ── Anomaly link methods ──────────────────────────────────────

    /// Insert a new anomaly link and return its ID.
    pub fn insert_anomaly_link(&self, link: &NewAnomalyLink) -> anyhow::Result<i64> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        db.execute(
            "INSERT INTO anomaly_links
                (port_anomaly_type, flow_direction, protocol, dst_port,
                 device_mac, device_ip, device_vlan, device_hostname,
                 behavior_anomaly_id, correlated, source, severity,
                 device_bytes, device_connections, port_is_baselined,
                 port_days_in_baseline, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                link.port_anomaly_type,
                link.flow_direction,
                link.protocol,
                link.dst_port,
                link.device_mac,
                link.device_ip,
                link.device_vlan,
                link.device_hostname,
                link.behavior_anomaly_id,
                link.correlated as i64,
                link.source,
                link.severity,
                link.device_bytes,
                link.device_connections,
                link.port_is_baselined as i64,
                link.port_days_in_baseline,
                now_iso(),
            ],
        )?;
        Ok(db.last_insert_rowid())
    }

    /// Check if an unresolved link already exists for this port+device combo.
    pub fn has_existing_link(
        &self,
        protocol: &str,
        dst_port: i64,
        direction: &str,
        device_mac: &str,
    ) -> anyhow::Result<bool> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM anomaly_links
             WHERE protocol = ?1 AND dst_port = ?2 AND flow_direction = ?3
               AND device_mac = ?4 AND resolved_at IS NULL",
            params![protocol, dst_port, direction, device_mac],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get all unresolved anomaly links for a specific port.
    pub fn get_links_for_port(
        &self,
        protocol: &str,
        dst_port: i64,
        direction: &str,
    ) -> anyhow::Result<Vec<AnomalyLink>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let mut stmt = db.prepare(
            "SELECT id, port_anomaly_type, flow_direction, protocol, dst_port,
                    device_mac, device_ip, device_vlan, device_hostname,
                    behavior_anomaly_id, correlated, source, severity,
                    device_bytes, device_connections, port_is_baselined,
                    port_days_in_baseline, created_at, resolved_at, resolved_by
             FROM anomaly_links
             WHERE protocol = ?1 AND dst_port = ?2 AND flow_direction = ?3
               AND resolved_at IS NULL
             ORDER BY device_bytes DESC",
        )?;
        let rows = stmt.query_map(params![protocol, dst_port, direction], Self::map_link_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get all unresolved anomaly links for a specific device.
    pub fn get_links_for_device(&self, mac: &str) -> anyhow::Result<Vec<AnomalyLink>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let mut stmt = db.prepare(
            "SELECT id, port_anomaly_type, flow_direction, protocol, dst_port,
                    device_mac, device_ip, device_vlan, device_hostname,
                    behavior_anomaly_id, correlated, source, severity,
                    device_bytes, device_connections, port_is_baselined,
                    port_days_in_baseline, created_at, resolved_at, resolved_by
             FROM anomaly_links
             WHERE device_mac = ?1 AND resolved_at IS NULL
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![mac], Self::map_link_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get all unresolved anomaly links.
    pub fn get_unresolved_links(&self) -> anyhow::Result<Vec<AnomalyLink>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let mut stmt = db.prepare(
            "SELECT id, port_anomaly_type, flow_direction, protocol, dst_port,
                    device_mac, device_ip, device_vlan, device_hostname,
                    behavior_anomaly_id, correlated, source, severity,
                    device_bytes, device_connections, port_is_baselined,
                    port_days_in_baseline, created_at, resolved_at, resolved_by
             FROM anomaly_links
             WHERE resolved_at IS NULL
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], Self::map_link_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Resolve an anomaly link.
    pub fn resolve_link(&self, id: i64, resolved_by: &str) -> anyhow::Result<bool> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let changed = db.execute(
            "UPDATE anomaly_links SET resolved_at = ?2, resolved_by = ?3
             WHERE id = ?1 AND resolved_at IS NULL",
            params![id, now_iso(), resolved_by],
        )?;
        Ok(changed > 0)
    }

    /// Query devices involved in a port flow from connection_history,
    /// enriched with anomaly_links data. This is used by classified_port_summary.
    fn query_involved_devices_inner(
        db: &rusqlite::Connection,
        protocol: &str,
        dst_port: i64,
        direction: &str,
        cutoff: &str,
    ) -> anyhow::Result<Vec<InvolvedDevice>> {
        let direction_filter = match direction {
            "outbound" => "AND dst_is_external = 1",
            "inbound" => "AND dst_is_external = 0 AND src_vlan IS NULL",
            "internal" => "AND dst_is_external = 0 AND src_vlan IS NOT NULL",
            _ => "",
        };

        let sql = format!(
            "SELECT src_mac, src_ip, src_vlan, src_hostname,
                    SUM(bytes_tx + bytes_rx) as total_bytes,
                    COUNT(*) as conn_count
             FROM connection_history
             WHERE first_seen >= ?1 AND dst_port = ?2 AND protocol = ?3
               AND src_mac IS NOT NULL
               {direction_filter}
             GROUP BY src_mac
             ORDER BY total_bytes DESC
             LIMIT 10"
        );
        let mut stmt = db.prepare(&sql)?;
        let device_rows: Vec<(String, String, Option<String>, Option<String>, i64, i64)> = stmt
            .query_map(params![cutoff, dst_port, protocol], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mut result = Vec::new();
        for (mac, ip, vlan, hostname, bytes, connections) in device_rows {
            // Check if there's an unresolved anomaly link for this device+port
            let link: Option<(i64, bool)> = db
                .query_row(
                    "SELECT behavior_anomaly_id, correlated FROM anomaly_links
                     WHERE protocol = ?1 AND dst_port = ?2 AND flow_direction = ?3
                       AND device_mac = ?4 AND resolved_at IS NULL
                     LIMIT 1",
                    params![protocol, dst_port, direction, mac],
                    |row| Ok((row.get::<_, Option<i64>>(0)?.unwrap_or(0), row.get::<_, i64>(1)? != 0)),
                )
                .ok();

            result.push(InvolvedDevice {
                mac,
                ip,
                hostname,
                vlan,
                bytes,
                connections,
                has_behavior_anomaly: link.map(|(id, _)| id > 0).unwrap_or(false),
                behavior_anomaly_id: link.and_then(|(id, _)| if id > 0 { Some(id) } else { None }),
                correlated: link.map(|(_, c)| c).unwrap_or(false),
            });
        }
        Ok(result)
    }

    /// Get port flow context for a specific port (used by behavior page).
    pub fn get_port_flow_context(
        &self,
        protocol: &str,
        dst_port: i64,
    ) -> anyhow::Result<Option<PortFlowContext>> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;

        // Check port_flow_baseline for this port (any direction)
        let baseline: Option<(i64, String)> = db
            .query_row(
                "SELECT days_present, flow_direction FROM port_flow_baseline
                 WHERE protocol = ?1 AND dst_port = ?2
                 LIMIT 1",
                params![protocol, dst_port],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        let (port_is_baselined, port_days_in_baseline) = match &baseline {
            Some((days, _)) => (true, *days),
            None => (false, 0),
        };

        // Count other devices using this port (from anomaly_links)
        let other_devices: i64 = db
            .query_row(
                "SELECT COUNT(DISTINCT device_mac) FROM anomaly_links
                 WHERE protocol = ?1 AND dst_port = ?2 AND resolved_at IS NULL",
                params![protocol, dst_port],
                |row| row.get(0),
            )
            .unwrap_or(0);

        // Check correlated status from links
        let has_correlated: bool = db
            .query_row(
                "SELECT COUNT(*) FROM anomaly_links
                 WHERE protocol = ?1 AND dst_port = ?2 AND correlated = 1 AND resolved_at IS NULL",
                params![protocol, dst_port],
                |row| row.get::<_, i64>(0).map(|c| c > 0),
            )
            .unwrap_or(false);

        // Get total network bytes on this port in last 24h
        let cutoff = now_iso_minus_secs(86400);
        let total_bytes: i64 = db
            .query_row(
                "SELECT COALESCE(SUM(bytes_tx + bytes_rx), 0) FROM connection_history
                 WHERE protocol = ?1 AND dst_port = ?2 AND first_seen >= ?3",
                params![protocol, dst_port, cutoff],
                |row| row.get(0),
            )
            .unwrap_or(0);

        // Determine network-level classification
        let classification = if !port_is_baselined {
            "new_port"
        } else {
            "normal"
        };

        Ok(Some(PortFlowContext {
            port: dst_port,
            protocol: protocol.to_string(),
            port_is_baselined,
            port_days_in_baseline,
            correlated: has_correlated,
            other_devices_count: other_devices,
            network_level_classification: classification.to_string(),
            total_network_bytes_on_port: total_bytes,
        }))
    }

    fn map_link_row(row: &rusqlite::Row) -> rusqlite::Result<AnomalyLink> {
        Ok(AnomalyLink {
            id: row.get(0)?,
            port_anomaly_type: row.get(1)?,
            flow_direction: row.get(2)?,
            protocol: row.get(3)?,
            dst_port: row.get(4)?,
            device_mac: row.get(5)?,
            device_ip: row.get(6)?,
            device_vlan: row.get(7)?,
            device_hostname: row.get(8)?,
            behavior_anomaly_id: row.get(9)?,
            correlated: row.get::<_, i64>(10)? != 0,
            source: row.get(11)?,
            severity: row.get(12)?,
            device_bytes: row.get(13)?,
            device_connections: row.get(14)?,
            port_is_baselined: row.get::<_, i64>(15)? != 0,
            port_days_in_baseline: row.get(16)?,
            created_at: row.get(17)?,
            resolved_at: row.get(18)?,
            resolved_by: row.get(19)?,
        })
    }

    /// Get the count of syslog events recorded today.
    pub fn syslog_event_counts(&self) -> anyhow::Result<(i64, i64)> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("db lock: {e}"))?;
        let today_start = today_iso();
        let week_start = now_iso_minus_secs(7 * 86400);

        let today: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM connection_history
                 WHERE data_source IN ('syslog', 'both') AND first_seen >= ?1",
                params![today_start],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let week: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM connection_history
                 WHERE data_source IN ('syslog', 'both') AND first_seen >= ?1",
                params![week_start],
                |row| row.get(0),
            )
            .unwrap_or(0);

        Ok((today, week))
    }
}

// ── Helper functions ──────────────────────────────────────────

fn now_iso() -> String {
    now_iso_pub()
}

/// Public ISO 8601 timestamp for current time. Used by syslog parser.
pub fn now_iso_pub() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let secs_per_day = 86400i64;
    let days_since_epoch = now / secs_per_day;
    let time_of_day = now % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (y, m, d) = days_to_ymd(days_since_epoch);
    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn today_iso() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days_since_epoch = now / 86400;
    let (y, m, d) = days_to_ymd(days_since_epoch);
    format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
}

fn now_iso_minus_secs(secs: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let ts = now - secs;
    // Convert unix timestamp to ISO 8601
    let secs_per_day = 86400i64;
    let days_since_epoch = ts / secs_per_day;
    let time_of_day = ts % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Compute date from days since 1970-01-01
    let (y, m, d) = days_to_ymd(days_since_epoch);
    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Simple days-since-epoch to (year, month, day) conversion.
fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Convert ISO week string "2026-W09" to (period_start, period_end) ISO dates.
fn week_to_period(week: &str) -> (String, String) {
    // Simple approximation: week N starts on Monday of that week
    // For now, just store the week string as both start/end — the snapshot generator
    // will provide the actual dates when creating snapshots.
    (format!("{week}-start"), format!("{week}-end"))
}

/// Map IP to VLAN label.
fn vlan_label(ip: &str) -> Option<String> {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
    match prefix.as_str() {
        "10.20.25" => Some("VLAN 25".into()),
        "10.20.30" => Some("VLAN 30".into()),
        "10.20.35" => Some("VLAN 35".into()),
        "10.2.2" => Some("VLAN 2".into()),
        "172.20.10" => Some("VLAN 10".into()),
        "172.20.6" => Some("VLAN 6".into()),
        "192.168.90" => Some("VLAN 90".into()),
        "192.168.99" => Some("VLAN 99".into()),
        _ => None,
    }
}

// ── SQL filter builder ────────────────────────────────────────

/// Bind value for parameterized queries.
enum BindValue {
    Text(String),
    Int(i64),
}

fn build_filter_clause(filters: &HistoryFilters) -> (String, Vec<BindValue>) {
    let mut conditions = Vec::new();
    let mut values = Vec::new();

    if let Some(ref v) = filters.src_ip {
        conditions.push(format!("src_ip = ?{}", values.len() + 1));
        values.push(BindValue::Text(v.clone()));
    }
    if let Some(ref v) = filters.dst_ip {
        conditions.push(format!("dst_ip = ?{}", values.len() + 1));
        values.push(BindValue::Text(v.clone()));
    }
    if let Some(v) = filters.dst_port {
        conditions.push(format!("dst_port = ?{}", values.len() + 1));
        values.push(BindValue::Int(v));
    }
    if let Some(ref v) = filters.protocol {
        conditions.push(format!("protocol = ?{}", values.len() + 1));
        values.push(BindValue::Text(v.clone()));
    }
    if let Some(ref v) = filters.country {
        conditions.push(format!("geo_country_code = ?{}", values.len() + 1));
        values.push(BindValue::Text(v.clone()));
    }
    if let Some(v) = filters.closed {
        conditions.push(format!("closed = ?{}", values.len() + 1));
        values.push(BindValue::Int(if v { 1 } else { 0 }));
    }
    if let Some(v) = filters.flagged {
        if v {
            conditions.push("flagged = 1".into());
        }
    }
    if let Some(ref v) = filters.after {
        conditions.push(format!("first_seen >= ?{}", values.len() + 1));
        values.push(BindValue::Text(v.clone()));
    }
    if let Some(ref v) = filters.before {
        conditions.push(format!("first_seen < ?{}", values.len() + 1));
        values.push(BindValue::Text(v.clone()));
    }

    let clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    (clause, values)
}

fn bind_and_query_scalar(
    stmt: &mut rusqlite::Statement,
    values: &[BindValue],
) -> anyhow::Result<i64> {
    // Bind all values then query
    let params: Vec<Box<dyn rusqlite::types::ToSql>> = values
        .iter()
        .map(|v| -> Box<dyn rusqlite::types::ToSql> {
            match v {
                BindValue::Text(s) => Box::new(s.clone()),
                BindValue::Int(i) => Box::new(*i),
            }
        })
        .collect();
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|b| b.as_ref()).collect();
    let result = stmt.query_row(param_refs.as_slice(), |row| row.get(0))?;
    Ok(result)
}

fn bind_and_query_rows(
    stmt: &mut rusqlite::Statement,
    values: &[BindValue],
) -> anyhow::Result<Vec<ConnectionHistoryRow>> {
    let params: Vec<Box<dyn rusqlite::types::ToSql>> = values
        .iter()
        .map(|v| -> Box<dyn rusqlite::types::ToSql> {
            match v {
                BindValue::Text(s) => Box::new(s.clone()),
                BindValue::Int(i) => Box::new(*i),
            }
        })
        .collect();
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|b| b.as_ref()).collect();

    let rows = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(ConnectionHistoryRow {
                id: row.get(0)?,
                conntrack_id: row.get(1)?,
                protocol: row.get(2)?,
                src_ip: row.get(3)?,
                dst_ip: row.get(4)?,
                dst_port: row.get(5)?,
                src_mac: row.get(6)?,
                src_vlan: row.get(7)?,
                src_hostname: row.get(8)?,
                dst_vlan: row.get(9)?,
                dst_hostname: row.get(10)?,
                first_seen: row.get(11)?,
                last_seen: row.get(12)?,
                closed: row.get::<_, i64>(13)? != 0,
                last_state: row.get(14)?,
                duration_seconds: row.get(15)?,
                bytes_tx: row.get(16)?,
                bytes_rx: row.get(17)?,
                data_source: row.get(18)?,
                poll_count: row.get(19)?,
                dst_is_external: row.get::<_, i64>(20)? != 0,
                geo_country_code: row.get(21)?,
                geo_country: row.get(22)?,
                geo_city: row.get(23)?,
                geo_asn: row.get(24)?,
                geo_org: row.get(25)?,
                geo_lat: row.get(26)?,
                geo_lon: row.get(27)?,
                flagged: row.get::<_, i64>(28)? != 0,
                anomaly_id: row.get(29)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

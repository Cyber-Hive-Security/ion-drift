//! Device behavioral fingerprinting store.
//!
//! Tracks device profiles, baseline behavior patterns, raw observations,
//! and anomalies. Backed by SQLite via `rusqlite`.

use std::path::Path;
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use tokio::sync::Mutex;

// ── Helpers ──────────────────────────────────────────────────

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ── VLAN Mapping ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlanSensitivity {
    Strictest,
    Strict,
    Moderate,
    Loose,
    Monitor,
}

/// Map an IP address to its VLAN number based on subnet.
pub fn ip_to_vlan(ip: &str) -> Option<u16> {
    let octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return None;
    }
    match (octets[0], octets[1], octets[2]) {
        (10, 20, 25) => Some(25),
        (10, 20, 30) => Some(30),
        (10, 20, 35) => Some(35),
        (10, 2, 2) => Some(2),
        (172, 20, 10) => Some(10),
        (172, 20, 6) => Some(6),
        (192, 168, 90) => Some(90),
        (192, 168, 99) => Some(99),
        _ => None,
    }
}

/// Get the sensitivity level for a VLAN.
pub fn sensitivity(vlan: u16) -> VlanSensitivity {
    match vlan {
        99 => VlanSensitivity::Strictest,
        90 | 2 => VlanSensitivity::Strict,
        25 | 10 => VlanSensitivity::Moderate,
        30 | 35 | 6 => VlanSensitivity::Loose,
        _ => VlanSensitivity::Monitor,
    }
}

/// Determine anomaly severity based on VLAN sensitivity and anomaly type.
pub fn anomaly_severity(vlan: u16, anomaly_type: &str) -> &'static str {
    let sens = sensitivity(vlan);
    match (sens, anomaly_type) {
        (VlanSensitivity::Strictest, "blocked_attempt") => "critical",
        (VlanSensitivity::Strictest, _) => "critical",
        (VlanSensitivity::Strict, "blocked_attempt") => "alert",
        (VlanSensitivity::Strict, "volume_spike") => "alert",
        (VlanSensitivity::Strict, _) => "warning",
        (VlanSensitivity::Moderate, "blocked_attempt") => "warning",
        (VlanSensitivity::Moderate, "volume_spike") => "warning",
        (VlanSensitivity::Moderate, _) => "info",
        (VlanSensitivity::Loose, "blocked_attempt") => "warning",
        (VlanSensitivity::Loose, _) => "info",
        (VlanSensitivity::Monitor, _) => "info",
    }
}

/// Auto-resolve timeout in seconds for stale anomalies (0 = never).
pub fn auto_resolve_timeout(sens: VlanSensitivity) -> i64 {
    match sens {
        VlanSensitivity::Strictest => 0,         // never
        VlanSensitivity::Strict => 0,            // never
        VlanSensitivity::Moderate => 48 * 3600,  // 48 hours
        VlanSensitivity::Loose => 24 * 3600,     // 24 hours
        VlanSensitivity::Monitor => 72 * 3600,   // 72 hours
    }
}

/// Classify a destination IP as a VLAN subnet string or "external".
pub fn classify_destination(dst_ip: &str) -> String {
    let octets: Vec<u8> = dst_ip.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return "external".to_string();
    }
    match (octets[0], octets[1], octets[2]) {
        (10, 20, 25) => "10.20.25.0/24".to_string(),
        (10, 20, 30) => "10.20.30.0/24".to_string(),
        (10, 20, 35) => "10.20.35.0/24".to_string(),
        (10, 2, 2) => "10.2.2.0/24".to_string(),
        (172, 20, 10) => "172.20.10.0/24".to_string(),
        (172, 20, 6) => "172.20.6.0/24".to_string(),
        (192, 168, 90) => "192.168.90.0/24".to_string(),
        (192, 168, 99) => "192.168.99.0/24".to_string(),
        // RFC1918 catch-all
        (10, _, _) => format!("10.{}.{}.0/24", octets[1], octets[2]),
        (172, 16..=31, _) => format!("172.{}.{}.0/24", octets[1], octets[2]),
        (192, 168, _) => format!("192.168.{}.0/24", octets[2]),
        _ => "external".to_string(),
    }
}

/// Classify flow direction based on source/destination VLANs.
pub fn classify_direction(src_ip: &str, dst_ip: &str) -> &'static str {
    let src_vlan = ip_to_vlan(src_ip);
    let dst_vlan = ip_to_vlan(dst_ip);
    let dst_external = classify_destination(dst_ip) == "external";

    match (src_vlan, dst_vlan, dst_external) {
        (_, _, true) => "outbound",
        (Some(s), Some(d), _) if s == d => "internal",
        (Some(_), Some(_), _) => "lateral",
        (None, Some(_), _) => "inbound",
        _ => "internal",
    }
}

// ── Data Structures ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct DeviceProfile {
    pub mac: String,
    pub hostname: Option<String>,
    pub manufacturer: Option<String>,
    pub current_ip: Option<String>,
    pub current_vlan: Option<i64>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub learning_until: i64,
    pub baseline_status: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceBaseline {
    pub id: i64,
    pub mac: String,
    pub protocol: String,
    pub dst_port: Option<i64>,
    pub dst_subnet: String,
    pub direction: String,
    pub avg_bytes_per_hour: f64,
    pub max_bytes_per_hour: f64,
    pub observation_count: i64,
    pub computed_at: i64,
}

#[derive(Debug, Clone)]
pub struct DeviceObservation {
    pub mac: String,
    pub timestamp: i64,
    pub ip: String,
    pub vlan: i64,
    pub protocol: String,
    pub dst_port: Option<i64>,
    pub dst_subnet: String,
    pub direction: String,
    pub bytes_sent: i64,
    pub bytes_recv: i64,
    pub connection_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceAnomaly {
    pub id: i64,
    pub mac: String,
    pub timestamp: i64,
    pub anomaly_type: String,
    pub severity: String,
    pub description: String,
    pub details: Option<String>,
    pub vlan: i64,
    pub firewall_correlation: Option<String>,
    pub firewall_rule_id: Option<String>,
    pub firewall_rule_comment: Option<String>,
    pub status: String,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
}

/// New anomaly to insert (no id yet).
#[derive(Debug, Clone)]
pub struct NewAnomaly {
    pub mac: String,
    pub anomaly_type: String,
    pub severity: String,
    pub description: String,
    pub details: Option<String>,
    pub vlan: i64,
    pub firewall_correlation: Option<String>,
    pub firewall_rule_id: Option<String>,
    pub firewall_rule_comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorOverview {
    pub total_devices: i64,
    pub baselined_devices: i64,
    pub learning_devices: i64,
    pub pending_anomalies: i64,
    pub critical_anomalies: i64,
    pub warning_anomalies: i64,
    pub vlan_summaries: Vec<VlanBehaviorSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VlanBehaviorSummary {
    pub vlan: i64,
    pub device_count: i64,
    pub baselined_count: i64,
    pub learning_count: i64,
    pub pending_anomaly_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertCount {
    pub pending_count: i64,
    pub critical_count: i64,
    pub warning_count: i64,
    pub anomaly_macs: Vec<String>,
}

// ── BehaviorStore ────────────────────────────────────────────

pub struct BehaviorStore {
    db: Arc<Mutex<Connection>>,
}

impl BehaviorStore {
    /// Public timestamp helper for use by the behavior engine.
    pub fn now_unix_pub() -> i64 {
        now_unix()
    }

    pub fn new(db_path: &Path) -> Result<Self, String> {
        let conn = Connection::open(db_path)
            .map_err(|e| format!("failed to open behavior db: {e}"))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("pragma failed: {e}"))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS device_profiles (
                mac TEXT PRIMARY KEY,
                hostname TEXT,
                manufacturer TEXT,
                current_ip TEXT,
                current_vlan INTEGER,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                learning_until INTEGER NOT NULL,
                baseline_status TEXT NOT NULL DEFAULT 'learning',
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS device_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                protocol TEXT NOT NULL,
                dst_port INTEGER,
                dst_subnet TEXT NOT NULL,
                direction TEXT NOT NULL,
                avg_bytes_per_hour REAL NOT NULL DEFAULT 0,
                max_bytes_per_hour REAL NOT NULL DEFAULT 0,
                observation_count INTEGER NOT NULL DEFAULT 0,
                computed_at INTEGER NOT NULL,
                UNIQUE(mac, protocol, dst_port, dst_subnet, direction)
            );

            CREATE TABLE IF NOT EXISTS device_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                ip TEXT NOT NULL,
                vlan INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                dst_port INTEGER,
                dst_subnet TEXT NOT NULL,
                direction TEXT NOT NULL,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_recv INTEGER NOT NULL DEFAULT 0,
                connection_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_observations_mac_ts
                ON device_observations(mac, timestamp);

            CREATE TABLE IF NOT EXISTS device_anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                anomaly_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                details TEXT,
                vlan INTEGER NOT NULL,
                firewall_correlation TEXT,
                firewall_rule_id TEXT,
                firewall_rule_comment TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                resolved_at INTEGER,
                resolved_by TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_anomalies_mac
                ON device_anomalies(mac);
            CREATE INDEX IF NOT EXISTS idx_anomalies_status
                ON device_anomalies(status);
            ",
        )
        .map_err(|e| format!("schema creation failed: {e}"))?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    // ── Profile methods ──

    pub async fn upsert_profile(
        &self,
        mac: &str,
        hostname: Option<&str>,
        manufacturer: Option<&str>,
        ip: &str,
        vlan: i64,
    ) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let learning_until = now + 7 * 86400;
        db.execute(
            "INSERT INTO device_profiles (mac, hostname, manufacturer, current_ip, current_vlan, first_seen, last_seen, learning_until)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)
             ON CONFLICT(mac) DO UPDATE SET
                hostname = COALESCE(?2, hostname),
                manufacturer = COALESCE(?3, manufacturer),
                current_ip = ?4,
                current_vlan = ?5,
                last_seen = ?6",
            params![mac, hostname, manufacturer, ip, vlan, now, learning_until],
        )
        .map_err(|e| format!("upsert_profile failed: {e}"))?;
        Ok(())
    }

    pub async fn get_profile(&self, mac: &str) -> Result<Option<DeviceProfile>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT mac, hostname, manufacturer, current_ip, current_vlan,
                    first_seen, last_seen, learning_until, baseline_status, notes
             FROM device_profiles WHERE mac = ?1",
            params![mac],
            |row| {
                Ok(DeviceProfile {
                    mac: row.get(0)?,
                    hostname: row.get(1)?,
                    manufacturer: row.get(2)?,
                    current_ip: row.get(3)?,
                    current_vlan: row.get(4)?,
                    first_seen: row.get(5)?,
                    last_seen: row.get(6)?,
                    learning_until: row.get(7)?,
                    baseline_status: row.get(8)?,
                    notes: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(|e| format!("get_profile failed: {e}"))
    }

    pub async fn get_all_profiles(&self) -> Result<Vec<DeviceProfile>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT mac, hostname, manufacturer, current_ip, current_vlan,
                        first_seen, last_seen, learning_until, baseline_status, notes
                 FROM device_profiles ORDER BY last_seen DESC",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DeviceProfile {
                    mac: row.get(0)?,
                    hostname: row.get(1)?,
                    manufacturer: row.get(2)?,
                    current_ip: row.get(3)?,
                    current_vlan: row.get(4)?,
                    first_seen: row.get(5)?,
                    last_seen: row.get(6)?,
                    learning_until: row.get(7)?,
                    baseline_status: row.get(8)?,
                    notes: row.get(9)?,
                })
            })
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    pub async fn get_profiles_by_vlan(&self, vlan: i64) -> Result<Vec<DeviceProfile>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT mac, hostname, manufacturer, current_ip, current_vlan,
                        first_seen, last_seen, learning_until, baseline_status, notes
                 FROM device_profiles WHERE current_vlan = ?1 ORDER BY last_seen DESC",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![vlan], |row| {
                Ok(DeviceProfile {
                    mac: row.get(0)?,
                    hostname: row.get(1)?,
                    manufacturer: row.get(2)?,
                    current_ip: row.get(3)?,
                    current_vlan: row.get(4)?,
                    first_seen: row.get(5)?,
                    last_seen: row.get(6)?,
                    learning_until: row.get(7)?,
                    baseline_status: row.get(8)?,
                    notes: row.get(9)?,
                })
            })
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    // ── Observation methods ──

    pub async fn record_observations(&self, observations: &[DeviceObservation]) -> Result<(), String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "INSERT INTO device_observations
                    (mac, timestamp, ip, vlan, protocol, dst_port, dst_subnet, direction,
                     bytes_sent, bytes_recv, connection_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        for obs in observations {
            stmt.execute(params![
                obs.mac,
                obs.timestamp,
                obs.ip,
                obs.vlan,
                obs.protocol,
                obs.dst_port,
                obs.dst_subnet,
                obs.direction,
                obs.bytes_sent,
                obs.bytes_recv,
                obs.connection_count,
            ])
            .map_err(|e| format!("insert observation failed: {e}"))?;
        }
        Ok(())
    }

    pub async fn get_observations(
        &self,
        mac: &str,
        since_secs_ago: i64,
    ) -> Result<Vec<DeviceObservation>, String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - since_secs_ago;
        let mut stmt = db
            .prepare(
                "SELECT mac, timestamp, ip, vlan, protocol, dst_port, dst_subnet, direction,
                        bytes_sent, bytes_recv, connection_count
                 FROM device_observations
                 WHERE mac = ?1 AND timestamp >= ?2
                 ORDER BY timestamp ASC",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![mac, cutoff], |row| {
                Ok(DeviceObservation {
                    mac: row.get(0)?,
                    timestamp: row.get(1)?,
                    ip: row.get(2)?,
                    vlan: row.get(3)?,
                    protocol: row.get(4)?,
                    dst_port: row.get(5)?,
                    dst_subnet: row.get(6)?,
                    direction: row.get(7)?,
                    bytes_sent: row.get(8)?,
                    bytes_recv: row.get(9)?,
                    connection_count: row.get(10)?,
                })
            })
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    pub async fn prune_observations(&self, max_age_secs: i64) -> Result<usize, String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - max_age_secs;
        db.execute(
            "DELETE FROM device_observations WHERE timestamp < ?1",
            params![cutoff],
        )
        .map_err(|e| format!("prune failed: {e}"))
    }

    // ── Baseline methods ──

    pub async fn get_baselines(&self, mac: &str) -> Result<Vec<DeviceBaseline>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT id, mac, protocol, dst_port, dst_subnet, direction,
                        avg_bytes_per_hour, max_bytes_per_hour, observation_count, computed_at
                 FROM device_baselines WHERE mac = ?1",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![mac], |row| {
                Ok(DeviceBaseline {
                    id: row.get(0)?,
                    mac: row.get(1)?,
                    protocol: row.get(2)?,
                    dst_port: row.get(3)?,
                    dst_subnet: row.get(4)?,
                    direction: row.get(5)?,
                    avg_bytes_per_hour: row.get(6)?,
                    max_bytes_per_hour: row.get(7)?,
                    observation_count: row.get(8)?,
                    computed_at: row.get(9)?,
                })
            })
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    /// Recompute baselines for a single device from its observations.
    /// If the device has passed its `learning_until` time, promotes to `baselined`.
    pub async fn recompute_baselines(&self, mac: &str, window_secs: i64) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let cutoff = now - window_secs;

        // Aggregate observations → baselines
        let mut stmt = db
            .prepare(
                "SELECT protocol, dst_port, dst_subnet, direction,
                        AVG(bytes_sent + bytes_recv) * 3600.0 / ?3,
                        MAX(bytes_sent + bytes_recv) * 3600.0 / ?3,
                        COUNT(*)
                 FROM device_observations
                 WHERE mac = ?1 AND timestamp >= ?2
                 GROUP BY protocol, dst_port, dst_subnet, direction",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;

        // ?3 = interval seconds between observations (60s typically)
        let interval_secs: f64 = 60.0;
        let rows: Vec<(String, Option<i64>, String, String, f64, f64, i64)> = stmt
            .query_map(params![mac, cutoff, interval_secs], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, f64>(4)?,
                    row.get::<_, f64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|e| format!("query failed: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))?;

        for (protocol, dst_port, dst_subnet, direction, avg_bph, max_bph, count) in &rows {
            db.execute(
                "INSERT INTO device_baselines
                    (mac, protocol, dst_port, dst_subnet, direction,
                     avg_bytes_per_hour, max_bytes_per_hour, observation_count, computed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(mac, protocol, dst_port, dst_subnet, direction)
                 DO UPDATE SET
                    avg_bytes_per_hour = ?6,
                    max_bytes_per_hour = ?7,
                    observation_count = ?8,
                    computed_at = ?9",
                params![mac, protocol, dst_port, dst_subnet, direction, avg_bph, max_bph, count, now],
            )
            .map_err(|e| format!("upsert baseline failed: {e}"))?;
        }

        // Auto-promote learning → baselined if past learning_until
        db.execute(
            "UPDATE device_profiles
             SET baseline_status = 'baselined'
             WHERE mac = ?1
               AND baseline_status = 'learning'
               AND learning_until <= ?2",
            params![mac, now],
        )
        .map_err(|e| format!("promote status failed: {e}"))?;

        Ok(())
    }

    pub async fn recompute_all_baselines(&self, window_secs: i64) -> Result<usize, String> {
        // Get all MACs, then recompute each
        let macs: Vec<String> = {
            let db = self.db.lock().await;
            let mut stmt = db
                .prepare("SELECT mac FROM device_profiles")
                .map_err(|e| format!("prepare failed: {e}"))?;
            stmt.query_map([], |row| row.get(0))
                .map_err(|e| format!("query failed: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("collect failed: {e}"))?
        };
        let count = macs.len();
        for mac in &macs {
            self.recompute_baselines(mac, window_secs).await?;
        }
        Ok(count)
    }

    // ── Anomaly methods ──

    pub async fn record_anomaly(&self, anomaly: &NewAnomaly) -> Result<i64, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        db.execute(
            "INSERT INTO device_anomalies
                (mac, timestamp, anomaly_type, severity, description, details,
                 vlan, firewall_correlation, firewall_rule_id, firewall_rule_comment)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                anomaly.mac,
                now,
                anomaly.anomaly_type,
                anomaly.severity,
                anomaly.description,
                anomaly.details,
                anomaly.vlan,
                anomaly.firewall_correlation,
                anomaly.firewall_rule_id,
                anomaly.firewall_rule_comment,
            ],
        )
        .map_err(|e| format!("record_anomaly failed: {e}"))?;
        Ok(db.last_insert_rowid())
    }

    /// Check if a similar anomaly already exists and is pending for dedup.
    pub async fn has_recent_anomaly(
        &self,
        mac: &str,
        anomaly_type: &str,
        dst_subnet: &str,
        within_secs: i64,
    ) -> Result<bool, String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - within_secs;
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_anomalies
                 WHERE mac = ?1 AND anomaly_type = ?2 AND status = 'pending'
                   AND timestamp >= ?3
                   AND (details LIKE '%' || ?4 || '%' OR ?4 = '')",
                params![mac, anomaly_type, cutoff, dst_subnet],
                |row| row.get(0),
            )
            .map_err(|e| format!("has_recent_anomaly failed: {e}"))?;
        Ok(count > 0)
    }

    pub async fn get_anomalies(
        &self,
        status: Option<&str>,
        severity: Option<&str>,
        vlan: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Vec<DeviceAnomaly>, String> {
        let db = self.db.lock().await;
        let mut sql = String::from(
            "SELECT id, mac, timestamp, anomaly_type, severity, description, details,
                    vlan, firewall_correlation, firewall_rule_id, firewall_rule_comment,
                    status, resolved_at, resolved_by
             FROM device_anomalies WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(s) = status {
            param_values.push(Box::new(s.to_string()));
            sql.push_str(&format!(" AND status = ?{}", param_values.len()));
        }
        if let Some(s) = severity {
            param_values.push(Box::new(s.to_string()));
            sql.push_str(&format!(" AND severity = ?{}", param_values.len()));
        }
        if let Some(v) = vlan {
            param_values.push(Box::new(v));
            sql.push_str(&format!(" AND vlan = ?{}", param_values.len()));
        }
        sql.push_str(" ORDER BY timestamp DESC");
        if let Some(l) = limit {
            param_values.push(Box::new(l));
            sql.push_str(&format!(" LIMIT ?{}", param_values.len()));
        }

        let mut stmt = db.prepare(&sql).map_err(|e| format!("prepare failed: {e}"))?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_ref.as_slice(), Self::map_anomaly_row)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    pub async fn get_anomalies_by_mac(&self, mac: &str) -> Result<Vec<DeviceAnomaly>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT id, mac, timestamp, anomaly_type, severity, description, details,
                        vlan, firewall_correlation, firewall_rule_id, firewall_rule_comment,
                        status, resolved_at, resolved_by
                 FROM device_anomalies WHERE mac = ?1 ORDER BY timestamp DESC",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![mac], Self::map_anomaly_row)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    pub async fn get_pending_anomaly_counts(&self) -> Result<AlertCount, String> {
        let db = self.db.lock().await;
        let pending: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_anomalies WHERE status = 'pending'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("count failed: {e}"))?;
        let critical: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_anomalies WHERE status = 'pending' AND severity = 'critical'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("count failed: {e}"))?;
        let warning: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_anomalies WHERE status = 'pending' AND severity IN ('warning', 'alert')",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("count failed: {e}"))?;
        let mut stmt = db
            .prepare("SELECT DISTINCT mac FROM device_anomalies WHERE status = 'pending'")
            .map_err(|e| format!("anomaly macs query failed: {e}"))?;
        let anomaly_macs: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| format!("anomaly macs query failed: {e}"))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(AlertCount {
            pending_count: pending,
            critical_count: critical,
            warning_count: warning,
            anomaly_macs,
        })
    }

    pub async fn resolve_anomaly(
        &self,
        id: i64,
        status: &str,
        resolved_by: &str,
    ) -> Result<bool, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let changed = db
            .execute(
                "UPDATE device_anomalies
                 SET status = ?2, resolved_at = ?3, resolved_by = ?4
                 WHERE id = ?1 AND status = 'pending'",
                params![id, status, now, resolved_by],
            )
            .map_err(|e| format!("resolve failed: {e}"))?;
        Ok(changed > 0)
    }

    /// Auto-resolve stale anomalies based on per-VLAN timeout rules.
    pub async fn auto_resolve_stale(&self) -> Result<usize, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let mut total = 0usize;

        // Get all VLANs with pending anomalies
        let vlans: Vec<i64> = {
            let mut stmt = db
                .prepare(
                    "SELECT DISTINCT vlan FROM device_anomalies WHERE status = 'pending'",
                )
                .map_err(|e| format!("prepare failed: {e}"))?;
            stmt.query_map([], |row| row.get(0))
                .map_err(|e| format!("query failed: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("collect failed: {e}"))?
        };

        for vlan in vlans {
            let timeout = auto_resolve_timeout(sensitivity(vlan as u16));
            if timeout == 0 {
                continue; // never auto-resolve
            }
            let cutoff = now - timeout;
            let changed = db
                .execute(
                    "UPDATE device_anomalies
                     SET status = 'auto_dismissed', resolved_at = ?1, resolved_by = 'system'
                     WHERE vlan = ?2 AND status = 'pending' AND timestamp < ?3
                       AND severity NOT IN ('critical', 'alert')",
                    params![now, vlan, cutoff],
                )
                .map_err(|e| format!("auto_resolve failed: {e}"))?;
            total += changed;
        }

        Ok(total)
    }

    // ── Overview ──

    pub async fn overview_stats(&self) -> Result<BehaviorOverview, String> {
        let db = self.db.lock().await;

        let total_devices: i64 = db
            .query_row("SELECT COUNT(*) FROM device_profiles", [], |row| row.get(0))
            .map_err(|e| format!("count failed: {e}"))?;
        let baselined_devices: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_profiles WHERE baseline_status = 'baselined'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("count failed: {e}"))?;
        let learning_devices: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_profiles WHERE baseline_status = 'learning'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("count failed: {e}"))?;

        let alerts = Self::pending_counts_inner(&db)?;

        // Per-VLAN summaries
        let mut stmt = db
            .prepare(
                "SELECT current_vlan,
                        COUNT(*),
                        SUM(CASE WHEN baseline_status = 'baselined' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN baseline_status = 'learning' THEN 1 ELSE 0 END)
                 FROM device_profiles
                 WHERE current_vlan IS NOT NULL
                 GROUP BY current_vlan
                 ORDER BY current_vlan",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let vlan_rows: Vec<(i64, i64, i64, i64)> = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|e| format!("query failed: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect failed: {e}"))?;

        // Count pending anomalies per VLAN
        let mut anomaly_stmt = db
            .prepare(
                "SELECT vlan, COUNT(*) FROM device_anomalies
                 WHERE status = 'pending' GROUP BY vlan",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let anomaly_counts: std::collections::HashMap<i64, i64> = anomaly_stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| format!("query failed: {e}"))?
            .collect::<Result<std::collections::HashMap<_, _>, _>>()
            .map_err(|e| format!("collect failed: {e}"))?;

        let vlan_summaries = vlan_rows
            .into_iter()
            .map(|(vlan, count, baselined, learning)| VlanBehaviorSummary {
                vlan,
                device_count: count,
                baselined_count: baselined,
                learning_count: learning,
                pending_anomaly_count: anomaly_counts.get(&vlan).copied().unwrap_or(0),
            })
            .collect();

        Ok(BehaviorOverview {
            total_devices,
            baselined_devices,
            learning_devices,
            pending_anomalies: alerts.pending_count,
            critical_anomalies: alerts.critical_count,
            warning_anomalies: alerts.warning_count,
            vlan_summaries,
        })
    }

    // ── Internal helpers ──

    fn pending_counts_inner(db: &Connection) -> Result<AlertCount, String> {
        let pending: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_anomalies WHERE status = 'pending'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("count failed: {e}"))?;
        let critical: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_anomalies WHERE status = 'pending' AND severity = 'critical'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("count failed: {e}"))?;
        let warning: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_anomalies WHERE status = 'pending' AND severity IN ('warning', 'alert')",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("count failed: {e}"))?;
        Ok(AlertCount {
            pending_count: pending,
            critical_count: critical,
            warning_count: warning,
            anomaly_macs: Vec::new(),
        })
    }

    fn map_anomaly_row(row: &rusqlite::Row) -> rusqlite::Result<DeviceAnomaly> {
        Ok(DeviceAnomaly {
            id: row.get(0)?,
            mac: row.get(1)?,
            timestamp: row.get(2)?,
            anomaly_type: row.get(3)?,
            severity: row.get(4)?,
            description: row.get(5)?,
            details: row.get(6)?,
            vlan: row.get(7)?,
            firewall_correlation: row.get(8)?,
            firewall_rule_id: row.get(9)?,
            firewall_rule_comment: row.get(10)?,
            status: row.get(11)?,
            resolved_at: row.get(12)?,
            resolved_by: row.get(13)?,
        })
    }
}

//! Operational metrics history store.
//!
//! Stores time-series data in SQLite for system resources, firewall drops,
//! connection counts, VLAN throughput, and log aggregates.

use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use serde::Serialize;
use tokio::sync::Mutex;

/// A single system metrics data point.
#[derive(Debug, Clone, Serialize)]
pub struct MetricsPoint {
    pub timestamp: i64,
    pub cpu_load: u32,
    pub memory_used: u64,
    pub memory_total: u64,
}

/// A single firewall drops data point.
#[derive(Debug, Clone, Serialize)]
pub struct DropMetricsPoint {
    pub timestamp: i64,
    pub drop_packets: u64,
    pub drop_bytes: u64,
}

/// A single connection tracking data point.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionMetricsPoint {
    pub timestamp: i64,
    pub total: u32,
    pub tcp: u32,
    pub udp: u32,
    pub other: u32,
}

/// A single VLAN throughput data point.
#[derive(Debug, Clone, Serialize)]
pub struct VlanMetricsPoint {
    pub timestamp: i64,
    pub vlan_name: String,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

/// An hourly log aggregate roll-up.
#[derive(Debug, Clone, Serialize)]
pub struct LogAggregate {
    pub timestamp: i64,
    pub period_start: i64,
    pub period_end: i64,
    pub total_entries: u32,
    pub drop_count: u32,
    pub accept_count: u32,
    pub top_drop_source: Option<String>,
    pub top_drop_source_count: u32,
    pub top_target_port: Option<u32>,
    pub top_target_port_count: u32,
    pub drops_by_interface: String,
}

/// Persistent metrics store backed by SQLite.
pub struct MetricsStore {
    db: Arc<Mutex<Connection>>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

impl MetricsStore {
    /// Create a new store, opening (or creating) the SQLite database at `db_path`.
    pub fn new(db_path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metrics (
                timestamp INTEGER NOT NULL,
                cpu_load INTEGER NOT NULL,
                memory_used INTEGER NOT NULL,
                memory_total INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp);

            CREATE TABLE IF NOT EXISTS drop_metrics (
                timestamp INTEGER NOT NULL,
                drop_packets INTEGER NOT NULL,
                drop_bytes INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_drop_metrics_ts ON drop_metrics (timestamp);

            CREATE TABLE IF NOT EXISTS connection_metrics (
                timestamp INTEGER NOT NULL,
                total INTEGER NOT NULL,
                tcp INTEGER NOT NULL,
                udp INTEGER NOT NULL,
                other INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_conn_metrics_ts ON connection_metrics (timestamp);

            CREATE TABLE IF NOT EXISTS vlan_metrics (
                timestamp INTEGER NOT NULL,
                vlan_name TEXT NOT NULL,
                rx_bps INTEGER NOT NULL,
                tx_bps INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vlan_metrics_ts ON vlan_metrics (timestamp);

            CREATE TABLE IF NOT EXISTS log_aggregates (
                timestamp INTEGER NOT NULL,
                period_start INTEGER NOT NULL,
                period_end INTEGER NOT NULL,
                total_entries INTEGER NOT NULL,
                drop_count INTEGER NOT NULL,
                accept_count INTEGER NOT NULL,
                top_drop_source TEXT,
                top_drop_source_count INTEGER NOT NULL DEFAULT 0,
                top_target_port INTEGER,
                top_target_port_count INTEGER NOT NULL DEFAULT 0,
                drops_by_interface TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_log_agg_ts ON log_aggregates (timestamp);",
        )?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    // ── System metrics ───────────────────────────────────────────

    /// Record a system metrics sample.
    pub async fn record(
        &self,
        cpu_load: u32,
        memory_used: u64,
        memory_total: u64,
    ) -> Result<(), String> {
        let now = now_unix();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO metrics (timestamp, cpu_load, memory_used, memory_total) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![now, cpu_load, memory_used, memory_total],
        )
        .map_err(|e| format!("metrics insert: {e}"))?;
        Ok(())
    }

    /// Query system metrics within the last `since_secs_ago` seconds.
    pub async fn query(&self, since_secs_ago: i64) -> Result<Vec<MetricsPoint>, String> {
        let cutoff = now_unix() - since_secs_ago;
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT timestamp, cpu_load, memory_used, memory_total
                 FROM metrics WHERE timestamp >= ?1 ORDER BY timestamp ASC",
            )
            .map_err(|e| format!("metrics query prepare: {e}"))?;

        let rows = stmt
            .query_map([cutoff], |row| {
                Ok(MetricsPoint {
                    timestamp: row.get(0)?,
                    cpu_load: row.get(1)?,
                    memory_used: row.get(2)?,
                    memory_total: row.get(3)?,
                })
            })
            .map_err(|e| format!("metrics query: {e}"))?;

        let mut points = Vec::new();
        for row in rows {
            points.push(row.map_err(|e| format!("metrics row: {e}"))?);
        }
        Ok(points)
    }

    // ── Drop metrics ─────────────────────────────────────────────

    /// Record a firewall drops sample.
    pub async fn record_drops(
        &self,
        drop_packets: u64,
        drop_bytes: u64,
    ) -> Result<(), String> {
        let now = now_unix();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO drop_metrics (timestamp, drop_packets, drop_bytes) VALUES (?1, ?2, ?3)",
            rusqlite::params![now, drop_packets, drop_bytes],
        )
        .map_err(|e| format!("drop_metrics insert: {e}"))?;
        Ok(())
    }

    /// Query drop metrics within the last `since_secs_ago` seconds.
    pub async fn query_drops(&self, since_secs_ago: i64) -> Result<Vec<DropMetricsPoint>, String> {
        let cutoff = now_unix() - since_secs_ago;
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT timestamp, drop_packets, drop_bytes
                 FROM drop_metrics WHERE timestamp >= ?1 ORDER BY timestamp ASC",
            )
            .map_err(|e| format!("drop_metrics query prepare: {e}"))?;

        let rows = stmt
            .query_map([cutoff], |row| {
                Ok(DropMetricsPoint {
                    timestamp: row.get(0)?,
                    drop_packets: row.get(1)?,
                    drop_bytes: row.get(2)?,
                })
            })
            .map_err(|e| format!("drop_metrics query: {e}"))?;

        let mut points = Vec::new();
        for row in rows {
            points.push(row.map_err(|e| format!("drop_metrics row: {e}"))?);
        }
        Ok(points)
    }

    // ── Connection metrics ───────────────────────────────────────

    /// Record a connection tracking sample.
    pub async fn record_connections(
        &self,
        total: u32,
        tcp: u32,
        udp: u32,
        other: u32,
    ) -> Result<(), String> {
        let now = now_unix();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO connection_metrics (timestamp, total, tcp, udp, other) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![now, total, tcp, udp, other],
        )
        .map_err(|e| format!("connection_metrics insert: {e}"))?;
        Ok(())
    }

    /// Query connection metrics within the last `since_secs_ago` seconds.
    pub async fn query_connections(
        &self,
        since_secs_ago: i64,
    ) -> Result<Vec<ConnectionMetricsPoint>, String> {
        let cutoff = now_unix() - since_secs_ago;
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT timestamp, total, tcp, udp, other
                 FROM connection_metrics WHERE timestamp >= ?1 ORDER BY timestamp ASC",
            )
            .map_err(|e| format!("connection_metrics query prepare: {e}"))?;

        let rows = stmt
            .query_map([cutoff], |row| {
                Ok(ConnectionMetricsPoint {
                    timestamp: row.get(0)?,
                    total: row.get(1)?,
                    tcp: row.get(2)?,
                    udp: row.get(3)?,
                    other: row.get(4)?,
                })
            })
            .map_err(|e| format!("connection_metrics query: {e}"))?;

        let mut points = Vec::new();
        for row in rows {
            points.push(row.map_err(|e| format!("connection_metrics row: {e}"))?);
        }
        Ok(points)
    }

    // ── VLAN metrics ─────────────────────────────────────────────

    /// Record VLAN throughput samples (one per VLAN).
    pub async fn record_vlan_metrics(
        &self,
        entries: &[(String, u64, u64)],
    ) -> Result<(), String> {
        let now = now_unix();
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "INSERT INTO vlan_metrics (timestamp, vlan_name, rx_bps, tx_bps) VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(|e| format!("vlan_metrics prepare: {e}"))?;

        for (name, rx, tx) in entries {
            stmt.execute(rusqlite::params![now, name, rx, tx])
                .map_err(|e| format!("vlan_metrics insert: {e}"))?;
        }
        Ok(())
    }

    /// Query VLAN metrics within the last `since_secs_ago` seconds.
    pub async fn query_vlan_metrics(
        &self,
        since_secs_ago: i64,
    ) -> Result<Vec<VlanMetricsPoint>, String> {
        let cutoff = now_unix() - since_secs_ago;
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT timestamp, vlan_name, rx_bps, tx_bps
                 FROM vlan_metrics WHERE timestamp >= ?1 ORDER BY timestamp ASC",
            )
            .map_err(|e| format!("vlan_metrics query prepare: {e}"))?;

        let rows = stmt
            .query_map([cutoff], |row| {
                Ok(VlanMetricsPoint {
                    timestamp: row.get(0)?,
                    vlan_name: row.get(1)?,
                    rx_bps: row.get(2)?,
                    tx_bps: row.get(3)?,
                })
            })
            .map_err(|e| format!("vlan_metrics query: {e}"))?;

        let mut points = Vec::new();
        for row in rows {
            points.push(row.map_err(|e| format!("vlan_metrics row: {e}"))?);
        }
        Ok(points)
    }

    // ── Log aggregates ───────────────────────────────────────────

    /// Record an hourly log aggregate.
    pub async fn record_log_aggregate(
        &self,
        period_start: i64,
        period_end: i64,
        total_entries: u32,
        drop_count: u32,
        accept_count: u32,
        top_drop_source: Option<&str>,
        top_drop_source_count: u32,
        top_target_port: Option<u32>,
        top_target_port_count: u32,
        drops_by_interface: &str,
    ) -> Result<(), String> {
        let now = now_unix();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO log_aggregates (
                timestamp, period_start, period_end,
                total_entries, drop_count, accept_count,
                top_drop_source, top_drop_source_count,
                top_target_port, top_target_port_count,
                drops_by_interface
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                now,
                period_start,
                period_end,
                total_entries,
                drop_count,
                accept_count,
                top_drop_source,
                top_drop_source_count,
                top_target_port,
                top_target_port_count,
                drops_by_interface,
            ],
        )
        .map_err(|e| format!("log_aggregates insert: {e}"))?;
        Ok(())
    }

    /// Query log aggregates within the last `since_secs_ago` seconds.
    pub async fn query_log_aggregates(
        &self,
        since_secs_ago: i64,
    ) -> Result<Vec<LogAggregate>, String> {
        let cutoff = now_unix() - since_secs_ago;
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT timestamp, period_start, period_end,
                        total_entries, drop_count, accept_count,
                        top_drop_source, top_drop_source_count,
                        top_target_port, top_target_port_count,
                        drops_by_interface
                 FROM log_aggregates WHERE timestamp >= ?1 ORDER BY timestamp ASC",
            )
            .map_err(|e| format!("log_aggregates query prepare: {e}"))?;

        let rows = stmt
            .query_map([cutoff], |row| {
                Ok(LogAggregate {
                    timestamp: row.get(0)?,
                    period_start: row.get(1)?,
                    period_end: row.get(2)?,
                    total_entries: row.get(3)?,
                    drop_count: row.get(4)?,
                    accept_count: row.get(5)?,
                    top_drop_source: row.get(6)?,
                    top_drop_source_count: row.get(7)?,
                    top_target_port: row.get(8)?,
                    top_target_port_count: row.get(9)?,
                    drops_by_interface: row.get(10)?,
                })
            })
            .map_err(|e| format!("log_aggregates query: {e}"))?;

        let mut points = Vec::new();
        for row in rows {
            points.push(row.map_err(|e| format!("log_aggregates row: {e}"))?);
        }
        Ok(points)
    }

    // ── Cleanup ──────────────────────────────────────────────────

    /// Delete data older than the specified age.
    /// System/drop/connection/vlan metrics: 7 days.
    /// Log aggregates: 30 days.
    pub async fn cleanup(&self, max_age_secs: i64) -> Result<(), String> {
        let cutoff = now_unix() - max_age_secs;
        let log_cutoff = now_unix() - 30 * 86400;

        let db = self.db.lock().await;
        db.execute("DELETE FROM metrics WHERE timestamp < ?1", [cutoff])
            .map_err(|e| format!("metrics cleanup: {e}"))?;
        db.execute("DELETE FROM drop_metrics WHERE timestamp < ?1", [cutoff])
            .map_err(|e| format!("drop_metrics cleanup: {e}"))?;
        db.execute(
            "DELETE FROM connection_metrics WHERE timestamp < ?1",
            [cutoff],
        )
        .map_err(|e| format!("connection_metrics cleanup: {e}"))?;
        db.execute("DELETE FROM vlan_metrics WHERE timestamp < ?1", [cutoff])
            .map_err(|e| format!("vlan_metrics cleanup: {e}"))?;
        db.execute(
            "DELETE FROM log_aggregates WHERE timestamp < ?1",
            [log_cutoff],
        )
        .map_err(|e| format!("log_aggregates cleanup: {e}"))?;

        Ok(())
    }
}

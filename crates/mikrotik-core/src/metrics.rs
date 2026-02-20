//! CPU and memory metrics history store.
//!
//! Polls system resources periodically and stores time-series data in SQLite
//! for 24-hour and 7-day history graphs.

use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use serde::Serialize;
use tokio::sync::Mutex;

/// A single metrics data point.
#[derive(Debug, Clone, Serialize)]
pub struct MetricsPoint {
    pub timestamp: i64,
    pub cpu_load: u32,
    pub memory_used: u64,
    pub memory_total: u64,
}

/// Persistent metrics store backed by SQLite.
pub struct MetricsStore {
    db: Arc<Mutex<Connection>>,
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
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp);",
        )?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    /// Record a metrics sample with the current timestamp.
    pub async fn record(
        &self,
        cpu_load: u32,
        memory_used: u64,
        memory_total: u64,
    ) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO metrics (timestamp, cpu_load, memory_used, memory_total) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![now, cpu_load, memory_used, memory_total],
        )
        .map_err(|e| format!("metrics insert: {e}"))?;

        Ok(())
    }

    /// Query metrics recorded within the last `since_secs_ago` seconds.
    pub async fn query(&self, since_secs_ago: i64) -> Result<Vec<MetricsPoint>, String> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - since_secs_ago;

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

    /// Delete metrics older than `max_age_secs` seconds.
    pub async fn cleanup(&self, max_age_secs: i64) -> Result<(), String> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - max_age_secs;

        let db = self.db.lock().await;
        db.execute("DELETE FROM metrics WHERE timestamp < ?1", [cutoff])
            .map_err(|e| format!("metrics cleanup: {e}"))?;

        Ok(())
    }
}

//! Lifetime traffic counter tracker.
//!
//! RouterOS resets interface counters on reboot. This module polls the WAN
//! interface, detects counter resets, and accumulates lifetime totals in a
//! SQLite database.

use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::MikrotikClient;

/// Accumulated lifetime traffic counters.
#[derive(Debug, Clone, Serialize)]
pub struct LifetimeTraffic {
    /// Total bytes received (download) over the router's lifetime.
    pub rx_bytes: u64,
    /// Total bytes transmitted (upload) over the router's lifetime.
    pub tx_bytes: u64,
    /// Name of the tracked interface.
    pub interface: String,
}

/// Persistent traffic tracker backed by SQLite.
pub struct TrafficTracker {
    db: Arc<Mutex<Connection>>,
    interface_name: String,
}

impl TrafficTracker {
    /// Create a new tracker, opening (or creating) the SQLite database at `db_path`.
    ///
    /// `interface_name` is the RouterOS interface name to track (e.g. `"1-WAN"`).
    pub fn new(db_path: &Path, interface_name: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS traffic (
                interface TEXT PRIMARY KEY,
                baseline_rx INTEGER NOT NULL DEFAULT 0,
                baseline_tx INTEGER NOT NULL DEFAULT 0,
                last_rx INTEGER NOT NULL DEFAULT 0,
                last_tx INTEGER NOT NULL DEFAULT 0
            );",
        )?;

        // Ensure a row exists for this interface
        conn.execute(
            "INSERT OR IGNORE INTO traffic (interface, baseline_rx, baseline_tx, last_rx, last_tx)
             VALUES (?1, 0, 0, 0, 0)",
            [interface_name],
        )?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            interface_name: interface_name.to_string(),
        })
    }

    /// Poll the router for current WAN counters and update the database.
    ///
    /// Returns the updated lifetime totals.
    pub async fn poll(&self, client: &MikrotikClient) -> Result<LifetimeTraffic, crate::MikrotikError> {
        let interfaces = client.interfaces().await?;
        let wan = interfaces
            .iter()
            .find(|i| i.name == self.interface_name)
            .ok_or_else(|| crate::MikrotikError::RouterOs {
                status: 0,
                message: format!("interface '{}' not found", self.interface_name),
                detail: None,
            })?;

        let current_rx = wan.rx_byte.unwrap_or(0);
        let current_tx = wan.tx_byte.unwrap_or(0);

        let db = self.db.lock().await;
        self.update_counters(&db, current_rx, current_tx)
            .map_err(|e| crate::MikrotikError::Database(format!("tracker: {e}")))
    }

    /// Get current lifetime totals without polling the router.
    pub async fn get_totals(&self) -> Result<LifetimeTraffic, crate::MikrotikError> {
        let db = self.db.lock().await;
        let (baseline_rx, baseline_tx, last_rx, last_tx): (u64, u64, u64, u64) = db
            .query_row(
                "SELECT baseline_rx, baseline_tx, last_rx, last_tx FROM traffic WHERE interface = ?1",
                [&self.interface_name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|e| crate::MikrotikError::Database(format!("tracker: {e}")))?;

        Ok(LifetimeTraffic {
            rx_bytes: baseline_rx + last_rx,
            tx_bytes: baseline_tx + last_tx,
            interface: self.interface_name.clone(),
        })
    }

    /// Core logic: compare current counters against last-known values,
    /// detect resets, and update the database.
    fn update_counters(
        &self,
        db: &Connection,
        current_rx: u64,
        current_tx: u64,
    ) -> Result<LifetimeTraffic, rusqlite::Error> {
        let (baseline_rx, baseline_tx, last_rx, last_tx): (u64, u64, u64, u64) = db.query_row(
            "SELECT baseline_rx, baseline_tx, last_rx, last_tx FROM traffic WHERE interface = ?1",
            [&self.interface_name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;

        // Detect reset: current counters are lower than last recorded values.
        // When a reset happens, the last_rx/last_tx values represent traffic
        // from the previous boot cycle — roll them into the baseline.
        let (new_baseline_rx, new_baseline_tx) = if current_rx < last_rx || current_tx < last_tx {
            tracing::info!(
                "Counter reset detected on '{}': rx {} -> {}, tx {} -> {}",
                self.interface_name,
                last_rx,
                current_rx,
                last_tx,
                current_tx
            );
            (baseline_rx + last_rx, baseline_tx + last_tx)
        } else {
            (baseline_rx, baseline_tx)
        };

        db.execute(
            "UPDATE traffic SET baseline_rx = ?1, baseline_tx = ?2, last_rx = ?3, last_tx = ?4
             WHERE interface = ?5",
            rusqlite::params![
                new_baseline_rx,
                new_baseline_tx,
                current_rx,
                current_tx,
                &self.interface_name
            ],
        )?;

        Ok(LifetimeTraffic {
            rx_bytes: new_baseline_rx + current_rx,
            tx_bytes: new_baseline_tx + current_tx,
            interface: self.interface_name.clone(),
        })
    }
}

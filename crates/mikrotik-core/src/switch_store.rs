//! Switch data store for multi-device monitoring.
//!
//! Stores per-port metrics, MAC address tables, neighbor discovery,
//! network identities, VLAN membership, and port role classifications
//! in a dedicated SQLite database.

use std::path::Path;
use std::sync::Arc;

use rusqlite::{params, Connection};
use serde::Serialize;
use tokio::sync::Mutex;

// ── Data types ──────────────────────────────────────────────────

/// A single switch port metrics entry.
#[derive(Debug, Clone, Serialize)]
pub struct PortMetricEntry {
    pub port_name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub speed: Option<String>,
    pub running: bool,
}

/// A MAC address table entry.
#[derive(Debug, Clone, Serialize)]
pub struct MacTableEntry {
    pub device_id: String,
    pub mac_address: String,
    pub port_name: String,
    pub bridge: String,
    pub vlan_id: Option<u32>,
    pub is_local: bool,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// A neighbor discovery entry (LLDP/MNDP/CDP).
#[derive(Debug, Clone, Serialize)]
pub struct NeighborEntry {
    pub device_id: String,
    pub interface: String,
    pub mac_address: Option<String>,
    pub address: Option<String>,
    pub identity: Option<String>,
    pub platform: Option<String>,
    pub board: Option<String>,
    pub version: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// A unified network identity record (correlation output).
#[derive(Debug, Clone, Serialize)]
pub struct NetworkIdentity {
    pub mac_address: String,
    pub best_ip: Option<String>,
    pub hostname: Option<String>,
    pub manufacturer: Option<String>,
    pub switch_device_id: Option<String>,
    pub switch_port: Option<String>,
    pub vlan_id: Option<u32>,
    pub discovery_protocol: Option<String>,
    pub remote_identity: Option<String>,
    pub remote_platform: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub confidence: f64,
}

/// A VLAN membership entry for a switch port.
#[derive(Debug, Clone, Serialize)]
pub struct VlanMembershipEntry {
    pub port_name: String,
    pub vlan_id: u32,
    pub tagged: bool,
}

/// A port role classification entry.
#[derive(Debug, Clone, Serialize)]
pub struct PortRoleEntry {
    pub device_id: String,
    pub port_name: String,
    pub role: String,
    pub vlan_count: u32,
    pub mac_count: u32,
    pub has_lldp_neighbor: bool,
    pub updated_at: i64,
}

// ── Store ───────────────────────────────────────────────────────

/// Persistent switch data store backed by SQLite.
pub struct SwitchStore {
    db: Arc<Mutex<Connection>>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

impl SwitchStore {
    /// Create a new store, opening (or creating) the SQLite database at `db_path`.
    pub fn new(db_path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS switch_port_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                port_name TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0,
                rx_packets INTEGER NOT NULL DEFAULT 0,
                tx_packets INTEGER NOT NULL DEFAULT 0,
                speed TEXT,
                running INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_spm_device_ts
                ON switch_port_metrics (device_id, timestamp);

            CREATE TABLE IF NOT EXISTS switch_mac_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                port_name TEXT NOT NULL,
                bridge TEXT NOT NULL,
                vlan_id INTEGER,
                is_local INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_smt_unique
                ON switch_mac_table (device_id, mac_address, port_name);
            CREATE INDEX IF NOT EXISTS idx_smt_device_port
                ON switch_mac_table (device_id, port_name);

            CREATE TABLE IF NOT EXISTS neighbor_discovery (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                interface TEXT NOT NULL,
                mac_address TEXT,
                address TEXT,
                identity TEXT,
                platform TEXT,
                board TEXT,
                version TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_nd_unique
                ON neighbor_discovery (device_id, interface, mac_address);
            CREATE INDEX IF NOT EXISTS idx_nd_device
                ON neighbor_discovery (device_id);

            CREATE TABLE IF NOT EXISTS network_identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL UNIQUE,
                best_ip TEXT,
                hostname TEXT,
                manufacturer TEXT,
                switch_device_id TEXT,
                switch_port TEXT,
                vlan_id INTEGER,
                discovery_protocol TEXT,
                remote_identity TEXT,
                remote_platform TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.0
            );
            CREATE INDEX IF NOT EXISTS idx_ni_mac
                ON network_identities (mac_address);

            CREATE TABLE IF NOT EXISTS switch_vlan_membership (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                port_name TEXT NOT NULL,
                vlan_id INTEGER NOT NULL,
                tagged INTEGER NOT NULL DEFAULT 0,
                timestamp INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_svm_unique
                ON switch_vlan_membership (device_id, port_name, vlan_id);

            CREATE TABLE IF NOT EXISTS switch_port_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                port_name TEXT NOT NULL,
                role TEXT NOT NULL,
                vlan_count INTEGER NOT NULL DEFAULT 0,
                mac_count INTEGER NOT NULL DEFAULT 0,
                has_lldp_neighbor INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_spr_unique
                ON switch_port_roles (device_id, port_name);

            PRAGMA journal_mode=WAL;",
        )?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    // ── Port metrics ────────────────────────────────────────────

    /// Record port metrics for a device (batch insert).
    pub async fn record_port_metrics(
        &self,
        device_id: &str,
        entries: &[PortMetricEntry],
    ) -> Result<(), rusqlite::Error> {
        let ts = now_unix();
        let db = self.db.lock().await;
        let mut stmt = db.prepare_cached(
            "INSERT INTO switch_port_metrics
             (device_id, port_name, timestamp, rx_bytes, tx_bytes, rx_packets, tx_packets, speed, running)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;
        for e in entries {
            stmt.execute(params![
                device_id,
                e.port_name,
                ts,
                e.rx_bytes as i64,
                e.tx_bytes as i64,
                e.rx_packets as i64,
                e.tx_packets as i64,
                e.speed,
                e.running as i32,
            ])?;
        }
        Ok(())
    }

    /// Get recent port metrics for a device.
    pub async fn get_port_metrics(
        &self,
        device_id: &str,
        since: i64,
    ) -> Result<Vec<(String, i64, i64, i64, Option<String>, bool)>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT port_name, rx_bytes, tx_bytes, timestamp, speed, running
             FROM switch_port_metrics
             WHERE device_id = ?1 AND timestamp >= ?2
             ORDER BY timestamp DESC",
        )?;
        let rows = stmt
            .query_map(params![device_id, since], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get::<_, i64>(3)?,
                    row.get(4)?,
                    row.get::<_, i32>(5)? != 0,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ── MAC table ───────────────────────────────────────────────

    /// Upsert a MAC address table entry.
    pub async fn upsert_mac_entry(
        &self,
        device_id: &str,
        mac_address: &str,
        port_name: &str,
        bridge: &str,
        vlan_id: Option<u32>,
        is_local: bool,
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO switch_mac_table
             (device_id, mac_address, port_name, bridge, vlan_id, is_local, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
             ON CONFLICT(device_id, mac_address, port_name) DO UPDATE SET
                 bridge = excluded.bridge,
                 vlan_id = excluded.vlan_id,
                 is_local = excluded.is_local,
                 last_seen = excluded.last_seen",
            params![
                device_id,
                mac_address,
                port_name,
                bridge,
                vlan_id.map(|v| v as i64),
                is_local as i32,
                now,
            ],
        )?;
        Ok(())
    }

    /// Get MAC table entries for a device (or all devices if None).
    pub async fn get_mac_table(
        &self,
        device_id: Option<&str>,
    ) -> Result<Vec<MacTableEntry>, rusqlite::Error> {
        let db = self.db.lock().await;
        let (sql, device_filter) = match device_id {
            Some(id) => (
                "SELECT device_id, mac_address, port_name, bridge, vlan_id, is_local, first_seen, last_seen
                 FROM switch_mac_table WHERE device_id = ?1 ORDER BY last_seen DESC",
                Some(id.to_string()),
            ),
            None => (
                "SELECT device_id, mac_address, port_name, bridge, vlan_id, is_local, first_seen, last_seen
                 FROM switch_mac_table ORDER BY last_seen DESC",
                None,
            ),
        };
        let mut stmt = db.prepare(sql)?;
        let rows = if let Some(ref id) = device_filter {
            stmt.query_map(params![id], map_mac_row)?
        } else {
            stmt.query_map([], map_mac_row)?
        };
        rows.collect()
    }

    // ── Neighbor discovery ──────────────────────────────────────

    /// Upsert a neighbor discovery entry.
    pub async fn upsert_neighbor(
        &self,
        device_id: &str,
        interface: &str,
        mac_address: Option<&str>,
        address: Option<&str>,
        identity: Option<&str>,
        platform: Option<&str>,
        board: Option<&str>,
        version: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        let mac = mac_address.unwrap_or("");
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO neighbor_discovery
             (device_id, interface, mac_address, address, identity, platform, board, version, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(device_id, interface, mac_address) DO UPDATE SET
                 address = excluded.address,
                 identity = excluded.identity,
                 platform = excluded.platform,
                 board = excluded.board,
                 version = excluded.version,
                 last_seen = excluded.last_seen",
            params![device_id, interface, mac, address, identity, platform, board, version, now],
        )?;
        Ok(())
    }

    /// Get neighbor entries for a device (or all devices if None).
    pub async fn get_neighbors(
        &self,
        device_id: Option<&str>,
    ) -> Result<Vec<NeighborEntry>, rusqlite::Error> {
        let db = self.db.lock().await;
        let (sql, device_filter) = match device_id {
            Some(id) => (
                "SELECT device_id, interface, mac_address, address, identity, platform, board, version, first_seen, last_seen
                 FROM neighbor_discovery WHERE device_id = ?1 ORDER BY last_seen DESC",
                Some(id.to_string()),
            ),
            None => (
                "SELECT device_id, interface, mac_address, address, identity, platform, board, version, first_seen, last_seen
                 FROM neighbor_discovery ORDER BY last_seen DESC",
                None,
            ),
        };
        let mut stmt = db.prepare(sql)?;
        let rows = if let Some(ref id) = device_filter {
            stmt.query_map(params![id], map_neighbor_row)?
        } else {
            stmt.query_map([], map_neighbor_row)?
        };
        rows.collect()
    }

    // ── Network identities ──────────────────────────────────────

    /// Upsert a network identity record.
    pub async fn upsert_network_identity(
        &self,
        mac_address: &str,
        best_ip: Option<&str>,
        hostname: Option<&str>,
        manufacturer: Option<&str>,
        switch_device_id: Option<&str>,
        switch_port: Option<&str>,
        vlan_id: Option<u32>,
        discovery_protocol: Option<&str>,
        remote_identity: Option<&str>,
        remote_platform: Option<&str>,
        confidence: f64,
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO network_identities
             (mac_address, best_ip, hostname, manufacturer, switch_device_id, switch_port,
              vlan_id, discovery_protocol, remote_identity, remote_platform, first_seen, last_seen, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11, ?12)
             ON CONFLICT(mac_address) DO UPDATE SET
                 best_ip = COALESCE(excluded.best_ip, network_identities.best_ip),
                 hostname = COALESCE(excluded.hostname, network_identities.hostname),
                 manufacturer = COALESCE(excluded.manufacturer, network_identities.manufacturer),
                 switch_device_id = COALESCE(excluded.switch_device_id, network_identities.switch_device_id),
                 switch_port = COALESCE(excluded.switch_port, network_identities.switch_port),
                 vlan_id = COALESCE(excluded.vlan_id, network_identities.vlan_id),
                 discovery_protocol = COALESCE(excluded.discovery_protocol, network_identities.discovery_protocol),
                 remote_identity = COALESCE(excluded.remote_identity, network_identities.remote_identity),
                 remote_platform = COALESCE(excluded.remote_platform, network_identities.remote_platform),
                 last_seen = excluded.last_seen,
                 confidence = MAX(excluded.confidence, network_identities.confidence)",
            params![
                mac_address,
                best_ip,
                hostname,
                manufacturer,
                switch_device_id,
                switch_port,
                vlan_id.map(|v| v as i64),
                discovery_protocol,
                remote_identity,
                remote_platform,
                now,
                confidence,
            ],
        )?;
        Ok(())
    }

    /// Get all network identity records.
    pub async fn get_network_identities(&self) -> Result<Vec<NetworkIdentity>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT mac_address, best_ip, hostname, manufacturer, switch_device_id, switch_port,
                    vlan_id, discovery_protocol, remote_identity, remote_platform,
                    first_seen, last_seen, confidence
             FROM network_identities ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(NetworkIdentity {
                mac_address: row.get(0)?,
                best_ip: row.get(1)?,
                hostname: row.get(2)?,
                manufacturer: row.get(3)?,
                switch_device_id: row.get(4)?,
                switch_port: row.get(5)?,
                vlan_id: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
                discovery_protocol: row.get(7)?,
                remote_identity: row.get(8)?,
                remote_platform: row.get(9)?,
                first_seen: row.get(10)?,
                last_seen: row.get(11)?,
                confidence: row.get(12)?,
            })
        })?;
        rows.collect()
    }

    // ── VLAN membership ─────────────────────────────────────────

    /// Set VLAN membership for a device (replace all entries for the device).
    pub async fn set_vlan_membership(
        &self,
        device_id: &str,
        entries: &[VlanMembershipEntry],
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        let db = self.db.lock().await;
        // Delete existing entries for this device and re-insert
        db.execute(
            "DELETE FROM switch_vlan_membership WHERE device_id = ?1",
            params![device_id],
        )?;
        let mut stmt = db.prepare_cached(
            "INSERT INTO switch_vlan_membership
             (device_id, port_name, vlan_id, tagged, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for e in entries {
            stmt.execute(params![
                device_id,
                e.port_name,
                e.vlan_id as i64,
                e.tagged as i32,
                now,
            ])?;
        }
        Ok(())
    }

    /// Get VLAN membership for a device.
    pub async fn get_vlan_membership(
        &self,
        device_id: &str,
    ) -> Result<Vec<VlanMembershipEntry>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT port_name, vlan_id, tagged
             FROM switch_vlan_membership
             WHERE device_id = ?1
             ORDER BY port_name, vlan_id",
        )?;
        let rows = stmt.query_map(params![device_id], |row| {
            Ok(VlanMembershipEntry {
                port_name: row.get(0)?,
                vlan_id: row.get::<_, i64>(1)? as u32,
                tagged: row.get::<_, i32>(2)? != 0,
            })
        })?;
        rows.collect()
    }

    // ── Port roles ──────────────────────────────────────────────

    /// Set a port role for a device.
    pub async fn set_port_role(
        &self,
        device_id: &str,
        port_name: &str,
        role: &str,
        vlan_count: u32,
        mac_count: u32,
        has_lldp_neighbor: bool,
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO switch_port_roles
             (device_id, port_name, role, vlan_count, mac_count, has_lldp_neighbor, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(device_id, port_name) DO UPDATE SET
                 role = excluded.role,
                 vlan_count = excluded.vlan_count,
                 mac_count = excluded.mac_count,
                 has_lldp_neighbor = excluded.has_lldp_neighbor,
                 updated_at = excluded.updated_at",
            params![
                device_id,
                port_name,
                role,
                vlan_count as i64,
                mac_count as i64,
                has_lldp_neighbor as i32,
                now,
            ],
        )?;
        Ok(())
    }

    /// Get port roles for a device (or all devices if None).
    pub async fn get_port_roles(
        &self,
        device_id: Option<&str>,
    ) -> Result<Vec<PortRoleEntry>, rusqlite::Error> {
        let db = self.db.lock().await;
        let (sql, device_filter) = match device_id {
            Some(id) => (
                "SELECT device_id, port_name, role, vlan_count, mac_count, has_lldp_neighbor, updated_at
                 FROM switch_port_roles WHERE device_id = ?1 ORDER BY port_name",
                Some(id.to_string()),
            ),
            None => (
                "SELECT device_id, port_name, role, vlan_count, mac_count, has_lldp_neighbor, updated_at
                 FROM switch_port_roles ORDER BY device_id, port_name",
                None,
            ),
        };
        let mut stmt = db.prepare(sql)?;
        let rows = if let Some(ref id) = device_filter {
            stmt.query_map(params![id], map_port_role_row)?
        } else {
            stmt.query_map([], map_port_role_row)?
        };
        rows.collect()
    }

    // ── Cleanup ─────────────────────────────────────────────────

    /// Prune old port metrics data.
    pub async fn cleanup(&self, max_age_secs: i64) -> Result<(), rusqlite::Error> {
        let cutoff = now_unix() - max_age_secs;
        let db = self.db.lock().await;
        db.execute(
            "DELETE FROM switch_port_metrics WHERE timestamp < ?1",
            params![cutoff],
        )?;
        Ok(())
    }

    /// Remove all data for a device (when device is deleted).
    pub async fn remove_device_data(&self, device_id: &str) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute_batch(&format!(
            "DELETE FROM switch_port_metrics WHERE device_id = '{device_id}';
             DELETE FROM switch_mac_table WHERE device_id = '{device_id}';
             DELETE FROM neighbor_discovery WHERE device_id = '{device_id}';
             DELETE FROM switch_vlan_membership WHERE device_id = '{device_id}';
             DELETE FROM switch_port_roles WHERE device_id = '{device_id}';
             DELETE FROM network_identities WHERE switch_device_id = '{device_id}';"
        ))?;
        Ok(())
    }
}

// ── Row mappers ─────────────────────────────────────────────────

fn map_mac_row(row: &rusqlite::Row<'_>) -> Result<MacTableEntry, rusqlite::Error> {
    Ok(MacTableEntry {
        device_id: row.get(0)?,
        mac_address: row.get(1)?,
        port_name: row.get(2)?,
        bridge: row.get(3)?,
        vlan_id: row.get::<_, Option<i64>>(4)?.map(|v| v as u32),
        is_local: row.get::<_, i32>(5)? != 0,
        first_seen: row.get(6)?,
        last_seen: row.get(7)?,
    })
}

fn map_neighbor_row(row: &rusqlite::Row<'_>) -> Result<NeighborEntry, rusqlite::Error> {
    Ok(NeighborEntry {
        device_id: row.get(0)?,
        interface: row.get(1)?,
        mac_address: row.get(2)?,
        address: row.get(3)?,
        identity: row.get(4)?,
        platform: row.get(5)?,
        board: row.get(6)?,
        version: row.get(7)?,
        first_seen: row.get(8)?,
        last_seen: row.get(9)?,
    })
}

fn map_port_role_row(row: &rusqlite::Row<'_>) -> Result<PortRoleEntry, rusqlite::Error> {
    Ok(PortRoleEntry {
        device_id: row.get(0)?,
        port_name: row.get(1)?,
        role: row.get(2)?,
        vlan_count: row.get::<_, i64>(3)? as u32,
        mac_count: row.get::<_, i64>(4)? as u32,
        has_lldp_neighbor: row.get::<_, i32>(5)? != 0,
        updated_at: row.get(6)?,
    })
}

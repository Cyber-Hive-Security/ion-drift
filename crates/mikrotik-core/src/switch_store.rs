//! Switch data store for multi-device monitoring.
//!
//! Stores per-port metrics, MAC address tables, neighbor discovery,
//! network identities, VLAN membership, and port role classifications
//! in a dedicated SQLite database.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
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
    pub device_type: Option<String>,
    pub device_type_source: Option<String>,
    pub device_type_confidence: f64,
    pub human_confirmed: bool,
    pub human_label: Option<String>,
    pub disposition: String,
    pub is_infrastructure: Option<bool>,
    pub switch_binding_source: String,
    pub link_speed_mbps: Option<u32>,
}

/// An nmap scan record.
#[derive(Debug, Clone, Serialize)]
pub struct NmapScan {
    pub id: String,
    pub vlan_id: u32,
    pub profile: String,
    pub status: String,
    pub target_count: i32,
    pub discovered_count: i32,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
}

/// An nmap scan result (per-host).
#[derive(Debug, Clone, Serialize)]
pub struct NmapResult {
    pub id: i64,
    pub scan_id: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub os_accuracy: Option<i32>,
    pub open_ports: Option<String>,
    pub device_type: Option<String>,
    pub created_at: String,
}

/// A scan exclusion entry.
#[derive(Debug, Clone, Serialize)]
pub struct ScanExclusion {
    pub ip_address: String,
    pub reason: Option<String>,
    pub created_at: String,
}

/// A traffic pattern classification result.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficClassification {
    pub mac_address: String,
    pub device_type: String,
    pub confidence: f64,
    pub evidence: String,
    pub classified_at: String,
}

/// Identity statistics summary.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityStats {
    pub total: i64,
    pub confirmed: i64,
    pub unconfirmed: i64,
    pub by_device_type: std::collections::HashMap<String, i64>,
    pub by_source: std::collections::HashMap<String, i64>,
    pub by_disposition: std::collections::HashMap<String, i64>,
}

/// A VLAN membership entry for a switch port.
#[derive(Debug, Clone, Serialize)]
pub struct VlanMembershipEntry {
    pub port_name: String,
    pub vlan_id: u32,
    pub tagged: bool,
}

/// An observed service detected via passive connection tracking analysis.
#[derive(Debug, Clone, Serialize)]
pub struct ObservedService {
    pub ip_address: String,
    pub port: u32,
    pub protocol: String,
    pub service_name: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub connection_count: i64,
}

/// A topology node position (auto-computed or human override).
#[derive(Debug, Clone, Serialize)]
pub struct TopologyPosition {
    pub node_id: String,
    pub x: f64,
    pub y: f64,
    pub source: String,
    pub updated_at: String,
}

/// A VLAN sector position (auto-computed or human override).
#[derive(Debug, Clone, Serialize)]
pub struct SectorPosition {
    pub vlan_id: u32,
    pub x: f64,
    pub y: f64,
    pub width: Option<f64>,
    pub height: Option<f64>,
    pub source: String,
    pub updated_at: String,
}

/// A MAC-to-port binding (human-managed port security expectation).
#[derive(Debug, Clone, Serialize)]
pub struct PortMacBinding {
    pub device_id: String,
    pub port_name: String,
    pub expected_mac: String,
    pub created_at: String,
    pub created_by: String,
}

/// A port violation event (binding enforcement alert).
#[derive(Debug, Clone, Serialize)]
pub struct PortViolation {
    pub id: i64,
    pub device_id: String,
    pub port_name: String,
    pub expected_mac: String,
    pub actual_mac: Option<String>,
    pub violation_type: String,
    pub first_seen: String,
    pub last_seen: String,
    pub resolved: bool,
    pub resolved_at: Option<String>,
}

/// A neighbor alias/hide rule for topology neighbor matching.
#[derive(Debug, Clone, Serialize)]
pub struct NeighborAlias {
    pub id: i64,
    pub match_type: String,       // "mac" or "identity"
    pub match_value: String,
    pub action: String,           // "alias" or "hide"
    pub target_device_id: Option<String>,
    pub created_at: String,
}

/// A manually-defined switch-to-switch backbone connection.
#[derive(Debug, Clone, Serialize)]
pub struct BackboneLink {
    pub id: i64,
    pub device_a: String,
    pub port_a: Option<String>,
    pub device_b: String,
    pub port_b: Option<String>,
    pub label: Option<String>,
    pub speed_mbps: Option<u32>,
    pub link_type: Option<String>,
    pub created_at: String,
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

/// A time-series MAC observation for the topology inference engine.
#[derive(Debug, Clone, Serialize)]
pub struct MacObservation {
    pub id: i64,
    pub mac_address: String,
    pub device_id: String,
    pub port_name: String,
    pub vlan_id: Option<u32>,
    pub timestamp: i64,
    pub observation_confidence: f64,
    pub edge_likelihood: f64,
    pub transit_likelihood: f64,
}

/// Persisted attachment state for the topology inference state machine.
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentStateRow {
    pub mac_address: String,
    pub state: String,
    pub current_device_id: Option<String>,
    pub current_port_name: Option<String>,
    pub previous_device_id: Option<String>,
    pub previous_port_name: Option<String>,
    pub current_score: f64,
    pub confidence: f64,
    pub consecutive_wins: u32,
    pub consecutive_losses: u32,
    pub updated_at: i64,
}

/// Port role probability distribution (replaces binary classification).
#[derive(Debug, Clone, Serialize)]
pub struct PortRoleProbability {
    pub device_id: String,
    pub port_name: String,
    pub trunk_prob: f64,
    pub uplink_prob: f64,
    pub access_prob: f64,
    pub wireless_prob: f64,
    pub computed_at: i64,
}

/// A port discovered on a device (from metrics), optionally enriched with role data.
#[derive(Debug, Clone, Serialize)]
pub struct DevicePort {
    pub port_name: String,
    pub speed: Option<String>,
    pub running: bool,
    pub role: Option<String>,
    pub mac_count: Option<u32>,
}

/// VLAN configuration metadata (media type, color, subnet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanConfig {
    pub vlan_id: u32,
    pub name: String,
    pub media_type: String,
    pub subnet: Option<String>,
    pub color: Option<String>,
}

// ── Store ───────────────────────────────────────────────────────

/// Persistent switch data store backed by SQLite.
pub struct SwitchStore {
    db: Arc<Mutex<Connection>>,
}

/// Parse a speed string from any device poller into Mbps.
///
/// Supported formats:
///   - RouterOS/SNMP: "1000Mbps", "10000Mbps"
///   - SwOS:          "10M", "100M", "1G", "2.5G", "5G", "10G"
fn parse_speed_mbps(s: &str) -> Option<u32> {
    // Try "1000Mbps" format (RouterOS / SNMP)
    if let Some(num_str) = s.strip_suffix("Mbps") {
        return num_str.parse::<u32>().ok();
    }
    // Try "10Gbps", "1Gbps" format (RouterOS v7 SFP+/ethernet)
    if let Some(num_str) = s.strip_suffix("Gbps") {
        if let Ok(gig) = num_str.parse::<f64>() {
            return Some((gig * 1000.0) as u32);
        }
    }
    // Try "1G", "2.5G", "10G" format (SwOS gigabit)
    if let Some(num_str) = s.strip_suffix('G') {
        if let Ok(gig) = num_str.parse::<f64>() {
            return Some((gig * 1000.0) as u32);
        }
    }
    // Try "100M", "10M" format (SwOS megabit)
    if let Some(num_str) = s.strip_suffix('M') {
        return num_str.parse::<u32>().ok();
    }
    None
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

            CREATE TABLE IF NOT EXISTS nmap_scans (
                id TEXT PRIMARY KEY,
                vlan_id INTEGER NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                target_count INTEGER DEFAULT 0,
                discovered_count INTEGER DEFAULT 0,
                started_at TEXT,
                completed_at TEXT,
                error TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS nmap_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES nmap_scans(id),
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                os_guess TEXT,
                os_accuracy INTEGER,
                open_ports TEXT,
                device_type TEXT,
                raw_xml TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_nr_scan
                ON nmap_results (scan_id);

            CREATE TABLE IF NOT EXISTS scan_exclusions (
                ip_address TEXT PRIMARY KEY,
                reason TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS traffic_classifications (
                mac_address TEXT PRIMARY KEY,
                device_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT NOT NULL,
                classified_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS topology_positions (
                node_id TEXT PRIMARY KEY,
                x REAL NOT NULL,
                y REAL NOT NULL,
                source TEXT NOT NULL DEFAULT 'auto',
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS topology_sector_positions (
                vlan_id INTEGER PRIMARY KEY,
                x REAL NOT NULL,
                y REAL NOT NULL,
                width REAL,
                height REAL,
                source TEXT NOT NULL DEFAULT 'auto',
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS backbone_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_a TEXT NOT NULL,
                port_a TEXT,
                device_b TEXT NOT NULL,
                port_b TEXT,
                label TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS neighbor_aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                match_type TEXT NOT NULL CHECK(match_type IN ('mac', 'identity')),
                match_value TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('alias', 'hide')),
                target_device_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(match_type, match_value)
            );

            CREATE TABLE IF NOT EXISTS observed_services (
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                service_name TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                connection_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (ip_address, port, protocol)
            );

            CREATE TABLE IF NOT EXISTS port_mac_bindings (
                device_id TEXT NOT NULL,
                port_name TEXT NOT NULL,
                expected_mac TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                created_by TEXT NOT NULL DEFAULT 'human',
                PRIMARY KEY (device_id, port_name)
            );

            CREATE TABLE IF NOT EXISTS port_violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                port_name TEXT NOT NULL,
                expected_mac TEXT NOT NULL,
                actual_mac TEXT,
                violation_type TEXT NOT NULL,
                first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen TEXT NOT NULL DEFAULT (datetime('now')),
                resolved INTEGER NOT NULL DEFAULT 0,
                resolved_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pv_unique
                ON port_violations (device_id, port_name, expected_mac, actual_mac);

            CREATE TABLE IF NOT EXISTS vlan_config (
                vlan_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                media_type TEXT NOT NULL DEFAULT 'wired' CHECK(media_type IN ('wired', 'wireless', 'mixed')),
                subnet TEXT,
                color TEXT
            );

            CREATE TABLE IF NOT EXISTS mac_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL,
                device_id TEXT NOT NULL,
                port_name TEXT NOT NULL,
                vlan_id INTEGER,
                timestamp INTEGER NOT NULL,
                observation_confidence REAL NOT NULL DEFAULT 0.5,
                edge_likelihood REAL NOT NULL DEFAULT 0.5,
                transit_likelihood REAL NOT NULL DEFAULT 0.5
            );
            CREATE INDEX IF NOT EXISTS idx_mo_mac_time
                ON mac_observations(mac_address, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_mo_device_port
                ON mac_observations(device_id, port_name, timestamp DESC);

            CREATE TABLE IF NOT EXISTS port_role_probabilities (
                device_id TEXT NOT NULL,
                port_name TEXT NOT NULL,
                trunk_prob REAL NOT NULL DEFAULT 0.0,
                uplink_prob REAL NOT NULL DEFAULT 0.0,
                access_prob REAL NOT NULL DEFAULT 0.0,
                wireless_prob REAL NOT NULL DEFAULT 0.0,
                computed_at INTEGER NOT NULL,
                PRIMARY KEY (device_id, port_name)
            );

            CREATE TABLE IF NOT EXISTS mac_attachment_state (
                mac_address TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'unknown',
                current_device_id TEXT,
                current_port_name TEXT,
                previous_device_id TEXT,
                previous_port_name TEXT,
                current_score REAL NOT NULL DEFAULT 0.0,
                confidence REAL NOT NULL DEFAULT 0.0,
                consecutive_wins INTEGER NOT NULL DEFAULT 0,
                consecutive_losses INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0
            );

            PRAGMA journal_mode=WAL;",
        )?;

        // Idempotent schema migrations — add columns to network_identities
        for alter in &[
            "ALTER TABLE network_identities ADD COLUMN device_type TEXT",
            "ALTER TABLE network_identities ADD COLUMN device_type_source TEXT",
            "ALTER TABLE network_identities ADD COLUMN device_type_confidence REAL DEFAULT 0.0",
            "ALTER TABLE network_identities ADD COLUMN human_confirmed INTEGER DEFAULT 0",
            "ALTER TABLE network_identities ADD COLUMN human_label TEXT",
            "ALTER TABLE network_identities ADD COLUMN disposition TEXT DEFAULT 'unknown'",
            "ALTER TABLE network_identities ADD COLUMN is_infrastructure INTEGER",
            "ALTER TABLE network_identities ADD COLUMN switch_binding_source TEXT DEFAULT 'auto'",
        ] {
            let _ = conn.execute(alter, []);
        }

        // Idempotent schema migrations — add previous binding columns to mac_attachment_state
        for alter in &[
            "ALTER TABLE mac_attachment_state ADD COLUMN previous_device_id TEXT",
            "ALTER TABLE mac_attachment_state ADD COLUMN previous_port_name TEXT",
        ] {
            let _ = conn.execute(alter, []);
        }

        // One-time migration: clear hardcoded VLAN config seeds so router sync
        // can repopulate with actual data. Detects the old seed by checking if
        // VLAN 40 has an empty subnet (the hardcoded seed used '' for Guest).
        let has_hardcoded_seed: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM vlan_config WHERE vlan_id = 40 AND (subnet = '' OR subnet IS NULL)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) > 0;
        if has_hardcoded_seed {
            let _ = conn.execute("DELETE FROM vlan_config", []);
        }

        // One-time migration: lowercase existing backbone_links port names
        let _ = conn.execute(
            "UPDATE backbone_links SET port_a = LOWER(port_a) WHERE port_a IS NOT NULL AND port_a != LOWER(port_a)",
            [],
        );
        let _ = conn.execute(
            "UPDATE backbone_links SET port_b = LOWER(port_b) WHERE port_b IS NOT NULL AND port_b != LOWER(port_b)",
            [],
        );

        // Migration: add speed_mbps column to backbone_links
        let _ = conn.execute(
            "ALTER TABLE backbone_links ADD COLUMN speed_mbps INTEGER",
            [],
        );

        // Migration: add link_type column to backbone_links
        let _ = conn.execute(
            "ALTER TABLE backbone_links ADD COLUMN link_type TEXT DEFAULT 'dac'",
            [],
        );

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

    /// Get the latest port link speed for every port on a device.
    /// Returns a map of port_name (lowercase) → speed in Mbps (e.g. 1000, 2500, 10000).
    /// Port names are lowercased for case-insensitive matching against edge port names.
    pub async fn get_port_speeds(
        &self,
        device_id: &str,
    ) -> Result<HashMap<String, u32>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT port_name, speed FROM switch_port_metrics
             WHERE device_id = ?1 AND speed IS NOT NULL
               AND id IN (
                 SELECT MAX(id) FROM switch_port_metrics
                 WHERE device_id = ?1
                 GROUP BY port_name
               )",
        )?;
        let rows = stmt.query_map(params![device_id], |row| {
            let port: String = row.get(0)?;
            let speed_str: String = row.get(1)?;
            Ok((port, speed_str))
        })?;

        let mut map = HashMap::new();
        for row in rows {
            let (port, speed_str) = row?;
            let port_lower = port.to_lowercase();
            // Parse multiple speed formats:
            //   RouterOS/SNMP: "1000Mbps", "10000Mbps"
            //   RouterOS v7:   "1Gbps", "10Gbps"
            //   SwOS:          "10M", "100M", "1G", "2.5G", "5G", "10G"
            if let Some(mbps) = parse_speed_mbps(&speed_str) {
                map.insert(port_lower, mbps);
            } else {
                tracing::warn!(device = %device_id, port = %port_lower, raw = %speed_str, "unparseable speed string");
            }
        }
        Ok(map)
    }

    /// Get the latest traffic rate (bytes/sec) for each port on a device.
    /// Computes rate from the two most recent metric samples per port.
    /// Returns port_name (lowercase) → total bps (rx + tx combined, converted to bits).
    pub async fn get_port_traffic_bps(
        &self,
        device_id: &str,
    ) -> Result<HashMap<String, u64>, rusqlite::Error> {
        let db = self.db.lock().await;
        // For each port, get the two most recent rows ordered by id DESC
        let mut stmt = db.prepare(
            "SELECT port_name, rx_bytes, tx_bytes, timestamp
             FROM switch_port_metrics
             WHERE device_id = ?1 AND running = 1
             ORDER BY port_name, id DESC",
        )?;
        let rows = stmt.query_map(params![device_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;

        // Group by port, take first two samples (most recent)
        let mut port_samples: HashMap<String, Vec<(i64, i64, i64)>> = HashMap::new();
        for row in rows {
            let (port, rx, tx, ts) = row?;
            let lower = port.to_lowercase();
            let samples = port_samples.entry(lower).or_default();
            if samples.len() < 2 {
                samples.push((rx, tx, ts));
            }
        }

        let mut map = HashMap::new();
        for (port, samples) in &port_samples {
            if samples.len() == 2 {
                let (rx1, tx1, ts1) = samples[0]; // newer
                let (rx0, tx0, ts0) = samples[1]; // older
                let dt = (ts1 - ts0).max(1) as u64;
                let rx_delta = (rx1 - rx0).max(0) as u64;
                let tx_delta = (tx1 - tx0).max(0) as u64;
                let bytes_per_sec = (rx_delta + tx_delta) / dt;
                let bps = bytes_per_sec * 8;
                if bps > 0 {
                    map.insert(port.clone(), bps);
                }
            }
        }
        Ok(map)
    }

    /// Get a distinct list of ports for a device, derived from port metrics
    /// and enriched with role data from switch_port_roles if available.
    pub async fn get_device_port_list(
        &self,
        device_id: &str,
    ) -> Result<Vec<DevicePort>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT m.port_name, m.speed, m.running, r.role, r.mac_count
             FROM switch_port_metrics m
             LEFT JOIN switch_port_roles r
               ON r.device_id = m.device_id AND LOWER(r.port_name) = LOWER(m.port_name)
             WHERE m.device_id = ?1
               AND m.id IN (
                 SELECT MAX(id) FROM switch_port_metrics
                 WHERE device_id = ?1
                 GROUP BY port_name
               )
             ORDER BY m.port_name COLLATE NOCASE",
        )?;
        let rows = stmt.query_map(params![device_id], |row| {
            Ok(DevicePort {
                port_name: row.get(0)?,
                speed: row.get(1)?,
                running: row.get::<_, i32>(2)? != 0,
                role: row.get(3)?,
                mac_count: row.get::<_, Option<i64>>(4)?.map(|v| v as u32),
            })
        })?;
        rows.collect()
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
        let port_lower = port_name.to_lowercase();
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
                &port_lower,
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
    ///
    /// Device type fields use a confidence hierarchy: a new device_type only overwrites
    /// an existing one if the new confidence is >= the existing, AND the record is not
    /// human-confirmed (human_confirmed = 1 locks the device_type).
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
        device_type: Option<&str>,
        device_type_source: Option<&str>,
        device_type_confidence: f64,
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO network_identities
             (mac_address, best_ip, hostname, manufacturer, switch_device_id, switch_port,
              vlan_id, discovery_protocol, remote_identity, remote_platform, first_seen, last_seen, confidence,
              device_type, device_type_source, device_type_confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(mac_address) DO UPDATE SET
                 best_ip = COALESCE(excluded.best_ip, network_identities.best_ip),
                 hostname = COALESCE(excluded.hostname, network_identities.hostname),
                 manufacturer = COALESCE(excluded.manufacturer, network_identities.manufacturer),
                 switch_device_id = CASE
                     WHEN COALESCE(network_identities.switch_binding_source, 'auto') = 'human'
                         THEN network_identities.switch_device_id
                     ELSE COALESCE(excluded.switch_device_id, network_identities.switch_device_id)
                 END,
                 switch_port = CASE
                     WHEN COALESCE(network_identities.switch_binding_source, 'auto') = 'human'
                         THEN network_identities.switch_port
                     ELSE COALESCE(excluded.switch_port, network_identities.switch_port)
                 END,
                 vlan_id = COALESCE(excluded.vlan_id, network_identities.vlan_id),
                 discovery_protocol = COALESCE(excluded.discovery_protocol, network_identities.discovery_protocol),
                 remote_identity = COALESCE(excluded.remote_identity, network_identities.remote_identity),
                 remote_platform = COALESCE(excluded.remote_platform, network_identities.remote_platform),
                 last_seen = excluded.last_seen,
                 confidence = MAX(excluded.confidence, network_identities.confidence),
                 device_type = CASE
                     WHEN network_identities.human_confirmed = 1 THEN network_identities.device_type
                     WHEN excluded.device_type IS NULL THEN network_identities.device_type
                     WHEN excluded.device_type_confidence >= COALESCE(network_identities.device_type_confidence, 0.0)
                         THEN excluded.device_type
                     ELSE network_identities.device_type
                 END,
                 device_type_source = CASE
                     WHEN network_identities.human_confirmed = 1 THEN network_identities.device_type_source
                     WHEN excluded.device_type IS NULL THEN network_identities.device_type_source
                     WHEN excluded.device_type_confidence >= COALESCE(network_identities.device_type_confidence, 0.0)
                         THEN excluded.device_type_source
                     ELSE network_identities.device_type_source
                 END,
                 device_type_confidence = CASE
                     WHEN network_identities.human_confirmed = 1 THEN network_identities.device_type_confidence
                     WHEN excluded.device_type IS NULL THEN network_identities.device_type_confidence
                     WHEN excluded.device_type_confidence >= COALESCE(network_identities.device_type_confidence, 0.0)
                         THEN excluded.device_type_confidence
                     ELSE network_identities.device_type_confidence
                 END",
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
                device_type,
                device_type_source,
                device_type_confidence,
            ],
        )?;
        Ok(())
    }

    /// Delete a network identity by MAC address.
    pub async fn delete_network_identity(&self, mac_address: &str) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let rows = db.execute(
            "DELETE FROM network_identities WHERE mac_address = ?1",
            params![mac_address],
        )?;
        Ok(rows > 0)
    }

    /// Get all network identity records.
    pub async fn get_network_identities(&self) -> Result<Vec<NetworkIdentity>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT mac_address, best_ip, hostname, manufacturer, switch_device_id, switch_port,
                    vlan_id, discovery_protocol, remote_identity, remote_platform,
                    first_seen, last_seen, confidence,
                    device_type, device_type_source, device_type_confidence,
                    human_confirmed, human_label, disposition,
                    is_infrastructure, switch_binding_source,
                    (SELECT speed FROM switch_port_metrics
                     WHERE device_id = network_identities.switch_device_id
                       AND LOWER(port_name) = LOWER(network_identities.switch_port)
                       AND speed IS NOT NULL
                     ORDER BY id DESC LIMIT 1) AS link_speed
             FROM network_identities ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], map_identity_row)?;
        rows.collect()
    }

    /// Get infrastructure-flagged identities (WAPs, unmanaged switches, etc.).
    pub async fn get_infrastructure_identities(&self) -> Result<Vec<NetworkIdentity>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT mac_address, best_ip, hostname, manufacturer, switch_device_id, switch_port,
                    vlan_id, discovery_protocol, remote_identity, remote_platform,
                    first_seen, last_seen, confidence,
                    device_type, device_type_source, device_type_confidence,
                    human_confirmed, human_label, disposition,
                    is_infrastructure, switch_binding_source,
                    (SELECT speed FROM switch_port_metrics
                     WHERE device_id = network_identities.switch_device_id
                       AND LOWER(port_name) = LOWER(network_identities.switch_port)
                       AND speed IS NOT NULL
                     ORDER BY id DESC LIMIT 1) AS link_speed
             FROM network_identities
             WHERE is_infrastructure = 1
                OR device_type IN ('access_point', 'switch', 'network_equipment')
             ORDER BY hostname, mac_address",
        )?;
        let rows = stmt.query_map([], map_identity_row)?;
        rows.collect()
    }

    /// Get unconfirmed identities ordered by confidence ASC (review queue).
    pub async fn get_review_queue(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<NetworkIdentity>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT mac_address, best_ip, hostname, manufacturer, switch_device_id, switch_port,
                    vlan_id, discovery_protocol, remote_identity, remote_platform,
                    first_seen, last_seen, confidence,
                    device_type, device_type_source, device_type_confidence,
                    human_confirmed, human_label, disposition,
                    is_infrastructure, switch_binding_source,
                    (SELECT speed FROM switch_port_metrics
                     WHERE device_id = network_identities.switch_device_id
                       AND LOWER(port_name) = LOWER(network_identities.switch_port)
                       AND speed IS NOT NULL
                     ORDER BY id DESC LIMIT 1) AS link_speed
             FROM network_identities
             WHERE human_confirmed = 0
             ORDER BY device_type_confidence ASC, last_seen DESC
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], map_identity_row)?;
        rows.collect()
    }

    /// Get identity statistics (total, confirmed, unconfirmed, by device_type, by source).
    pub async fn get_identity_stats(&self) -> Result<IdentityStats, rusqlite::Error> {
        let db = self.db.lock().await;

        let total: i64 = db.query_row(
            "SELECT COUNT(*) FROM network_identities",
            [],
            |row| row.get(0),
        )?;
        let confirmed: i64 = db.query_row(
            "SELECT COUNT(*) FROM network_identities WHERE human_confirmed = 1",
            [],
            |row| row.get(0),
        )?;

        let mut by_device_type = std::collections::HashMap::new();
        {
            let mut stmt = db.prepare(
                "SELECT COALESCE(device_type, 'unknown'), COUNT(*)
                 FROM network_identities GROUP BY COALESCE(device_type, 'unknown')",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for r in rows {
                let (k, v) = r?;
                by_device_type.insert(k, v);
            }
        }

        let mut by_source = std::collections::HashMap::new();
        {
            let mut stmt = db.prepare(
                "SELECT COALESCE(device_type_source, 'none'), COUNT(*)
                 FROM network_identities GROUP BY COALESCE(device_type_source, 'none')",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for r in rows {
                let (k, v) = r?;
                by_source.insert(k, v);
            }
        }

        let mut by_disposition = std::collections::HashMap::new();
        {
            let mut stmt = db.prepare(
                "SELECT COALESCE(disposition, 'unknown'), COUNT(*)
                 FROM network_identities GROUP BY COALESCE(disposition, 'unknown')",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for r in rows {
                let (k, v) = r?;
                by_disposition.insert(k, v);
            }
        }

        Ok(IdentityStats {
            total,
            confirmed,
            unconfirmed: total - confirmed,
            by_device_type,
            by_source,
            by_disposition,
        })
    }

    /// Set a human override on an identity's device type, label, switch binding,
    /// and/or infrastructure classification.
    pub async fn update_identity_human_override(
        &self,
        mac: &str,
        device_type: Option<&str>,
        label: Option<&str>,
        switch_device_id: Option<&str>,
        switch_port: Option<&str>,
        is_infrastructure: Option<Option<bool>>,
    ) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        // Convert is_infrastructure Option<Option<bool>> to SQL:
        //   None → don't change, Some(None) → set NULL (auto), Some(Some(v)) → set 0/1
        let infra_sql_val: Option<Option<i32>> = is_infrastructure.map(|opt| opt.map(|b| b as i32));

        let rows = db.execute(
            "UPDATE network_identities SET
                 human_confirmed = 1,
                 device_type = COALESCE(?2, device_type),
                 device_type_source = CASE WHEN ?2 IS NOT NULL THEN 'human' ELSE device_type_source END,
                 device_type_confidence = CASE WHEN ?2 IS NOT NULL THEN 1.0 ELSE device_type_confidence END,
                 human_label = COALESCE(?3, human_label),
                 switch_device_id = CASE WHEN ?4 IS NOT NULL THEN ?4 ELSE switch_device_id END,
                 switch_port = CASE WHEN ?5 IS NOT NULL THEN ?5 ELSE switch_port END,
                 switch_binding_source = CASE WHEN ?4 IS NOT NULL OR ?5 IS NOT NULL THEN 'human' ELSE switch_binding_source END,
                 is_infrastructure = CASE WHEN ?6 = 1 THEN ?7 ELSE is_infrastructure END
             WHERE mac_address = ?1",
            params![
                mac,
                device_type,
                label,
                switch_device_id,
                switch_port,
                infra_sql_val.is_some() as i32,
                infra_sql_val.flatten(),
            ],
        )?;
        Ok(rows > 0)
    }

    /// Bulk-confirm identities (set human_confirmed = 1 without changing device_type).
    pub async fn bulk_confirm_identities(&self, macs: &[&str]) -> Result<usize, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut count = 0usize;
        for mac in macs {
            let rows = db.execute(
                "UPDATE network_identities SET human_confirmed = 1 WHERE mac_address = ?1",
                params![mac],
            )?;
            count += rows;
        }
        Ok(count)
    }

    /// Reset a single identity field back to auto-detected state.
    /// `field` must be one of: `device_type`, `human_label`, `switch_binding`, `is_infrastructure`.
    /// Returns `Ok(true)` if a row was modified, `Ok(false)` if MAC not found.
    /// Returns an error if `field` is not one of the valid reset targets.
    pub async fn reset_identity_field(&self, mac: &str, field: &str) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let sql = match field {
            "device_type" => {
                "UPDATE network_identities \
                 SET device_type = NULL, device_type_source = 'auto', \
                     device_type_confidence = 0.0, human_confirmed = 0 \
                 WHERE mac_address = ?1"
            }
            "human_label" => {
                "UPDATE network_identities \
                 SET human_label = NULL, human_confirmed = 0 \
                 WHERE mac_address = ?1"
            }
            "switch_binding" => {
                "UPDATE network_identities \
                 SET switch_binding_source = 'auto' \
                 WHERE mac_address = ?1"
            }
            "is_infrastructure" => {
                "UPDATE network_identities \
                 SET is_infrastructure = NULL \
                 WHERE mac_address = ?1"
            }
            _ => {
                return Err(rusqlite::Error::InvalidParameterName(format!(
                    "unknown field: {field}"
                )));
            }
        };
        let rows = db.execute(sql, params![mac])?;
        Ok(rows > 0)
    }

    // ── Nmap scans ──────────────────────────────────────────────

    /// Insert a new nmap scan record.
    pub async fn insert_nmap_scan(&self, scan: &NmapScan) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO nmap_scans (id, vlan_id, profile, status, target_count, started_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))",
            params![
                scan.id,
                scan.vlan_id as i64,
                scan.profile,
                scan.status,
                scan.target_count,
                scan.started_at,
            ],
        )?;
        Ok(())
    }

    /// Update a scan's status, discovered count, and optional error.
    pub async fn update_nmap_scan(
        &self,
        id: &str,
        status: &str,
        discovered: i32,
        error: Option<&str>,
        completed_at: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "UPDATE nmap_scans SET status = ?2, discovered_count = ?3, error = ?4, completed_at = ?5
             WHERE id = ?1",
            params![id, status, discovered, error, completed_at],
        )?;
        Ok(())
    }

    /// Insert an nmap result for a scan.
    pub async fn insert_nmap_result(&self, result: &NmapResult) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO nmap_results
             (scan_id, ip_address, mac_address, hostname, os_guess, os_accuracy,
              open_ports, device_type, raw_xml, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))",
            params![
                result.scan_id,
                result.ip_address,
                result.mac_address,
                result.hostname,
                result.os_guess,
                result.os_accuracy,
                result.open_ports,
                result.device_type,
                Option::<String>::None, // raw_xml omitted for storage efficiency
            ],
        )?;
        Ok(())
    }

    /// Get recent scans.
    pub async fn get_nmap_scans(&self, limit: usize) -> Result<Vec<NmapScan>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT id, vlan_id, profile, status, target_count, discovered_count,
                    started_at, completed_at, error, created_at
             FROM nmap_scans ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(NmapScan {
                id: row.get(0)?,
                vlan_id: row.get::<_, i64>(1)? as u32,
                profile: row.get(2)?,
                status: row.get(3)?,
                target_count: row.get(4)?,
                discovered_count: row.get(5)?,
                started_at: row.get(6)?,
                completed_at: row.get(7)?,
                error: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    /// Get a single scan by ID.
    pub async fn get_nmap_scan(&self, id: &str) -> Result<Option<NmapScan>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT id, vlan_id, profile, status, target_count, discovered_count,
                    started_at, completed_at, error, created_at
             FROM nmap_scans WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(NmapScan {
                id: row.get(0)?,
                vlan_id: row.get::<_, i64>(1)? as u32,
                profile: row.get(2)?,
                status: row.get(3)?,
                target_count: row.get(4)?,
                discovered_count: row.get(5)?,
                started_at: row.get(6)?,
                completed_at: row.get(7)?,
                error: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Get results for a scan.
    pub async fn get_nmap_results(
        &self,
        scan_id: &str,
    ) -> Result<Vec<NmapResult>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT id, scan_id, ip_address, mac_address, hostname, os_guess,
                    os_accuracy, open_ports, device_type, created_at
             FROM nmap_results WHERE scan_id = ?1 ORDER BY ip_address",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok(NmapResult {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                ip_address: row.get(2)?,
                mac_address: row.get(3)?,
                hostname: row.get(4)?,
                os_guess: row.get(5)?,
                os_accuracy: row.get(6)?,
                open_ports: row.get(7)?,
                device_type: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    // ── Scan exclusions ─────────────────────────────────────────

    /// Get all scan exclusions.
    pub async fn get_scan_exclusions(&self) -> Result<Vec<ScanExclusion>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT ip_address, reason, created_at FROM scan_exclusions ORDER BY ip_address",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ScanExclusion {
                ip_address: row.get(0)?,
                reason: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        rows.collect()
    }

    /// Add a scan exclusion.
    pub async fn add_scan_exclusion(
        &self,
        ip: &str,
        reason: &str,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT OR REPLACE INTO scan_exclusions (ip_address, reason, created_at)
             VALUES (?1, ?2, datetime('now'))",
            params![ip, reason],
        )?;
        Ok(())
    }

    /// Remove a scan exclusion.
    pub async fn remove_scan_exclusion(&self, ip: &str) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let rows = db.execute(
            "DELETE FROM scan_exclusions WHERE ip_address = ?1",
            params![ip],
        )?;
        Ok(rows > 0)
    }

    // ── Traffic classifications ──────────────────────────────────

    /// Upsert a traffic pattern classification.
    pub async fn upsert_traffic_classification(
        &self,
        mac: &str,
        device_type: &str,
        confidence: f64,
        evidence: &str,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT OR REPLACE INTO traffic_classifications
             (mac_address, device_type, confidence, evidence, classified_at)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))",
            params![mac, device_type, confidence, evidence],
        )?;
        Ok(())
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
        let port_lower = port_name.to_lowercase();
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
                &port_lower,
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

    // ── MAC observations (topology inference) ────────────────────

    /// Record a batch of MAC observations for the topology inference engine.
    pub async fn insert_mac_observations(
        &self,
        observations: &[MacObservation],
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare_cached(
            "INSERT INTO mac_observations
             (mac_address, device_id, port_name, vlan_id, timestamp,
              observation_confidence, edge_likelihood, transit_likelihood)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for obs in observations {
            stmt.execute(params![
                &obs.mac_address,
                &obs.device_id,
                &obs.port_name,
                obs.vlan_id.map(|v| v as i64),
                obs.timestamp,
                obs.observation_confidence,
                obs.edge_likelihood,
                obs.transit_likelihood,
            ])?;
        }
        Ok(())
    }

    /// Get recent MAC observations within a time window.
    pub async fn get_recent_observations(
        &self,
        mac_address: &str,
        since: i64,
    ) -> Result<Vec<MacObservation>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare_cached(
            "SELECT id, mac_address, device_id, port_name, vlan_id, timestamp,
                    observation_confidence, edge_likelihood, transit_likelihood
             FROM mac_observations
             WHERE mac_address = ?1 AND timestamp >= ?2
             ORDER BY timestamp DESC",
        )?;
        let rows = stmt.query_map(params![mac_address, since], map_mac_observation_row)?;
        rows.collect()
    }

    /// Get observation counts per (device_id, port_name) for a MAC within a time window.
    /// Returns Vec of (device_id, port_name, count, avg_confidence, avg_edge_likelihood).
    pub async fn get_observation_counts(
        &self,
        mac_address: &str,
        since: i64,
    ) -> Result<Vec<(String, String, u32, f64, f64)>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare_cached(
            "SELECT device_id, port_name, COUNT(*) as cnt,
                    AVG(observation_confidence) as avg_conf,
                    AVG(edge_likelihood) as avg_edge
             FROM mac_observations
             WHERE mac_address = ?1 AND timestamp >= ?2
             GROUP BY device_id, port_name
             ORDER BY cnt DESC",
        )?;
        let rows = stmt.query_map(params![mac_address, since], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u32,
                row.get::<_, f64>(3)?,
                row.get::<_, f64>(4)?,
            ))
        })?;
        rows.collect()
    }

    /// Prune observations older than the retention window.
    pub async fn prune_old_observations(&self, max_age_secs: i64) -> Result<usize, rusqlite::Error> {
        let cutoff = now_unix() - max_age_secs;
        let db = self.db.lock().await;
        let affected = db.execute(
            "DELETE FROM mac_observations WHERE timestamp < ?1",
            params![cutoff],
        )?;
        Ok(affected)
    }

    // ── Port role probabilities (topology inference) ────────────

    /// Upsert port role probabilities for a device+port.
    pub async fn set_port_role_probabilities(
        &self,
        device_id: &str,
        port_name: &str,
        trunk_prob: f64,
        uplink_prob: f64,
        access_prob: f64,
        wireless_prob: f64,
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        let port_lower = port_name.to_lowercase();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO port_role_probabilities
             (device_id, port_name, trunk_prob, uplink_prob, access_prob, wireless_prob, computed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(device_id, port_name) DO UPDATE SET
                 trunk_prob = excluded.trunk_prob,
                 uplink_prob = excluded.uplink_prob,
                 access_prob = excluded.access_prob,
                 wireless_prob = excluded.wireless_prob,
                 computed_at = excluded.computed_at",
            params![device_id, &port_lower, trunk_prob, uplink_prob, access_prob, wireless_prob, now],
        )?;
        Ok(())
    }

    /// Batch upsert port role probabilities.
    pub async fn set_port_role_probabilities_batch(
        &self,
        entries: &[PortRoleProbability],
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        let db = self.db.lock().await;
        let mut stmt = db.prepare_cached(
            "INSERT INTO port_role_probabilities
             (device_id, port_name, trunk_prob, uplink_prob, access_prob, wireless_prob, computed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(device_id, port_name) DO UPDATE SET
                 trunk_prob = excluded.trunk_prob,
                 uplink_prob = excluded.uplink_prob,
                 access_prob = excluded.access_prob,
                 wireless_prob = excluded.wireless_prob,
                 computed_at = excluded.computed_at",
        )?;
        for entry in entries {
            stmt.execute(params![
                &entry.device_id,
                &entry.port_name,
                entry.trunk_prob,
                entry.uplink_prob,
                entry.access_prob,
                entry.wireless_prob,
                now,
            ])?;
        }
        Ok(())
    }

    /// Get port role probabilities for a device (or all devices if None).
    pub async fn get_port_role_probabilities(
        &self,
        device_id: Option<&str>,
    ) -> Result<Vec<PortRoleProbability>, rusqlite::Error> {
        let db = self.db.lock().await;
        let (sql, device_filter) = match device_id {
            Some(id) => (
                "SELECT device_id, port_name, trunk_prob, uplink_prob, access_prob, wireless_prob, computed_at
                 FROM port_role_probabilities WHERE device_id = ?1 ORDER BY port_name",
                Some(id.to_string()),
            ),
            None => (
                "SELECT device_id, port_name, trunk_prob, uplink_prob, access_prob, wireless_prob, computed_at
                 FROM port_role_probabilities ORDER BY device_id, port_name",
                None,
            ),
        };
        let mut stmt = db.prepare(sql)?;
        let rows = if let Some(ref id) = device_filter {
            stmt.query_map(params![id], map_port_role_prob_row)?
        } else {
            stmt.query_map([], map_port_role_prob_row)?
        };
        rows.collect()
    }

    // ── MAC attachment state (topology inference) ────────────────

    /// Get all recent observations across all MACs (for bulk inference).
    pub async fn get_all_recent_observations(
        &self,
        since: i64,
    ) -> Result<Vec<MacObservation>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare_cached(
            "SELECT id, mac_address, device_id, port_name, vlan_id, timestamp,
                    observation_confidence, edge_likelihood, transit_likelihood
             FROM mac_observations
             WHERE timestamp >= ?1
             ORDER BY mac_address, timestamp DESC",
        )?;
        let rows = stmt.query_map(params![since], map_mac_observation_row)?;
        rows.collect()
    }

    /// Get all attachment states.
    pub async fn get_all_attachment_states(&self) -> Result<Vec<AttachmentStateRow>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare_cached(
            "SELECT mac_address, state, current_device_id, current_port_name,
                    previous_device_id, previous_port_name,
                    current_score, confidence, consecutive_wins, consecutive_losses,
                    updated_at
             FROM mac_attachment_state",
        )?;
        let rows = stmt.query_map([], map_attachment_state_row)?;
        rows.collect()
    }

    /// Get a single attachment state by MAC.
    pub async fn get_attachment_state(
        &self,
        mac: &str,
    ) -> Result<Option<AttachmentStateRow>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare_cached(
            "SELECT mac_address, state, current_device_id, current_port_name,
                    previous_device_id, previous_port_name,
                    current_score, confidence, consecutive_wins, consecutive_losses,
                    updated_at
             FROM mac_attachment_state WHERE mac_address = ?1",
        )?;
        let mut rows = stmt.query_map(params![mac], map_attachment_state_row)?;
        match rows.next() {
            Some(Ok(row)) => Ok(Some(row)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Upsert an attachment state (from the inference state machine).
    pub async fn upsert_attachment_state_row(
        &self,
        row: &AttachmentStateRow,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO mac_attachment_state
             (mac_address, state, current_device_id, current_port_name,
              previous_device_id, previous_port_name,
              current_score, confidence, consecutive_wins, consecutive_losses, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(mac_address) DO UPDATE SET
                 state = excluded.state,
                 current_device_id = excluded.current_device_id,
                 current_port_name = excluded.current_port_name,
                 previous_device_id = excluded.previous_device_id,
                 previous_port_name = excluded.previous_port_name,
                 current_score = excluded.current_score,
                 confidence = excluded.confidence,
                 consecutive_wins = excluded.consecutive_wins,
                 consecutive_losses = excluded.consecutive_losses,
                 updated_at = excluded.updated_at",
            params![
                &row.mac_address,
                &row.state,
                &row.current_device_id,
                &row.current_port_name,
                &row.previous_device_id,
                &row.previous_port_name,
                row.current_score,
                row.confidence,
                row.consecutive_wins as i64,
                row.consecutive_losses as i64,
                row.updated_at,
            ],
        )?;
        Ok(())
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

    /// Prune stale MAC table entries not seen within the given age (seconds).
    /// This cleans up entries left behind when switch ports are renamed —
    /// the old port_name row stops getting updated while the new one takes over.
    pub async fn prune_stale_mac_entries(&self, max_age_secs: i64) -> Result<usize, rusqlite::Error> {
        let cutoff = now_unix() - max_age_secs;
        let db = self.db.lock().await;
        let affected = db.execute(
            "DELETE FROM switch_mac_table WHERE last_seen < ?1 AND is_local = 0",
            params![cutoff],
        )?;
        Ok(affected)
    }

    /// Prune stale port role entries not updated within the given age (seconds).
    pub async fn prune_stale_port_roles(&self, max_age_secs: i64) -> Result<usize, rusqlite::Error> {
        let cutoff = now_unix() - max_age_secs;
        let db = self.db.lock().await;
        let affected = db.execute(
            "DELETE FROM switch_port_roles WHERE updated_at < ?1",
            params![cutoff],
        )?;
        Ok(affected)
    }

    /// Prune port metrics for port names that no longer appear in recent data.
    /// When a port is renamed, old-name entries stop being inserted but linger
    /// until the general 7-day cleanup. This removes them earlier so the switch
    /// detail page doesn't show duplicate ports.
    pub async fn prune_renamed_port_metrics(&self, max_age_secs: i64) -> Result<usize, rusqlite::Error> {
        let cutoff = now_unix() - max_age_secs;
        let db = self.db.lock().await;
        // Delete metrics for (device_id, port_name) combos where the most recent
        // entry for that port is older than the cutoff.
        let affected = db.execute(
            "DELETE FROM switch_port_metrics
             WHERE rowid IN (
                 SELECT m.rowid FROM switch_port_metrics m
                 INNER JOIN (
                     SELECT device_id, port_name, MAX(timestamp) as max_ts
                     FROM switch_port_metrics
                     GROUP BY device_id, port_name
                     HAVING max_ts < ?1
                 ) stale ON m.device_id = stale.device_id AND m.port_name = stale.port_name
             )",
            params![cutoff],
        )?;
        Ok(affected)
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

    // ── Observed services (passive discovery) ────────────────────

    /// Upsert an observed service from connection tracking analysis.
    pub async fn upsert_observed_service(
        &self,
        ip: &str,
        port: u32,
        protocol: &str,
        service_name: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO observed_services
             (ip_address, port, protocol, service_name, first_seen, last_seen, connection_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1)
             ON CONFLICT(ip_address, port, protocol) DO UPDATE SET
                 service_name = COALESCE(excluded.service_name, observed_services.service_name),
                 last_seen = excluded.last_seen,
                 connection_count = observed_services.connection_count + 1",
            params![ip, port as i64, protocol, service_name, now],
        )?;
        Ok(())
    }

    /// Get observed services for an IP (or all if None).
    pub async fn get_observed_services(
        &self,
        ip: Option<&str>,
    ) -> Result<Vec<ObservedService>, rusqlite::Error> {
        let db = self.db.lock().await;
        let (sql, filter) = match ip {
            Some(addr) => (
                "SELECT ip_address, port, protocol, service_name, first_seen, last_seen, connection_count
                 FROM observed_services WHERE ip_address = ?1 ORDER BY port",
                Some(addr.to_string()),
            ),
            None => (
                "SELECT ip_address, port, protocol, service_name, first_seen, last_seen, connection_count
                 FROM observed_services ORDER BY ip_address, port",
                None,
            ),
        };
        let mut stmt = db.prepare(sql)?;
        let rows = if let Some(ref addr) = filter {
            stmt.query_map(params![addr], map_observed_service_row)?
        } else {
            stmt.query_map([], map_observed_service_row)?
        };
        rows.collect()
    }

    /// Get observed services as a JSON-serializable port list for a given IP,
    /// suitable for display alongside network identities.
    pub async fn get_services_for_ip(
        &self,
        ip: &str,
    ) -> Result<Vec<ObservedService>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT ip_address, port, protocol, service_name, first_seen, last_seen, connection_count
             FROM observed_services
             WHERE ip_address = ?1
             ORDER BY port",
        )?;
        let rows = stmt.query_map(params![ip], map_observed_service_row)?;
        rows.collect()
    }

    /// Prune observed services not seen in the given number of seconds.
    pub async fn prune_observed_services(&self, max_age_secs: i64) -> Result<usize, rusqlite::Error> {
        let cutoff = now_unix() - max_age_secs;
        let db = self.db.lock().await;
        let rows = db.execute(
            "DELETE FROM observed_services WHERE last_seen < ?1",
            params![cutoff],
        )?;
        Ok(rows)
    }

    // ── Topology positions ─────────────────────────────────────────

    /// Get all topology position overrides.
    pub async fn get_topology_positions(&self) -> Result<Vec<TopologyPosition>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT node_id, x, y, source, updated_at FROM topology_positions ORDER BY node_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TopologyPosition {
                node_id: row.get(0)?,
                x: row.get(1)?,
                y: row.get(2)?,
                source: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Upsert a topology position (human or auto).
    pub async fn set_topology_position(
        &self,
        node_id: &str,
        x: f64,
        y: f64,
        source: &str,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO topology_positions (node_id, x, y, source, updated_at)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))
             ON CONFLICT(node_id) DO UPDATE SET x = ?2, y = ?3, source = ?4, updated_at = datetime('now')",
            rusqlite::params![node_id, x, y, source],
        )?;
        Ok(())
    }

    /// Batch-upsert topology positions (e.g. when a VLAN sector is dragged).
    pub async fn set_topology_positions_batch(
        &self,
        positions: &[(String, f64, f64)],
        source: &str,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        let tx = db.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO topology_positions (node_id, x, y, source, updated_at)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))
                 ON CONFLICT(node_id) DO UPDATE SET x = ?2, y = ?3, source = ?4, updated_at = datetime('now')",
            )?;
            for (node_id, x, y) in positions {
                stmt.execute(rusqlite::params![node_id, x, y, source])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Delete a topology position override (revert to auto).
    pub async fn delete_topology_position(&self, node_id: &str) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "DELETE FROM topology_positions WHERE node_id = ?1",
            rusqlite::params![node_id],
        )?;
        Ok(affected > 0)
    }

    // ── Sector positions ──────────────────────────────────────────

    /// Get all sector position overrides.
    pub async fn get_sector_positions(&self) -> Result<Vec<SectorPosition>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT vlan_id, x, y, width, height, source, updated_at
             FROM topology_sector_positions ORDER BY vlan_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SectorPosition {
                vlan_id: row.get(0)?,
                x: row.get(1)?,
                y: row.get(2)?,
                width: row.get(3)?,
                height: row.get(4)?,
                source: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?;
        rows.collect()
    }

    /// Upsert a sector position (human or auto).
    pub async fn set_sector_position(
        &self,
        vlan_id: u32,
        x: f64,
        y: f64,
        width: Option<f64>,
        height: Option<f64>,
        source: &str,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO topology_sector_positions (vlan_id, x, y, width, height, source, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))
             ON CONFLICT(vlan_id) DO UPDATE SET
                x = ?2, y = ?3, width = ?4, height = ?5, source = ?6, updated_at = datetime('now')",
            rusqlite::params![vlan_id, x, y, width, height, source],
        )?;
        Ok(())
    }

    /// Delete a sector position override (revert to auto).
    pub async fn delete_sector_position(&self, vlan_id: u32) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "DELETE FROM topology_sector_positions WHERE vlan_id = ?1",
            rusqlite::params![vlan_id],
        )?;
        Ok(affected > 0)
    }

    // ── Backbone links ──────────────────────────────────────────────

    /// Get all backbone links.
    pub async fn get_backbone_links(&self) -> Result<Vec<BackboneLink>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT id, device_a, port_a, device_b, port_b, label, speed_mbps, link_type, created_at
             FROM backbone_links ORDER BY device_a, device_b",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BackboneLink {
                id: row.get(0)?,
                device_a: row.get(1)?,
                port_a: row.get(2)?,
                device_b: row.get(3)?,
                port_b: row.get(4)?,
                label: row.get(5)?,
                speed_mbps: row.get::<_, Option<u32>>(6)?,
                link_type: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    /// Create a backbone link. Normalizes so device_a < device_b lexicographically.
    pub async fn create_backbone_link(
        &self,
        device_a: &str,
        port_a: Option<&str>,
        device_b: &str,
        port_b: Option<&str>,
        label: Option<&str>,
        link_type: Option<&str>,
        speed_mbps: Option<u32>,
    ) -> Result<i64, rusqlite::Error> {
        let pa_lower = port_a.map(|p| p.to_lowercase());
        let pb_lower = port_b.map(|p| p.to_lowercase());
        let (da, pa, db_dev, pb) = if device_a <= device_b {
            (device_a, pa_lower.as_deref(), device_b, pb_lower.as_deref())
        } else {
            (device_b, pb_lower.as_deref(), device_a, pa_lower.as_deref())
        };
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO backbone_links (device_a, port_a, device_b, port_b, label, link_type, speed_mbps)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![da, pa, db_dev, pb, label, link_type, speed_mbps],
        )?;
        Ok(db.last_insert_rowid())
    }

    /// Update a backbone link's mutable fields (ports, label, type, speed).
    pub async fn update_backbone_link(
        &self,
        id: i64,
        port_a: Option<&str>,
        port_b: Option<&str>,
        label: Option<&str>,
        link_type: Option<&str>,
        speed_mbps: Option<u32>,
    ) -> Result<bool, rusqlite::Error> {
        let pa_lower = port_a.map(|p| p.to_lowercase());
        let pb_lower = port_b.map(|p| p.to_lowercase());
        let db = self.db.lock().await;
        let affected = db.execute(
            "UPDATE backbone_links SET port_a = ?2, port_b = ?3, label = ?4, link_type = ?5, speed_mbps = ?6
             WHERE id = ?1",
            rusqlite::params![id, pa_lower, pb_lower, label, link_type, speed_mbps],
        )?;
        Ok(affected > 0)
    }

    /// Delete a backbone link by id.
    pub async fn delete_backbone_link(&self, id: i64) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "DELETE FROM backbone_links WHERE id = ?1",
            rusqlite::params![id],
        )?;
        Ok(affected > 0)
    }

    // ── VLAN config ───────────────────────────────────────────────────

    /// Get all VLAN configs, ordered by vlan_id.
    pub async fn get_vlan_configs(&self) -> Result<Vec<VlanConfig>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT vlan_id, name, media_type, subnet, color FROM vlan_config ORDER BY vlan_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(VlanConfig {
                vlan_id: row.get::<_, i64>(0)? as u32,
                name: row.get(1)?,
                media_type: row.get(2)?,
                subnet: row.get(3)?,
                color: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Upsert a VLAN config entry.
    pub async fn upsert_vlan_config(&self, config: &VlanConfig) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO vlan_config (vlan_id, name, media_type, subnet, color)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(vlan_id) DO UPDATE SET
                 name = excluded.name,
                 media_type = excluded.media_type,
                 subnet = excluded.subnet,
                 color = excluded.color",
            params![
                config.vlan_id as i64,
                config.name,
                config.media_type,
                config.subnet,
                config.color,
            ],
        )?;
        Ok(())
    }

    /// Insert a VLAN config only if the vlan_id doesn't already exist.
    /// Returns true if a new row was inserted, false if it already existed.
    pub async fn insert_vlan_config_if_missing(&self, config: &VlanConfig) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "INSERT OR IGNORE INTO vlan_config (vlan_id, name, media_type, subnet, color)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                config.vlan_id as i64,
                config.name,
                config.media_type,
                config.subnet,
                config.color,
            ],
        )?;
        Ok(affected > 0)
    }

    // ── Neighbor aliases ──────────────────────────────────────────────

    /// Get all neighbor aliases.
    pub async fn get_neighbor_aliases(&self) -> Result<Vec<NeighborAlias>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT id, match_type, match_value, action, target_device_id, created_at
             FROM neighbor_aliases ORDER BY match_type, match_value",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(NeighborAlias {
                id: row.get(0)?,
                match_type: row.get(1)?,
                match_value: row.get(2)?,
                action: row.get(3)?,
                target_device_id: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;
        rows.collect()
    }

    /// Create or replace a neighbor alias.
    pub async fn create_neighbor_alias(
        &self,
        match_type: &str,
        match_value: &str,
        action: &str,
        target_device_id: Option<&str>,
    ) -> Result<i64, rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT OR REPLACE INTO neighbor_aliases (match_type, match_value, action, target_device_id)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![match_type, match_value, action, target_device_id],
        )?;
        Ok(db.last_insert_rowid())
    }

    /// Delete a neighbor alias by id.
    pub async fn delete_neighbor_alias(&self, id: i64) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "DELETE FROM neighbor_aliases WHERE id = ?1",
            rusqlite::params![id],
        )?;
        Ok(affected > 0)
    }

    // ── Disposition ─────────────────────────────────────────────────

    /// Set the disposition of a network identity.
    pub async fn set_disposition(
        &self,
        mac: &str,
        disposition: &str,
    ) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "UPDATE network_identities SET disposition = ?2 WHERE mac_address = ?1",
            params![mac, disposition],
        )?;
        Ok(affected > 0)
    }

    /// Bulk-set disposition on multiple MACs.
    pub async fn bulk_set_disposition(
        &self,
        macs: &[&str],
        disposition: &str,
    ) -> Result<usize, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut count = 0usize;
        for mac in macs {
            let rows = db.execute(
                "UPDATE network_identities SET disposition = ?2 WHERE mac_address = ?1",
                params![mac, disposition],
            )?;
            count += rows;
        }
        Ok(count)
    }

    // ── Port MAC bindings ───────────────────────────────────────────

    /// Get all port MAC bindings.
    pub async fn get_port_bindings(
        &self,
        device_id: Option<&str>,
    ) -> Result<Vec<PortMacBinding>, rusqlite::Error> {
        let db = self.db.lock().await;
        let (sql, filter) = match device_id {
            Some(id) => (
                "SELECT device_id, port_name, expected_mac, created_at, created_by
                 FROM port_mac_bindings WHERE device_id = ?1 ORDER BY port_name",
                Some(id.to_string()),
            ),
            None => (
                "SELECT device_id, port_name, expected_mac, created_at, created_by
                 FROM port_mac_bindings ORDER BY device_id, port_name",
                None,
            ),
        };
        let mut stmt = db.prepare(sql)?;
        let rows = if let Some(ref id) = filter {
            stmt.query_map(params![id], map_port_binding_row)?
        } else {
            stmt.query_map([], map_port_binding_row)?
        };
        rows.collect()
    }

    /// Create or update a port MAC binding.
    pub async fn upsert_port_binding(
        &self,
        device_id: &str,
        port_name: &str,
        expected_mac: &str,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO port_mac_bindings (device_id, port_name, expected_mac)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(device_id, port_name) DO UPDATE SET
                 expected_mac = excluded.expected_mac,
                 created_at = datetime('now')",
            params![device_id, port_name, expected_mac.to_uppercase()],
        )?;
        Ok(())
    }

    /// Delete a port MAC binding.
    pub async fn delete_port_binding(
        &self,
        device_id: &str,
        port_name: &str,
    ) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "DELETE FROM port_mac_bindings WHERE device_id = ?1 AND port_name = ?2",
            params![device_id, port_name],
        )?;
        Ok(affected > 0)
    }

    // ── Port violations ─────────────────────────────────────────────

    /// Get active (unresolved) port violations, optionally filtered by device.
    pub async fn get_port_violations(
        &self,
        device_id: Option<&str>,
    ) -> Result<Vec<PortViolation>, rusqlite::Error> {
        let db = self.db.lock().await;
        let (sql, filter) = match device_id {
            Some(id) => (
                "SELECT id, device_id, port_name, expected_mac, actual_mac, violation_type,
                        first_seen, last_seen, resolved, resolved_at
                 FROM port_violations WHERE device_id = ?1 AND resolved = 0
                 ORDER BY last_seen DESC",
                Some(id.to_string()),
            ),
            None => (
                "SELECT id, device_id, port_name, expected_mac, actual_mac, violation_type,
                        first_seen, last_seen, resolved, resolved_at
                 FROM port_violations WHERE resolved = 0
                 ORDER BY last_seen DESC",
                None,
            ),
        };
        let mut stmt = db.prepare(sql)?;
        let rows = if let Some(ref id) = filter {
            stmt.query_map(params![id], map_port_violation_row)?
        } else {
            stmt.query_map([], map_port_violation_row)?
        };
        rows.collect()
    }

    /// Upsert a port violation (create if new, update last_seen if existing).
    pub async fn upsert_port_violation(
        &self,
        device_id: &str,
        port_name: &str,
        expected_mac: &str,
        actual_mac: Option<&str>,
        violation_type: &str,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO port_violations
             (device_id, port_name, expected_mac, actual_mac, violation_type)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(device_id, port_name, expected_mac, actual_mac) DO UPDATE SET
                 last_seen = datetime('now'),
                 resolved = 0,
                 resolved_at = NULL",
            params![device_id, port_name, expected_mac.to_uppercase(), actual_mac.map(|m| m.to_uppercase()), violation_type],
        )?;
        Ok(())
    }

    /// Resolve a port violation by ID.
    pub async fn resolve_port_violation(&self, id: i64) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "UPDATE port_violations SET resolved = 1, resolved_at = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(affected > 0)
    }

    /// Auto-resolve violations for a device+port when the correct MAC is back.
    pub async fn auto_resolve_violations(
        &self,
        device_id: &str,
        port_name: &str,
    ) -> Result<usize, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "UPDATE port_violations SET resolved = 1, resolved_at = datetime('now')
             WHERE device_id = ?1 AND port_name = ?2 AND resolved = 0",
            params![device_id, port_name],
        )?;
        Ok(affected)
    }

    /// Prune resolved violations older than max_age_secs.
    pub async fn prune_port_violations(&self, max_age_days: i64) -> Result<usize, rusqlite::Error> {
        let db = self.db.lock().await;
        let affected = db.execute(
            "DELETE FROM port_violations
             WHERE resolved = 1 AND resolved_at < datetime('now', ?1)",
            params![format!("-{max_age_days} days")],
        )?;
        Ok(affected)
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

fn map_observed_service_row(row: &rusqlite::Row<'_>) -> Result<ObservedService, rusqlite::Error> {
    Ok(ObservedService {
        ip_address: row.get(0)?,
        port: row.get::<_, i64>(1)? as u32,
        protocol: row.get(2)?,
        service_name: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
        connection_count: row.get(6)?,
    })
}

fn map_identity_row(row: &rusqlite::Row<'_>) -> Result<NetworkIdentity, rusqlite::Error> {
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
        device_type: row.get(13)?,
        device_type_source: row.get(14)?,
        device_type_confidence: row.get::<_, Option<f64>>(15)?.unwrap_or(0.0),
        human_confirmed: row.get::<_, Option<i32>>(16)?.unwrap_or(0) != 0,
        human_label: row.get(17)?,
        disposition: row.get::<_, Option<String>>(18)?.unwrap_or_else(|| "unknown".to_string()),
        is_infrastructure: row.get::<_, Option<i32>>(19)?.map(|v| v != 0),
        switch_binding_source: row.get::<_, Option<String>>(20)?.unwrap_or_else(|| "auto".to_string()),
        link_speed_mbps: row.get::<_, Option<String>>(21)?.and_then(|s| parse_speed_mbps(&s)),
    })
}

fn map_port_binding_row(row: &rusqlite::Row<'_>) -> Result<PortMacBinding, rusqlite::Error> {
    Ok(PortMacBinding {
        device_id: row.get(0)?,
        port_name: row.get(1)?,
        expected_mac: row.get(2)?,
        created_at: row.get(3)?,
        created_by: row.get(4)?,
    })
}

fn map_port_violation_row(row: &rusqlite::Row<'_>) -> Result<PortViolation, rusqlite::Error> {
    Ok(PortViolation {
        id: row.get(0)?,
        device_id: row.get(1)?,
        port_name: row.get(2)?,
        expected_mac: row.get(3)?,
        actual_mac: row.get(4)?,
        violation_type: row.get(5)?,
        first_seen: row.get(6)?,
        last_seen: row.get(7)?,
        resolved: row.get::<_, i32>(8)? != 0,
        resolved_at: row.get(9)?,
    })
}

fn map_mac_observation_row(row: &rusqlite::Row<'_>) -> Result<MacObservation, rusqlite::Error> {
    Ok(MacObservation {
        id: row.get(0)?,
        mac_address: row.get(1)?,
        device_id: row.get(2)?,
        port_name: row.get(3)?,
        vlan_id: row.get::<_, Option<i64>>(4)?.map(|v| v as u32),
        timestamp: row.get(5)?,
        observation_confidence: row.get(6)?,
        edge_likelihood: row.get(7)?,
        transit_likelihood: row.get(8)?,
    })
}

fn map_port_role_prob_row(row: &rusqlite::Row<'_>) -> Result<PortRoleProbability, rusqlite::Error> {
    Ok(PortRoleProbability {
        device_id: row.get(0)?,
        port_name: row.get(1)?,
        trunk_prob: row.get(2)?,
        uplink_prob: row.get(3)?,
        access_prob: row.get(4)?,
        wireless_prob: row.get(5)?,
        computed_at: row.get(6)?,
    })
}

fn map_attachment_state_row(row: &rusqlite::Row<'_>) -> Result<AttachmentStateRow, rusqlite::Error> {
    Ok(AttachmentStateRow {
        mac_address: row.get(0)?,
        state: row.get(1)?,
        current_device_id: row.get(2)?,
        current_port_name: row.get(3)?,
        previous_device_id: row.get(4)?,
        previous_port_name: row.get(5)?,
        current_score: row.get(6)?,
        confidence: row.get(7)?,
        consecutive_wins: row.get::<_, i64>(8)? as u32,
        consecutive_losses: row.get::<_, i64>(9)? as u32,
        updated_at: row.get(10)?,
    })
}

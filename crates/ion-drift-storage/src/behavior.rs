//! Device behavioral fingerprinting store.
//!
//! Tracks device profiles, baseline behavior patterns, raw observations,
//! and anomalies. Backed by SQLite via `rusqlite`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// ── Helpers ──────────────────────────────────────────────────

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── VLAN Registry ────────────────────────────────────────────
//
// All VLAN-specific behavior (subnet→VLAN mapping, sensitivity levels,
// anomaly severity, auto-resolve timeouts) is driven by VlanConfig
// entries loaded from the database. No hardcoded VLAN IDs or subnets.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VlanSensitivity {
    Strictest,
    Strict,
    Moderate,
    Loose,
    Monitor,
}

impl VlanSensitivity {
    pub fn from_str(s: &str) -> Self {
        match s {
            "strictest" => Self::Strictest,
            "strict" => Self::Strict,
            "moderate" => Self::Moderate,
            "loose" => Self::Loose,
            _ => Self::Monitor,
        }
    }
}

/// Parsed subnet entry for IP→VLAN matching.
#[derive(Debug, Clone)]
struct SubnetEntry {
    vlan_id: u16,
    /// Network address as u32.
    network: u32,
    /// Prefix length (e.g. 24).
    prefix_len: u8,
    /// Bitmask computed from prefix_len.
    mask: u32,
}

/// Runtime VLAN registry loaded from database VlanConfig entries.
/// Provides all the lookup functions the behavior engine needs.
#[derive(Debug, Clone)]
pub struct VlanRegistry {
    /// VLAN ID → name.
    names: HashMap<u16, String>,
    /// VLAN ID → sensitivity level.
    sensitivities: HashMap<u16, VlanSensitivity>,
    /// Sorted subnet entries for IP→VLAN matching (longest prefix first).
    subnets: Vec<SubnetEntry>,
}

impl Default for VlanRegistry {
    fn default() -> Self {
        Self {
            names: HashMap::new(),
            sensitivities: HashMap::new(),
            subnets: Vec::new(),
        }
    }
}

impl VlanRegistry {
    /// Build a VlanRegistry from a list of VlanConfig entries.
    pub fn from_configs(configs: &[crate::switch::VlanConfig]) -> Self {
        let mut names = HashMap::new();
        let mut sensitivities = HashMap::new();
        let mut subnets = Vec::new();

        for cfg in configs {
            let vid = cfg.vlan_id as u16;
            names.insert(vid, cfg.name.clone());
            sensitivities.insert(vid, VlanSensitivity::from_str(&cfg.sensitivity));

            if let Some(subnet_str) = &cfg.subnet {
                if let Some(entry) = Self::parse_cidr(subnet_str, vid) {
                    subnets.push(entry);
                }
            }
        }

        // Sort by longest prefix first for most-specific match
        subnets.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));

        Self {
            names,
            sensitivities,
            subnets,
        }
    }

    fn parse_cidr(cidr: &str, vlan_id: u16) -> Option<SubnetEntry> {
        let slash_pos = cidr.find('/')?;
        let network_str = &cidr[..slash_pos];
        let prefix_len: u8 = cidr[slash_pos + 1..].parse().ok()?;
        let octets: Vec<u8> = network_str
            .split('.')
            .filter_map(|o| o.parse().ok())
            .collect();
        if octets.len() != 4 || prefix_len > 32 {
            return None;
        }
        let network = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        Some(SubnetEntry {
            vlan_id,
            network,
            prefix_len,
            mask,
        })
    }

    fn ip_to_u32(ip: &str) -> Option<u32> {
        let octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
        if octets.len() != 4 {
            return None;
        }
        Some(u32::from_be_bytes([
            octets[0], octets[1], octets[2], octets[3],
        ]))
    }

    /// Map an IP address to its VLAN number based on configured subnets.
    pub fn ip_to_vlan(&self, ip: &str) -> Option<u16> {
        let ip_u32 = Self::ip_to_u32(ip)?;
        for entry in &self.subnets {
            if (ip_u32 & entry.mask) == (entry.network & entry.mask) {
                return Some(entry.vlan_id);
            }
        }
        None
    }

    /// Returns true if the IP belongs to any configured VLAN subnet.
    pub fn is_internal_ip(&self, ip: &str) -> bool {
        self.ip_to_vlan(ip).is_some()
    }

    /// Human-readable VLAN name.
    pub fn vlan_name(&self, vlan: i64) -> String {
        if vlan == -1 {
            return "WAN / External".to_string();
        }
        self.names
            .get(&(vlan as u16))
            .cloned()
            .unwrap_or_else(|| format!("VLAN {vlan}"))
    }

    /// Get the sensitivity level for a VLAN.
    pub fn sensitivity(&self, vlan: u16) -> VlanSensitivity {
        self.sensitivities
            .get(&vlan)
            .copied()
            .unwrap_or(VlanSensitivity::Monitor)
    }

    /// Determine anomaly severity based on VLAN sensitivity and anomaly type.
    pub fn anomaly_severity(&self, vlan: u16, anomaly_type: &str) -> &'static str {
        let sens = self.sensitivity(vlan);
        match (sens, anomaly_type) {
            (VlanSensitivity::Strictest, _) => "critical",
            (VlanSensitivity::Strict, "blocked_attempt" | "volume_spike") => "alert",
            (VlanSensitivity::Strict, _) => "warning",
            (VlanSensitivity::Moderate, "blocked_attempt" | "volume_spike") => "warning",
            (VlanSensitivity::Moderate, _) => "info",
            (VlanSensitivity::Loose, "blocked_attempt") => "warning",
            (VlanSensitivity::Loose, _) => "info",
            (VlanSensitivity::Monitor, _) => "info",
        }
    }

    /// Auto-resolve timeout in seconds for stale anomalies (0 = never).
    pub fn auto_resolve_timeout(&self, vlan: u16) -> i64 {
        match self.sensitivity(vlan) {
            VlanSensitivity::Strictest => 0,
            VlanSensitivity::Strict => 0,
            VlanSensitivity::Moderate => 48 * 3600,
            VlanSensitivity::Loose => 24 * 3600,
            VlanSensitivity::Monitor => 72 * 3600,
        }
    }

    /// Classify a destination IP as a VLAN subnet string or a /16 group.
    /// Uses configured subnets for known VLANs, falls back to RFC1918 /24 or external /16.
    pub fn classify_destination(&self, dst_ip: &str) -> String {
        let octets: Vec<u8> = dst_ip.split('.').filter_map(|o| o.parse().ok()).collect();
        if octets.len() != 4 {
            return format!("{}.0.0.0/8", dst_ip.split('.').next().unwrap_or("0"));
        }

        // Check if IP matches a configured VLAN subnet — return that subnet
        if let Some(ip_u32) = Self::ip_to_u32(dst_ip) {
            for entry in &self.subnets {
                if (ip_u32 & entry.mask) == (entry.network & entry.mask) {
                    let net_bytes = entry.network.to_be_bytes();
                    return format!(
                        "{}.{}.{}.{}/{}",
                        net_bytes[0], net_bytes[1], net_bytes[2], net_bytes[3], entry.prefix_len
                    );
                }
            }
        }

        // RFC1918 catch-all — keep /24 for internal networks
        match (octets[0], octets[1]) {
            (10, _) => format!("10.{}.{}.0/24", octets[1], octets[2]),
            (172, 16..=31) => format!("172.{}.{}.0/24", octets[1], octets[2]),
            (192, 168) => format!("192.168.{}.0/24", octets[2]),
            // External IPs grouped at /16 to reduce baseline fragmentation
            _ => format!("{}.{}.0.0/16", octets[0], octets[1]),
        }
    }

    /// Classify flow direction based on source/destination VLANs.
    pub fn classify_direction(&self, src_ip: &str, dst_ip: &str) -> &'static str {
        let src_vlan = self.ip_to_vlan(src_ip);
        let dst_vlan = self.ip_to_vlan(dst_ip);
        let dst_external = !self.is_internal_ip(dst_ip);

        match (src_vlan, dst_vlan, dst_external) {
            (_, _, true) => "outbound",
            (Some(s), Some(d), _) if s == d => "internal",
            (Some(_), Some(_), _) => "lateral",
            (None, Some(_), _) => "inbound",
            _ => "internal",
        }
    }
}

/// Check if IP is RFC1918 private.
pub fn is_internal_ip(ip: &str) -> bool {
    let octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return false;
    }
    matches!(
        (octets[0], octets[1]),
        (10, _) | (172, 16..=31) | (192, 168)
    )
}

// ── Confidence Scoring ───────────────────────────────────────

/// Compute a confidence score (0.0–1.0) for an anomaly.
///
/// Higher confidence means the anomaly is more likely to be a real issue
/// rather than noise. Factors include baseline maturity, observation count,
/// baseline age, cross-correlation with firewall events, VLAN sensitivity,
/// and anomaly type.
pub fn compute_confidence(
    anomaly_type: &str,
    baseline_status: &str,
    observation_count: i64,
    baseline_age_days: f64,
    is_correlated: bool,
    vlan_sensitivity: VlanSensitivity,
) -> f64 {
    let mut score: f64 = 0.5;

    // Baseline maturity
    match baseline_status {
        "baselined" => score += 0.15,
        "sparse" => score -= 0.1,
        "learning" => score -= 0.2,
        _ => {}
    }

    // Observation count — more data means more reliable anomaly detection
    if observation_count > 1000 {
        score += 0.1;
    } else if observation_count > 100 {
        score += 0.05;
    } else if observation_count < 10 {
        score -= 0.1;
    }

    // Baseline age — older baselines are more trustworthy
    if baseline_age_days > 30.0 {
        score += 0.1;
    } else if baseline_age_days > 7.0 {
        score += 0.05;
    }

    // Cross-correlation boost (firewall rule matched)
    if is_correlated {
        score += 0.15;
    }

    // VLAN sensitivity — stricter VLANs produce higher-confidence anomalies
    match vlan_sensitivity {
        VlanSensitivity::Strictest => score += 0.1,
        VlanSensitivity::Strict => score += 0.1,
        VlanSensitivity::Moderate => {}
        VlanSensitivity::Loose => score -= 0.05,
        VlanSensitivity::Monitor => score -= 0.05,
    }

    // Anomaly type weight
    match anomaly_type {
        "blocked_attempt" => score += 0.1,
        "new_destination" => score += 0.05,
        "volume_spike" => {} // neutral — relies on other factors
        _ => {}
    }

    score.clamp(0.0, 1.0)
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
    pub confidence: f64,
    pub description: String,
    pub details: Option<String>,
    pub vlan: i64,
    pub firewall_correlation: Option<String>,
    pub firewall_rule_id: Option<String>,
    pub firewall_rule_comment: Option<String>,
    pub status: String,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
    pub tier: i32,
    pub dedup_key: Option<String>,
    pub occurrence_count: i64,
    pub last_occurrence: Option<i64>,
}

/// New anomaly to insert (no id yet).
#[derive(Debug, Clone)]
pub struct NewAnomaly {
    pub mac: String,
    pub anomaly_type: String,
    pub severity: String,
    pub confidence: f64,
    pub description: String,
    pub details: Option<String>,
    pub vlan: i64,
    pub firewall_correlation: Option<String>,
    pub firewall_rule_id: Option<String>,
    pub firewall_rule_comment: Option<String>,
    pub tier: i32,
    pub dedup_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InfrastructurePolicy {
    pub id: i64,
    pub service: String,
    pub protocol: Option<String>,
    pub port: Option<i64>,
    pub authorized_targets: Vec<String>,
    pub vlan_scope: Option<Vec<i64>>,
    pub source: String,
    pub priority: String,
    pub last_synced: i64,
    pub router_entity_id: Option<String>,
    /// True for admin-created policies; false for router-synced. Stale reaper skips user_created policies.
    pub user_created: bool,
}

// ── Source of Authority (SoA) Model ──────────────────────────────
// Governs how every signal is classified, trusted, and acted upon.
// T1 (Router) > T2 (RouterOS Switch) > T3 (SwOS/SNMP).

/// Classification of a detection signal's trustworthiness.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    /// Direct from router or switch config/state (T1/T2). Actionable by Arc.
    Authoritative,
    /// Derived from authoritative data. Actionable by Arc.
    Observed,
    /// Multi-signal heuristic. Arc plan-only — never auto-execute.
    Inferred,
}

impl DataClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            Self::Observed => "observed",
            Self::Inferred => "inferred",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "observed" => Self::Observed,
            "inferred" => Self::Inferred,
            _ => Self::Authoritative,
        }
    }
}

/// Which authority tier provided the data.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SourceTier {
    /// T1: RouterOS REST API (primary authority for L3/identity/policy).
    Router,
    /// T2: RouterOS switch (CRS series — primary for L2/topology).
    RosSwitch,
    /// T3: SwOS or SNMP managed switch (support only).
    SwosSnmp,
    /// Inference from multiple sources (no single authority).
    MultiSignal,
    /// Operator-created (policy editor, manual identity).
    Admin,
}

impl SourceTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::RosSwitch => "ros_switch",
            Self::SwosSnmp => "swos_snmp",
            Self::MultiSignal => "multi_signal",
            Self::Admin => "admin",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "ros_switch" => Self::RosSwitch,
            "swos_snmp" => Self::SwosSnmp,
            "multi_signal" => Self::MultiSignal,
            "admin" => Self::Admin,
            _ => Self::Router,
        }
    }
}

// ── Policy Deviation Types ──────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PolicyDeviation {
    pub id: i64,
    pub mac_address: String,
    pub ip_address: String,
    pub vlan: Option<i64>,
    pub deviation_type: String,
    pub expected: String,
    pub actual: String,
    pub policy_source: Option<String>,
    pub attack_techniques: Vec<String>,
    pub severity: String,
    pub status: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub occurrence_count: i64,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
    // Phase 3: structured service metadata + SoA classification
    pub service: String,
    pub protocol: Option<String>,
    pub port: Option<i64>,
    pub policy_id: Option<i64>,
    pub classification: DataClassification,
    pub observed_from: SourceTier,
}

pub struct NewPolicyDeviation {
    pub mac_address: String,
    pub ip_address: String,
    pub vlan: Option<i64>,
    pub deviation_type: String,
    pub expected: String,
    pub actual: String,
    pub policy_source: Option<String>,
    pub attack_techniques: Vec<String>,
    pub severity: String,
    // Phase 3: structured service metadata + SoA classification
    pub service: String,
    pub protocol: Option<String>,
    pub port: Option<i64>,
    pub policy_id: Option<i64>,
    pub classification: DataClassification,
    pub observed_from: SourceTier,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PolicyDeviationCounts {
    pub total: i64,
    pub new: i64,
    pub acknowledged: i64,
    pub resolved: i64,
    pub dns: i64,
    pub ntp: i64,
    pub gateway: i64,
}

#[derive(Debug, Clone)]
pub struct FirewallIonTag {
    pub rule_id: String,
    pub chain: String,
    pub action: String,
    pub tag: String,
    pub comment: String,
    pub rule_summary: String,
    pub last_synced: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Investigation {
    pub id: i64,
    pub anomaly_id: i64,
    pub device_mac: String,
    pub device_hostname: Option<String>,
    pub device_manufacturer: Option<String>,
    pub device_disposition: Option<String>,
    pub device_first_seen: i64,
    pub device_baseline_status: Option<String>,
    pub vlan_id: i64,
    pub vlan_sensitivity: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_country: Option<String>,
    pub dst_city: Option<String>,
    pub dst_asn: Option<i64>,
    pub dst_org: Option<String>,
    pub dst_is_cdn: bool,
    pub dst_reverse_dns: Option<String>,
    pub dst_seen_by_device_count: i64,
    pub anomaly_type: String,
    pub prior_anomaly_count_24h: i64,
    pub prior_anomaly_count_7d: i64,
    pub same_pattern_count_24h: i64,
    pub baseline_coverage_pct: Option<f64>,
    pub current_volume_bytes: Option<i64>,
    pub baseline_volume_bytes: Option<i64>,
    pub volume_ratio: Option<f64>,
    pub unique_destinations_1h: Option<i64>,
    pub unique_ports_1h: Option<i64>,
    pub other_devices_same_dest: Option<i64>,
    pub firewall_rule_id: Option<String>,
    pub firewall_action: Option<String>,
    pub firewall_rule_comment: Option<String>,
    pub firewall_correlation: Option<String>,
    pub verdict: String,
    pub recommended_action: String,
    pub reason: String,
    pub summary: String,
    pub evidence_chain: Option<String>,
    pub investigated_at: i64,
    pub duration_ms: i64,
}

#[derive(Debug, Clone)]
pub struct NewInvestigation {
    pub anomaly_id: i64,
    pub device_mac: String,
    pub device_hostname: Option<String>,
    pub device_manufacturer: Option<String>,
    pub device_disposition: Option<String>,
    pub device_first_seen: i64,
    pub device_baseline_status: Option<String>,
    pub vlan_id: i64,
    pub vlan_sensitivity: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_country: Option<String>,
    pub dst_city: Option<String>,
    pub dst_asn: Option<i64>,
    pub dst_org: Option<String>,
    pub dst_is_cdn: bool,
    pub dst_reverse_dns: Option<String>,
    pub dst_seen_by_device_count: i64,
    pub anomaly_type: String,
    pub prior_anomaly_count_24h: i64,
    pub prior_anomaly_count_7d: i64,
    pub same_pattern_count_24h: i64,
    pub baseline_coverage_pct: Option<f64>,
    pub current_volume_bytes: Option<i64>,
    pub baseline_volume_bytes: Option<i64>,
    pub volume_ratio: Option<f64>,
    pub unique_destinations_1h: Option<i64>,
    pub unique_ports_1h: Option<i64>,
    pub other_devices_same_dest: Option<i64>,
    pub firewall_rule_id: Option<String>,
    pub firewall_action: Option<String>,
    pub firewall_rule_comment: Option<String>,
    pub firewall_correlation: Option<String>,
    pub verdict: String,
    pub recommended_action: String,
    pub reason: String,
    pub summary: String,
    pub evidence_chain: Option<String>,
    pub investigated_at: i64,
    pub duration_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvestigationStats {
    pub benign: i64,
    pub routine: i64,
    pub suspicious: i64,
    pub threat: i64,
    pub inconclusive: i64,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorOverview {
    pub total_devices: i64,
    pub baselined_devices: i64,
    pub sparse_devices: i64,
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
    pub sparse_count: i64,
    pub pending_anomaly_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorResetResult {
    pub anomalies: usize,
    pub baselines: usize,
    pub observations: usize,
    pub profiles: usize,
    pub boosts: usize,
    pub watermarks: usize,
    pub policy_deviations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertCount {
    pub pending_count: i64,
    pub critical_count: i64,
    pub warning_count: i64,
    pub tier1_pending: i64,
    pub anomaly_macs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatternSuppression {
    pub id: i64,
    pub device_id: Option<String>,
    pub vlan: Option<i64>,
    pub protocol: Option<String>,
    pub destination_port: Option<i64>,
    pub traffic_class: Option<String>,
    pub action: String,
    pub created_by: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WanScanBucket {
    pub bucket: i64,
    pub total_probes: i64,
    pub unique_sources: i64,
    pub unique_ports: i64,
    pub top_ports: Option<String>,
    pub top_countries: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewPatternSuppression {
    pub device_id: Option<String>,
    pub vlan: Option<i64>,
    pub protocol: Option<String>,
    pub destination_port: Option<i64>,
    pub traffic_class: Option<String>,
    /// One of: suppress, dismissed, accepted
    pub action: String,
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

    fn pattern_key(
        device_id: Option<&str>,
        vlan: Option<i64>,
        protocol: Option<&str>,
        destination_port: Option<i64>,
        traffic_class: Option<&str>,
    ) -> String {
        let did = device_id.unwrap_or("*");
        let v = vlan
            .map(|n| n.to_string())
            .unwrap_or_else(|| "*".to_string());
        let p = protocol.unwrap_or("*");
        let dp = destination_port
            .map(|n| n.to_string())
            .unwrap_or_else(|| "*".to_string());
        let tc = traffic_class.unwrap_or("*");
        format!("{did}|{v}|{p}|{dp}|{tc}")
    }

    fn parse_pattern_fields(
        details: Option<&str>,
    ) -> (Option<String>, Option<i64>, Option<String>) {
        let Some(raw) = details else {
            return (None, None, None);
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(raw) else {
            return (None, None, None);
        };
        let protocol = json
            .get("protocol")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let destination_port = json.get("dst_port").and_then(|v| v.as_i64());
        let traffic_class = json
            .get("traffic_class")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        (protocol, destination_port, traffic_class)
    }

    pub fn new(db_path: &Path) -> Result<Self, String> {
        let conn =
            Connection::open(db_path).map_err(|e| format!("failed to open behavior db: {e}"))?;

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

            CREATE TABLE IF NOT EXISTS engine_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scheduler_watermarks (
                task_name TEXT PRIMARY KEY,
                last_run INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS anomaly_suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                vlan INTEGER,
                protocol TEXT,
                destination_port INTEGER,
                traffic_class TEXT,
                action TEXT NOT NULL DEFAULT 'suppress',
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_anomaly_suppressions_match
                ON anomaly_suppressions(device_id, vlan, protocol, destination_port, traffic_class);

            CREATE TABLE IF NOT EXISTS anomaly_priority_boosts (
                pattern_key TEXT PRIMARY KEY,
                device_id TEXT,
                vlan INTEGER,
                protocol TEXT,
                destination_port INTEGER,
                traffic_class TEXT,
                boost INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL
            );
            ",
        )
        .map_err(|e| format!("schema creation failed: {e}"))?;

        // Migration: add confidence column to device_anomalies if missing
        let has_confidence: bool = conn
            .prepare("SELECT confidence FROM device_anomalies LIMIT 0")
            .is_ok();
        if !has_confidence {
            conn.execute_batch(
                "ALTER TABLE device_anomalies ADD COLUMN confidence REAL NOT NULL DEFAULT 0.5;",
            )
            .map_err(|e| format!("migration (confidence column) failed: {e}"))?;
        }

        // Migration: create investigations table
        let has_investigations: bool = conn
            .prepare("SELECT id FROM investigations LIMIT 0")
            .is_ok();
        if !has_investigations {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    anomaly_id INTEGER NOT NULL UNIQUE,
                    device_mac TEXT NOT NULL,
                    device_hostname TEXT,
                    device_manufacturer TEXT,
                    device_disposition TEXT,
                    device_first_seen INTEGER NOT NULL DEFAULT 0,
                    device_baseline_status TEXT,
                    vlan_id INTEGER NOT NULL,
                    vlan_sensitivity TEXT,
                    dst_ip TEXT,
                    dst_country TEXT,
                    dst_city TEXT,
                    dst_asn INTEGER,
                    dst_org TEXT,
                    dst_is_cdn INTEGER NOT NULL DEFAULT 0,
                    dst_reverse_dns TEXT,
                    dst_seen_by_device_count INTEGER NOT NULL DEFAULT 0,
                    anomaly_type TEXT NOT NULL,
                    prior_anomaly_count_24h INTEGER NOT NULL DEFAULT 0,
                    prior_anomaly_count_7d INTEGER NOT NULL DEFAULT 0,
                    same_pattern_count_24h INTEGER NOT NULL DEFAULT 0,
                    baseline_coverage_pct REAL,
                    current_volume_bytes INTEGER,
                    baseline_volume_bytes INTEGER,
                    volume_ratio REAL,
                    unique_destinations_1h INTEGER,
                    unique_ports_1h INTEGER,
                    other_devices_same_dest INTEGER,
                    firewall_rule_id TEXT,
                    firewall_action TEXT,
                    firewall_rule_comment TEXT,
                    firewall_correlation TEXT,
                    verdict TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    evidence_chain TEXT,
                    investigated_at INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_investigations_anomaly ON investigations(anomaly_id);
                CREATE INDEX IF NOT EXISTS idx_investigations_verdict ON investigations(verdict);
                CREATE INDEX IF NOT EXISTS idx_investigations_device ON investigations(device_mac);
                CREATE INDEX IF NOT EXISTS idx_investigations_time ON investigations(investigated_at);",
            )
            .map_err(|e| format!("investigations table creation failed: {e}"))?;
        }

        // Migration: add v3 columns (tier, dedup_key, occurrence_count, last_occurrence)
        let has_tier: bool = conn.prepare("SELECT tier FROM device_anomalies LIMIT 0").is_ok();
        if !has_tier {
            conn.execute_batch(
                "ALTER TABLE device_anomalies ADD COLUMN tier INTEGER NOT NULL DEFAULT 2;
                 ALTER TABLE device_anomalies ADD COLUMN dedup_key TEXT;
                 ALTER TABLE device_anomalies ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1;
                 ALTER TABLE device_anomalies ADD COLUMN last_occurrence INTEGER;
                 CREATE INDEX IF NOT EXISTS idx_anomaly_tier ON device_anomalies(tier, status);
                 CREATE INDEX IF NOT EXISTS idx_anomaly_dedup ON device_anomalies(mac, anomaly_type, dedup_key, status);",
            ).map_err(|e| format!("migration (v3 columns) failed: {e}"))?;
        }

        // Migration: WAN scan pressure and sensitive ports tables
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS wan_scan_pressure (
                bucket INTEGER PRIMARY KEY,
                total_probes INTEGER NOT NULL DEFAULT 0,
                unique_sources INTEGER NOT NULL DEFAULT 0,
                unique_ports INTEGER NOT NULL DEFAULT 0,
                top_ports TEXT,
                top_countries TEXT
            );

            CREATE TABLE IF NOT EXISTS wan_sensitive_ports (
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                service_name TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                PRIMARY KEY (port, protocol)
            );

            -- Seed default sensitive ports
            INSERT OR IGNORE INTO wan_sensitive_ports (port, protocol, service_name, source) VALUES
                (22, 'tcp', 'SSH', 'default'),
                (80, 'tcp', 'HTTP', 'default'),
                (443, 'tcp', 'HTTPS', 'default'),
                (8291, 'tcp', 'WinBox', 'default'),
                (8728, 'tcp', 'RouterOS API', 'default'),
                (8729, 'tcp', 'RouterOS API-SSL', 'default'),
                (161, 'udp', 'SNMP', 'default'),
                (3389, 'tcp', 'RDP', 'default');",
        ).map_err(|e| format!("WAN tables creation failed: {e}"))?;

        // Migration: infrastructure policy table (Phase 2)
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS infrastructure_policy (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                protocol TEXT,
                port INTEGER,
                authorized_targets TEXT NOT NULL,
                vlan_scope TEXT NOT NULL DEFAULT '__global__',
                source TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'high',
                last_synced INTEGER NOT NULL,
                router_entity_id TEXT,
                UNIQUE(service, protocol, port, vlan_scope)
            );

            CREATE INDEX IF NOT EXISTS idx_policy_service ON infrastructure_policy(service, protocol, port);
            CREATE INDEX IF NOT EXISTS idx_policy_vlan ON infrastructure_policy(vlan_scope);

            CREATE TABLE IF NOT EXISTS firewall_ion_tags (
                rule_id TEXT PRIMARY KEY,
                chain TEXT NOT NULL,
                action TEXT NOT NULL,
                tag TEXT NOT NULL,
                comment TEXT NOT NULL,
                rule_summary TEXT NOT NULL,
                last_synced INTEGER NOT NULL
            );",
        ).map_err(|e| format!("Phase 2 tables creation failed: {e}"))?;

        // Migration: add user_created flag to infrastructure_policy (protects admin policies from stale reaper)
        let has_user_created: bool = conn
            .prepare("SELECT user_created FROM infrastructure_policy LIMIT 0")
            .is_ok();
        if !has_user_created {
            conn.execute_batch(
                "ALTER TABLE infrastructure_policy ADD COLUMN user_created INTEGER NOT NULL DEFAULT 0;",
            )
            .map_err(|e| format!("migration (user_created column) failed: {e}"))?;
        }

        // Migration: policy deviations table (Phase 2 — DNS deviation detection)
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS policy_deviations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                vlan INTEGER,
                deviation_type TEXT NOT NULL,
                expected TEXT NOT NULL,
                actual TEXT NOT NULL,
                policy_source TEXT,
                attack_techniques TEXT NOT NULL DEFAULT '[]',
                severity TEXT NOT NULL DEFAULT 'informational',
                status TEXT NOT NULL DEFAULT 'new',
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                resolved_at INTEGER,
                resolved_by TEXT,
                UNIQUE(mac_address, deviation_type, actual)
            );

            CREATE INDEX IF NOT EXISTS idx_deviations_status ON policy_deviations(status);
            CREATE INDEX IF NOT EXISTS idx_deviations_mac ON policy_deviations(mac_address);
            CREATE INDEX IF NOT EXISTS idx_deviations_type ON policy_deviations(deviation_type);",
        ).map_err(|e| format!("Policy deviations table creation failed: {e}"))?;

        // Migration: Phase 3 — add service metadata + SoA classification to policy_deviations
        let has_service_col: bool = conn
            .prepare("SELECT service FROM policy_deviations LIMIT 0")
            .is_ok();
        if !has_service_col {
            conn.execute_batch(
                "ALTER TABLE policy_deviations ADD COLUMN service TEXT NOT NULL DEFAULT '';
                 ALTER TABLE policy_deviations ADD COLUMN protocol TEXT;
                 ALTER TABLE policy_deviations ADD COLUMN port INTEGER;
                 ALTER TABLE policy_deviations ADD COLUMN policy_id INTEGER;
                 ALTER TABLE policy_deviations ADD COLUMN classification TEXT NOT NULL DEFAULT 'authoritative';
                 ALTER TABLE policy_deviations ADD COLUMN observed_from TEXT NOT NULL DEFAULT 'router';",
            )
            .map_err(|e| format!("migration (Phase 3 service metadata) failed: {e}"))?;

            // Backfill existing deviations with service metadata from deviation_type prefix
            conn.execute_batch(
                "UPDATE policy_deviations SET service='dns', protocol='udp', port=53
                   WHERE deviation_type LIKE 'dns%' AND service='';
                 UPDATE policy_deviations SET service='ntp', protocol='udp', port=123
                   WHERE deviation_type LIKE 'ntp%' AND service='';",
            )
            .map_err(|e| format!("migration (Phase 3 backfill) failed: {e}"))?;

            tracing::info!("Phase 3 migration: added service metadata + SoA classification to policy_deviations");
        }

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

    /// Fetch profiles for multiple MACs in a single query.
    /// Returns a HashMap keyed by MAC address.
    pub async fn get_profiles_bulk(&self, macs: &[&str]) -> Result<HashMap<String, DeviceProfile>, String> {
        if macs.is_empty() {
            return Ok(HashMap::new());
        }

        let db = self.db.lock().await;

        // Build "WHERE mac IN (?, ?, ...)" with dynamic placeholders
        let placeholders: Vec<&str> = macs.iter().map(|_| "?").collect();
        let sql = format!(
            "SELECT mac, hostname, manufacturer, current_ip, current_vlan,
                    first_seen, last_seen, learning_until, baseline_status, notes
             FROM device_profiles WHERE mac IN ({})",
            placeholders.join(", ")
        );

        let mut stmt = db.prepare(&sql).map_err(|e| format!("prepare bulk profiles: {e}"))?;

        // Bind each MAC as a parameter
        let params_vec: Vec<&dyn rusqlite::types::ToSql> = macs.iter().map(|m| m as &dyn rusqlite::types::ToSql).collect();
        let rows = stmt
            .query_map(params_vec.as_slice(), |row| {
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
            .map_err(|e| format!("bulk profile query: {e}"))?;

        let mut map = HashMap::with_capacity(macs.len());
        for row in rows {
            let profile = row.map_err(|e| format!("bulk profile row: {e}"))?;
            map.insert(profile.mac.clone(), profile);
        }
        Ok(map)
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

    pub async fn record_observations(
        &self,
        observations: &[DeviceObservation],
    ) -> Result<(), String> {
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

    /// Minimum distinct baseline entries for a device to be considered "baselined".
    /// Below this threshold, the device is promoted to "sparse" instead.
    const MIN_BASELINE_ENTRIES: i64 = 10;
    /// Minimum total observation count for "baselined" promotion after learning period.
    const MIN_OBSERVATION_COUNT: i64 = 200;
    /// Observation count that triggers early "baselined" promotion before learning_until.
    /// Active servers and workstations hit this in 3-4 days.
    const FAST_TRACK_OBSERVATION_COUNT: i64 = 5000;
    /// Devices with fewer than this many baseline observations after the learning
    /// period are promoted to "sparse" — not enough data for meaningful baselines.
    const SPARSE_THRESHOLD: i64 = 50;

    /// Recompute baselines for a single device from its observations.
    /// Does NOT handle promotion — use `promote_eligible_devices()` instead.
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
                params![
                    mac, protocol, dst_port, dst_subnet, direction, avg_bph, max_bph, count, now
                ],
            )
            .map_err(|e| format!("upsert baseline failed: {e}"))?;
        }

        Ok(())
    }

    /// Promote eligible devices from `learning` to `baselined` or `sparse`.
    ///
    /// Dual-threshold promotion:
    /// 1. **Time-gated:** `learning_until <= now` AND observation_count >= MIN_OBSERVATION_COUNT
    ///    → promoted to `baselined` (normal 7-day graduation)
    /// 2. **Fast-tracked:** observation_count >= FAST_TRACK_OBSERVATION_COUNT regardless of time
    ///    → promoted to `baselined` (active devices graduate early)
    /// 3. **Sparse:** time expired AND observation_count < SPARSE_THRESHOLD
    ///    → promoted to `sparse` (barely active, thin baseline)
    /// 4. **Stays learning:** time expired but observations between SPARSE_THRESHOLD and
    ///    MIN_OBSERVATION_COUNT → learning_until extended by 3 days (needs more data)
    ///
    /// This is decoupled from baseline recomputation so it can run on a
    /// short cadence (e.g. every 5 minutes) independent of nightly maintenance.
    pub async fn promote_eligible_devices(&self) -> Result<(usize, usize), String> {
        let db = self.db.lock().await;
        let now = now_unix();

        // Find all learning devices — both time-expired and potential fast-tracks
        let mut stmt = db
            .prepare(
                "SELECT mac, learning_until FROM device_profiles
                 WHERE baseline_status = 'learning'",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let learning_devices: Vec<(String, i64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| format!("query failed: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect failed: {e}"))?;

        let mut promoted_baselined = 0usize;
        let mut promoted_sparse = 0usize;

        for (mac, learning_until) in &learning_devices {
            let time_expired = *learning_until <= now;

            // Count distinct baseline entries
            let baseline_count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM device_baselines WHERE mac = ?1",
                    params![mac],
                    |row| row.get(0),
                )
                .map_err(|e| format!("baseline count failed: {e}"))?;

            // Count total observations
            let obs_count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM device_observations WHERE mac = ?1",
                    params![mac],
                    |row| row.get(0),
                )
                .map_err(|e| format!("observation count failed: {e}"))?;

            // Fast-track: very active devices graduate early regardless of time
            let fast_track = obs_count >= Self::FAST_TRACK_OBSERVATION_COUNT
                && baseline_count >= Self::MIN_BASELINE_ENTRIES;

            let new_status = if fast_track {
                promoted_baselined += 1;
                "baselined"
            } else if time_expired && baseline_count >= Self::MIN_BASELINE_ENTRIES
                && obs_count >= Self::MIN_OBSERVATION_COUNT
            {
                // Normal graduation: time expired + sufficient data
                promoted_baselined += 1;
                "baselined"
            } else if time_expired && obs_count < Self::SPARSE_THRESHOLD {
                // Barely active device — sparse
                promoted_sparse += 1;
                "sparse"
            } else if time_expired {
                // Time expired but between sparse and baselined thresholds —
                // extend learning by 3 days to collect more data
                let extended = now + 3 * 86400;
                db.execute(
                    "UPDATE device_profiles SET learning_until = ?2 WHERE mac = ?1",
                    params![mac, extended],
                )
                .map_err(|e| format!("extend learning failed: {e}"))?;
                tracing::debug!(
                    mac = %mac, obs_count, baseline_count,
                    "learning extended 3 days — insufficient data for baseline"
                );
                continue; // Don't update baseline_status
            } else {
                continue; // Still within learning period, not fast-tracked
            };

            db.execute(
                "UPDATE device_profiles SET baseline_status = ?2 WHERE mac = ?1",
                params![mac, new_status],
            )
            .map_err(|e| format!("promote failed: {e}"))?;
        }

        Ok((promoted_baselined, promoted_sparse))
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

    // ── Scheduler watermark methods ──

    /// Get the last-run timestamp for a named task, or None if never run.
    pub async fn get_watermark(&self, task_name: &str) -> Result<Option<i64>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT last_run FROM scheduler_watermarks WHERE task_name = ?1",
            params![task_name],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("get_watermark failed: {e}"))
    }

    /// Set the last-run timestamp for a named task.
    pub async fn set_watermark(&self, task_name: &str, timestamp: i64) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        db.execute(
            "INSERT INTO scheduler_watermarks (task_name, last_run, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(task_name) DO UPDATE SET last_run = ?2, updated_at = ?3",
            params![task_name, timestamp, now],
        )
        .map_err(|e| format!("set_watermark failed: {e}"))?;
        Ok(())
    }

    // ── Anomaly methods ──

    pub async fn record_anomaly(&self, anomaly: &NewAnomaly) -> Result<i64, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        db.execute(
            "INSERT INTO device_anomalies
                (mac, timestamp, anomaly_type, severity, confidence, description, details,
                 vlan, firewall_correlation, firewall_rule_id, firewall_rule_comment,
                 tier, dedup_key, occurrence_count, last_occurrence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1, ?2)",
            params![
                anomaly.mac,
                now,
                anomaly.anomaly_type,
                anomaly.severity,
                anomaly.confidence,
                anomaly.description,
                anomaly.details,
                anomaly.vlan,
                anomaly.firewall_correlation,
                anomaly.firewall_rule_id,
                anomaly.firewall_rule_comment,
                anomaly.tier,
                anomaly.dedup_key,
            ],
        )
        .map_err(|e| format!("record_anomaly failed: {e}"))?;
        Ok(db.last_insert_rowid())
    }

    /// Get the total observation count and earliest baseline computed_at for a device.
    /// Used for confidence scoring.
    pub async fn get_baseline_stats(&self, mac: &str) -> Result<(i64, i64), String> {
        let db = self.db.lock().await;
        let total_obs: i64 = db
            .query_row(
                "SELECT COALESCE(SUM(observation_count), 0) FROM device_baselines WHERE mac = ?1",
                params![mac],
                |row| row.get(0),
            )
            .map_err(|e| format!("baseline stats obs count failed: {e}"))?;
        let earliest_computed: i64 = db
            .query_row(
                "SELECT COALESCE(MIN(computed_at), 0) FROM device_baselines WHERE mac = ?1",
                params![mac],
                |row| row.get(0),
            )
            .map_err(|e| format!("baseline stats computed_at failed: {e}"))?;
        Ok((total_obs, earliest_computed))
    }

    /// Check for recent elevated observations (multi-window persistence).
    /// Returns the count of recent observations in the given flow that exceed
    /// the specified byte threshold within the last `window_secs`.
    pub async fn count_elevated_observations(
        &self,
        mac: &str,
        protocol: &str,
        dst_port: Option<i64>,
        dst_subnet: &str,
        direction: &str,
        byte_threshold: f64,
        window_secs: i64,
    ) -> Result<i64, String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - window_secs;
        let hourly_threshold = byte_threshold / 60.0; // convert hourly back to per-observation
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_observations
                 WHERE mac = ?1 AND protocol = ?2
                   AND dst_subnet = ?4 AND direction = ?5
                   AND timestamp >= ?6
                   AND (bytes_sent + bytes_recv) > ?7
                   AND (dst_port = ?3 OR (?3 IS NULL AND dst_port IS NULL))",
                params![
                    mac,
                    protocol,
                    dst_port,
                    dst_subnet,
                    direction,
                    cutoff,
                    hourly_threshold
                ],
                |row| row.get(0),
            )
            .map_err(|e| format!("count_elevated_observations failed: {e}"))?;
        Ok(count)
    }

    /// Check for existing pending/flagged anomaly with same dedup key.
    /// Returns Some(id) if found (for occurrence_count update), None if no match.
    pub async fn find_dedup_anomaly(
        &self,
        mac: &str,
        anomaly_type: &str,
        dedup_key: &str,
    ) -> Result<Option<i64>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT id FROM device_anomalies
             WHERE mac = ?1 AND anomaly_type = ?2 AND dedup_key = ?3
               AND status IN ('pending', 'flagged')
             LIMIT 1",
            params![mac, anomaly_type, dedup_key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("find_dedup_anomaly failed: {e}"))
    }

    /// Increment occurrence count on an existing anomaly instead of creating a new one.
    pub async fn bump_anomaly_occurrence(&self, anomaly_id: i64) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        db.execute(
            "UPDATE device_anomalies
             SET occurrence_count = occurrence_count + 1,
                 last_occurrence = ?1,
                 timestamp = ?1
             WHERE id = ?2",
            params![now, anomaly_id],
        )
        .map_err(|e| format!("bump_anomaly_occurrence failed: {e}"))?;
        Ok(())
    }

    pub async fn get_anomalies(
        &self,
        status: Option<&str>,
        severity: Option<&str>,
        vlan: Option<i64>,
        tier: Option<i32>,
        limit: Option<i64>,
    ) -> Result<Vec<DeviceAnomaly>, String> {
        let db = self.db.lock().await;
        let mut sql = String::from(
            "SELECT id, mac, timestamp, anomaly_type, severity, confidence, description, details,
                    vlan, firewall_correlation, firewall_rule_id, firewall_rule_comment,
                    status, resolved_at, resolved_by,
                    tier, dedup_key, occurrence_count, last_occurrence
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
        if let Some(t) = tier {
            param_values.push(Box::new(t));
            sql.push_str(&format!(" AND tier = ?{}", param_values.len()));
        }
        sql.push_str(" ORDER BY timestamp DESC");
        if let Some(l) = limit {
            param_values.push(Box::new(l));
            sql.push_str(&format!(" LIMIT ?{}", param_values.len()));
        }

        let mut stmt = db
            .prepare(&sql)
            .map_err(|e| format!("prepare failed: {e}"))?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
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
                "SELECT id, mac, timestamp, anomaly_type, severity, confidence, description, details,
                        vlan, firewall_correlation, firewall_rule_id, firewall_rule_comment,
                        status, resolved_at, resolved_by,
                        tier, dedup_key, occurrence_count, last_occurrence
                 FROM device_anomalies WHERE mac = ?1 ORDER BY timestamp DESC",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![mac], Self::map_anomaly_row)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("row collect failed: {e}"))
    }

    pub async fn get_anomaly_by_id(&self, id: i64) -> Result<Option<DeviceAnomaly>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT id, mac, timestamp, anomaly_type, severity, confidence, description, details,
                    vlan, firewall_correlation, firewall_rule_id, firewall_rule_comment,
                    status, resolved_at, resolved_by,
                    tier, dedup_key, occurrence_count, last_occurrence
             FROM device_anomalies WHERE id = ?1",
            params![id],
            Self::map_anomaly_row,
        )
        .optional()
        .map_err(|e| format!("get_anomaly_by_id failed: {e}"))
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
        let tier1_pending: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_anomalies WHERE status = 'pending' AND tier = 1",
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
            tier1_pending,
            anomaly_macs,
        })
    }

    /// Returns daily anomaly counts grouped by VLAN for the last `days` days.
    pub async fn anomaly_trend(
        &self,
        days: i64,
    ) -> Result<Vec<(String, i64, i64)>, String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - (days * 86400);
        let mut stmt = db
            .prepare(
                "SELECT date(timestamp, 'unixepoch') AS day, vlan, COUNT(*) AS cnt
                 FROM device_anomalies
                 WHERE timestamp >= ?1
                 GROUP BY day, vlan
                 ORDER BY day, vlan",
            )
            .map_err(|e| format!("anomaly trend query failed: {e}"))?;
        let rows: Vec<(String, i64, i64)> = stmt
            .query_map(rusqlite::params![cutoff], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|e| format!("anomaly trend query failed: {e}"))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
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

    pub async fn apply_operator_feedback(
        &self,
        id: i64,
        status: &str,
        actor: &str,
    ) -> Result<(), String> {
        let Some(anomaly) = self.get_anomaly_by_id(id).await? else {
            return Ok(());
        };
        let (protocol, destination_port, traffic_class) =
            Self::parse_pattern_fields(anomaly.details.as_deref());

        match status {
            "accepted" => {
                self.recompute_baselines(&anomaly.mac, 7 * 86400).await?;
            }
            "dismissed" => {
                let rule = NewPatternSuppression {
                    device_id: Some(anomaly.mac),
                    vlan: Some(anomaly.vlan),
                    protocol,
                    destination_port,
                    traffic_class,
                    action: "suppress".to_string(),
                };
                let _ = self.add_suppression_rule(&rule, actor).await?;
            }
            "flagged" => {
                self.bump_priority_boost(
                    Some(&anomaly.mac),
                    Some(anomaly.vlan),
                    protocol.as_deref(),
                    destination_port,
                    traffic_class.as_deref(),
                )
                .await?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Bulk-update anomaly status for specific IDs.
    pub async fn bulk_resolve_anomalies(
        &self,
        ids: &[i64],
        status: &str,
        resolved_by: &str,
    ) -> Result<usize, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let mut updated = 0usize;
        for id in ids {
            let changed = db
                .execute(
                    "UPDATE device_anomalies
                     SET status = ?2, resolved_at = ?3, resolved_by = ?4
                     WHERE id = ?1 AND status = 'pending'",
                    params![id, status, now, resolved_by],
                )
                .map_err(|e| format!("bulk resolve failed: {e}"))?;
            updated += changed;
        }
        Ok(updated)
    }

    pub async fn list_suppression_rules(&self) -> Result<Vec<PatternSuppression>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT id, device_id, vlan, protocol, destination_port, traffic_class, action, created_by, created_at
                 FROM anomaly_suppressions ORDER BY created_at DESC, id DESC",
            )
            .map_err(|e| format!("list suppressions prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(PatternSuppression {
                    id: row.get(0)?,
                    device_id: row.get(1)?,
                    vlan: row.get(2)?,
                    protocol: row.get(3)?,
                    destination_port: row.get(4)?,
                    traffic_class: row.get(5)?,
                    action: row.get(6)?,
                    created_by: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })
            .map_err(|e| format!("list suppressions query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("list suppressions collect failed: {e}"))
    }

    pub async fn add_suppression_rule(
        &self,
        rule: &NewPatternSuppression,
        actor: &str,
    ) -> Result<i64, String> {
        let action = match rule.action.as_str() {
            "suppress" | "dismissed" | "accepted" => rule.action.as_str(),
            _ => return Err("invalid suppression action".to_string()),
        };
        let db = self.db.lock().await;
        let now = now_unix();
        db.execute(
            "INSERT INTO anomaly_suppressions
                (device_id, vlan, protocol, destination_port, traffic_class, action, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rule.device_id.as_deref(),
                rule.vlan,
                rule.protocol.as_deref(),
                rule.destination_port,
                rule.traffic_class.as_deref(),
                action,
                actor,
                now
            ],
        )
        .map_err(|e| format!("add suppression failed: {e}"))?;
        Ok(db.last_insert_rowid())
    }

    pub async fn delete_suppression_rule(&self, id: i64) -> Result<bool, String> {
        let db = self.db.lock().await;
        let changed = db
            .execute(
                "DELETE FROM anomaly_suppressions WHERE id = ?1",
                params![id],
            )
            .map_err(|e| format!("delete suppression failed: {e}"))?;
        Ok(changed > 0)
    }

    pub async fn match_suppression_rule(
        &self,
        device_id: &str,
        vlan: i64,
        protocol: &str,
        destination_port: Option<i64>,
        traffic_class: &str,
    ) -> Result<Option<String>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT action
             FROM anomaly_suppressions
             WHERE (device_id IS NULL OR device_id = ?1)
               AND (vlan IS NULL OR vlan = ?2)
               AND (protocol IS NULL OR protocol = ?3)
               AND (destination_port IS NULL OR destination_port = ?4)
               AND (traffic_class IS NULL OR traffic_class = ?5)
             ORDER BY
               ((CASE WHEN device_id IS NULL THEN 0 ELSE 1 END) +
                (CASE WHEN vlan IS NULL THEN 0 ELSE 1 END) +
                (CASE WHEN protocol IS NULL THEN 0 ELSE 1 END) +
                (CASE WHEN destination_port IS NULL THEN 0 ELSE 1 END) +
                (CASE WHEN traffic_class IS NULL THEN 0 ELSE 1 END)) DESC,
               id DESC
             LIMIT 1",
            params![device_id, vlan, protocol, destination_port, traffic_class],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("match suppression failed: {e}"))
    }

    pub async fn bump_priority_boost(
        &self,
        device_id: Option<&str>,
        vlan: Option<i64>,
        protocol: Option<&str>,
        destination_port: Option<i64>,
        traffic_class: Option<&str>,
    ) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let key = Self::pattern_key(device_id, vlan, protocol, destination_port, traffic_class);
        db.execute(
            "INSERT INTO anomaly_priority_boosts
                (pattern_key, device_id, vlan, protocol, destination_port, traffic_class, boost, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)
             ON CONFLICT(pattern_key) DO UPDATE SET boost = boost + 1, updated_at = excluded.updated_at",
            params![key, device_id, vlan, protocol, destination_port, traffic_class, now],
        )
        .map_err(|e| format!("bump priority boost failed: {e}"))?;
        Ok(())
    }

    pub async fn get_priority_boost(
        &self,
        device_id: &str,
        vlan: i64,
        protocol: &str,
        destination_port: Option<i64>,
        traffic_class: &str,
    ) -> Result<i64, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT COALESCE(MAX(boost), 0)
             FROM anomaly_priority_boosts
             WHERE (device_id IS NULL OR device_id = ?1)
               AND (vlan IS NULL OR vlan = ?2)
               AND (protocol IS NULL OR protocol = ?3)
               AND (destination_port IS NULL OR destination_port = ?4)
               AND (traffic_class IS NULL OR traffic_class = ?5)",
            params![device_id, vlan, protocol, destination_port, traffic_class],
            |row| row.get(0),
        )
        .map_err(|e| format!("get priority boost failed: {e}"))
    }

    /// Archive reviewed anomalies (accepted/dismissed/flagged/auto_dismissed).
    pub async fn archive_reviewed(&self, actor: &str) -> Result<usize, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        db.execute(
            "UPDATE device_anomalies
             SET status = 'archived', resolved_at = COALESCE(resolved_at, ?1), resolved_by = COALESCE(resolved_by, ?2)
             WHERE status IN ('accepted', 'dismissed', 'flagged', 'auto_dismissed')",
            params![now, actor],
        )
        .map_err(|e| format!("archive reviewed failed: {e}"))
    }

    /// Delete archived anomalies.
    pub async fn delete_archived(&self) -> Result<usize, String> {
        let db = self.db.lock().await;
        db.execute("DELETE FROM device_anomalies WHERE status = 'archived'", [])
            .map_err(|e| format!("delete archived failed: {e}"))
    }

    /// Auto-resolve stale anomalies based on per-VLAN timeout rules.
    pub async fn auto_resolve_stale(&self, registry: &VlanRegistry) -> Result<usize, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let mut total = 0usize;

        // Get all VLANs with pending anomalies
        let vlans: Vec<i64> = {
            let mut stmt = db
                .prepare("SELECT DISTINCT vlan FROM device_anomalies WHERE status = 'pending'")
                .map_err(|e| format!("prepare failed: {e}"))?;
            stmt.query_map([], |row| row.get(0))
                .map_err(|e| format!("query failed: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("collect failed: {e}"))?
        };

        for vlan in vlans {
            let timeout = registry.auto_resolve_timeout(vlan as u16);
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
        let sparse_devices: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_profiles WHERE baseline_status = 'sparse'",
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
                        SUM(CASE WHEN baseline_status = 'learning' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN baseline_status = 'sparse' THEN 1 ELSE 0 END)
                 FROM device_profiles
                 WHERE current_vlan IS NOT NULL
                 GROUP BY current_vlan
                 ORDER BY current_vlan",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let vlan_rows: Vec<(i64, i64, i64, i64, i64)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
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
            .map(
                |(vlan, count, baselined, learning, sparse)| VlanBehaviorSummary {
                    vlan,
                    device_count: count,
                    baselined_count: baselined,
                    learning_count: learning,
                    sparse_count: sparse,
                    pending_anomaly_count: anomaly_counts.get(&vlan).copied().unwrap_or(0),
                },
            )
            .collect();

        Ok(BehaviorOverview {
            total_devices,
            baselined_devices,
            sparse_devices,
            learning_devices,
            pending_anomalies: alerts.pending_count,
            critical_anomalies: alerts.critical_count,
            warning_anomalies: alerts.warning_count,
            vlan_summaries,
        })
    }

    // ── Engine Metadata ──

    pub async fn get_metadata(&self, key: &str) -> Result<Option<String>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT value FROM engine_metadata WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("get_metadata failed: {e}"))
    }

    pub async fn set_metadata(&self, key: &str, value: &str) -> Result<(), String> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO engine_metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )
        .map_err(|e| format!("set_metadata failed: {e}"))?;
        Ok(())
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
        let tier1_pending: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_anomalies WHERE status = 'pending' AND tier = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("count failed: {e}"))?;
        Ok(AlertCount {
            pending_count: pending,
            critical_count: critical,
            warning_count: warning,
            tier1_pending,
            anomaly_macs: Vec::new(),
        })
    }

    /// Delete ALL anomalies regardless of status. Returns the number deleted.
    pub async fn delete_all_anomalies(&self) -> Result<usize, String> {
        let db = self.db.lock().await;
        db.execute("DELETE FROM device_anomalies", [])
            .map_err(|e| format!("delete all anomalies failed: {e}"))
    }

    /// Preview what a full reset would delete (row counts per table, no mutation).
    pub async fn reset_preview(&self) -> Result<BehaviorResetResult, String> {
        let db = self.db.lock().await;
        let count = |table: &str| -> Result<usize, String> {
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get::<_, usize>(0))
                .map_err(|e| format!("count {table}: {e}"))
        };
        Ok(BehaviorResetResult {
            anomalies: count("device_anomalies")?,
            baselines: count("device_baselines")?,
            observations: count("device_observations")?,
            profiles: count("device_profiles")?,
            boosts: count("anomaly_priority_boosts")?,
            watermarks: count("scheduler_watermarks")?,
            policy_deviations: count("policy_deviations")?,
        })
    }

    /// Full behavior engine reset: delete all anomalies, baselines, observations,
    /// profiles, priority boosts, and watermarks. Suppressions are kept (user-created).
    /// Returns counts of deleted rows per table.
    pub async fn reset_all(&self) -> Result<BehaviorResetResult, String> {
        let db = self.db.lock().await;
        let anomalies = db.execute("DELETE FROM device_anomalies", [])
            .map_err(|e| format!("reset anomalies: {e}"))?;
        let baselines = db.execute("DELETE FROM device_baselines", [])
            .map_err(|e| format!("reset baselines: {e}"))?;
        let observations = db.execute("DELETE FROM device_observations", [])
            .map_err(|e| format!("reset observations: {e}"))?;
        let profiles = db.execute("DELETE FROM device_profiles", [])
            .map_err(|e| format!("reset profiles: {e}"))?;
        let boosts = db.execute("DELETE FROM anomaly_priority_boosts", [])
            .map_err(|e| format!("reset boosts: {e}"))?;
        let watermarks = db.execute("DELETE FROM scheduler_watermarks", [])
            .map_err(|e| format!("reset watermarks: {e}"))?;
        let policy_deviations = db.execute("DELETE FROM policy_deviations", [])
            .map_err(|e| format!("reset policy_deviations: {e}"))?;
        Ok(BehaviorResetResult {
            anomalies,
            baselines,
            observations,
            profiles,
            boosts,
            watermarks,
            policy_deviations,
        })
    }

    /// Delete all policy deviations.
    pub async fn delete_all_policy_deviations(&self) -> Result<usize, String> {
        let db = self.db.lock().await;
        db.execute("DELETE FROM policy_deviations", [])
            .map_err(|e| format!("delete all policy deviations failed: {e}"))
    }

    // ── Investigation methods ──

    pub async fn record_investigation(&self, inv: &NewInvestigation) -> Result<i64, String> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT OR REPLACE INTO investigations
                (anomaly_id, device_mac, device_hostname, device_manufacturer,
                 device_disposition, device_first_seen, device_baseline_status,
                 vlan_id, vlan_sensitivity,
                 dst_ip, dst_country, dst_city, dst_asn, dst_org,
                 dst_is_cdn, dst_reverse_dns, dst_seen_by_device_count,
                 anomaly_type, prior_anomaly_count_24h, prior_anomaly_count_7d,
                 same_pattern_count_24h, baseline_coverage_pct,
                 current_volume_bytes, baseline_volume_bytes, volume_ratio,
                 unique_destinations_1h, unique_ports_1h, other_devices_same_dest,
                 firewall_rule_id, firewall_action, firewall_rule_comment, firewall_correlation,
                 verdict, recommended_action, reason, summary, evidence_chain,
                 investigated_at, duration_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39)",
            params![
                inv.anomaly_id, inv.device_mac, inv.device_hostname, inv.device_manufacturer,
                inv.device_disposition, inv.device_first_seen, inv.device_baseline_status,
                inv.vlan_id, inv.vlan_sensitivity,
                inv.dst_ip, inv.dst_country, inv.dst_city, inv.dst_asn, inv.dst_org,
                inv.dst_is_cdn as i32, inv.dst_reverse_dns, inv.dst_seen_by_device_count,
                inv.anomaly_type, inv.prior_anomaly_count_24h, inv.prior_anomaly_count_7d,
                inv.same_pattern_count_24h, inv.baseline_coverage_pct,
                inv.current_volume_bytes, inv.baseline_volume_bytes, inv.volume_ratio,
                inv.unique_destinations_1h, inv.unique_ports_1h, inv.other_devices_same_dest,
                inv.firewall_rule_id, inv.firewall_action, inv.firewall_rule_comment, inv.firewall_correlation,
                inv.verdict, inv.recommended_action, inv.reason, inv.summary, inv.evidence_chain,
                inv.investigated_at, inv.duration_ms,
            ],
        )
        .map_err(|e| format!("record_investigation failed: {e}"))?;
        Ok(db.last_insert_rowid())
    }

    pub async fn get_investigation_by_anomaly(&self, anomaly_id: i64) -> Result<Option<Investigation>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT id, anomaly_id, device_mac, device_hostname, device_manufacturer,
                    device_disposition, device_first_seen, device_baseline_status,
                    vlan_id, vlan_sensitivity,
                    dst_ip, dst_country, dst_city, dst_asn, dst_org,
                    dst_is_cdn, dst_reverse_dns, dst_seen_by_device_count,
                    anomaly_type, prior_anomaly_count_24h, prior_anomaly_count_7d,
                    same_pattern_count_24h, baseline_coverage_pct,
                    current_volume_bytes, baseline_volume_bytes, volume_ratio,
                    unique_destinations_1h, unique_ports_1h, other_devices_same_dest,
                    firewall_rule_id, firewall_action, firewall_rule_comment, firewall_correlation,
                    verdict, recommended_action, reason, summary, evidence_chain,
                    investigated_at, duration_ms
             FROM investigations WHERE anomaly_id = ?1",
            params![anomaly_id],
            Self::map_investigation_row,
        )
        .optional()
        .map_err(|e| format!("get_investigation_by_anomaly failed: {e}"))
    }

    pub async fn get_investigations_by_device(
        &self,
        mac: &str,
        limit: i64,
    ) -> Result<Vec<Investigation>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT id, anomaly_id, device_mac, device_hostname, device_manufacturer,
                        device_disposition, device_first_seen, device_baseline_status,
                        vlan_id, vlan_sensitivity,
                        dst_ip, dst_country, dst_city, dst_asn, dst_org,
                        dst_is_cdn, dst_reverse_dns, dst_seen_by_device_count,
                        anomaly_type, prior_anomaly_count_24h, prior_anomaly_count_7d,
                        same_pattern_count_24h, baseline_coverage_pct,
                        current_volume_bytes, baseline_volume_bytes, volume_ratio,
                        unique_destinations_1h, unique_ports_1h, other_devices_same_dest,
                        firewall_rule_id, firewall_action, firewall_rule_comment, firewall_correlation,
                        verdict, recommended_action, reason, summary, evidence_chain,
                        investigated_at, duration_ms
                 FROM investigations WHERE device_mac = ?1 ORDER BY investigated_at DESC LIMIT ?2",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![mac, limit], Self::map_investigation_row)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect failed: {e}"))
    }

    pub async fn get_investigation_stats(&self, hours: i64) -> Result<InvestigationStats, String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - (hours * 3600);
        let mut stats = InvestigationStats {
            benign: 0,
            routine: 0,
            suspicious: 0,
            threat: 0,
            inconclusive: 0,
            total: 0,
        };
        let mut stmt = db
            .prepare("SELECT verdict, COUNT(*) FROM investigations WHERE investigated_at >= ?1 GROUP BY verdict")
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![cutoff], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| format!("query failed: {e}"))?;
        for row in rows {
            let (verdict, count) = row.map_err(|e| format!("row failed: {e}"))?;
            match verdict.as_str() {
                "benign" => stats.benign = count,
                "routine" => stats.routine = count,
                "suspicious" => stats.suspicious = count,
                "threat" => stats.threat = count,
                "inconclusive" => stats.inconclusive = count,
                _ => {}
            }
            stats.total += count;
        }
        Ok(stats)
    }

    /// Count anomaly dispositions (accepted/dismissed/flagged) in the last 7 days.
    pub async fn get_anomaly_disposition_counts_7d(&self) -> Result<(i64, i64, i64), String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - (7 * 24 * 3600);
        let mut accepted = 0i64;
        let mut dismissed = 0i64;
        let mut flagged = 0i64;
        let mut stmt = db
            .prepare("SELECT status, COUNT(*) FROM device_anomalies WHERE resolved_at >= ?1 AND status IN ('accepted', 'dismissed', 'flagged') GROUP BY status")
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![cutoff], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| format!("query failed: {e}"))?;
        for row in rows {
            let (status, count) = row.map_err(|e| format!("row failed: {e}"))?;
            match status.as_str() {
                "accepted" => accepted = count,
                "dismissed" => dismissed = count,
                "flagged" => flagged = count,
                _ => {}
            }
        }
        Ok((accepted, dismissed, flagged))
    }

    pub async fn get_investigations(
        &self,
        verdict: Option<&str>,
        mac: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Investigation>, String> {
        let db = self.db.lock().await;
        let mut sql = String::from(
            "SELECT id, anomaly_id, device_mac, device_hostname, device_manufacturer,
                    device_disposition, device_first_seen, device_baseline_status,
                    vlan_id, vlan_sensitivity,
                    dst_ip, dst_country, dst_city, dst_asn, dst_org,
                    dst_is_cdn, dst_reverse_dns, dst_seen_by_device_count,
                    anomaly_type, prior_anomaly_count_24h, prior_anomaly_count_7d,
                    same_pattern_count_24h, baseline_coverage_pct,
                    current_volume_bytes, baseline_volume_bytes, volume_ratio,
                    unique_destinations_1h, unique_ports_1h, other_devices_same_dest,
                    firewall_rule_id, firewall_action, firewall_rule_comment, firewall_correlation,
                    verdict, recommended_action, reason, summary, evidence_chain,
                    investigated_at, duration_ms
             FROM investigations WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(v) = verdict {
            param_values.push(Box::new(v.to_string()));
            sql.push_str(&format!(" AND verdict = ?{}", param_values.len()));
        }
        if let Some(m) = mac {
            param_values.push(Box::new(m.to_string()));
            sql.push_str(&format!(" AND device_mac = ?{}", param_values.len()));
        }
        sql.push_str(" ORDER BY investigated_at DESC");
        param_values.push(Box::new(limit));
        sql.push_str(&format!(" LIMIT ?{}", param_values.len()));
        param_values.push(Box::new(offset));
        sql.push_str(&format!(" OFFSET ?{}", param_values.len()));

        let mut stmt = db
            .prepare(&sql)
            .map_err(|e| format!("prepare failed: {e}"))?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_ref.as_slice(), Self::map_investigation_row)
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect failed: {e}"))
    }

    /// Count anomalies for a device within a time window.
    pub async fn count_anomalies_since(&self, mac: &str, since: i64) -> Result<i64, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT COUNT(*) FROM device_anomalies WHERE mac = ?1 AND timestamp >= ?2",
            params![mac, since],
            |row| row.get(0),
        )
        .map_err(|e| format!("count_anomalies_since failed: {e}"))
    }

    /// Count anomalies of the same type and pattern for a device within a time window.
    pub async fn count_same_pattern_anomalies(
        &self,
        mac: &str,
        anomaly_type: &str,
        since: i64,
    ) -> Result<i64, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT COUNT(*) FROM device_anomalies WHERE mac = ?1 AND anomaly_type = ?2 AND timestamp >= ?3",
            params![mac, anomaly_type, since],
            |row| row.get(0),
        )
        .map_err(|e| format!("count_same_pattern_anomalies failed: {e}"))
    }

    /// Count unique destinations a device has communicated with in a time window.
    pub async fn count_unique_destinations(&self, mac: &str, window_secs: i64) -> Result<i64, String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - window_secs;
        db.query_row(
            "SELECT COUNT(DISTINCT dst_subnet) FROM device_observations WHERE mac = ?1 AND timestamp >= ?2",
            params![mac, cutoff],
            |row| row.get(0),
        )
        .map_err(|e| format!("count_unique_destinations failed: {e}"))
    }

    /// Count unique destination ports a device has communicated with in a time window.
    pub async fn count_unique_ports(&self, mac: &str, window_secs: i64) -> Result<i64, String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - window_secs;
        db.query_row(
            "SELECT COUNT(DISTINCT dst_port) FROM device_observations WHERE mac = ?1 AND timestamp >= ?2 AND dst_port IS NOT NULL",
            params![mac, cutoff],
            |row| row.get(0),
        )
        .map_err(|e| format!("count_unique_ports failed: {e}"))
    }

    /// Count how many baselines a device has vs how many unique flows observed.
    pub async fn baseline_coverage(&self, mac: &str) -> Result<(i64, i64), String> {
        let db = self.db.lock().await;
        let baseline_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM device_baselines WHERE mac = ?1",
                params![mac],
                |row| row.get(0),
            )
            .map_err(|e| format!("baseline count failed: {e}"))?;
        let flow_count: i64 = db
            .query_row(
                "SELECT COUNT(DISTINCT protocol || ':' || COALESCE(dst_port, -1) || ':' || dst_subnet || ':' || direction)
                 FROM device_observations WHERE mac = ?1 AND timestamp >= ?2",
                params![mac, now_unix() - 7 * 86400],
                |row| row.get(0),
            )
            .map_err(|e| format!("flow count failed: {e}"))?;
        Ok((baseline_count, flow_count))
    }

    /// Get IDs of recent anomalies that haven't been investigated yet.
    /// Used by the investigation engine to find work.
    pub async fn get_uninvestigated_anomaly_ids(&self, since: i64) -> Result<Vec<i64>, String> {
        let db = self.db.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT a.id FROM device_anomalies a
                 LEFT JOIN investigations i ON i.anomaly_id = a.id
                 WHERE a.timestamp >= ?1
                   AND a.status = 'pending'
                   AND i.id IS NULL
                 ORDER BY a.timestamp ASC
                 LIMIT 100",
            )
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map(params![since], |row| row.get(0))
            .map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect failed: {e}"))
    }

    // ── WAN scan pressure methods ──

    /// Record a batch of WAN scan probes into the 5-minute pressure bucket.
    pub async fn record_wan_scan_probes(
        &self,
        probes: &[(String, u16, Option<String>)],  // (src_ip, dst_port, country_code)
    ) -> Result<(), String> {
        if probes.is_empty() { return Ok(()); }
        let db = self.db.lock().await;
        let now = now_unix();
        let bucket = now - (now % 300);  // 5-minute bucket

        let unique_sources: std::collections::HashSet<&str> = probes.iter().map(|(ip, _, _)| ip.as_str()).collect();
        let unique_ports: std::collections::HashSet<u16> = probes.iter().map(|(_, p, _)| *p).collect();

        // Count top ports
        let mut port_counts: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
        for (_, port, _) in probes {
            *port_counts.entry(*port).or_default() += 1;
        }
        let mut top_ports: Vec<_> = port_counts.into_iter().collect();
        top_ports.sort_by(|a, b| b.1.cmp(&a.1));
        top_ports.truncate(10);
        let top_ports_json = serde_json::to_string(&top_ports.iter().map(|(p, c)| serde_json::json!({"port": p, "count": c})).collect::<Vec<_>>()).unwrap_or_default();

        // Count top countries
        let mut country_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for (_, _, cc) in probes {
            if let Some(c) = cc.as_deref() {
                *country_counts.entry(c).or_default() += 1;
            }
        }
        let mut top_countries: Vec<_> = country_counts.into_iter().collect();
        top_countries.sort_by(|a, b| b.1.cmp(&a.1));
        top_countries.truncate(10);
        let top_countries_json = serde_json::to_string(&top_countries.iter().map(|(c, n)| serde_json::json!({"country": c, "count": n})).collect::<Vec<_>>()).unwrap_or_default();

        db.execute(
            "INSERT INTO wan_scan_pressure (bucket, total_probes, unique_sources, unique_ports, top_ports, top_countries)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(bucket) DO UPDATE SET
                total_probes = total_probes + ?2,
                unique_sources = MAX(unique_sources, ?3),
                unique_ports = MAX(unique_ports, ?4),
                top_ports = ?5,
                top_countries = ?6",
            params![
                bucket,
                probes.len() as i64,
                unique_sources.len() as i64,
                unique_ports.len() as i64,
                top_ports_json,
                top_countries_json,
            ],
        ).map_err(|e| format!("record_wan_scan_probes failed: {e}"))?;
        Ok(())
    }

    /// Check if a port is in the WAN sensitive ports list.
    pub async fn is_wan_sensitive_port(&self, port: u16, protocol: &str) -> Result<bool, String> {
        let db = self.db.lock().await;
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM wan_sensitive_ports WHERE port = ?1 AND protocol = ?2",
            params![port as i64, protocol],
            |row| row.get(0),
        ).map_err(|e| format!("is_wan_sensitive_port failed: {e}"))?;
        Ok(count > 0)
    }

    /// Get WAN scan pressure buckets for the last N hours.
    pub async fn get_wan_scan_pressure(&self, hours: i64) -> Result<Vec<WanScanBucket>, String> {
        let db = self.db.lock().await;
        let cutoff = now_unix() - (hours * 3600);
        let mut stmt = db.prepare(
            "SELECT bucket, total_probes, unique_sources, unique_ports, top_ports, top_countries
             FROM wan_scan_pressure WHERE bucket >= ?1 ORDER BY bucket ASC",
        ).map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt.query_map(params![cutoff], |row| {
            Ok(WanScanBucket {
                bucket: row.get(0)?,
                total_probes: row.get(1)?,
                unique_sources: row.get(2)?,
                unique_ports: row.get(3)?,
                top_ports: row.get(4)?,
                top_countries: row.get(5)?,
            })
        }).map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| format!("collect failed: {e}"))
    }


    // ── Policy Methods ──

    /// Upsert an infrastructure policy entry.
    pub async fn upsert_policy(
        &self,
        service: &str,
        protocol: Option<&str>,
        port: Option<i64>,
        authorized_targets: &[String],
        vlan_scope: Option<&[i64]>,
        source: &str,
        priority: &str,
        router_entity_id: Option<&str>,
    ) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let targets_json = serde_json::to_string(authorized_targets).unwrap_or_default();
        let vlan_json = vlan_scope
            .map(|v| {
                let mut sorted = v.to_vec();
                sorted.sort();
                serde_json::to_string(&sorted).unwrap_or_default()
            })
            .unwrap_or_else(|| "__global__".to_string());
        let is_admin = source == "admin_policy";
        db.execute(
            "INSERT INTO infrastructure_policy
                (service, protocol, port, authorized_targets, vlan_scope, source, priority, last_synced, router_entity_id, user_created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(service, protocol, port, vlan_scope) DO UPDATE SET
                authorized_targets = CASE WHEN user_created = 1 AND ?10 = 0 THEN authorized_targets ELSE ?4 END,
                source = CASE WHEN user_created = 1 AND ?10 = 0 THEN source ELSE ?6 END,
                priority = CASE WHEN user_created = 1 AND ?10 = 0 THEN priority ELSE ?7 END,
                last_synced = ?8,
                router_entity_id = CASE WHEN user_created = 1 AND ?10 = 0 THEN router_entity_id ELSE ?9 END,
                user_created = MAX(user_created, ?10)",
            params![service, protocol, port, targets_json, vlan_json, source, priority, now, router_entity_id, is_admin as i32],
        ).map_err(|e| format!("upsert_policy failed: {e}"))?;
        Ok(())
    }

    /// Get all policies for a given service+protocol+port, optionally filtered by VLAN.
    pub async fn get_policies_for_service(
        &self,
        service: &str,
        protocol: Option<&str>,
        port: Option<i64>,
        vlan: Option<i64>,
    ) -> Result<Vec<InfrastructurePolicy>, String> {
        let db = self.db.lock().await;
        let mut sql = String::from(
            "SELECT id, service, protocol, port, authorized_targets, vlan_scope, source, priority, last_synced, router_entity_id, user_created
             FROM infrastructure_policy WHERE service = ?1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        param_values.push(Box::new(service.to_string()));

        if let Some(p) = protocol {
            param_values.push(Box::new(p.to_string()));
            sql.push_str(&format!(" AND (protocol = ?{} OR protocol IS NULL)", param_values.len()));
        }
        if let Some(pt) = port {
            param_values.push(Box::new(pt));
            sql.push_str(&format!(" AND (port = ?{} OR port IS NULL)", param_values.len()));
        }

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let mut stmt = db.prepare(&sql).map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            let targets_str: String = row.get(4)?;
            let vlan_str: Option<String> = row.get(5)?;
            Ok(InfrastructurePolicy {
                id: row.get(0)?,
                service: row.get(1)?,
                protocol: row.get(2)?,
                port: row.get(3)?,
                authorized_targets: serde_json::from_str(&targets_str).unwrap_or_else(|e| {
                    tracing::warn!(targets = %targets_str, error = %e, "corrupt authorized_targets JSON in policy row, defaulting to empty");
                    Vec::new()
                }),
                vlan_scope: vlan_str
                    .filter(|s| s != "__global__")
                    .and_then(|s| serde_json::from_str(&s).map_err(|e| {
                        tracing::warn!(vlan_scope = %s, error = %e, "corrupt vlan_scope JSON in policy row, treating as global");
                        e
                    }).ok()),
                source: row.get(6)?,
                priority: row.get(7)?,
                last_synced: row.get(8)?,
                router_entity_id: row.get(9)?,
                user_created: row.get::<_, i32>(10).unwrap_or(0) != 0,
            })
        }).map_err(|e| format!("query failed: {e}"))?;

        let mut results: Vec<InfrastructurePolicy> = Vec::new();
        for row in rows {
            let policy = row.map_err(|e| format!("row error: {e}"))?;
            // Filter by VLAN if specified
            if let Some(v) = vlan {
                if let Some(ref scope) = policy.vlan_scope {
                    if !scope.contains(&v) {
                        continue;
                    }
                }
                // vlan_scope == None means global (all VLANs) — include it
            }
            results.push(policy);
        }
        Ok(results)
    }

    /// Check if a destination IP is authorized for a given service on a VLAN.
    /// Returns Some(policy) if authorized, None if not.
    pub async fn check_policy_authorization(
        &self,
        service: &str,
        protocol: Option<&str>,
        port: Option<i64>,
        vlan: Option<i64>,
        destination_ip: &str,
    ) -> Result<Option<InfrastructurePolicy>, String> {
        let policies = self.get_policies_for_service(service, protocol, port, vlan).await?;
        for policy in policies {
            for target in &policy.authorized_targets {
                if ip_matches_target(destination_ip, target) {
                    return Ok(Some(policy));
                }
            }
        }
        Ok(None)
    }

    /// Check if ANY policy exists for a given service+protocol+port.
    /// Used to determine if we should apply policy rules or fall through to behavioral rules.
    pub async fn has_policy_for_service(
        &self,
        service: &str,
        protocol: Option<&str>,
        port: Option<i64>,
    ) -> Result<bool, String> {
        let db = self.db.lock().await;
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM infrastructure_policy WHERE service = ?1 AND (protocol = ?2 OR protocol IS NULL) AND (port = ?3 OR port IS NULL)",
            params![service, protocol, port],
            |row| row.get(0),
        ).map_err(|e| format!("has_policy_for_service failed: {e}"))?;
        Ok(count > 0)
    }

    /// Get all policies (for display on the policy page).
    pub async fn get_all_policies(&self) -> Result<Vec<InfrastructurePolicy>, String> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT id, service, protocol, port, authorized_targets, vlan_scope, source, priority, last_synced, router_entity_id, user_created
             FROM infrastructure_policy ORDER BY service, port",
        ).map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt.query_map([], |row| {
            let targets_str: String = row.get(4)?;
            let vlan_str: Option<String> = row.get(5)?;
            Ok(InfrastructurePolicy {
                id: row.get(0)?,
                service: row.get(1)?,
                protocol: row.get(2)?,
                port: row.get(3)?,
                authorized_targets: serde_json::from_str(&targets_str).unwrap_or_else(|e| {
                    tracing::warn!(targets = %targets_str, error = %e, "corrupt authorized_targets JSON in policy row, defaulting to empty");
                    Vec::new()
                }),
                vlan_scope: vlan_str
                    .filter(|s| s != "__global__")
                    .and_then(|s| serde_json::from_str(&s).map_err(|e| {
                        tracing::warn!(vlan_scope = %s, error = %e, "corrupt vlan_scope JSON in policy row, treating as global");
                        e
                    }).ok()),
                source: row.get(6)?,
                priority: row.get(7)?,
                last_synced: row.get(8)?,
                router_entity_id: row.get(9)?,
                user_created: row.get::<_, i32>(10).unwrap_or(0) != 0,
            })
        }).map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| format!("collect failed: {e}"))
    }

    /// Get a single policy by ID.
    pub async fn get_policy_by_id(&self, id: i64) -> Result<Option<InfrastructurePolicy>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT id, service, protocol, port, authorized_targets, vlan_scope, source, priority, last_synced, router_entity_id, user_created
             FROM infrastructure_policy WHERE id = ?1",
            params![id],
            |row| {
                let targets_str: String = row.get(4)?;
                let vlan_str: Option<String> = row.get(5)?;
                Ok(InfrastructurePolicy {
                    id: row.get(0)?,
                    service: row.get(1)?,
                    protocol: row.get(2)?,
                    port: row.get(3)?,
                    authorized_targets: serde_json::from_str(&targets_str).unwrap_or_default(),
                    vlan_scope: vlan_str
                        .filter(|s| s != "__global__")
                        .and_then(|s| serde_json::from_str(&s).ok()),
                    source: row.get(6)?,
                    priority: row.get(7)?,
                    last_synced: row.get(8)?,
                    router_entity_id: row.get(9)?,
                    user_created: row.get::<_, i32>(10).unwrap_or(0) != 0,
                })
            },
        )
        .optional()
        .map_err(|e| format!("get_policy_by_id failed: {e}"))
    }

    /// Create an admin policy (user_created = 1, protected from stale reaper).
    pub async fn create_admin_policy(
        &self,
        service: &str,
        protocol: Option<&str>,
        port: Option<i64>,
        authorized_targets: &[String],
        vlan_scope: Option<&[i64]>,
        priority: &str,
    ) -> Result<i64, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let targets_json = serde_json::to_string(authorized_targets).unwrap_or_default();
        let vlan_json = vlan_scope
            .map(|v| {
                let mut sorted = v.to_vec();
                sorted.sort();
                serde_json::to_string(&sorted).unwrap_or_default()
            })
            .unwrap_or_else(|| "__global__".to_string());
        db.execute(
            "INSERT INTO infrastructure_policy
                (service, protocol, port, authorized_targets, vlan_scope, source, priority, last_synced, user_created)
             VALUES (?1, ?2, ?3, ?4, ?5, 'admin_policy', ?6, ?7, 1)",
            params![service, protocol, port, targets_json, vlan_json, priority, now],
        ).map_err(|e| {
            if e.to_string().contains("UNIQUE constraint") {
                "policy with same service/protocol/port/vlan already exists".to_string()
            } else {
                format!("create_admin_policy failed: {e}")
            }
        })?;
        Ok(db.last_insert_rowid())
    }

    /// Update an admin policy. Returns error if the policy is router-synced (user_created = 0).
    pub async fn update_admin_policy(
        &self,
        id: i64,
        authorized_targets: &[String],
        vlan_scope: Option<&[i64]>,
        priority: &str,
    ) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let targets_json = serde_json::to_string(authorized_targets).unwrap_or_default();
        let vlan_json = vlan_scope
            .map(|v| {
                let mut sorted = v.to_vec();
                sorted.sort();
                serde_json::to_string(&sorted).unwrap_or_default()
            })
            .unwrap_or_else(|| "__global__".to_string());
        let updated = db.execute(
            "UPDATE infrastructure_policy
             SET authorized_targets = ?1, vlan_scope = ?2, priority = ?3, last_synced = ?4
             WHERE id = ?5 AND user_created = 1",
            params![targets_json, vlan_json, priority, now, id],
        ).map_err(|e| format!("update_admin_policy failed: {e}"))?;
        if updated == 0 {
            return Err("policy not found or is router-synced (not editable)".to_string());
        }
        Ok(())
    }

    /// Delete an admin policy. Returns error if the policy is router-synced (user_created = 0).
    pub async fn delete_admin_policy(&self, id: i64) -> Result<(), String> {
        let db = self.db.lock().await;
        let deleted = db.execute(
            "DELETE FROM infrastructure_policy WHERE id = ?1 AND user_created = 1",
            params![id],
        ).map_err(|e| format!("delete_admin_policy failed: {e}"))?;
        if deleted == 0 {
            return Err("policy not found or is router-synced (not deletable)".to_string());
        }
        Ok(())
    }

    /// Upsert a firewall ION tag.
    pub async fn upsert_ion_tag(
        &self,
        rule_id: &str,
        chain: &str,
        action: &str,
        tag: &str,
        comment: &str,
        rule_summary: &str,
    ) -> Result<(), String> {
        let db = self.db.lock().await;
        let now = now_unix();
        db.execute(
            "INSERT INTO firewall_ion_tags (rule_id, chain, action, tag, comment, rule_summary, last_synced)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(rule_id) DO UPDATE SET
                chain = ?2, action = ?3, tag = ?4, comment = ?5, rule_summary = ?6, last_synced = ?7",
            params![rule_id, chain, action, tag, comment, rule_summary, now],
        ).map_err(|e| format!("upsert_ion_tag failed: {e}"))?;
        Ok(())
    }

    /// Get all ION tags.
    pub async fn get_ion_tags(&self) -> Result<Vec<FirewallIonTag>, String> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT rule_id, chain, action, tag, comment, rule_summary, last_synced FROM firewall_ion_tags",
        ).map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt.query_map([], |row| {
            Ok(FirewallIonTag {
                rule_id: row.get(0)?,
                chain: row.get(1)?,
                action: row.get(2)?,
                tag: row.get(3)?,
                comment: row.get(4)?,
                rule_summary: row.get(5)?,
                last_synced: row.get(6)?,
            })
        }).map_err(|e| format!("query failed: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| format!("collect failed: {e}"))
    }

    /// Get the ION tag for a specific firewall rule.
    pub async fn get_ion_tag_for_rule(&self, rule_id: &str) -> Result<Option<FirewallIonTag>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT rule_id, chain, action, tag, comment, rule_summary, last_synced FROM firewall_ion_tags WHERE rule_id = ?1",
            params![rule_id],
            |row| Ok(FirewallIonTag {
                rule_id: row.get(0)?,
                chain: row.get(1)?,
                action: row.get(2)?,
                tag: row.get(3)?,
                comment: row.get(4)?,
                rule_summary: row.get(5)?,
                last_synced: row.get(6)?,
            }),
        ).optional().map_err(|e| format!("get_ion_tag_for_rule failed: {e}"))
    }

    /// Remove stale policies not updated in the latest sync.
    /// Admin policies (user_created = 1) are never reaped — only router-synced policies are cleaned up.
    pub async fn remove_stale_policies(&self, sync_cutoff: i64) -> Result<usize, String> {
        let db = self.db.lock().await;
        let deleted = db.execute(
            "DELETE FROM infrastructure_policy WHERE user_created = 0 AND last_synced < ?1",
            params![sync_cutoff],
        ).map_err(|e| format!("remove_stale_policies failed: {e}"))?;
        Ok(deleted)
    }

    /// Remove stale ION tags not updated in the latest sync.
    pub async fn remove_stale_ion_tags(&self, sync_cutoff: i64) -> Result<usize, String> {
        let db = self.db.lock().await;
        let deleted = db.execute(
            "DELETE FROM firewall_ion_tags WHERE last_synced < ?1",
            params![sync_cutoff],
        ).map_err(|e| format!("remove_stale_ion_tags failed: {e}"))?;
        Ok(deleted)
    }

    // ── Policy Deviation Methods ──

    /// Record a policy deviation. Upserts: if the same (mac, type, actual) exists, increment count + update last_seen.
    pub async fn record_policy_deviation(&self, dev: &NewPolicyDeviation) -> Result<i64, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let techniques_json = serde_json::to_string(&dev.attack_techniques).unwrap_or_else(|_| "[]".to_string());

        // Try insert; on conflict update count and last_seen
        let classification_str = dev.classification.as_str();
        let observed_from_str = dev.observed_from.as_str();
        let changed = db.execute(
            "INSERT INTO policy_deviations
                (mac_address, ip_address, vlan, deviation_type, expected, actual, policy_source,
                 attack_techniques, severity, status, first_seen, last_seen, occurrence_count,
                 service, protocol, port, policy_id, classification, observed_from)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'new', ?10, ?10, 1,
                     ?11, ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT(mac_address, deviation_type, actual) DO UPDATE SET
                last_seen = ?10,
                occurrence_count = occurrence_count + 1,
                ip_address = ?2,
                expected = ?5,
                severity = CASE WHEN ?9 = 'warning' AND severity = 'informational' THEN 'warning' ELSE severity END,
                status = CASE WHEN status = 'resolved' THEN 'new' ELSE status END,
                resolved_at = CASE WHEN status = 'resolved' THEN NULL ELSE resolved_at END,
                resolved_by = CASE WHEN status = 'resolved' THEN NULL ELSE resolved_by END",
            params![
                dev.mac_address, dev.ip_address, dev.vlan, dev.deviation_type,
                dev.expected, dev.actual, dev.policy_source, techniques_json,
                dev.severity, now,
                dev.service, dev.protocol, dev.port, dev.policy_id,
                classification_str, observed_from_str
            ],
        ).map_err(|e| format!("record_policy_deviation failed: {e}"))?;

        if changed > 0 {
            let id: i64 = db.query_row(
                "SELECT id FROM policy_deviations WHERE mac_address = ?1 AND deviation_type = ?2 AND actual = ?3",
                params![dev.mac_address, dev.deviation_type, dev.actual],
                |row| row.get(0),
            ).map_err(|e| format!("get deviation id: {e}"))?;
            Ok(id)
        } else {
            Ok(0)
        }
    }

    /// Get policy deviations with optional filters.
    pub async fn get_policy_deviations(
        &self,
        status: Option<&str>,
        mac: Option<&str>,
        deviation_type: Option<&str>,
        limit: Option<i64>,
    ) -> Result<(Vec<PolicyDeviation>, i64), String> {
        let db = self.db.lock().await;
        let mut where_clause = String::from(" WHERE 1=1");
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(s) = status {
            param_values.push(Box::new(s.to_string()));
            where_clause.push_str(&format!(" AND status = ?{}", param_values.len()));
        } else {
            // By default, hide resolved and dismissed deviations.
            // Resolved = policy action taken (authorize/flag all). Dismissed = user chose to ignore.
            // Pass status explicitly to query specific states.
            where_clause.push_str(" AND status NOT IN ('dismissed', 'resolved')");
        }
        if let Some(m) = mac {
            param_values.push(Box::new(m.to_string()));
            where_clause.push_str(&format!(" AND mac_address = ?{}", param_values.len()));
        }
        if let Some(dt) = deviation_type {
            param_values.push(Box::new(dt.to_string()));
            where_clause.push_str(&format!(" AND deviation_type = ?{}", param_values.len()));
        }

        // Count total matching rows (before LIMIT)
        let count_sql = format!("SELECT COUNT(*) FROM policy_deviations{where_clause}");
        let count_params: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let total_count: i64 = db.query_row(&count_sql, count_params.as_slice(), |row| row.get(0))
            .unwrap_or(0);

        let mut sql = format!(
            "SELECT id, mac_address, ip_address, vlan, deviation_type, expected, actual,
                    policy_source, attack_techniques, severity, status,
                    first_seen, last_seen, occurrence_count, resolved_at, resolved_by,
                    classification, observed_from, service, protocol, port, policy_id
             FROM policy_deviations{where_clause} ORDER BY last_seen DESC",
        );

        if let Some(lim) = limit {
            param_values.push(Box::new(lim));
            sql.push_str(&format!(" LIMIT ?{}", param_values.len()));
        }

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let mut stmt = db.prepare(&sql).map_err(|e| format!("prepare deviations: {e}"))?;
        let rows = stmt.query_map(params_ref.as_slice(), Self::map_deviation_row)
            .map_err(|e| format!("query deviations: {e}"))?;
        let deviations = rows.collect::<Result<Vec<_>, _>>().map_err(|e| format!("collect deviations: {e}"))?;
        Ok((deviations, total_count))
    }

    /// Get deviations for a specific device MAC.
    pub async fn get_device_policy_deviations(&self, mac: &str) -> Result<Vec<PolicyDeviation>, String> {
        self.get_policy_deviations(None, Some(mac), None, None).await.map(|(devs, _)| devs)
    }

    /// Resolve a deviation by ID with a status and optional resolver name.
    pub async fn resolve_policy_deviation(
        &self,
        id: i64,
        status: &str,
        resolved_by: Option<&str>,
    ) -> Result<bool, String> {
        let db = self.db.lock().await;
        let now = now_unix();
        let changed = db.execute(
            "UPDATE policy_deviations SET status = ?1, resolved_at = ?2, resolved_by = ?3 WHERE id = ?4",
            params![status, now, resolved_by, id],
        ).map_err(|e| format!("resolve_policy_deviation: {e}"))?;
        Ok(changed > 0)
    }

    /// Get summary counts of deviations by status.
    pub async fn policy_deviation_counts(&self) -> Result<PolicyDeviationCounts, String> {
        let db = self.db.lock().await;
        let mut counts = PolicyDeviationCounts::default();

        counts.total = db.query_row(
            "SELECT COUNT(*) FROM policy_deviations WHERE status != 'dismissed'", [], |row| row.get(0),
        ).unwrap_or(0);
        counts.new = db.query_row(
            "SELECT COUNT(*) FROM policy_deviations WHERE status = 'new'", [], |row| row.get(0),
        ).unwrap_or(0);
        counts.acknowledged = db.query_row(
            "SELECT COUNT(*) FROM policy_deviations WHERE status = 'acknowledged'", [], |row| row.get(0),
        ).unwrap_or(0);
        counts.resolved = db.query_row(
            "SELECT COUNT(*) FROM policy_deviations WHERE status = 'resolved'", [], |row| row.get(0),
        ).unwrap_or(0);
        counts.dns = db.query_row(
            "SELECT COUNT(*) FROM policy_deviations WHERE deviation_type LIKE 'dns%'", [], |row| row.get(0),
        ).unwrap_or(0);
        counts.ntp = db.query_row(
            "SELECT COUNT(*) FROM policy_deviations WHERE deviation_type LIKE 'ntp%'", [], |row| row.get(0),
        ).unwrap_or(0);
        counts.gateway = db.query_row(
            "SELECT COUNT(*) FROM policy_deviations WHERE deviation_type LIKE 'gateway%'", [], |row| row.get(0),
        ).unwrap_or(0);

        Ok(counts)
    }

    /// Get a single policy deviation by ID.
    pub async fn get_policy_deviation(&self, id: i64) -> Result<Option<PolicyDeviation>, String> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT id, mac_address, ip_address, vlan, deviation_type, expected, actual,
                    policy_source, attack_techniques, severity, status,
                    first_seen, last_seen, occurrence_count, resolved_at, resolved_by,
                    classification, observed_from, service, protocol, port, policy_id
             FROM policy_deviations WHERE id = ?1",
            params![id],
            Self::map_deviation_row,
        ).optional().map_err(|e| format!("get_policy_deviation: {e}"))
    }

    fn map_deviation_row(row: &rusqlite::Row) -> rusqlite::Result<PolicyDeviation> {
        let techniques_str: String = row.get(8)?;
        let classification_str: String = row.get(16).unwrap_or_else(|_| "authoritative".to_string());
        let observed_from_str: String = row.get(17).unwrap_or_else(|_| "router".to_string());
        Ok(PolicyDeviation {
            id: row.get(0)?,
            mac_address: row.get(1)?,
            ip_address: row.get(2)?,
            vlan: row.get(3)?,
            deviation_type: row.get(4)?,
            expected: row.get(5)?,
            actual: row.get(6)?,
            policy_source: row.get(7)?,
            attack_techniques: serde_json::from_str(&techniques_str).unwrap_or_default(),
            severity: row.get(9)?,
            status: row.get(10)?,
            first_seen: row.get(11)?,
            last_seen: row.get(12)?,
            occurrence_count: row.get(13)?,
            resolved_at: row.get(14)?,
            resolved_by: row.get(15)?,
            service: row.get(18).unwrap_or_default(),
            protocol: row.get(19).unwrap_or_default(),
            port: row.get(20).unwrap_or_default(),
            policy_id: row.get(21).unwrap_or_default(),
            classification: DataClassification::from_str_lossy(&classification_str),
            observed_from: SourceTier::from_str_lossy(&observed_from_str),
        })
    }

    /// Update the tier of an anomaly (called after investigation determines the tier).
    pub async fn update_anomaly_tier(&self, anomaly_id: i64, tier: i32) -> Result<(), String> {
        let db = self.db.lock().await;
        db.execute(
            "UPDATE device_anomalies SET tier = ?1 WHERE id = ?2",
            params![tier, anomaly_id],
        ).map_err(|e| format!("update_anomaly_tier failed: {e}"))?;
        Ok(())
    }

    // ── Row mappers ──

    fn map_anomaly_row(row: &rusqlite::Row) -> rusqlite::Result<DeviceAnomaly> {
        Ok(DeviceAnomaly {
            id: row.get(0)?,
            mac: row.get(1)?,
            timestamp: row.get(2)?,
            anomaly_type: row.get(3)?,
            severity: row.get(4)?,
            confidence: row.get(5)?,
            description: row.get(6)?,
            details: row.get(7)?,
            vlan: row.get(8)?,
            firewall_correlation: row.get(9)?,
            firewall_rule_id: row.get(10)?,
            firewall_rule_comment: row.get(11)?,
            status: row.get(12)?,
            resolved_at: row.get(13)?,
            resolved_by: row.get(14)?,
            tier: row.get(15)?,
            dedup_key: row.get(16)?,
            occurrence_count: row.get(17)?,
            last_occurrence: row.get(18)?,
        })
    }

    fn map_investigation_row(row: &rusqlite::Row) -> rusqlite::Result<Investigation> {
        Ok(Investigation {
            id: row.get(0)?,
            anomaly_id: row.get(1)?,
            device_mac: row.get(2)?,
            device_hostname: row.get(3)?,
            device_manufacturer: row.get(4)?,
            device_disposition: row.get(5)?,
            device_first_seen: row.get(6)?,
            device_baseline_status: row.get(7)?,
            vlan_id: row.get(8)?,
            vlan_sensitivity: row.get(9)?,
            dst_ip: row.get(10)?,
            dst_country: row.get(11)?,
            dst_city: row.get(12)?,
            dst_asn: row.get(13)?,
            dst_org: row.get(14)?,
            dst_is_cdn: row.get::<_, i32>(15)? != 0,
            dst_reverse_dns: row.get(16)?,
            dst_seen_by_device_count: row.get(17)?,
            anomaly_type: row.get(18)?,
            prior_anomaly_count_24h: row.get(19)?,
            prior_anomaly_count_7d: row.get(20)?,
            same_pattern_count_24h: row.get(21)?,
            baseline_coverage_pct: row.get(22)?,
            current_volume_bytes: row.get(23)?,
            baseline_volume_bytes: row.get(24)?,
            volume_ratio: row.get(25)?,
            unique_destinations_1h: row.get(26)?,
            unique_ports_1h: row.get(27)?,
            other_devices_same_dest: row.get(28)?,
            firewall_rule_id: row.get(29)?,
            firewall_action: row.get(30)?,
            firewall_rule_comment: row.get(31)?,
            firewall_correlation: row.get(32)?,
            verdict: row.get(33)?,
            recommended_action: row.get(34)?,
            reason: row.get(35)?,
            summary: row.get(36)?,
            evidence_chain: row.get(37)?,
            investigated_at: row.get(38)?,
            duration_ms: row.get(39)?,
        })
    }

    /// Add a WAN sensitive port if it does not already exist.
    pub async fn add_wan_sensitive_port_if_missing(
        &self,
        port: u16,
        protocol: &str,
        service_name: &str,
    ) -> Result<(), String> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT OR IGNORE INTO wan_sensitive_ports (port, protocol, service_name, source) VALUES (?1, ?2, ?3, 'auto')",
            params![port as i64, protocol, service_name],
        ).map_err(|e| format!("add_wan_sensitive_port_if_missing failed: {e}"))?;
        Ok(())
    }
}

/// Check if an IP address matches a target (exact IP or CIDR notation).
/// Check if an IP matches a target (exact match or CIDR).
pub fn ip_matches_target(ip: &str, target: &str) -> bool {
    if ip == target {
        return true;
    }
    // CIDR match
    if let Some(slash_pos) = target.find('/') {
        let network = &target[..slash_pos];
        let prefix_len: u32 = match target[slash_pos + 1..].parse() {
            Ok(p) => p,
            Err(_) => return false,
        };
        if prefix_len > 32 {
            return false;
        }
        let net_octets: Vec<u8> = network.split('.').filter_map(|o| o.parse().ok()).collect();
        let ip_octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
        if net_octets.len() != 4 || ip_octets.len() != 4 {
            return false;
        }
        let net_u32 = u32::from_be_bytes([net_octets[0], net_octets[1], net_octets[2], net_octets[3]]);
        let ip_u32 = u32::from_be_bytes([ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]]);
        let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
        return (net_u32 & mask) == (ip_u32 & mask);
    }
    false
}

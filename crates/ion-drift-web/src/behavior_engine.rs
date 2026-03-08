//! Behavioral fingerprinting engine.
//!
//! Collects device observations from the router's connection table,
//! detects anomalies against learned baselines, and correlates with
//! firewall rules.

use std::collections::HashMap;

use ion_drift_storage::behavior::{
    self, BehaviorStore, DeviceObservation, NewAnomaly, VlanRegistry, compute_confidence,
};
use mikrotik_core::MikrotikClient;
use mikrotik_core::resources::firewall::FilterRule;
use tokio::sync::RwLock;

use crate::geo::GeoCache;
use crate::log_parser;
use crate::oui::OuiDb;

/// In-memory tracker for volume spike candidates.
/// Requires 2 consecutive detections (2 × 60s cycles = 2 min) before firing.
#[derive(Default)]
pub struct SpikeCandidates {
    /// Map of (mac, dedup_key) → consecutive detection count.
    candidates: std::sync::Mutex<HashMap<(String, String), u32>>,
}

impl SpikeCandidates {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear a candidate (spike was not detected this cycle).
    fn clear(&self, mac: &str, dedup_key: &str) {
        let mut map = self.candidates.lock().unwrap();
        map.remove(&(mac.to_string(), dedup_key.to_string()));
    }

    /// Prune all candidates (called periodically to avoid memory growth).
    pub fn prune(&self) {
        let mut map = self.candidates.lock().unwrap();
        map.clear();
    }
}

/// Normalize RouterOS protocol numbers to names.
fn normalize_protocol(proto: &str) -> &'static str {
    match proto {
        "6" | "tcp" => "tcp",
        "17" | "udp" => "udp",
        "1" | "icmp" => "icmp",
        _ => "other",
    }
}

fn has_policy_match(outcome: &str) -> bool {
    outcome != "policy_unknown"
}

fn classify_traffic_class(direction: &str, protocol: &str, dst_port: Option<i64>) -> &'static str {
    let is_dhcp = matches!(dst_port, Some(67 | 68));
    if is_dhcp {
        return "dhcp_activity";
    }
    let is_management_port = matches!(
        dst_port,
        Some(22 | 23 | 161 | 162 | 443 | 8291 | 8728 | 8729)
    );
    if is_management_port {
        return "management_protocol";
    }

    match direction {
        "inbound" => "internet_scan",
        "lateral" => {
            if matches!(dst_port, Some(22 | 23 | 445 | 3389)) {
                "lateral_movement"
            } else {
                "internal_service_access"
            }
        }
        "internal" => {
            if protocol == "arp" {
                "broadcast_service"
            } else {
                "internal_service_access"
            }
        }
        "outbound" => "external_service_access",
        _ => "unknown",
    }
}

fn zone_from_vlan_name(vlan_name: &str) -> &'static str {
    let n = vlan_name.to_ascii_lowercase();
    if n.contains("guest") {
        "Guest"
    } else if n.contains("iot") {
        "IoT"
    } else if n.contains("service") || n.contains("server") {
        "Services"
    } else if n.contains("manage") || n.contains("admin") {
        "Management"
    } else if n.contains("infra") {
        "Infrastructure"
    } else {
        "Trusted"
    }
}

fn zone_from_vlan(registry: &VlanRegistry, vlan: Option<i64>, ip: &str) -> String {
    if !registry.is_internal_ip(ip) {
        return "WAN".to_string();
    }
    if let Some(v) = vlan {
        let vlan_name = registry.vlan_name(v);
        return zone_from_vlan_name(&vlan_name).to_string();
    }
    "Trusted".to_string()
}

fn escalate_severity(base: &str, boost: i64) -> String {
    let steps = boost.max(0) as usize;
    let mut idx = match base {
        "info" => 0usize,
        "warning" => 1usize,
        "alert" => 2usize,
        "critical" => 3usize,
        _ => 0usize,
    };
    idx = (idx + steps).min(3);
    match idx {
        0 => "info".to_string(),
        1 => "warning".to_string(),
        2 => "alert".to_string(),
        _ => "critical".to_string(),
    }
}

/// Classify IP to VLAN: known VLAN → that VLAN, external → -1, unknown internal → 0.
fn classify_vlan(registry: &VlanRegistry, ip: &str) -> i64 {
    match registry.ip_to_vlan(ip) {
        Some(v) => v as i64,
        None if !registry.is_internal_ip(ip) => -1, // WAN / External
        None => 0,                                  // Unclassified internal
    }
}

// ── Observation Collection ───────────────────────────────────

/// Collect device observations from ARP + DHCP + connection tracking.
/// Called every 60 seconds.
pub async fn collect_observations(
    client: &MikrotikClient,
    store: &BehaviorStore,
    oui_db: &OuiDb,
    registry: &VlanRegistry,
) -> Result<usize, String> {
    // Fetch ARP + DHCP concurrently
    let (arp_result, dhcp_result) = tokio::join!(client.arp_table(), client.dhcp_leases(),);
    let arp_entries = arp_result.map_err(|e| format!("ARP fetch failed: {e}"))?;
    let dhcp_leases = dhcp_result.map_err(|e| format!("DHCP fetch failed: {e}"))?;

    // Build IP→MAC and IP→hostname maps
    let mut ip_to_mac: HashMap<String, String> = HashMap::new();
    let mut ip_to_hostname: HashMap<String, String> = HashMap::new();

    for lease in &dhcp_leases {
        if let Some(ref mac) = lease.mac_address {
            ip_to_mac.insert(lease.address.clone(), mac.to_uppercase());
            if let Some(ref hostname) = lease.host_name {
                ip_to_hostname.insert(lease.address.clone(), hostname.clone());
            }
        }
    }
    for arp in &arp_entries {
        if let Some(ref mac) = arp.mac_address {
            ip_to_mac
                .entry(arp.address.clone())
                .or_insert_with(|| mac.to_uppercase());
        }
    }

    // Upsert device profiles for all known devices
    for (ip, mac) in &ip_to_mac {
        let hostname = ip_to_hostname.get(ip).map(|s| s.as_str());
        let manufacturer = oui_db.lookup(mac).map(|s| s.to_string());
        let vlan = classify_vlan(registry, ip);
        if let Err(e) = store
            .upsert_profile(mac, hostname, manufacturer.as_deref(), ip, vlan)
            .await
        {
            tracing::debug!(mac, error = %e, "profile upsert failed");
        }
    }

    // Fetch connection tracking
    let connections = client
        .firewall_connections_full()
        .await
        .map_err(|e| format!("connections fetch failed: {e}"))?;

    let now = behavior::BehaviorStore::now_unix_pub();

    // Group connections by source MAC
    let mut observations: HashMap<
        String,
        HashMap<(String, Option<i64>, String, String), (i64, i64, i64)>,
    > = HashMap::new();

    for conn in &connections {
        let src_addr = match conn.src_address.as_deref() {
            Some(a) => a,
            None => continue,
        };
        let dst_addr = match conn.dst_address.as_deref() {
            Some(a) => a,
            None => continue,
        };

        let src_ip = src_addr;
        let dst_ip = dst_addr;
        let dst_port: Option<u16> = conn.dst_port.as_deref().and_then(|p| p.parse().ok());

        // Look up source MAC
        let mac = match ip_to_mac.get(src_ip) {
            Some(m) => m.clone(),
            None => continue,
        };

        let protocol = conn
            .protocol
            .as_deref()
            .map(normalize_protocol)
            .unwrap_or("other")
            .to_string();

        let dst_subnet = registry.classify_destination(dst_ip);
        let direction = registry.classify_direction(src_ip, dst_ip).to_string();
        let dst_port_val = dst_port.map(|p| p as i64);

        let key = (protocol, dst_port_val, dst_subnet, direction);
        let entry = observations
            .entry(mac)
            .or_default()
            .entry(key)
            .or_insert((0, 0, 0));
        entry.0 += conn.orig_bytes.unwrap_or(0) as i64;
        entry.1 += conn.repl_bytes.unwrap_or(0) as i64;
        entry.2 += 1;
    }

    // Convert to DeviceObservation records
    let mut obs_records: Vec<DeviceObservation> = Vec::new();
    for (mac, flows) in &observations {
        let ip = ip_to_mac
            .iter()
            .find(|(_, m)| *m == mac)
            .map(|(ip, _)| ip.clone())
            .unwrap_or_default();
        let vlan = classify_vlan(registry, &ip);

        for ((protocol, dst_port, dst_subnet, direction), (bytes_sent, bytes_recv, conn_count)) in
            flows
        {
            obs_records.push(DeviceObservation {
                mac: mac.clone(),
                timestamp: now,
                ip: ip.clone(),
                vlan,
                protocol: protocol.clone(),
                dst_port: *dst_port,
                dst_subnet: dst_subnet.clone(),
                direction: direction.clone(),
                bytes_sent: *bytes_sent,
                bytes_recv: *bytes_recv,
                connection_count: *conn_count,
            });
        }
    }

    let count = obs_records.len();
    if !obs_records.is_empty() {
        store.record_observations(&obs_records).await?;
    }
    Ok(count)
}

// ── Anomaly Detection ────────────────────────────────────────

/// Detect anomalies for baselined and sparse devices.
/// Called after each observation collection.
pub async fn detect_anomalies(
    store: &BehaviorStore,
    spike_candidates: &SpikeCandidates,
    registry: &VlanRegistry,
    firewall_rules: &[FilterRule],
) -> Result<usize, String> {
    let profiles = store.get_all_profiles().await?;
    let mut anomaly_count = 0;

    for profile in &profiles {
        // Detect on both baselined and sparse devices
        if profile.baseline_status != "baselined" && profile.baseline_status != "sparse" {
            continue;
        }

        let baselines = store.get_baselines(&profile.mac).await?;
        if baselines.is_empty() {
            continue;
        }

        // Build baseline lookup
        let baseline_map: HashMap<
            (String, Option<i64>, String, String),
            &ion_drift_storage::behavior::DeviceBaseline,
        > = baselines
            .iter()
            .map(|b| {
                (
                    (
                        b.protocol.clone(),
                        b.dst_port,
                        b.dst_subnet.clone(),
                        b.direction.clone(),
                    ),
                    b,
                )
            })
            .collect();

        // Get last 120s of observations
        let recent_obs = store.get_observations(&profile.mac, 120).await?;
        let vlan = profile.current_vlan.unwrap_or(0);

        // Fetch baseline stats for confidence scoring
        let (total_obs_count, earliest_computed) = store.get_baseline_stats(&profile.mac).await?;
        let baseline_age_days = if earliest_computed > 0 {
            (BehaviorStore::now_unix_pub() - earliest_computed) as f64 / 86400.0
        } else {
            0.0
        };
        let vlan_sens = registry.sensitivity(if vlan >= 0 { vlan as u16 } else { 0 });

        // Absolute byte floor for volume spikes: 5 MB/hr projected
        const VOLUME_SPIKE_FLOOR: f64 = 5_000_000.0;

        for obs in &recent_obs {
            let key = (
                obs.protocol.clone(),
                obs.dst_port,
                obs.dst_subnet.clone(),
                obs.direction.clone(),
            );

            if let Some(baseline) = baseline_map.get(&key) {
                // Check volume spike with hardened logic:
                // 1. Absolute floor: projected hourly > 5 MB
                // 2. Exceeds max * 3.0 AND avg * 5.0
                // 3. Multi-window persistence: at least 2 elevated observations in last 5 minutes
                let total_bytes = (obs.bytes_sent + obs.bytes_recv) as f64;
                let hourly_projected = total_bytes * 60.0; // 60s observation → hourly

                let exceeds_max = baseline.max_bytes_per_hour > 0.0
                    && hourly_projected > baseline.max_bytes_per_hour * 3.0;
                let exceeds_avg = baseline.avg_bytes_per_hour > 0.0
                    && hourly_projected > baseline.avg_bytes_per_hour * 5.0;
                let above_floor = hourly_projected > VOLUME_SPIKE_FLOOR;

                let dedup_key = format!("{}:{}", obs.dst_subnet, obs.dst_port.unwrap_or(-1));
                if above_floor && exceeds_max && exceeds_avg {
                    // Multi-window persistence: require at least 2 elevated
                    // observations in the last 5 minutes (300s)
                    let elevated_count = store
                        .count_elevated_observations(
                            &profile.mac,
                            &obs.protocol,
                            obs.dst_port,
                            &obs.dst_subnet,
                            &obs.direction,
                            baseline.max_bytes_per_hour * 3.0,
                            300,
                        )
                        .await?;

                    if elevated_count >= 2 {
                        if !store
                            .has_recent_anomaly(&profile.mac, "volume_spike", &dedup_key, 3600)
                            .await?
                        {
                            let base_severity = registry.anomaly_severity(
                                if vlan >= 0 { vlan as u16 } else { 0 },
                                "volume_spike",
                            );
                            let dst_vlan_val =
                                registry
                                    .ip_to_vlan(obs.dst_subnet.trim_end_matches(|c: char| {
                                        c == '/' || c.is_ascii_digit()
                                    }));
                            let src_ip = profile.current_ip.as_deref().unwrap_or("");
                            let (fw_corr, fw_rule_id, fw_rule_comment) = correlate_with_firewall(
                                firewall_rules,
                                src_ip,
                                &obs.dst_subnet,
                                &obs.protocol,
                                obs.dst_port.map(|p| p as u16),
                            );
                            let traffic_class =
                                classify_traffic_class(&obs.direction, &obs.protocol, obs.dst_port);
                            let suppression_action = store
                                .match_suppression_rule(
                                    &profile.mac,
                                    vlan,
                                    &obs.protocol,
                                    obs.dst_port,
                                    traffic_class,
                                )
                                .await?;
                            if matches!(suppression_action.as_deref(), Some("suppress")) {
                                continue;
                            }
                            let priority_boost = store
                                .get_priority_boost(
                                    &profile.mac,
                                    vlan,
                                    &obs.protocol,
                                    obs.dst_port,
                                    traffic_class,
                                )
                                .await?;
                            let has_fw = has_policy_match(&fw_corr);
                            let source_zone = zone_from_vlan(registry, Some(vlan), src_ip);
                            let destination_zone = zone_from_vlan(
                                registry,
                                dst_vlan_val.map(|v| v as i64),
                                &obs.dst_subnet,
                            );
                            let confidence = compute_confidence(
                                "volume_spike",
                                &profile.baseline_status,
                                total_obs_count,
                                baseline_age_days,
                                has_fw,
                                vlan_sens,
                            );
                            let confidence = (confidence + (priority_boost as f64 * 0.05)).min(1.0);
                            let severity = escalate_severity(base_severity, priority_boost);
                            let details_json = serde_json::json!({
                                "src_ip": profile.current_ip,
                                "src_hostname": profile.hostname,
                                "src_manufacturer": profile.manufacturer,
                                "dst_subnet": obs.dst_subnet,
                                "dst_vlan": dst_vlan_val,
                                "dst_vlan_name": dst_vlan_val.map(|v| registry.vlan_name(v as i64)),
                                "protocol": obs.protocol,
                                "dst_port": obs.dst_port,
                                "direction": obs.direction,
                                "policy_outcome": fw_corr,
                                "traffic_class": traffic_class,
                                "source_zone": source_zone,
                                "destination_zone": destination_zone,
                                "projected_hourly": hourly_projected,
                                "baseline_max": baseline.max_bytes_per_hour,
                                "baseline_avg": baseline.avg_bytes_per_hour,
                                "elevated_observation_count": elevated_count,
                            });
                            let anomaly_id = store.record_anomaly(&NewAnomaly {
                                    mac: profile.mac.clone(),
                                    anomaly_type: "volume_spike".to_string(),
                                    severity,
                                    confidence,
                                    description: format!(
                                        "Traffic volume spike to {} ({} {}): {:.0} bytes/hr projected vs {:.0} baseline max / {:.0} baseline avg",
                                        obs.dst_subnet,
                                        obs.protocol,
                                        obs.dst_port.map(|p| p.to_string()).unwrap_or_default(),
                                        hourly_projected,
                                        baseline.max_bytes_per_hour,
                                        baseline.avg_bytes_per_hour,
                                    ),
                                    details: Some(details_json.to_string()),
                                    vlan,
                                    firewall_correlation: Some(
                                        details_json["policy_outcome"]
                                            .as_str()
                                            .unwrap_or("policy_unknown")
                                            .to_string()
                                    ),
                                    firewall_rule_id: fw_rule_id,
                                    firewall_rule_comment: fw_rule_comment,
                                })
                                .await?;
                            if let Some(action) = suppression_action.as_deref() {
                                if action == "dismissed" || action == "accepted" {
                                    let _ = store
                                        .resolve_anomaly(anomaly_id, action, "system-pattern")
                                        .await;
                                }
                            }
                            anomaly_count += 1;
                        }
                    }
                } else {
                    // Not spiking this cycle — reset persistence counter
                    spike_candidates.clear(&profile.mac, &dedup_key);
                }
            } else {
                // New behavior — not in any baseline
                let anomaly_type = if baseline_map.keys().any(|k| k.2 == obs.dst_subnet) {
                    if baseline_map.keys().any(|k| k.0 == obs.protocol) {
                        "new_port"
                    } else {
                        "new_protocol"
                    }
                } else {
                    "new_destination"
                };

                let dedup_key = format!(
                    "{}:{}:{}",
                    obs.dst_subnet,
                    obs.protocol,
                    obs.dst_port.unwrap_or(-1)
                );
                if !store
                    .has_recent_anomaly(&profile.mac, anomaly_type, &dedup_key, 3600)
                    .await?
                {
                    let base_severity = registry
                        .anomaly_severity(if vlan >= 0 { vlan as u16 } else { 0 }, anomaly_type);
                    let hostname = profile.hostname.as_deref().unwrap_or(&profile.mac);
                    let dst_vlan_val = registry.ip_to_vlan(
                        obs.dst_subnet
                            .trim_end_matches(|c: char| c == '/' || c.is_ascii_digit()),
                    );
                    let src_ip = profile.current_ip.as_deref().unwrap_or("");
                    let (fw_corr, fw_rule_id, fw_rule_comment) = correlate_with_firewall(
                        firewall_rules,
                        src_ip,
                        &obs.dst_subnet,
                        &obs.protocol,
                        obs.dst_port.map(|p| p as u16),
                    );
                    let traffic_class =
                        classify_traffic_class(&obs.direction, &obs.protocol, obs.dst_port);
                    let suppression_action = store
                        .match_suppression_rule(
                            &profile.mac,
                            vlan,
                            &obs.protocol,
                            obs.dst_port,
                            traffic_class,
                        )
                        .await?;
                    if matches!(suppression_action.as_deref(), Some("suppress")) {
                        continue;
                    }
                    let priority_boost = store
                        .get_priority_boost(
                            &profile.mac,
                            vlan,
                            &obs.protocol,
                            obs.dst_port,
                            traffic_class,
                        )
                        .await?;
                    let has_fw = has_policy_match(&fw_corr);
                    let source_zone = zone_from_vlan(registry, Some(vlan), src_ip);
                    let destination_zone =
                        zone_from_vlan(registry, dst_vlan_val.map(|v| v as i64), &obs.dst_subnet);
                    let confidence = compute_confidence(
                        anomaly_type,
                        &profile.baseline_status,
                        total_obs_count,
                        baseline_age_days,
                        has_fw,
                        vlan_sens,
                    );
                    let confidence = (confidence + (priority_boost as f64 * 0.05)).min(1.0);
                    let severity = escalate_severity(base_severity, priority_boost);
                    let details_json = serde_json::json!({
                        "src_ip": profile.current_ip,
                        "src_hostname": profile.hostname,
                        "src_manufacturer": profile.manufacturer,
                        "dst_subnet": obs.dst_subnet,
                        "dst_vlan": dst_vlan_val,
                        "dst_vlan_name": dst_vlan_val.map(|v| registry.vlan_name(v as i64)),
                        "protocol": obs.protocol,
                        "dst_port": obs.dst_port,
                        "direction": obs.direction,
                        "policy_outcome": fw_corr,
                        "traffic_class": traffic_class,
                        "source_zone": source_zone,
                        "destination_zone": destination_zone,
                    });
                    let anomaly_id = store
                        .record_anomaly(&NewAnomaly {
                            mac: profile.mac.clone(),
                            anomaly_type: anomaly_type.to_string(),
                            severity,
                            confidence,
                            description: format!(
                                "{} from {}: {} {} to {}",
                                anomaly_type.replace('_', " "),
                                hostname,
                                obs.protocol,
                                obs.dst_port.map(|p| p.to_string()).unwrap_or_default(),
                                obs.dst_subnet,
                            ),
                            details: Some(details_json.to_string()),
                            vlan,
                            firewall_correlation: Some(
                                details_json["policy_outcome"]
                                    .as_str()
                                    .unwrap_or("policy_unknown")
                                    .to_string(),
                            ),
                            firewall_rule_id: fw_rule_id,
                            firewall_rule_comment: fw_rule_comment,
                        })
                        .await?;
                    if let Some(action) = suppression_action.as_deref() {
                        if action == "dismissed" || action == "accepted" {
                            let _ = store
                                .resolve_anomaly(anomaly_id, action, "system-pattern")
                                .await;
                        }
                    }
                    anomaly_count += 1;
                }
            }
        }
    }

    Ok(anomaly_count)
}

// ── Blocked Attempt Detection ────────────────────────────────

/// Detect blocked attempts from firewall drop logs.
/// Called every 60 seconds.
pub async fn detect_blocked_attempts(
    client: &MikrotikClient,
    store: &BehaviorStore,
    oui_db: &OuiDb,
    geo_cache: &GeoCache,
    registry: &VlanRegistry,
) -> Result<usize, String> {
    let log_entries = client
        .log_entries()
        .await
        .map_err(|e| format!("log fetch failed: {e}"))?;

    let mut anomaly_count = 0;

    // Fetch ARP + DHCP for MAC/hostname lookup
    let (arp_result, dhcp_result) = tokio::join!(client.arp_table(), client.dhcp_leases(),);
    let arp_entries = arp_result.map_err(|e| format!("ARP fetch failed: {e}"))?;
    let dhcp_leases = dhcp_result.map_err(|e| format!("DHCP fetch failed: {e}"))?;

    let mut ip_to_mac: HashMap<String, String> = HashMap::new();
    let mut ip_to_hostname: HashMap<String, String> = HashMap::new();
    for lease in &dhcp_leases {
        if let Some(ref m) = lease.mac_address {
            ip_to_mac.insert(lease.address.clone(), m.to_uppercase());
            if let Some(ref h) = lease.host_name {
                ip_to_hostname.insert(lease.address.clone(), h.clone());
            }
        }
    }
    for arp in &arp_entries {
        if let Some(ref m) = arp.mac_address {
            ip_to_mac
                .entry(arp.address.clone())
                .or_insert_with(|| m.to_uppercase());
        }
    }

    for entry in &log_entries {
        let topics = entry.topics.as_deref().unwrap_or("");
        if !topics.contains("firewall") {
            continue;
        }

        let parsed = log_parser::parse_log_entry(entry, geo_cache, oui_db);
        let fields = match parsed.parsed {
            Some(ref f) => f,
            None => continue,
        };

        if fields.action.as_deref() != Some("drop") {
            continue;
        }

        let src_ip = match fields.src_ip.as_deref() {
            Some(ip) => ip,
            None => continue,
        };

        // Find MAC for the source IP
        let mac = match fields.mac.as_ref().or_else(|| ip_to_mac.get(src_ip)) {
            Some(m) => m.to_uppercase(),
            None => continue,
        };

        let dst_ip = fields.dst_ip.as_deref().unwrap_or("unknown");
        let dst_port = fields.dst_port.unwrap_or(0);
        let protocol = fields.protocol.as_deref().unwrap_or("unknown");
        let vlan = classify_vlan(registry, src_ip);

        // Dedup: same device + dst_ip + dst_port within 1 hour
        let dedup_key = format!("{dst_ip}:{dst_port}");
        if store
            .has_recent_anomaly(&mac, "blocked_attempt", &dedup_key, 3600)
            .await?
        {
            continue;
        }

        let base_severity =
            registry.anomaly_severity(if vlan >= 0 { vlan as u16 } else { 0 }, "blocked_attempt");

        // Enrich source context
        let src_hostname = ip_to_hostname.get(src_ip).cloned();
        let src_manufacturer = oui_db.lookup(&mac).map(|s| s.to_string());

        // Enrich destination context
        let dst_vlan = registry.ip_to_vlan(dst_ip).map(|v| v as i64);
        let dst_vlan_name = dst_vlan.map(|v| registry.vlan_name(v).to_string());
        let dst_hostname = ip_to_hostname.get(dst_ip).cloned();

        // GeoIP enrichment for description
        let dst_country = if let Some(ref country) = fields.dst_country {
            format!(" ({})", country.country)
        } else {
            String::new()
        };

        // Compute confidence for blocked attempts — use device profile if available
        let blocked_confidence = if let Ok(Some(prof)) = store.get_profile(&mac).await {
            let (obs_count, earliest) = store.get_baseline_stats(&mac).await.unwrap_or((0, 0));
            let age_days = if earliest > 0 {
                (BehaviorStore::now_unix_pub() - earliest) as f64 / 86400.0
            } else {
                0.0
            };
            compute_confidence(
                "blocked_attempt",
                &prof.baseline_status,
                obs_count,
                age_days,
                true, // firewall correlated by definition
                registry.sensitivity(if vlan >= 0 { vlan as u16 } else { 0 }),
            )
        } else {
            // Unknown device — moderate confidence
            compute_confidence(
                "blocked_attempt",
                "learning",
                0,
                0.0,
                true,
                registry.sensitivity(if vlan >= 0 { vlan as u16 } else { 0 }),
            )
        };

        let traffic_direction = fields.direction.as_deref().unwrap_or("unknown");
        let traffic_class = classify_traffic_class(traffic_direction, protocol, Some(dst_port));
        let suppression_action = store
            .match_suppression_rule(&mac, vlan, protocol, Some(dst_port), traffic_class)
            .await?;
        if matches!(suppression_action.as_deref(), Some("suppress")) {
            continue;
        }
        let priority_boost = store
            .get_priority_boost(&mac, vlan, protocol, Some(dst_port), traffic_class)
            .await?;
        let severity = escalate_severity(base_severity, priority_boost);
        let blocked_confidence = (blocked_confidence + (priority_boost as f64 * 0.05)).min(1.0);
        let source_zone = zone_from_vlan(registry, Some(vlan), src_ip);
        let destination_zone = zone_from_vlan(registry, dst_vlan, dst_ip);
        let details_json = serde_json::json!({
            "src_ip": src_ip,
            "src_hostname": src_hostname,
            "src_manufacturer": src_manufacturer,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "dst_hostname": dst_hostname,
            "dst_vlan": dst_vlan,
            "dst_vlan_name": dst_vlan_name,
            "protocol": protocol,
            "direction": fields.direction,
            "in_interface": fields.in_interface,
            "dst_country": fields.dst_country,
            "dst_subnet": dedup_key,
            "policy_outcome": "expected_deny",
            "traffic_class": traffic_class,
            "source_zone": source_zone,
            "destination_zone": destination_zone,
        });
        let anomaly_id = store
            .record_anomaly(&NewAnomaly {
                mac: mac.clone(),
                anomaly_type: "blocked_attempt".to_string(),
                severity,
                confidence: blocked_confidence,
                description: format!(
                    "Blocked {} connection to {dst_ip}:{dst_port}{dst_country} via {protocol}",
                    fields.direction.as_deref().unwrap_or("unknown"),
                ),
                details: Some(details_json.to_string()),
                vlan,
                firewall_correlation: Some(
                    details_json["policy_outcome"]
                        .as_str()
                        .unwrap_or("expected_deny")
                        .to_string(),
                ),
                firewall_rule_id: None,
                firewall_rule_comment: None,
            })
            .await?;
        if let Some(action) = suppression_action.as_deref() {
            if action == "dismissed" || action == "accepted" {
                let _ = store
                    .resolve_anomaly(anomaly_id, action, "system-pattern")
                    .await;
            }
        }
        anomaly_count += 1;
    }

    Ok(anomaly_count)
}

// ── Firewall Correlation ─────────────────────────────────────

/// Check if a CIDR-like address specification matches an IP.
fn cidr_matches(spec: &str, ip: &str) -> bool {
    if spec == ip {
        return true;
    }
    if let Some(slash_pos) = spec.find('/') {
        let network = &spec[..slash_pos];
        let prefix_len: u32 = match spec[slash_pos + 1..].parse() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let net_octets: Vec<u8> = network.split('.').filter_map(|o| o.parse().ok()).collect();
        let ip_octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
        if net_octets.len() != 4 || ip_octets.len() != 4 {
            return false;
        }
        let net_u32 =
            u32::from_be_bytes([net_octets[0], net_octets[1], net_octets[2], net_octets[3]]);
        let ip_u32 = u32::from_be_bytes([ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]]);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        return (net_u32 & mask) == (ip_u32 & mask);
    }
    false
}

/// Check if a port specification matches a port number.
fn port_matches(spec: &str, port: u16) -> bool {
    for part in spec.split(',') {
        let part = part.trim();
        if let Some(dash) = part.find('-') {
            let lo: u16 = part[..dash].trim().parse().unwrap_or(0);
            let hi: u16 = part[dash + 1..].trim().parse().unwrap_or(0);
            if port >= lo && port <= hi {
                return true;
            }
        } else if let Ok(p) = part.parse::<u16>() {
            if port == p {
                return true;
            }
        }
    }
    false
}

/// Correlate an observation with cached firewall rules.
/// Returns (correlation_type, rule_id, rule_comment).
pub fn correlate_with_firewall(
    rules: &[FilterRule],
    src_ip: &str,
    dst_ip: &str,
    protocol: &str,
    dst_port: Option<u16>,
) -> (String, Option<String>, Option<String>) {
    let proto_lower = protocol.to_lowercase();

    for rule in rules {
        // Skip disabled rules
        if rule.disabled == Some(true) {
            continue;
        }

        // Protocol match
        if let Some(ref rule_proto) = rule.protocol {
            if normalize_protocol(rule_proto) != normalize_protocol(&proto_lower) {
                continue;
            }
        }

        // Source address match
        if let Some(ref src) = rule.src_address {
            if !cidr_matches(src, src_ip) {
                continue;
            }
        }

        // Destination address match
        if let Some(ref dst) = rule.dst_address {
            if !cidr_matches(dst, dst_ip) {
                continue;
            }
        }

        // Destination port match
        if let Some(ref dp) = rule.dst_port {
            if let Some(port) = dst_port {
                if !port_matches(dp, port) {
                    continue;
                }
            } else {
                continue; // Rule specifies port but observation has none
            }
        }

        // Matched — determine correlation type
        let correlation = match rule.action.as_str() {
            "accept" | "passthrough" => "expected_allow",
            "drop" | "reject" => "expected_deny",
            _ => "policy_unknown",
        };

        return (
            correlation.to_string(),
            Some(rule.id.clone()),
            rule.comment.clone(),
        );
    }

    ("policy_unknown".to_string(), None, None)
}

/// Refresh firewall rules cache if stale (>5 minutes).
pub async fn refresh_firewall_cache(
    client: &MikrotikClient,
    cache: &RwLock<(Vec<FilterRule>, std::time::Instant)>,
) {
    let needs_refresh = {
        let cached = cache.read().await;
        cached.1.elapsed() > std::time::Duration::from_secs(300)
    };
    if needs_refresh {
        match client.firewall_filter_rules().await {
            Ok(rules) => {
                let mut cached = cache.write().await;
                *cached = (rules, std::time::Instant::now());
                tracing::debug!("firewall rules cache refreshed");
            }
            Err(e) => {
                tracing::warn!("failed to refresh firewall rules cache: {e}");
            }
        }
    }
}

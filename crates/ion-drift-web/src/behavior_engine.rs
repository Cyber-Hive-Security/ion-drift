//! Behavioral fingerprinting engine.
//!
//! Collects device observations from the router's connection table,
//! detects anomalies against learned baselines, and correlates with
//! firewall rules.

use std::collections::HashMap;

use mikrotik_core::behavior::{
    self, BehaviorStore, DeviceObservation, NewAnomaly,
};
use mikrotik_core::resources::firewall::FilterRule;
use mikrotik_core::MikrotikClient;
use tokio::sync::RwLock;

use crate::geo::GeoDb;
use crate::log_parser;
use crate::oui::OuiDb;

/// Normalize RouterOS protocol numbers to names.
fn normalize_protocol(proto: &str) -> &'static str {
    match proto {
        "6" | "tcp" => "tcp",
        "17" | "udp" => "udp",
        "1" | "icmp" => "icmp",
        _ => "other",
    }
}

/// Split "IP:port" into (IP, port). Uses rfind to handle IPv4 correctly.
fn split_addr_port(addr: &str) -> (&str, Option<u16>) {
    if let Some(colon) = addr.rfind(':') {
        let port_str = &addr[colon + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return (&addr[..colon], Some(port));
        }
    }
    (addr, None)
}

/// Classify IP to VLAN: known VLAN → that VLAN, external → -1, unknown internal → 0.
fn classify_vlan(ip: &str) -> i64 {
    match behavior::ip_to_vlan(ip) {
        Some(v) => v as i64,
        None if !behavior::is_internal_ip(ip) => -1, // WAN / External
        None => 0,                                    // Unclassified internal
    }
}

// ── Observation Collection ───────────────────────────────────

/// Collect device observations from ARP + DHCP + connection tracking.
/// Called every 60 seconds.
pub async fn collect_observations(
    client: &MikrotikClient,
    store: &BehaviorStore,
    oui_db: &OuiDb,
) -> Result<usize, String> {
    // Fetch ARP + DHCP concurrently
    let (arp_result, dhcp_result) = tokio::join!(
        client.arp_table(),
        client.dhcp_leases(),
    );
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
            ip_to_mac.entry(arp.address.clone()).or_insert_with(|| mac.to_uppercase());
        }
    }

    // Upsert device profiles for all known devices
    for (ip, mac) in &ip_to_mac {
        let hostname = ip_to_hostname.get(ip).map(|s| s.as_str());
        let manufacturer = oui_db.lookup(mac).map(|s| s.to_string());
        let vlan = classify_vlan(ip);
        if let Err(e) = store.upsert_profile(mac, hostname, manufacturer.as_deref(), ip, vlan).await {
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
    let mut observations: HashMap<String, HashMap<(String, Option<i64>, String, String), (i64, i64, i64)>> =
        HashMap::new();

    for conn in &connections {
        let src_addr = match conn.src_address.as_deref() {
            Some(a) => a,
            None => continue,
        };
        let dst_addr = match conn.dst_address.as_deref() {
            Some(a) => a,
            None => continue,
        };

        let (src_ip, _src_port) = split_addr_port(src_addr);
        let (dst_ip, dst_port) = split_addr_port(dst_addr);

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

        let dst_subnet = behavior::classify_destination(dst_ip);
        let direction = behavior::classify_direction(src_ip, dst_ip).to_string();
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
        let vlan = classify_vlan(&ip);

        for ((protocol, dst_port, dst_subnet, direction), (bytes_sent, bytes_recv, conn_count)) in flows {
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

/// Detect anomalies for baselined devices.
/// Called after each observation collection.
pub async fn detect_anomalies(store: &BehaviorStore) -> Result<usize, String> {
    let profiles = store.get_all_profiles().await?;
    let mut anomaly_count = 0;

    for profile in &profiles {
        if profile.baseline_status != "baselined" {
            continue;
        }

        let baselines = store.get_baselines(&profile.mac).await?;
        if baselines.is_empty() {
            continue;
        }

        // Build baseline lookup
        let baseline_map: HashMap<(String, Option<i64>, String, String), &mikrotik_core::behavior::DeviceBaseline> =
            baselines.iter().map(|b| {
                ((b.protocol.clone(), b.dst_port, b.dst_subnet.clone(), b.direction.clone()), b)
            }).collect();

        // Get last 120s of observations
        let recent_obs = store.get_observations(&profile.mac, 120).await?;
        let vlan = profile.current_vlan.unwrap_or(0);

        for obs in &recent_obs {
            let key = (
                obs.protocol.clone(),
                obs.dst_port,
                obs.dst_subnet.clone(),
                obs.direction.clone(),
            );

            if let Some(baseline) = baseline_map.get(&key) {
                // Check volume spike: project to hourly rate, compare to 3x max
                let total_bytes = (obs.bytes_sent + obs.bytes_recv) as f64;
                let hourly_projected = total_bytes * 60.0; // 60s observation → hourly
                if baseline.max_bytes_per_hour > 0.0
                    && hourly_projected > baseline.max_bytes_per_hour * 3.0
                {
                    let dedup_key = format!("{}:{}", obs.dst_subnet, obs.dst_port.unwrap_or(-1));
                    if !store
                        .has_recent_anomaly(&profile.mac, "volume_spike", &dedup_key, 3600)
                        .await?
                    {
                        let severity = behavior::anomaly_severity(if vlan >= 0 { vlan as u16 } else { 0 }, "volume_spike");
                        let dst_vlan_val = behavior::ip_to_vlan(obs.dst_subnet.trim_end_matches(|c: char| c == '/' || c.is_ascii_digit()));
                        store
                            .record_anomaly(&NewAnomaly {
                                mac: profile.mac.clone(),
                                anomaly_type: "volume_spike".to_string(),
                                severity: severity.to_string(),
                                description: format!(
                                    "Traffic volume spike to {} ({} {}): {:.0} bytes/hr projected vs {:.0} baseline max",
                                    obs.dst_subnet,
                                    obs.protocol,
                                    obs.dst_port.map(|p| p.to_string()).unwrap_or_default(),
                                    hourly_projected,
                                    baseline.max_bytes_per_hour,
                                ),
                                details: Some(serde_json::json!({
                                    "src_ip": profile.current_ip,
                                    "src_hostname": profile.hostname,
                                    "src_manufacturer": profile.manufacturer,
                                    "dst_subnet": obs.dst_subnet,
                                    "dst_vlan": dst_vlan_val,
                                    "dst_vlan_name": dst_vlan_val.map(|v| behavior::vlan_name(v as i64)),
                                    "protocol": obs.protocol,
                                    "dst_port": obs.dst_port,
                                    "direction": obs.direction,
                                    "projected_hourly": hourly_projected,
                                    "baseline_max": baseline.max_bytes_per_hour,
                                }).to_string()),
                                vlan,
                                firewall_correlation: None,
                                firewall_rule_id: None,
                                firewall_rule_comment: None,
                            })
                            .await?;
                        anomaly_count += 1;
                    }
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
                    let severity = behavior::anomaly_severity(if vlan >= 0 { vlan as u16 } else { 0 }, anomaly_type);
                    let hostname = profile.hostname.as_deref().unwrap_or(&profile.mac);
                    let dst_vlan_val = behavior::ip_to_vlan(obs.dst_subnet.trim_end_matches(|c: char| c == '/' || c.is_ascii_digit()));
                    store
                        .record_anomaly(&NewAnomaly {
                            mac: profile.mac.clone(),
                            anomaly_type: anomaly_type.to_string(),
                            severity: severity.to_string(),
                            description: format!(
                                "{} from {}: {} {} to {}",
                                anomaly_type.replace('_', " "),
                                hostname,
                                obs.protocol,
                                obs.dst_port.map(|p| p.to_string()).unwrap_or_default(),
                                obs.dst_subnet,
                            ),
                            details: Some(serde_json::json!({
                                "src_ip": profile.current_ip,
                                "src_hostname": profile.hostname,
                                "src_manufacturer": profile.manufacturer,
                                "dst_subnet": obs.dst_subnet,
                                "dst_vlan": dst_vlan_val,
                                "dst_vlan_name": dst_vlan_val.map(|v| behavior::vlan_name(v as i64)),
                                "protocol": obs.protocol,
                                "dst_port": obs.dst_port,
                                "direction": obs.direction,
                            }).to_string()),
                            vlan,
                            firewall_correlation: None,
                            firewall_rule_id: None,
                            firewall_rule_comment: None,
                        })
                        .await?;
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
    geo_db: &GeoDb,
) -> Result<usize, String> {
    let log_entries = client
        .log_entries()
        .await
        .map_err(|e| format!("log fetch failed: {e}"))?;

    let mut anomaly_count = 0;

    // Fetch ARP + DHCP for MAC/hostname lookup
    let (arp_result, dhcp_result) = tokio::join!(
        client.arp_table(),
        client.dhcp_leases(),
    );
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
            ip_to_mac.entry(arp.address.clone()).or_insert_with(|| m.to_uppercase());
        }
    }

    for entry in &log_entries {
        let topics = entry.topics.as_deref().unwrap_or("");
        if !topics.contains("firewall") {
            continue;
        }

        let parsed = log_parser::parse_log_entry(entry, geo_db, oui_db);
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
        let vlan = classify_vlan(src_ip);

        // Dedup: same device + dst_ip + dst_port within 1 hour
        let dedup_key = format!("{dst_ip}:{dst_port}");
        if store
            .has_recent_anomaly(&mac, "blocked_attempt", &dedup_key, 3600)
            .await?
        {
            continue;
        }

        let severity = behavior::anomaly_severity(if vlan >= 0 { vlan as u16 } else { 0 }, "blocked_attempt");

        // Enrich source context
        let src_hostname = ip_to_hostname.get(src_ip).cloned();
        let src_manufacturer = oui_db.lookup(&mac).map(|s| s.to_string());

        // Enrich destination context
        let dst_vlan = behavior::ip_to_vlan(dst_ip).map(|v| v as i64);
        let dst_vlan_name = dst_vlan.map(|v| behavior::vlan_name(v).to_string());
        let dst_hostname = ip_to_hostname.get(dst_ip).cloned();

        // GeoIP enrichment for description
        let dst_country = if let Some(ref country) = fields.dst_country {
            format!(" ({})", country.name)
        } else {
            String::new()
        };

        store
            .record_anomaly(&NewAnomaly {
                mac: mac.clone(),
                anomaly_type: "blocked_attempt".to_string(),
                severity: severity.to_string(),
                description: format!(
                    "Blocked {} connection to {dst_ip}:{dst_port}{dst_country} via {protocol}",
                    fields.direction.as_deref().unwrap_or("unknown"),
                ),
                details: Some(serde_json::json!({
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
                }).to_string()),
                vlan,
                firewall_correlation: Some("blocked_attempting".to_string()),
                firewall_rule_id: None,
                firewall_rule_comment: None,
            })
            .await?;
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
        let net_u32 = u32::from_be_bytes([net_octets[0], net_octets[1], net_octets[2], net_octets[3]]);
        let ip_u32 = u32::from_be_bytes([ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]]);
        let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
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
            "accept" | "passthrough" => "expected",
            "drop" | "reject" => "blocked_attempting",
            _ => "expected",
        };

        return (
            correlation.to_string(),
            Some(rule.id.clone()),
            rule.comment.clone(),
        );
    }

    ("no_match".to_string(), None, None)
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

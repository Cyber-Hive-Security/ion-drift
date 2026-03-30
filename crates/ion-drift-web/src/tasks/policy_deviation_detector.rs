//! Policy deviation detector — background task that compares observed network traffic
//! against the infrastructure policy map and records deviations.
//!
//! Supports DNS (port 53) and NTP (port 123) detection. Gateway detection deferred to Phase 3.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::RwLock;

use ion_drift_storage::BehaviorStore;
use ion_drift_storage::behavior::{VlanRegistry, ip_matches_target};

use crate::attack_techniques::AttackTechniqueDb;
use crate::connection_store::ConnectionStore;
use crate::device_manager::DeviceManager;

// ── Service type definitions ────────────────────────────────────

/// Port-based service types supported by the deviation detector.
/// Each variant carries the metadata needed for detection.
enum ServiceType {
    Dns,
    Ntp,
}

impl ServiceType {
    fn service_name(&self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Ntp => "ntp",
        }
    }

    fn protocol(&self) -> &'static str {
        match self {
            Self::Dns => "udp",
            Self::Ntp => "udp",
        }
    }

    fn port(&self) -> i64 {
        match self {
            Self::Dns => 53,
            Self::Ntp => 123,
        }
    }

    /// Should we skip source IPs that appear as servers for this service?
    /// True for DNS: a DNS server's outbound port-53 traffic is recursive resolution, not a violation.
    /// False for NTP: NTP servers don't chain queries the same way.
    fn skip_observed_servers(&self) -> bool {
        match self {
            Self::Dns => true,
            Self::Ntp => false,
        }
    }

    fn unauthorized_type(&self) -> &'static str {
        match self {
            Self::Dns => "dns_unauthorized",
            Self::Ntp => "ntp_unauthorized",
        }
    }

    fn unclassified_type(&self) -> &'static str {
        match self {
            Self::Dns => "dns_unclassified",
            Self::Ntp => "ntp_unclassified",
        }
    }

    fn default_policy_source(&self) -> &'static str {
        match self {
            Self::Dns => "dhcp_option_6",
            Self::Ntp => "dhcp_option_42",
        }
    }
}

// ── Severity computation ────────────────────────────────────────

/// Compute deviation severity: VLAN sensitivity is the floor, policy priority can only escalate.
fn compute_severity(registry: &VlanRegistry, vlan: i64, policy_priority: &str) -> String {
    let vlan_severity = registry.anomaly_severity(vlan as u16, "policy_deviation");
    let priority_rank = match policy_priority {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    let vlan_rank = match vlan_severity {
        "critical" => 4,
        "alert" => 3,
        "warning" => 2,
        "info" => 1,
        _ => 0,
    };
    // Take the higher of the two
    match priority_rank.max(vlan_rank) {
        4 => "critical",
        3 => "warning",  // map "alert" and "high" to "warning" for deviation display
        2 => "warning",
        1 => "informational",
        _ => "informational",
    }.to_string()
}

// ── Task entrypoint ─────────────────────────────────────────────

/// Spawn the policy deviation detector task. Runs every 60 seconds.
pub fn spawn_policy_deviation_detector(
    behavior_store: Arc<BehaviorStore>,
    connection_store: Arc<ConnectionStore>,
    vlan_registry: Arc<RwLock<VlanRegistry>>,
    attack_db: Arc<AttackTechniqueDb>,
    device_manager: Arc<tokio::sync::RwLock<DeviceManager>>,
) {
    tokio::spawn(async move {
        // Wait 30s after startup to let policy sync and connections populate
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        // Fetch router WAN IP from ip/dhcp-client — excludes router's own traffic from detection.
        let wan_ip = fetch_wan_ip(&device_manager).await;
        if let Some(ref ip) = wan_ip {
            tracing::info!(wan_ip = %ip, "policy deviation detector: excluding router WAN IP");
        } else {
            tracing::warn!("policy deviation detector: could not determine WAN IP — router's own traffic may generate false positives");
        }

        tracing::info!("policy deviation detector started (DNS + NTP)");

        let mut last_check = chrono::Utc::now() - chrono::Duration::seconds(120);

        loop {
            let now = chrono::Utc::now();

            // Run detection for each supported service type
            for service in &[ServiceType::Dns, ServiceType::Ntp] {
                if let Err(e) = detect_port_service(
                    service,
                    &behavior_store,
                    &connection_store,
                    &vlan_registry,
                    &attack_db,
                    &last_check,
                    &wan_ip,
                ).await {
                    tracing::warn!(
                        service = service.service_name(),
                        "policy deviation detection failed: {e}",
                    );
                }
            }

            last_check = now;
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
}

/// Fetch the router's WAN IP from ip/dhcp-client.
async fn fetch_wan_ip(device_manager: &tokio::sync::RwLock<DeviceManager>) -> Option<String> {
    let dm = device_manager.read().await;
    let router = dm.get_router()?;
    let client = match &router.client {
        crate::device_manager::DeviceClient::RouterOs(c) => c,
        _ => return None,
    };
    let result: serde_json::Value = client.get("ip/dhcp-client").await.ok()?;
    // ip/dhcp-client returns an array; find the one with status=bound
    let entries = result.as_array()?;
    for entry in entries {
        if entry.get("status").and_then(|s| s.as_str()) == Some("bound") {
            // address field is "x.x.x.x/prefix"
            let addr = entry.get("address").and_then(|a| a.as_str())?;
            let ip = addr.split('/').next().unwrap_or(addr);
            return Some(ip.to_string());
        }
    }
    None
}

// ── Generic port-based service detector ─────────────────────────

async fn detect_port_service(
    service: &ServiceType,
    behavior_store: &BehaviorStore,
    connection_store: &Arc<ConnectionStore>,
    vlan_registry: &RwLock<VlanRegistry>,
    attack_db: &AttackTechniqueDb,
    last_check: &chrono::DateTime<chrono::Utc>,
    wan_ip: &Option<String>,
) -> Result<(), String> {
    let svc_name = service.service_name();
    let dst_port = service.port();

    // 1. Load policies for this service
    let policies = behavior_store.get_policies_for_service(svc_name, None, None, None).await?;

    // Build VLAN → authorized IPs map (deduplicated)
    let mut vlan_authorized: HashMap<i64, Vec<String>> = HashMap::new();
    let mut global_authorized: Vec<String> = Vec::new();
    let mut all_server_ips: HashSet<String> = HashSet::new();
    // Track the highest policy priority per VLAN for severity computation
    let mut vlan_policy_priority: HashMap<i64, String> = HashMap::new();
    let mut global_policy_priority = "low".to_string();

    for policy in &policies {
        for target in &policy.authorized_targets {
            all_server_ips.insert(target.clone());
        }

        if let Some(ref scopes) = policy.vlan_scope {
            for &vlan_id in scopes {
                let entry = vlan_authorized.entry(vlan_id).or_default();
                for target in &policy.authorized_targets {
                    if !entry.contains(target) {
                        entry.push(target.clone());
                    }
                }
                // Track highest priority for this VLAN
                let current = vlan_policy_priority.entry(vlan_id).or_insert_with(|| "low".to_string());
                if priority_rank(&policy.priority) > priority_rank(current) {
                    *current = policy.priority.clone();
                }
            }
        } else {
            for target in &policy.authorized_targets {
                if !global_authorized.contains(target) {
                    global_authorized.push(target.clone());
                }
            }
            if priority_rank(&policy.priority) > priority_rank(&global_policy_priority) {
                global_policy_priority = policy.priority.clone();
            }
        }
    }

    // 2. Query recent connections for this port since last watermark
    let since_str = last_check.format("%Y-%m-%d %H:%M:%S").to_string();
    let connections = {
        let store = connection_store.clone();
        let since = since_str.clone();
        let port = dst_port;
        let wan_ip = wan_ip.clone();
        tokio::task::spawn_blocking(move || {
            let db = store.lock_db()?;
            // Exclude router's own WAN IP from detection — its NTP/DNS traffic
            // to upstream servers is not a policy deviation.
            let wan_exclude = if let Some(ref wip) = wan_ip {
                format!(" AND src_ip != '{}'", wip.replace('\'', ""))
            } else {
                String::new()
            };
            let query = format!(
                "SELECT src_mac, src_ip, dst_ip, src_vlan
                 FROM connection_history
                 WHERE dst_port = ?1
                   AND first_seen >= datetime(?2)
                   AND src_mac IS NOT NULL
                   AND bytes_rx > 0
                   {}
                 GROUP BY src_mac, src_ip, src_vlan, dst_ip",
                wan_exclude,
            );
            let mut stmt = db.prepare(&query)
                .map_err(|e| format!("{} deviation query: {e}", "service"))?;

            let rows: Vec<(String, String, String, Option<String>)> = stmt.query_map(
                rusqlite::params![port, since],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                )),
            ).map_err(|e| format!("deviation query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();

            Ok::<_, String>(rows)
        })
        .await
        .map_err(|e| format!("spawn_blocking: {e}"))?
    }?;

    if connections.is_empty() {
        return Ok(());
    }

    // Build server IP exclusion set (for services that need it, like DNS)
    // Observation-derived: any IP that receives inbound traffic on this port is a server
    let observed_servers: HashSet<String> = if service.skip_observed_servers() {
        connections.iter().map(|(_, _, dst_ip, _)| dst_ip.clone()).collect()
    } else {
        HashSet::new()
    };

    let server_ips: HashSet<&str> = all_server_ips.iter().map(|s| s.as_str())
        .chain(observed_servers.iter().map(|s| s.as_str()))
        .collect();

    let registry = vlan_registry.read().await;
    let attack_techniques = attack_db.techniques_for_deviation(svc_name);

    let mut deviation_count = 0u32;

    for (src_mac, src_ip, dst_ip, _src_vlan_str) in &connections {
        // Skip server IPs if configured for this service type
        if service.skip_observed_servers() && server_ips.iter().any(|&server_ip| ip_matches_target(src_ip, server_ip)) {
            continue;
        }

        // Resolve source IP to VLAN
        let vlan_id = registry.ip_to_vlan(src_ip);
        if vlan_id.is_none() {
            continue; // Can't determine VLAN — skip (likely WAN traffic)
        }
        let vlan = vlan_id.unwrap() as i64;

        // Get authorized servers for this VLAN
        let authorized = vlan_authorized.get(&vlan);
        let has_vlan_policy = authorized.is_some();
        let has_global_policy = !global_authorized.is_empty();

        if has_vlan_policy {
            let auth_list = authorized.unwrap();
            let is_authorized = auth_list.iter().any(|target| ip_matches_target(dst_ip, target));
            if is_authorized {
                continue;
            }
            let globally_authorized = global_authorized.iter().any(|target| ip_matches_target(dst_ip, target));
            if globally_authorized {
                continue;
            }

            let policy_priority = vlan_policy_priority.get(&vlan).map(|s| s.as_str()).unwrap_or("low");
            let severity = compute_severity(&registry, vlan, policy_priority);

            let dev = ion_drift_storage::behavior::NewPolicyDeviation {
                mac_address: src_mac.clone(),
                ip_address: src_ip.clone(),
                vlan: Some(vlan),
                deviation_type: service.unauthorized_type().to_string(),
                expected: auth_list.join(", "),
                actual: dst_ip.clone(),
                policy_source: Some(service.default_policy_source().to_string()),
                attack_techniques: attack_techniques.clone(),
                severity,
            };
            behavior_store.record_policy_deviation(&dev).await?;
            deviation_count += 1;
        } else if has_global_policy {
            let globally_authorized = global_authorized.iter().any(|target| ip_matches_target(dst_ip, target));
            if globally_authorized {
                continue;
            }

            let severity = compute_severity(&registry, vlan, &global_policy_priority);

            let dev = ion_drift_storage::behavior::NewPolicyDeviation {
                mac_address: src_mac.clone(),
                ip_address: src_ip.clone(),
                vlan: Some(vlan),
                deviation_type: service.unauthorized_type().to_string(),
                expected: global_authorized.join(", "),
                actual: dst_ip.clone(),
                policy_source: Some("global_policy".to_string()),
                attack_techniques: attack_techniques.clone(),
                severity,
            };
            behavior_store.record_policy_deviation(&dev).await?;
            deviation_count += 1;
        } else {
            let severity = compute_severity(&registry, vlan, "low");

            let dev = ion_drift_storage::behavior::NewPolicyDeviation {
                mac_address: src_mac.clone(),
                ip_address: src_ip.clone(),
                vlan: Some(vlan),
                deviation_type: service.unclassified_type().to_string(),
                expected: "no policy defined".to_string(),
                actual: dst_ip.clone(),
                policy_source: None,
                attack_techniques: attack_techniques.clone(),
                severity,
            };
            behavior_store.record_policy_deviation(&dev).await?;
            deviation_count += 1;
        }
    }

    if deviation_count > 0 {
        tracing::info!(
            service = svc_name,
            count = deviation_count,
            "policy deviations recorded",
        );
    }

    Ok(())
}

fn priority_rank(priority: &str) -> u8 {
    match priority {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

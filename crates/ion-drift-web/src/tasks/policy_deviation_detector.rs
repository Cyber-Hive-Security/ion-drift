//! DNS policy deviation detector — background task that compares observed DNS traffic
//! against the infrastructure policy map and records deviations.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use ion_drift_storage::BehaviorStore;
use ion_drift_storage::behavior::VlanRegistry;

use crate::attack_techniques::AttackTechniqueDb;
use crate::connection_store::ConnectionStore;

/// Spawn the policy deviation detector task. Runs every 60 seconds.
pub fn spawn_policy_deviation_detector(
    behavior_store: Arc<BehaviorStore>,
    connection_store: Arc<ConnectionStore>,
    vlan_registry: Arc<RwLock<VlanRegistry>>,
    attack_db: Arc<AttackTechniqueDb>,
) {
    tokio::spawn(async move {
        // Wait 30s after startup to let policy sync and connections populate
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        tracing::info!("policy deviation detector started");

        let mut last_check = chrono::Utc::now() - chrono::Duration::seconds(120);

        loop {
            let now = chrono::Utc::now();
            if let Err(e) = run_detection_cycle(
                &behavior_store,
                &connection_store,
                &vlan_registry,
                &attack_db,
                &last_check,
            ).await {
                tracing::warn!("policy deviation detection cycle failed: {e}");
            }
            last_check = now;

            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
}

async fn run_detection_cycle(
    behavior_store: &BehaviorStore,
    connection_store: &Arc<ConnectionStore>,
    vlan_registry: &RwLock<VlanRegistry>,
    attack_db: &AttackTechniqueDb,
    last_check: &chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    // 1. Load DNS policies: service=dns
    let dns_policies = behavior_store.get_policies_for_service("dns", None, None, None).await?;

    // Build VLAN → authorized DNS IPs map
    let mut vlan_authorized: HashMap<i64, Vec<String>> = HashMap::new();
    let mut global_authorized: Vec<String> = Vec::new();

    for policy in &dns_policies {
        if let Some(ref scopes) = policy.vlan_scope {
            for &vlan_id in scopes {
                vlan_authorized
                    .entry(vlan_id)
                    .or_default()
                    .extend(policy.authorized_targets.clone());
            }
        } else {
            // Global policy — applies to all VLANs
            global_authorized.extend(policy.authorized_targets.clone());
        }
    }

    // 2. Query recent connections with dst_port=53 since last watermark
    let since_str = last_check.format("%Y-%m-%d %H:%M:%S").to_string();
    let dns_connections = {
        let store = connection_store.clone();
        let since = since_str.clone();
        tokio::task::spawn_blocking(move || {
            let db = store.lock_db()?;
            let mut stmt = db.prepare(
                "SELECT src_mac, src_ip, dst_ip, src_vlan
                 FROM connection_history
                 WHERE dst_port = 53
                   AND first_seen >= datetime(?1)
                   AND src_mac IS NOT NULL
                 GROUP BY src_mac, dst_ip",
            ).map_err(|e| format!("dns deviation query: {e}"))?;

            let rows: Vec<(String, String, String, Option<String>)> = stmt.query_map(
                rusqlite::params![since],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                )),
            ).map_err(|e| format!("dns deviation query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();

            Ok::<_, String>(rows)
        })
        .await
        .map_err(|e| format!("spawn_blocking: {e}"))?
    }?;

    if dns_connections.is_empty() {
        return Ok(());
    }

    let registry = vlan_registry.read().await;
    let attack_techniques = attack_db.techniques_for_deviation("dns");

    let mut deviation_count = 0u32;

    for (src_mac, src_ip, dst_ip, _src_vlan_str) in &dns_connections {
        // Resolve source IP to VLAN
        let vlan_id = registry.ip_to_vlan(src_ip);
        if vlan_id.is_none() {
            // Can't determine VLAN — skip (likely WAN traffic)
            continue;
        }
        let vlan = vlan_id.unwrap() as i64;

        // Get authorized DNS servers for this VLAN
        let authorized = vlan_authorized.get(&vlan);

        // Check against four policy states
        let has_vlan_policy = authorized.is_some();
        let has_global_policy = !global_authorized.is_empty();

        if has_vlan_policy {
            let auth_list = authorized.unwrap();
            // Check if dst_ip is in the authorized list
            let is_authorized = auth_list.iter().any(|target| ip_matches_target(dst_ip, target));
            if is_authorized {
                continue; // Authorized — no deviation
            }

            // Also check global policies
            let globally_authorized = global_authorized.iter().any(|target| ip_matches_target(dst_ip, target));
            if globally_authorized {
                continue;
            }

            // Deviation: wrong DNS server
            let expected = auth_list.join(", ");
            let dev = ion_drift_storage::behavior::NewPolicyDeviation {
                mac_address: src_mac.clone(),
                ip_address: src_ip.clone(),
                vlan: Some(vlan),
                deviation_type: "dns_unauthorized".to_string(),
                expected,
                actual: dst_ip.clone(),
                policy_source: Some("dhcp_option_6".to_string()),
                attack_techniques: attack_techniques.clone(),
                severity: "informational".to_string(),
            };
            behavior_store.record_policy_deviation(&dev).await?;
            deviation_count += 1;
        } else if has_global_policy {
            // Only global policy exists — check against it
            let globally_authorized = global_authorized.iter().any(|target| ip_matches_target(dst_ip, target));
            if globally_authorized {
                continue;
            }

            let expected = global_authorized.join(", ");
            let dev = ion_drift_storage::behavior::NewPolicyDeviation {
                mac_address: src_mac.clone(),
                ip_address: src_ip.clone(),
                vlan: Some(vlan),
                deviation_type: "dns_unauthorized".to_string(),
                expected,
                actual: dst_ip.clone(),
                policy_source: Some("global_policy".to_string()),
                attack_techniques: attack_techniques.clone(),
                severity: "informational".to_string(),
            };
            behavior_store.record_policy_deviation(&dev).await?;
            deviation_count += 1;
        } else {
            // No DNS policy for this VLAN — unclassified
            let dev = ion_drift_storage::behavior::NewPolicyDeviation {
                mac_address: src_mac.clone(),
                ip_address: src_ip.clone(),
                vlan: Some(vlan),
                deviation_type: "dns_unclassified".to_string(),
                expected: "no policy defined".to_string(),
                actual: dst_ip.clone(),
                policy_source: None,
                attack_techniques: attack_techniques.clone(),
                severity: "informational".to_string(),
            };
            behavior_store.record_policy_deviation(&dev).await?;
            deviation_count += 1;
        }
    }

    if deviation_count > 0 {
        tracing::info!("policy deviation detector: {deviation_count} DNS deviations recorded");
    }

    Ok(())
}

/// Check if an IP matches a target (exact match or CIDR).
/// Duplicated from behavior.rs to avoid circular deps — simple utility.
fn ip_matches_target(ip: &str, target: &str) -> bool {
    if ip == target {
        return true;
    }
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

//! DNS policy deviation detector — background task that compares observed DNS traffic
//! against the infrastructure policy map and records deviations.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::RwLock;

use ion_drift_storage::BehaviorStore;
use ion_drift_storage::behavior::{VlanRegistry, ip_matches_target};

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

    // Build VLAN → authorized DNS IPs map (deduplicated)
    let mut vlan_authorized: HashMap<i64, Vec<String>> = HashMap::new();
    let mut global_authorized: Vec<String> = Vec::new();
    // Collect ALL authorized DNS server IPs — devices at these IPs are DNS servers
    // and their outbound port-53 traffic is recursive resolution, not a deviation.
    let mut all_dns_server_ips: HashSet<String> = HashSet::new();

    for policy in &dns_policies {
        for target in &policy.authorized_targets {
            all_dns_server_ips.insert(target.clone());
        }

        if let Some(ref scopes) = policy.vlan_scope {
            for &vlan_id in scopes {
                let entry = vlan_authorized.entry(vlan_id).or_default();
                for target in &policy.authorized_targets {
                    if !entry.contains(target) {
                        entry.push(target.clone());
                    }
                }
            }
        } else {
            for target in &policy.authorized_targets {
                if !global_authorized.contains(target) {
                    global_authorized.push(target.clone());
                }
            }
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
                "SELECT src_mac, MAX(src_ip), dst_ip, MAX(src_vlan)
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
        // Skip DNS servers — their outbound port-53 traffic is recursive resolution,
        // not a policy violation. A device is a DNS server if its IP appears in any
        // policy's authorized_targets (derived from DHCP config).
        if all_dns_server_ips.contains(src_ip) {
            continue;
        }

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

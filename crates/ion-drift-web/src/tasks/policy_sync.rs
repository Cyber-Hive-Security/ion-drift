//! Infrastructure policy synchronization.
//!
//! Polls the router every 60 minutes to build the Global Policy Map --
//! an authoritative record of what services should exist on the network.

use std::sync::Arc;

use ion_drift_storage::behavior::BehaviorStore;
use mikrotik_core::MikrotikClient;
use tokio::sync::RwLock;
use ion_drift_storage::behavior::VlanRegistry;

/// Spawn the policy sync background task.
pub fn spawn_policy_sync(
    client: MikrotikClient,
    behavior_store: Arc<BehaviorStore>,
    vlan_registry: Arc<RwLock<VlanRegistry>>,
) {
    tokio::spawn(async move {
        // Run immediately on startup, then every 60 minutes
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = sync_policies(&client, &behavior_store, &vlan_registry).await {
                tracing::warn!("policy sync failed: {e}");
            }
        }
    });
}

/// Map a DHCP network CIDR to the VLAN(s) it serves.
fn network_to_vlans(network_cidr: &str, registry: &VlanRegistry) -> Option<Vec<i64>> {
    // Extract the network address from the CIDR
    let ip = network_cidr.split('/').next()?;
    if let Some(vlan) = registry.ip_to_vlan(ip) {
        Some(vec![vlan as i64])
    } else {
        None
    }
}

/// Parse ION tags from a firewall rule comment.
/// Returns matched tags: "ignore", "critical", "digest"
fn parse_ion_tags(comment: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let upper = comment.to_uppercase();
    if upper.contains("[ION-CRITICAL]") {
        tags.push("critical".to_string());
    }
    if upper.contains("[ION-DIGEST]") {
        tags.push("digest".to_string());
    }
    if upper.contains("[ION-IGNORE]") {
        tags.push("ignore".to_string());
    }
    tags
}

/// Build a human-readable summary of a firewall rule for display.
fn rule_summary(rule: &mikrotik_core::resources::firewall::FilterRule) -> String {
    let mut parts = vec![format!("chain={}", rule.chain)];
    if let Some(ref src) = rule.src_address {
        parts.push(format!("src={src}"));
    }
    if let Some(ref dst) = rule.dst_address {
        parts.push(format!("dst={dst}"));
    }
    if let Some(ref proto) = rule.protocol {
        parts.push(format!("proto={proto}"));
    }
    if let Some(ref dport) = rule.dst_port {
        parts.push(format!("dport={dport}"));
    }
    parts.push(format!("action={}", rule.action));
    parts.join(" ")
}

async fn sync_policies(
    client: &MikrotikClient,
    store: &BehaviorStore,
    vlan_registry: &RwLock<VlanRegistry>,
) -> Result<(), String> {
    let sync_start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    tracing::info!("starting policy sync");
    let registry = vlan_registry.read().await;
    let mut policies_synced = true;
    let mut tags_synced = true;

    // 1. Fetch DHCP server networks -> NTP, DNS, Gateway policies
    match client.dhcp_networks().await {
        Ok(networks) => {
            for net in &networks {
                let vlan_scope = network_to_vlans(&net.address, &registry);
                let vlan_json = vlan_scope.as_deref();

                // NTP servers from DHCP options
                if let Some(ref ntp) = net.ntp_server {
                    let servers: Vec<String> = ntp.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                    if !servers.is_empty() {
                        store.upsert_policy(
                            "ntp", Some("udp"), Some(123i64),
                            &servers, vlan_json,
                            "dhcp_option_42", "high",
                            Some(&net.id),
                        ).await?;
                    }
                }

                // DNS servers from DHCP options
                if let Some(ref dns) = net.dns_server {
                    let servers: Vec<String> = dns.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                    if !servers.is_empty() {
                        store.upsert_policy(
                            "dns", Some("udp"), Some(53i64),
                            &servers, vlan_json,
                            "dhcp_option_6", "high",
                            Some(&net.id),
                        ).await?;
                        // Also add TCP DNS policy
                        store.upsert_policy(
                            "dns", Some("tcp"), Some(53i64),
                            &servers, vlan_json,
                            "dhcp_option_6", "high",
                            Some(&net.id),
                        ).await?;
                    }
                }

                // Gateway from DHCP
                if let Some(ref gw) = net.gateway {
                    if !gw.is_empty() {
                        store.upsert_policy(
                            "gateway", None, None,
                            &[gw.clone()], vlan_json,
                            "dhcp_gateway", "medium",
                            Some(&net.id),
                        ).await?;
                    }
                }
            }
            tracing::info!("synced {} DHCP networks", networks.len());
        }
        Err(e) => { policies_synced = false; tracing::warn!("failed to fetch DHCP networks: {e}"); },
    }

    // 2. Fetch DNS server config -> upstream resolver policy
    match client.dns_config().await {
        Ok(dns) => {
            if let Some(ref servers) = dns.servers {
                let upstreams: Vec<String> = servers.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                if !upstreams.is_empty() {
                    store.upsert_policy(
                        "dns", Some("udp"), Some(53i64),
                        &upstreams, None, // global scope
                        "ip_dns_upstream", "high",
                        None,
                    ).await?;
                }
            }
            tracing::info!("synced DNS config");
        }
        Err(e) => { policies_synced = false; tracing::warn!("failed to fetch DNS config: {e}"); },
    }

    // 3. Fetch IP routes -> gateway policies
    match client.ip_routes().await {
        Ok(routes) => {
            for route in &routes {
                if route.disabled.unwrap_or(false) || route.dynamic.unwrap_or(false) {
                    continue;
                }
                if let Some(ref gw) = route.gateway {
                    // Default route
                    if route.dst_address == "0.0.0.0/0" {
                        store.upsert_policy(
                            "gateway", None, None,
                            &[gw.clone()], None,
                            "ip_route_default", "high",
                            Some(&route.id),
                        ).await?;
                    }
                }
            }
            tracing::info!("synced {} routes", routes.len());
        }
        Err(e) => { policies_synced = false; tracing::warn!("failed to fetch routes: {e}"); },
    }

    // 4. Fetch address lists -> management/custom policies
    match client.firewall_address_lists().await {
        Ok(entries) => {
            // Group entries by list name
            let mut lists: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            for entry in &entries {
                if entry.disabled.unwrap_or(false) {
                    continue;
                }
                lists.entry(entry.list.clone()).or_default().push(entry.address.clone());
            }
            for (list_name, addresses) in &lists {
                let service = match list_name.to_lowercase().as_str() {
                    "management" | "trusted" | "servers" => "management",
                    _ => "custom",
                };
                store.upsert_policy(
                    service, None, None,
                    addresses, None,
                    &format!("address_list:{list_name}"), "medium",
                    None,
                ).await?;
            }
            tracing::info!("synced {} address lists ({} entries)", lists.len(), entries.len());
        }
        Err(e) => { policies_synced = false; tracing::warn!("failed to fetch address lists: {e}"); },
    }

    // 5. Fetch firewall rules -> ION tags + WAN sensitive port auto-discovery
    match client.firewall_filter_rules().await {
        Ok(rules) => {
            let mut tag_count = 0;
            for rule in &rules {
                if let Some(ref comment) = rule.comment {
                    let tags = parse_ion_tags(comment);
                    if !tags.is_empty() {
                        // Tag precedence: CRITICAL > DIGEST > IGNORE
                        let effective_tag = if tags.contains(&"critical".to_string()) {
                            "critical"
                        } else if tags.contains(&"digest".to_string()) {
                            "digest"
                        } else {
                            &tags[0]
                        };
                        store.upsert_ion_tag(
                            &rule.id,
                            &rule.chain,
                            &rule.action,
                            effective_tag,
                            comment,
                            &rule_summary(rule),
                        ).await?;
                        tag_count += 1;
                    }
                }
            }

            // Auto-discover WAN sensitive ports from firewall accept rules
            for rule in &rules {
                if rule.action != "accept" || rule.disabled.unwrap_or(false) {
                    continue;
                }
                // Check if this is a WAN-facing rule
                // input chain qualifies ONLY if no LAN-specific interface filter is set
                let has_lan_filter = rule.in_interface_list.as_deref().map_or(false, |l| l != "WAN")
                    || rule.in_interface.as_deref().map_or(false, |i| i != "ether1");
                let is_wan = rule.in_interface.as_deref() == Some("ether1")
                    || rule.in_interface_list.as_deref() == Some("WAN")
                    || (rule.chain == "input" && !has_lan_filter);
                if !is_wan {
                    continue;
                }
                if let Some(ref dst_port) = rule.dst_port {
                    let protocol = rule.protocol.as_deref().unwrap_or("tcp");
                    for port_str in dst_port.split(',') {
                        let trimmed = port_str.trim();
                        // Handle port ranges like "8080-8090"
                        if let Some((start_s, end_s)) = trimmed.split_once('-') {
                            if let (Ok(start), Ok(end)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
                                for port in start..=end {
                                    let service_name = format!("fw-rule:{}", rule.id);
                                    store.add_wan_sensitive_port_if_missing(port, protocol, &service_name).await?;
                                }
                            }
                        } else if let Ok(port) = trimmed.parse::<u16>() {
                            let service_name = format!("fw-rule:{}", rule.id);
                            store.add_wan_sensitive_port_if_missing(port, protocol, &service_name).await?;
                        }
                    }
                }
            }

            tracing::info!("synced {} ION tags from firewall rules", tag_count);
        }
        Err(e) => { tags_synced = false; tracing::warn!("failed to fetch firewall rules: {e}"); },
    }

    // 6. Clean up stale entries — only for categories that were fully synced
    if policies_synced {
        let stale_policies = store.remove_stale_policies(sync_start).await?;
        if stale_policies > 0 {
            tracing::info!("removed {stale_policies} stale policies");
        }
    } else {
        tracing::warn!("skipping stale policy cleanup due to fetch failures");
    }
    if tags_synced {
        let stale_tags = store.remove_stale_ion_tags(sync_start).await?;
        if stale_tags > 0 {
            tracing::info!("removed {stale_tags} stale ION tags");
        }
    } else {
        tracing::warn!("skipping stale ION tag cleanup due to fetch failures");
    }

    drop(registry);
    tracing::info!("policy sync complete");
    Ok(())
}

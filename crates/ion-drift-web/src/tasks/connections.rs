use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::connection_store;
use crate::geo;

/// Build an IP→MAC lookup from the router's ARP table and DHCP leases.
/// DHCP entries take priority (more authoritative); ARP fills gaps.
async fn build_ip_to_mac(client: &mikrotik_core::MikrotikClient) -> HashMap<String, String> {
    let (arp_result, dhcp_result) = tokio::join!(client.arp_table(), client.dhcp_leases());

    let mut ip_to_mac: HashMap<String, String> = HashMap::new();

    // DHCP leases first (authoritative)
    if let Ok(leases) = dhcp_result {
        for lease in &leases {
            if let Some(ref mac) = lease.mac_address {
                ip_to_mac.insert(lease.address.clone(), mac.to_uppercase());
            }
        }
    } else if let Err(e) = dhcp_result {
        tracing::debug!("connection persister: DHCP fetch failed: {e}");
    }

    // ARP fills gaps
    if let Ok(entries) = arp_result {
        for entry in &entries {
            if let Some(ref mac) = entry.mac_address {
                ip_to_mac
                    .entry(entry.address.clone())
                    .or_insert_with(|| mac.to_uppercase());
            }
        }
    } else if let Err(e) = arp_result {
        tracing::debug!("connection persister: ARP fetch failed: {e}");
    }

    ip_to_mac
}

/// Persist active connections to history every 30 seconds (same cadence as the connections page poll).
pub fn spawn_connection_persister(
    store: Arc<connection_store::ConnectionStore>,
    client: mikrotik_core::MikrotikClient,
    geo_cache: Arc<geo::GeoCache>,
    vlan_registry: Arc<RwLock<ion_drift_storage::behavior::VlanRegistry>>,
) {
    tokio::spawn(async move {
        // Wait 1 minute before starting (let server stabilize)
        tokio::time::sleep(Duration::from_secs(60)).await;
        tracing::info!("connection history persister starting");

        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            // Fetch connections and IP→MAC map concurrently
            let (conn_result, ip_to_mac) = tokio::join!(
                client.firewall_connections_full(),
                build_ip_to_mac(&client),
            );

            let connections = match conn_result {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("connection persister: failed to fetch connections: {e}");
                    continue;
                }
            };

            let conn_registry = vlan_registry.read().await.clone();
            let mut inserted = 0usize;
            let mut updated = 0usize;
            let mut active_ids: Vec<String> = Vec::with_capacity(connections.len());

            for c in &connections {
                let conntrack_id = c.id.clone();
                active_ids.push(conntrack_id.clone());

                let protocol = c
                    .protocol
                    .as_deref()
                    .map(|p| match p {
                        "6" | "tcp" => "tcp",
                        "17" | "udp" => "udp",
                        "1" | "icmp" => "icmp",
                        _ => "other",
                    })
                    .unwrap_or("other")
                    .to_string();

                let src_ip = c.src_address.as_deref().unwrap_or("");
                let dst_ip = c.dst_address.as_deref().unwrap_or("");
                let dst_port = c
                    .dst_port
                    .as_deref()
                    .and_then(|p| p.parse::<i64>().ok());

                let src_mac = ip_to_mac.get(src_ip).cloned();

                let poll_conn = connection_store::PollConnection {
                    conntrack_id,
                    protocol,
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    dst_port,
                    src_mac,
                    tcp_state: c.tcp_state.clone(),
                    bytes_tx: c.orig_bytes.unwrap_or(0) as i64,
                    bytes_rx: c.repl_bytes.unwrap_or(0) as i64,
                };

                match store.upsert_from_poll(&poll_conn, &geo_cache, &conn_registry) {
                    Ok(true) => inserted += 1,
                    Ok(false) => updated += 1,
                    Err(e) => tracing::debug!("connection persist error: {e}"),
                }
            }

            // Close connections that disappeared from the poll
            match store.close_stale(&active_ids, 60) {
                Ok(closed) => {
                    if closed > 0 || inserted > 0 {
                        tracing::debug!(
                            "connections: +{inserted} new, ~{updated} updated, -{closed} closed"
                        );
                    }
                }
                Err(e) => tracing::warn!("connection close_stale error: {e}"),
            }
        }
    });
}


/// Prune old connection history nightly.
pub fn spawn_connection_pruner(store: Arc<connection_store::ConnectionStore>) {
    tokio::spawn(async move {
        // Wait 3 hours before first prune (avoid startup load)
        tokio::time::sleep(Duration::from_secs(3 * 3600)).await;

        loop {
            match store.prune(30) {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("connection history: pruned {count} old rows");
                    }
                }
                Err(e) => tracing::warn!("connection history prune failed: {e}"),
            }

            // Sleep 24 hours
            tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
        }
    });
}

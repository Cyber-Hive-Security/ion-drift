use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use mikrotik_core::resources::connection::FullConnectionEntry;
use mikrotik_core::resources::ip::{ArpEntry, DhcpLease};
use tokio::sync::RwLock;

use crate::connection_store;
use crate::geo;
use crate::router_queue::{Priority, QueuedRequest, RouterQueue};

/// Build an IP→MAC lookup from pre-fetched ARP entries and DHCP leases.
/// DHCP entries take priority (more authoritative); ARP fills gaps.
fn build_ip_to_mac(arp_entries: &[ArpEntry], dhcp_leases: &[DhcpLease]) -> HashMap<String, String> {
    let mut ip_to_mac: HashMap<String, String> = HashMap::new();

    // DHCP leases first (authoritative)
    for lease in dhcp_leases {
        if let Some(ref mac) = lease.mac_address {
            ip_to_mac.insert(lease.address.clone(), mac.to_uppercase());
        }
    }

    // ARP fills gaps
    for entry in arp_entries {
        if let Some(ref mac) = entry.mac_address {
            ip_to_mac
                .entry(entry.address.clone())
                .or_insert_with(|| mac.to_uppercase());
        }
    }

    ip_to_mac
}

/// Persist active connections to history at a configurable interval.
pub fn spawn_connection_persister(
    store: Arc<connection_store::ConnectionStore>,
    queue: RouterQueue,
    geo_cache: Arc<geo::GeoCache>,
    vlan_registry: Arc<RwLock<ion_drift_storage::behavior::VlanRegistry>>,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        // Wait 1 minute before starting (let server stabilize)
        tokio::time::sleep(Duration::from_secs(60)).await;
        tracing::info!("connection history persister starting (interval={interval_secs}s)");

        // Seed previous byte counts from open connections to avoid inflated
        // first-poll deltas after a restart.
        let mut prev_bytes: HashMap<String, (i64, i64)> = match store.get_open_connection_bytes() {
            Ok(map) => {
                tracing::info!("delta tracker: seeded {} open connections", map.len());
                map
            }
            Err(e) => {
                tracing::warn!("delta tracker: seed failed, first cycle may inflate: {e}");
                HashMap::new()
            }
        };

        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;

            // Fetch ARP, DHCP, and connections as a single batch through the queue
            let results = queue
                .submit(
                    "connections",
                    Priority::High,
                    vec![
                        QueuedRequest::get("ip/arp"),
                        QueuedRequest::get("ip/dhcp-server/lease"),
                        QueuedRequest::get("ip/firewall/connection"),
                    ],
                )
                .await;
            let results = match results {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("connection persister: batch failed: {e}");
                    continue;
                }
            };

            let arp_entries: Vec<ArpEntry> = match &results[0] {
                Ok(v) => serde_json::from_value(v.clone()).unwrap_or_default(),
                Err(e) => {
                    tracing::warn!("connection persister: ARP fetch failed: {e}");
                    Vec::new()
                }
            };
            let dhcp_leases: Vec<DhcpLease> = match &results[1] {
                Ok(v) => serde_json::from_value(v.clone()).unwrap_or_default(),
                Err(e) => {
                    tracing::warn!("connection persister: DHCP fetch failed: {e}");
                    Vec::new()
                }
            };
            let ip_to_mac = build_ip_to_mac(&arp_entries, &dhcp_leases);

            let connections: Vec<FullConnectionEntry> = match &results[2] {
                Ok(v) => serde_json::from_value(v.clone()).unwrap_or_default(),
                Err(e) => {
                    tracing::warn!("connection persister: failed to fetch connections: {e}");
                    continue;
                }
            };

            let conn_registry = vlan_registry.read().await.clone();
            let mut inserted = 0usize;
            let mut updated = 0usize;
            let mut active_ids: HashSet<String> = HashSet::with_capacity(connections.len());
            let mut deltas: Vec<(String, Option<String>, i64, i64)> = Vec::new();

            for c in &connections {
                let conntrack_id = c.id.clone();
                active_ids.insert(conntrack_id.clone());

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
                let cur_tx = c.orig_bytes.unwrap_or(0) as i64;
                let cur_rx = c.repl_bytes.unwrap_or(0) as i64;

                // Compute bandwidth delta
                let (delta_tx, delta_rx) =
                    if let Some(&(prev_tx, prev_rx)) = prev_bytes.get(&conntrack_id) {
                        // Clamp to 0 if counter reset (conntrack ID reuse)
                        ((cur_tx - prev_tx).max(0), (cur_rx - prev_rx).max(0))
                    } else {
                        // First observation — full value is the delta
                        (cur_tx, cur_rx)
                    };

                // Update previous bytes tracker
                prev_bytes.insert(conntrack_id.clone(), (cur_tx, cur_rx));

                // Record non-zero deltas
                if delta_tx > 0 || delta_rx > 0 {
                    deltas.push((conntrack_id.clone(), src_mac.clone(), delta_tx, delta_rx));
                }

                let poll_conn = connection_store::PollConnection {
                    conntrack_id,
                    protocol,
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    dst_port,
                    src_mac,
                    tcp_state: c.tcp_state.clone(),
                    bytes_tx: cur_tx,
                    bytes_rx: cur_rx,
                };

                match store.upsert_from_poll(&poll_conn, &geo_cache, &conn_registry) {
                    Ok(true) => inserted += 1,
                    Ok(false) => updated += 1,
                    Err(e) => tracing::debug!("connection persist error: {e}"),
                }
            }

            // Record bandwidth deltas in batch
            if let Err(e) = store.record_bandwidth_deltas(&deltas) {
                tracing::warn!("bandwidth delta recording failed: {e}");
            }

            // Close connections that disappeared from the poll
            let active_ids_vec: Vec<String> = active_ids.iter().cloned().collect();
            match store.close_stale(&active_ids_vec, 60) {
                Ok(closed) => {
                    // Clean up prev_bytes for closed connections
                    if closed > 0 {
                        prev_bytes.retain(|id, _| active_ids.contains(id));
                    }

                    if closed > 0 || inserted > 0 {
                        tracing::debug!(
                            "connections: +{inserted} new, ~{updated} updated, -{closed} closed, {delta_count} deltas",
                            delta_count = deltas.len(),
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

            // Prune bandwidth deltas (keep 48 hours)
            match store.prune_bandwidth_deltas(48) {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("bandwidth deltas: pruned {count} old rows");
                    }
                }
                Err(e) => tracing::warn!("bandwidth delta prune failed: {e}"),
            }

            // Sleep 24 hours
            tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
        }
    });
}

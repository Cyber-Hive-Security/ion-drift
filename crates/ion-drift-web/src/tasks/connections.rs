use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::connection_store;
use crate::geo;

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

            let connections = match client.firewall_connections_full().await {
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

                let poll_conn = connection_store::PollConnection {
                    conntrack_id,
                    protocol,
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    dst_port,
                    src_mac: None,
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

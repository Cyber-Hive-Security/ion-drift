use std::sync::Arc;
use std::time::Duration;

use mikrotik_core::SwitchStore;
use mikrotik_core::switch_store::{PortMetricEntry, VlanMembershipEntry};
use mikrotik_core::swos_client::{SwosClient, SwosLink};
use tokio::sync::{watch, RwLock};

use crate::device_manager::{DeviceManager, DeviceStatus};

/// Spawn SwOS pollers for all enabled SwOS switch devices.
///
/// Each switch gets its own tokio task with an independent polling interval
/// from its `poll_interval_secs` configuration (default 30s). Uses the
/// PollerRegistry for lifecycle management.
pub fn spawn_swos_pollers(
    device_manager: Arc<RwLock<DeviceManager>>,
    switch_store: Arc<SwitchStore>,
    poller_registry: Arc<RwLock<crate::poller_registry::PollerRegistry>>,
) {
    let dm = device_manager.clone();
    tokio::spawn(async move {
        // 30-second startup delay to let the server stabilize
        tokio::time::sleep(Duration::from_secs(30)).await;

        let dm_read = dm.read().await;
        let switches = dm_read.get_swos_switches();

        if switches.is_empty() {
            tracing::info!("no SwOS switch devices configured, SwOS poller idle");
            return;
        }

        let mut registry = poller_registry.write().await;
        for entry in switches {
            registry.start_poller(entry, device_manager.clone(), switch_store.clone());
        }
        drop(registry);
        drop(dm_read);
    });
}

/// Run the polling loop for a single SwOS switch device.
///
/// Called by the PollerRegistry. Exits when the cancellation signal is received.
pub async fn run_swos_poller(
    device_id: String,
    client: SwosClient,
    store: Arc<SwitchStore>,
    dm: Arc<RwLock<DeviceManager>>,
    poll_interval: u64,
    mut cancel_rx: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(poll_interval.max(10)));
    let mut cycle: u32 = 0;

    loop {
        tokio::select! {
            _ = cancel_rx.changed() => {
                tracing::info!(device = %device_id, "SwOS poller cancelled");
                break;
            }
            _ = interval.tick() => {
                poll_swos_switch(&device_id, &client, &store, &dm, cycle).await;
                cycle = cycle.wrapping_add(1);
            }
        }
    }
}

/// Run one poll cycle for a SwOS switch device.
async fn poll_swos_switch(
    device_id: &str,
    client: &SwosClient,
    store: &SwitchStore,
    dm: &Arc<RwLock<DeviceManager>>,
    cycle: u32,
) {
    // Test connectivity via sys.b and update status
    let sys = match client.get_system().await {
        Ok(sys) => {
            let mut dm_w = dm.write().await;
            dm_w.set_status(
                device_id,
                DeviceStatus::Online {
                    identity: sys.identity.clone(),
                },
            );
            sys
        }
        Err(e) => {
            tracing::warn!(device = %device_id, error = %e, "SwOS poll: connectivity failed");
            let mut dm_w = dm.write().await;
            dm_w.set_status(
                device_id,
                DeviceStatus::Offline {
                    error: e.to_string(),
                },
            );
            return; // Skip data collection if device is unreachable
        }
    };

    // Fetch link status first — we need port names for MAC table entries
    let links = match client.get_links().await {
        Ok(links) => links,
        Err(e) => {
            tracing::warn!(device = %device_id, "SwOS link.b: {e}");
            Vec::new()
        }
    };

    // Collect hosts and stats sequentially — SwOS is a tiny embedded HTTP/1.0
    // server that cannot handle concurrent connections reliably. Parallel
    // requests cause intermittent failures (empty responses, connection resets),
    // especially on lower-end models like CSS106.
    let hosts_res = client.get_hosts().await;
    let stats_res = client.get_stats().await;

    // ── Port metrics (from stats + link status) ─────────────────────
    if let Ok(stats) = stats_res {
        let entries: Vec<PortMetricEntry> = stats
            .iter()
            .map(|s| {
                let port_name = port_name_from_links(&links, s.port_index);
                let link = links.iter().find(|l| l.port_index == s.port_index);
                let running = link.map(|l| l.link_up).unwrap_or(false);
                let speed = link.and_then(|l| l.speed.clone());

                PortMetricEntry {
                    port_name,
                    rx_bytes: s.rx_bytes,
                    tx_bytes: s.tx_bytes,
                    rx_packets: s.rx_packets,
                    tx_packets: s.tx_packets,
                    speed,
                    running,
                }
            })
            .collect();

        if let Err(e) = store.record_port_metrics(device_id, &entries).await {
            tracing::warn!(device = %device_id, "SwOS port metrics: {e}");
        }
    } else if let Err(e) = stats_res {
        tracing::warn!(device = %device_id, "SwOS stats.b: {e}");
    }

    // ── Dynamic host (MAC) table ────────────────────────────────────
    if let Ok(hosts) = hosts_res {
        tracing::debug!(
            device = %device_id,
            host_count = hosts.len(),
            link_count = links.len(),
            cycle = cycle,
            "SwOS host table result"
        );
        // Log link index→name mapping periodically for debugging
        if cycle % 10 == 0 && !links.is_empty() {
            let link_indices: Vec<String> = links.iter().map(|l| format!("{}={}", l.port_index, l.port_name)).collect();
            tracing::info!(device = %device_id, link_map = ?link_indices, "SwOS port index→name map");
        }
        for host in &hosts {
            let port_name = port_name_from_links(&links, host.port_index);
            // Log mismatches where fallback name is used
            if !links.is_empty() && !links.iter().any(|l| l.port_index == host.port_index) {
                tracing::warn!(
                    device = %device_id,
                    mac = %host.mac_address,
                    host_port_index = host.port_index,
                    resolved_name = %port_name,
                    link_count = links.len(),
                    "SwOS port index not found in link data — using fallback name"
                );
            }
            // SwOS has no bridge concept — use "swos" as bridge name
            let bridge = "swos";
            let vlan_id = host.vlan_id.map(|v| v as u32);
            // SwOS switch's own MAC never appears in !dhost.b
            let is_local = false;

            if let Err(e) = store
                .upsert_mac_entry(device_id, &host.mac_address, &port_name, bridge, vlan_id, is_local)
                .await
            {
                tracing::warn!(
                    device = %device_id,
                    mac = %host.mac_address,
                    "SwOS mac upsert: {e}"
                );
            }
        }

        tracing::debug!(
            device = %device_id,
            identity = %sys.identity,
            hosts = hosts.len(),
            "SwOS host table polled"
        );
    } else if let Err(e) = hosts_res {
        tracing::warn!(device = %device_id, "SwOS !dhost.b: {e}");
    }

    // ── VLAN membership (every 4th cycle to reduce load) ────────────
    if cycle % 4 == 0 {
        match client.get_vlans().await {
            Ok(vlans) => {
                let mut membership_entries = Vec::new();

                for vlan in &vlans {
                    for &port_idx in &vlan.member_ports {
                        let port_name = port_name_from_links(&links, port_idx);
                        membership_entries.push(VlanMembershipEntry {
                            port_name,
                            vlan_id: vlan.vlan_id as u32,
                            // SwOS doesn't distinguish tagged/untagged in the vlan.b member bitmask
                            // — treat all as tagged (trunk ports)
                            tagged: true,
                        });
                    }
                }

                if let Err(e) = store.set_vlan_membership(device_id, &membership_entries).await {
                    tracing::warn!(device = %device_id, "SwOS vlan membership: {e}");
                }
            }
            Err(e) => {
                tracing::warn!(device = %device_id, "SwOS vlan.b: {e}");
            }
        }
    }

    tracing::debug!(device = %device_id, "SwOS poll cycle complete");
}

/// Map a 0-based port index to a port name using link.b data.
///
/// Falls back to "PortN" (1-based) if link data is unavailable.
fn port_name_from_links(links: &[SwosLink], port_index: u8) -> String {
    links
        .iter()
        .find(|l| l.port_index == port_index)
        .map(|l| l.port_name.clone())
        .unwrap_or_else(|| format!("Port{}", port_index + 1))
}

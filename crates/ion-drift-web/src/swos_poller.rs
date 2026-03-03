use std::sync::Arc;
use std::time::Duration;

use mikrotik_core::SwitchStore;
use mikrotik_core::switch_store::{PortMetricEntry, VlanMembershipEntry};
use mikrotik_core::swos_client::{SwosClient, SwosLink};
use tokio::sync::RwLock;

use crate::device_manager::{DeviceManager, DeviceStatus};

/// Spawn SwOS pollers for all enabled SwOS switch devices.
///
/// Each switch gets its own tokio task with an independent polling interval
/// from its `poll_interval_secs` configuration (default 30s).
pub fn spawn_swos_pollers(
    device_manager: Arc<RwLock<DeviceManager>>,
    switch_store: Arc<SwitchStore>,
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

        for entry in switches {
            let device_id = entry.record.id.clone();
            let device_name = entry.record.name.clone();
            let poll_interval = entry.record.poll_interval_secs as u64;
            // get_swos_switches() only returns SwOS devices, so unwrap is safe
            let client = entry.client.as_swos().cloned().unwrap();
            let store = switch_store.clone();
            let dm_ref = device_manager.clone();

            tracing::info!(
                id = %device_id,
                name = %device_name,
                interval_secs = poll_interval,
                "starting SwOS poller"
            );

            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(poll_interval.max(10)));
                let mut cycle: u32 = 0;

                loop {
                    poll_swos_switch(&device_id, &client, &store, &dm_ref, cycle).await;
                    cycle = cycle.wrapping_add(1);
                    interval.tick().await;
                }
            });
        }
        drop(dm_read);
    });
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

    // Collect hosts and stats concurrently
    let (hosts_res, stats_res) = tokio::join!(client.get_hosts(), client.get_stats(),);

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
        for host in &hosts {
            let port_name = port_name_from_links(&links, host.port_index);
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

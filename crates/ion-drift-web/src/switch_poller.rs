use std::sync::Arc;
use std::time::Duration;

use mikrotik_core::{MikrotikClient, SwitchStore};
use mikrotik_core::switch_store::{PortMetricEntry, VlanMembershipEntry};
use tokio::sync::RwLock;

use crate::device_manager::{DeviceManager, DeviceStatus};

/// Spawn switch pollers for all enabled switch devices.
///
/// Each switch gets its own tokio task with an independent polling interval
/// from its `poll_interval_secs` configuration.
pub fn spawn_switch_pollers(
    device_manager: Arc<RwLock<DeviceManager>>,
    switch_store: Arc<SwitchStore>,
) {
    let dm = device_manager.clone();
    tokio::spawn(async move {
        // 30-second startup delay to let the server stabilize
        tokio::time::sleep(Duration::from_secs(30)).await;

        let dm_read = dm.read().await;
        let switches = dm_read.get_switches();

        if switches.is_empty() {
            tracing::info!("no switch devices configured, switch poller idle");
            return;
        }

        for entry in switches {
            let device_id = entry.record.id.clone();
            let device_name = entry.record.name.clone();
            let poll_interval = entry.record.poll_interval_secs as u64;
            let client = entry.client.clone();
            let store = switch_store.clone();
            let dm_ref = device_manager.clone();

            tracing::info!(
                id = %device_id,
                name = %device_name,
                interval_secs = poll_interval,
                "starting switch poller"
            );

            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(poll_interval.max(10)));
                interval.tick().await; // skip immediate tick

                loop {
                    interval.tick().await;
                    poll_switch(&device_id, &client, &store, &dm_ref).await;
                }
            });
        }
        drop(dm_read);
    });
}

/// Run one poll cycle for a switch device.
async fn poll_switch(
    device_id: &str,
    client: &MikrotikClient,
    store: &SwitchStore,
    dm: &Arc<RwLock<DeviceManager>>,
) {
    // Test connectivity and update status
    match client.test_connection().await {
        Ok(identity) => {
            let mut dm_w = dm.write().await;
            dm_w.set_status(device_id, DeviceStatus::Online { identity });
        }
        Err(e) => {
            tracing::warn!(device = %device_id, error = %e, "switch poll: connectivity failed");
            let mut dm_w = dm.write().await;
            dm_w.set_status(
                device_id,
                DeviceStatus::Offline {
                    error: e.to_string(),
                },
            );
            return; // Skip data collection if device is unreachable
        }
    }

    // Collect data concurrently
    let (ethernet_res, bridge_hosts_res, bridge_ports_res, bridge_vlans_res, neighbors_res) =
        tokio::join!(
            client.ethernet_interfaces(),
            client.bridge_hosts(),
            client.bridge_ports(),
            client.bridge_vlans(),
            client.ip_neighbors(),
        );

    // ── Ethernet / port metrics ───────────────────────────────────
    if let Ok(interfaces) = ethernet_res {
        let entries: Vec<PortMetricEntry> = interfaces
            .iter()
            .map(|iface| PortMetricEntry {
                port_name: iface.name.clone(),
                rx_bytes: iface.rx_byte.unwrap_or(0),
                tx_bytes: iface.tx_byte.unwrap_or(0),
                rx_packets: iface.rx_packet.unwrap_or(0),
                tx_packets: iface.tx_packet.unwrap_or(0),
                speed: iface.speed.clone(),
                running: iface.running,
            })
            .collect();
        if let Err(e) = store.record_port_metrics(device_id, &entries).await {
            tracing::warn!(device = %device_id, "port metrics: {e}");
        }
    } else if let Err(e) = ethernet_res {
        tracing::warn!(device = %device_id, "ethernet_interfaces: {e}");
    }

    // ── Bridge hosts → MAC table ──────────────────────────────────
    if let Ok(hosts) = bridge_hosts_res {
        for host in &hosts {
            let on_iface = host.on_interface.as_deref().unwrap_or("");
            let is_local = host.local.unwrap_or(false);

            if let Err(e) = store
                .upsert_mac_entry(
                    device_id,
                    &host.mac_address,
                    on_iface,
                    &host.bridge,
                    None, // VLAN ID — resolved separately from bridge vlans
                    is_local,
                )
                .await
            {
                tracing::warn!(
                    device = %device_id,
                    mac = %host.mac_address,
                    "mac upsert: {e}"
                );
            }
        }
    } else if let Err(e) = bridge_hosts_res {
        tracing::warn!(device = %device_id, "bridge_hosts: {e}");
    }

    // ── Bridge VLANs → VLAN membership ────────────────────────────
    if let Ok(vlans) = bridge_vlans_res {
        let mut membership_entries = Vec::new();

        for vlan in &vlans {
            // vlan_ids can be "10" or "10,20" — handle the primary one
            let vlan_id: Option<u32> = vlan
                .vlan_ids
                .split(',')
                .next()
                .and_then(|s| s.trim().parse().ok());

            let vlan_id = match vlan_id {
                Some(v) => v,
                None => continue,
            };

            // Tagged ports
            if let Some(ref tagged) = vlan.tagged {
                for port in tagged.split(',') {
                    let port = port.trim();
                    if !port.is_empty() {
                        membership_entries.push(VlanMembershipEntry {
                            port_name: port.to_string(),
                            vlan_id,
                            tagged: true,
                        });
                    }
                }
            }

            // Untagged ports
            if let Some(ref untagged) = vlan.untagged {
                for port in untagged.split(',') {
                    let port = port.trim();
                    if !port.is_empty() {
                        membership_entries.push(VlanMembershipEntry {
                            port_name: port.to_string(),
                            vlan_id,
                            tagged: false,
                        });
                    }
                }
            }
        }

        if let Err(e) = store.set_vlan_membership(device_id, &membership_entries).await {
            tracing::warn!(device = %device_id, "vlan membership: {e}");
        }
    } else if let Err(e) = bridge_vlans_res {
        tracing::warn!(device = %device_id, "bridge_vlans: {e}");
    }

    // ── Bridge ports (log for now — port config info) ─────────────
    if let Err(e) = bridge_ports_res {
        tracing::warn!(device = %device_id, "bridge_ports: {e}");
    }

    // ── IP Neighbors → neighbor discovery ─────────────────────────
    if let Ok(neighbors) = neighbors_res {
        for nb in &neighbors {
            if let Err(e) = store
                .upsert_neighbor(
                    device_id,
                    nb.interface.as_deref().or(nb.interface_name.as_deref()).unwrap_or(""),
                    nb.mac_address.as_deref(),
                    nb.address.as_deref().or(nb.address4.as_deref()),
                    nb.identity.as_deref(),
                    nb.platform.as_deref(),
                    nb.board.as_deref(),
                    nb.version.as_deref(),
                )
                .await
            {
                tracing::warn!(device = %device_id, "neighbor upsert: {e}");
            }
        }
    } else if let Err(e) = neighbors_res {
        tracing::warn!(device = %device_id, "ip_neighbors: {e}");
    }

    tracing::debug!(device = %device_id, "switch poll cycle complete");
}

/// Spawn a neighbor discovery poller that runs against ALL devices every 120s.
pub fn spawn_neighbor_poller(
    device_manager: Arc<RwLock<DeviceManager>>,
    switch_store: Arc<SwitchStore>,
) {
    tokio::spawn(async move {
        // 60-second startup delay
        tokio::time::sleep(Duration::from_secs(60)).await;
        tracing::info!("neighbor discovery poller starting (all devices, 120s interval)");

        let mut interval = tokio::time::interval(Duration::from_secs(120));
        interval.tick().await;

        loop {
            interval.tick().await;

            let dm_read = device_manager.read().await;
            let devices: Vec<(String, MikrotikClient)> = dm_read
                .all_devices()
                .into_iter()
                .map(|d| (d.record.id.clone(), d.client.clone()))
                .collect();
            drop(dm_read);

            for (device_id, client) in &devices {
                match client.ip_neighbors().await {
                    Ok(neighbors) => {
                        for nb in &neighbors {
                            if let Err(e) = switch_store
                                .upsert_neighbor(
                                    device_id,
                                    nb.interface.as_deref().or(nb.interface_name.as_deref()).unwrap_or(""),
                                    nb.mac_address.as_deref(),
                                    nb.address.as_deref().or(nb.address4.as_deref()),
                                    nb.identity.as_deref(),
                                    nb.platform.as_deref(),
                                    nb.board.as_deref(),
                                    nb.version.as_deref(),
                                )
                                .await
                            {
                                tracing::warn!(device = %device_id, "neighbor upsert: {e}");
                            }
                        }
                        tracing::debug!(
                            device = %device_id,
                            count = neighbors.len(),
                            "neighbor poll complete"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(device = %device_id, "neighbor poll failed: {e}");
                    }
                }
            }
        }
    });
}

/// Spawn a device health check that pings all devices every 60s.
pub fn spawn_device_health_check(device_manager: Arc<RwLock<DeviceManager>>) {
    tokio::spawn(async move {
        // 20-second startup delay
        tokio::time::sleep(Duration::from_secs(20)).await;
        tracing::info!("device health check starting (60s interval)");

        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;

        loop {
            interval.tick().await;

            let dm_read = device_manager.read().await;
            let devices: Vec<(String, MikrotikClient)> = dm_read
                .all_devices()
                .into_iter()
                .map(|d| (d.record.id.clone(), d.client.clone()))
                .collect();
            drop(dm_read);

            for (device_id, client) in &devices {
                let status = match client.test_connection().await {
                    Ok(identity) => DeviceStatus::Online { identity },
                    Err(e) => DeviceStatus::Offline {
                        error: e.to_string(),
                    },
                };

                let mut dm_w = device_manager.write().await;
                dm_w.set_status(device_id, status);
            }
        }
    });
}

use std::sync::Arc;
use std::time::Duration;

use mikrotik_core::MikrotikClient;
use ion_drift_storage::SwitchStore;
use ion_drift_storage::switch::{PortMetricEntry, VlanMembershipEntry};
use tokio::sync::{watch, RwLock};

use crate::device_manager::{DeviceClient, DeviceManager, DeviceStatus};
use crate::task_supervisor::TaskSupervisor;

/// Spawn switch pollers for all enabled RouterOS devices (switches + router).
///
/// Each device gets its own tokio task with an independent polling interval
/// from its `poll_interval_secs` configuration. Uses the PollerRegistry
/// for lifecycle management so pollers can be started/stopped dynamically.
pub fn spawn_switch_pollers(
    supervisor: &TaskSupervisor,
    device_manager: Arc<RwLock<DeviceManager>>,
    switch_store: Arc<SwitchStore>,
    poller_registry: Arc<RwLock<crate::poller_registry::PollerRegistry>>,
) {
    supervisor.spawn("switch_pollers", move || {
        let device_manager = device_manager.clone();
        let switch_store = switch_store.clone();
        let poller_registry = poller_registry.clone();
        Box::pin(async move {
    let dm = device_manager.clone();
        // 30-second startup delay to let the server stabilize
        tokio::time::sleep(Duration::from_secs(30)).await;

        let dm_read = dm.read().await;
        let mut routeros_devices: Vec<&crate::device_manager::DeviceEntry> =
            dm_read.get_switches();
        // Include the router so it also gets port metrics for backbone port selection
        if let Some(router) = dm_read.get_router() {
            routeros_devices.push(router);
        }

        if routeros_devices.is_empty() {
            tracing::info!("no RouterOS devices configured, switch poller idle");
            return;
        }

        let mut registry = poller_registry.write().await;
        for entry in routeros_devices {
            registry.start_poller(entry, device_manager.clone(), switch_store.clone());
        }
        drop(registry);
        drop(dm_read);

        // Keep the task alive — individual pollers run in their own tasks,
        // but the supervisor expects this task to stay running.
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    })});
}

/// Run the polling loop for a single RouterOS switch device.
///
/// Called by the PollerRegistry. Exits when the cancellation signal is received.
pub async fn run_switch_poller(
    device_id: String,
    client: MikrotikClient,
    store: Arc<SwitchStore>,
    dm: Arc<RwLock<DeviceManager>>,
    poll_interval: u64,
    mut cancel_rx: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(poll_interval.max(10)));

    loop {
        tokio::select! {
            _ = cancel_rx.changed() => {
                tracing::info!(device = %device_id, "switch poller cancelled");
                break;
            }
            _ = interval.tick() => {
                poll_switch(&device_id, &client, &store, &dm).await;
            }
        }
    }
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
    let (ethernet_res, monitor_res, bridge_hosts_res, bridge_ports_res, bridge_vlans_res, neighbors_res) =
        tokio::join!(
            client.ethernet_interfaces(),
            client.monitor_ethernet(),
            client.bridge_hosts(),
            client.bridge_ports(),
            client.bridge_vlans(),
            client.ip_neighbors(),
        );

    // ── Ethernet / port metrics ───────────────────────────────────
    // Build a map of actual negotiated speeds from monitor endpoint
    let monitor_speeds: std::collections::HashMap<String, String> = match &monitor_res {
        Ok(entries) => entries
            .iter()
            .filter_map(|m| m.rate.clone().map(|r| (m.name.clone(), r)))
            .collect(),
        Err(e) => {
            tracing::debug!(device = %device_id, "ethernet monitor: {e} (falling back to static speed)");
            std::collections::HashMap::new()
        }
    };

    if let Ok(interfaces) = ethernet_res {
        let entries: Vec<PortMetricEntry> = interfaces
            .iter()
            .map(|iface| {
                // Prefer actual negotiated speed from monitor, fall back to static
                let speed = monitor_speeds
                    .get(&iface.name)
                    .cloned()
                    .or_else(|| iface.speed.clone());
                PortMetricEntry {
                    port_name: iface.name.clone(),
                    rx_bytes: iface.rx_bytes.unwrap_or(0),
                    tx_bytes: iface.tx_bytes.unwrap_or(0),
                    rx_packets: iface.rx_packets.unwrap_or(0),
                    tx_packets: iface.tx_packets.unwrap_or(0),
                    speed,
                    running: iface.running,
                }
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

/// Spawn a neighbor discovery poller that runs against RouterOS devices every 120s.
///
/// SwOS devices are skipped — they don't support LLDP/neighbor discovery.
pub fn spawn_neighbor_poller(
    supervisor: &TaskSupervisor,
    device_manager: Arc<RwLock<DeviceManager>>,
    switch_store: Arc<SwitchStore>,
) {
    supervisor.spawn("neighbor_poller", move || {
        let device_manager = device_manager.clone();
        let switch_store = switch_store.clone();
        Box::pin(async move {
        // 60-second startup delay
        tokio::time::sleep(Duration::from_secs(60)).await;
        tracing::info!("neighbor discovery poller starting (RouterOS devices, 120s interval)");

        let mut interval = tokio::time::interval(Duration::from_secs(120));
        interval.tick().await;

        loop {
            interval.tick().await;

            let dm_read = device_manager.read().await;
            // Only poll RouterOS devices (SwOS has no LLDP)
            let devices: Vec<(String, MikrotikClient)> = dm_read
                .all_devices()
                .into_iter()
                .filter_map(|d| {
                    d.client
                        .as_routeros()
                        .map(|c| (d.record.id.clone(), c.clone()))
                })
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
    })});
}

/// Spawn a device health check that pings all devices every 60s.
///
/// Works with both RouterOS and SwOS devices via `DeviceClient::test_connection()`.
/// Skips devices that have been polled recently by their own per-device poller
/// (i.e. within the last `poll_interval_secs`), to avoid redundant connectivity checks.
pub fn spawn_device_health_check(supervisor: &TaskSupervisor, device_manager: Arc<RwLock<DeviceManager>>) {
    supervisor.spawn("device_health_check", move || {
        let device_manager = device_manager.clone();
        Box::pin(async move {
        // Brief startup delay to let device clients initialize
        tokio::time::sleep(Duration::from_secs(5)).await;
        tracing::info!("device health check starting (60s interval)");

        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            let now = tokio::time::Instant::now();
            let dm_read = device_manager.read().await;
            let devices: Vec<(String, DeviceClient, Option<tokio::time::Instant>, u64)> = dm_read
                .all_devices()
                .into_iter()
                .map(|d| {
                    (
                        d.record.id.clone(),
                        d.client.clone(),
                        d.last_poll,
                        d.record.poll_interval_secs as u64,
                    )
                })
                .collect();
            drop(dm_read);

            for (device_id, client, last_poll, poll_interval_secs) in &devices {
                // Skip if this device was polled recently by its own poller
                if let Some(last) = last_poll {
                    if now.duration_since(*last) < Duration::from_secs(*poll_interval_secs) {
                        tracing::trace!(
                            device = %device_id,
                            "health check: skipping, recently polled"
                        );
                        continue;
                    }
                }

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
    })});
}

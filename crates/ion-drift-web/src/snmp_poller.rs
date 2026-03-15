use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ion_drift_storage::SwitchStore;
use mikrotik_core::snmp_client::SnmpClient;
use mikrotik_core::snmp_profile::{self, InterfaceClass};
use ion_drift_storage::switch::{PortMetricEntry, VlanMembershipEntry};
use tokio::sync::{watch, RwLock};

use crate::device_manager::{DeviceManager, DeviceStatus};

/// Spawn SNMP pollers for all enabled SNMP switch devices.
///
/// Each switch gets its own tokio task with an independent polling interval
/// from its `poll_interval_secs` configuration (default 30s). Uses the
/// PollerRegistry for lifecycle management.
pub fn spawn_snmp_pollers(
    device_manager: Arc<RwLock<DeviceManager>>,
    switch_store: Arc<SwitchStore>,
    poller_registry: Arc<RwLock<crate::poller_registry::PollerRegistry>>,
) {
    let dm = device_manager.clone();
    tokio::spawn(async move {
        // 30-second startup delay to let the server stabilize
        tokio::time::sleep(Duration::from_secs(30)).await;

        let dm_read = dm.read().await;
        let switches = dm_read.get_snmp_switches();

        if switches.is_empty() {
            tracing::info!("no SNMP switch devices configured, SNMP poller idle");
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

/// Run the polling loop for a single SNMP switch device.
///
/// Called by the PollerRegistry. Exits when the cancellation signal is received.
pub async fn run_snmp_poller(
    device_id: String,
    client: SnmpClient,
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
                tracing::info!(device = %device_id, "SNMP poller cancelled");
                break;
            }
            _ = interval.tick() => {
                poll_snmp_switch(&device_id, &client, &store, &dm, cycle).await;
                cycle = cycle.wrapping_add(1);
            }
        }
    }
}

/// Run one poll cycle for an SNMP switch device.
async fn poll_snmp_switch(
    device_id: &str,
    client: &SnmpClient,
    store: &SwitchStore,
    dm: &Arc<RwLock<DeviceManager>>,
    cycle: u32,
) {
    // ── System info (connectivity check) ────────────────────────────
    let sys = match client.get_system_info().await {
        Ok(sys) => {
            let mut dm_w = dm.write().await;
            dm_w.set_status(
                device_id,
                DeviceStatus::Online {
                    identity: sys.sys_name.clone(),
                },
            );
            sys
        }
        Err(e) => {
            tracing::warn!(device = %device_id, error = %e, "SNMP poll: connectivity failed");
            let mut dm_w = dm.write().await;
            dm_w.set_status(
                device_id,
                DeviceStatus::Offline {
                    error: e.to_string(),
                },
            );
            return;
        }
    };

    // ── Interfaces (port names, counters, MAC addresses) ────────────
    let interfaces = match client.get_interfaces().await {
        Ok(ifaces) => ifaces,
        Err(e) => {
            tracing::warn!(device = %device_id, "SNMP interfaces: {e}");
            Vec::new()
        }
    };

    // Detect vendor profile from sysDescr and classify interfaces
    let profile = snmp_profile::detect_profile(&sys.sys_descr);
    tracing::debug!(device = %device_id, vendor = %profile.vendor, "SNMP profile detected");

    let classified = snmp_profile::classify_interfaces(&interfaces, profile);

    // Build ifIndex -> ifName map for resolving bridge port numbers (includes ALL interfaces)
    let if_name_map: HashMap<u32, String> = interfaces
        .iter()
        .map(|i| (i.index, i.name.clone()))
        .collect();

    // Build ifIndex -> canonical name map for port metric/MAC name resolution
    let canonical_name_map: HashMap<u32, String> = classified
        .iter()
        .filter(|i| i.class == InterfaceClass::Physical)
        .map(|i| (i.index, i.canonical_name.clone()))
        .collect();

    // Physical port names for VLAN membership filtering
    let physical_port_names: std::collections::HashSet<String> = canonical_name_map
        .values()
        .cloned()
        .collect();

    // On first cycle, purge any stale port metrics/MAC entries with non-canonical
    // names (e.g., from before the profile was applied or after a name change)
    if cycle == 0 && !physical_port_names.is_empty() {
        if let Err(e) = store.purge_non_canonical_ports(device_id, &physical_port_names).await {
            tracing::warn!(device = %device_id, "purge non-canonical ports: {e}");
        }
    }

    // Collect interface MACs for is_local detection
    let local_macs: Vec<String> = interfaces
        .iter()
        .filter_map(|i| i.mac_address.clone())
        .collect();

    // ── Bridge port -> ifIndex mapping ──────────────────────────────
    let bridge_port_map = match client.get_bridge_port_map().await {
        Ok(map) => map,
        Err(e) => {
            tracing::debug!(device = %device_id, "SNMP bridge port map: {e}");
            HashMap::new()
        }
    };

    // ── MAC table + LLDP neighbors (sequential to reduce load) ─────
    // Each method creates a new SNMPv3 session — running them concurrently
    // overwhelms low-end switches (Netgear) with dual engine discovery.
    let mac_res = client.get_mac_table().await;
    let lldp_res = client.get_lldp_neighbors().await;

    // ── Port metrics (physical ports only, from classified interfaces) ──
    let physical: Vec<_> = classified
        .iter()
        .filter(|i| i.class == InterfaceClass::Physical)
        .collect();

    if !physical.is_empty() {
        let entries: Vec<PortMetricEntry> = physical
            .iter()
            .map(|iface| {
                let speed = if iface.speed_mbps > 0 {
                    Some(format!("{}Mbps", iface.speed_mbps))
                } else {
                    None
                };
                PortMetricEntry {
                    port_name: iface.canonical_name.clone(),
                    port_index: iface.index as u16,
                    rx_bytes: iface.rx_bytes,
                    tx_bytes: iface.tx_bytes,
                    rx_packets: iface.rx_packets,
                    tx_packets: iface.tx_packets,
                    speed,
                    running: iface.oper_status,
                }
            })
            .collect();

        if let Err(e) = store.record_port_metrics(device_id, &entries).await {
            tracing::warn!(device = %device_id, "SNMP port metrics: {e}");
        }
    }

    // ── MAC table entries ───────────────────────────────────────────
    let mut mac_entries = match mac_res {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(device = %device_id, "SNMP Q-BRIDGE MAC table: {e}");
            Vec::new()
        }
    };

    // Fallback to BRIDGE-MIB if Q-BRIDGE returned nothing
    if mac_entries.is_empty() {
        match client.get_mac_table_bridge().await {
            Ok(entries) => {
                tracing::debug!(
                    device = %device_id,
                    count = entries.len(),
                    "SNMP BRIDGE-MIB fallback MAC table"
                );
                mac_entries = entries;
            }
            Err(e) => {
                tracing::debug!(device = %device_id, "SNMP BRIDGE-MIB MAC table: {e}");
            }
        }
    }

    for entry in &mac_entries {
        // Resolve bridge port -> ifIndex -> canonical name (or raw ifName fallback)
        let if_idx = bridge_port_map.get(&entry.port_index).copied();
        let port_name = if_idx
            .and_then(|idx| canonical_name_map.get(&idx).cloned())
            .or_else(|| if_idx.and_then(|idx| if_name_map.get(&idx).cloned()))
            .unwrap_or_else(|| format!("port{}", entry.port_index));

        let is_local = local_macs
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&entry.mac_address));

        let vlan_id = entry.vlan_id.map(|v| v as u32);

        if let Err(e) = store
            .upsert_mac_entry(device_id, &entry.mac_address, &port_name, "snmp", vlan_id, is_local)
            .await
        {
            tracing::warn!(
                device = %device_id,
                mac = %entry.mac_address,
                "SNMP mac upsert: {e}"
            );
        }
    }

    // ── LLDP neighbors ──────────────────────────────────────────────
    if let Ok(neighbors) = lldp_res {
        for nb in &neighbors {
            // Resolve local port index to canonical name (or raw ifName fallback)
            let interface = canonical_name_map
                .get(&nb.local_port_index)
                .or_else(|| if_name_map.get(&nb.local_port_index))
                .cloned()
                .unwrap_or_else(|| format!("port{}", nb.local_port_index));

            if let Err(e) = store
                .upsert_neighbor(
                    device_id,
                    &interface,
                    nb.remote_chassis_id.as_deref(),
                    None, // no IP address from LLDP
                    Some(&nb.remote_sys_name),
                    Some(&nb.remote_port_id),
                    nb.remote_port_desc.as_deref(),
                    None, // no version from LLDP
                )
                .await
            {
                tracing::warn!(device = %device_id, "SNMP neighbor upsert: {e}");
            }
        }

        tracing::info!(
            device = %device_id,
            identity = %sys.sys_name,
            interfaces = interfaces.len(),
            macs = mac_entries.len(),
            lldp = neighbors.len(),
            "SNMP poll cycle complete"
        );
    } else if let Err(e) = lldp_res {
        tracing::warn!(device = %device_id, "SNMP LLDP: {e}");
    }

    // ── VLAN membership (every 4th cycle to reduce load) ────────────
    if cycle % 4 == 0 {
        match client.get_vlan_membership().await {
            Ok(vlans) => {
                let mut membership_entries = Vec::new();

                for vlan in &vlans {
                    let untagged_set: std::collections::HashSet<u32> =
                        vlan.untagged_ports.iter().copied().collect();

                    for &port_idx in &vlan.egress_ports {
                        // Resolve port index -> canonical name (or raw ifName fallback)
                        let if_idx = bridge_port_map.get(&port_idx).copied();
                        let port_name = if_idx
                            .and_then(|idx| canonical_name_map.get(&idx).cloned())
                            .or_else(|| if_idx.and_then(|idx| if_name_map.get(&idx).cloned()))
                            .unwrap_or_else(|| format!("port{}", port_idx));

                        // Skip non-physical ports (VLANs, tunnels, loopback, etc.)
                        if !physical_port_names.contains(&port_name) {
                            continue;
                        }

                        let tagged = !untagged_set.contains(&port_idx);

                        membership_entries.push(VlanMembershipEntry {
                            port_name,
                            vlan_id: vlan.vlan_id as u32,
                            tagged,
                        });
                    }
                }

                if let Err(e) = store.set_vlan_membership(device_id, &membership_entries).await {
                    tracing::warn!(device = %device_id, "SNMP vlan membership: {e}");
                }
            }
            Err(e) => {
                tracing::debug!(device = %device_id, "SNMP vlan membership: {e}");
            }
        }
    }
}

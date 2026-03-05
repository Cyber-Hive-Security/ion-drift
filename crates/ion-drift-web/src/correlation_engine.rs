use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use mikrotik_core::{MikrotikClient, SwitchStore};
use mikrotik_core::switch_store::{BackboneLink, MacTableEntry};
use tokio::sync::RwLock;

use crate::device_manager::DeviceManager;
use crate::oui::OuiDb;

/// Technitium internal DNS server for PTR lookups.
const DNS_SERVER: IpAddr = {
    // 10.20.25.6 — const IpAddr construction
    use std::net::{IpAddr, Ipv4Addr};
    IpAddr::V4(Ipv4Addr::new(10, 20, 25, 6))
};

/// Spawn the correlation engine that runs every 60s to:
/// 1. Classify port roles (access/trunk/uplink/unused)
/// 2. Build unified network identities from MAC/neighbor/OUI/ARP/DHCP data
pub fn spawn_correlation_engine(
    switch_store: Arc<SwitchStore>,
    oui_db: Arc<OuiDb>,
    device_manager: Arc<RwLock<DeviceManager>>,
    router_client: MikrotikClient,
) {
    tokio::spawn(async move {
        // 90-second startup delay — let switch pollers collect initial data
        tokio::time::sleep(Duration::from_secs(90)).await;
        tracing::info!("correlation engine starting (60s interval)");

        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;

        loop {
            interval.tick().await;

            if let Err(e) = run_correlation(&switch_store, &oui_db, &device_manager, &router_client).await {
                tracing::warn!("correlation engine error: {e}");
            }
        }
    });
}

async fn run_correlation(
    store: &SwitchStore,
    oui_db: &OuiDb,
    device_manager: &Arc<RwLock<DeviceManager>>,
    router_client: &MikrotikClient,
) -> anyhow::Result<()> {
    // ── 0. Prune stale entries ──────────────────────────────────
    // Entries older than 1 hour are leftovers from port renames or
    // devices that moved. Keeps tables reflecting current state.
    match store.prune_stale_mac_entries(3600).await {
        Ok(n) if n > 0 => tracing::info!(count = n, "pruned stale MAC table entries"),
        Err(e) => tracing::warn!("MAC table prune failed: {e}"),
        _ => {}
    }
    match store.prune_renamed_port_metrics(3600).await {
        Ok(n) if n > 0 => tracing::info!(count = n, "pruned renamed port metrics"),
        Err(e) => tracing::warn!("port metrics prune failed: {e}"),
        _ => {}
    }
    match store.prune_stale_port_roles(3600).await {
        Ok(n) if n > 0 => tracing::info!(count = n, "pruned stale port roles"),
        Err(e) => tracing::warn!("port roles prune failed: {e}"),
        _ => {}
    }

    // ── 0b. Sync VLAN config from router ─────────────────────────
    // Discovers VLANs from the router's VLAN interfaces and IP addresses.
    // Only inserts new VLANs — never overwrites human edits.
    if let Err(e) = sync_vlan_config_from_router(store, router_client).await {
        tracing::warn!("VLAN config sync: {e}");
    }

    // Load VLAN configs for use throughout correlation (subnet matching, wireless detection)
    let vlan_configs = store.get_vlan_configs().await.unwrap_or_default();

    // Build subnet list for VLAN-from-IP inference
    let vlan_subnets: Vec<(u32, String)> = vlan_configs
        .iter()
        .filter_map(|c| c.subnet.as_ref().filter(|s| !s.is_empty()).map(|s| (c.vlan_id, s.clone())))
        .collect();

    // ── 1. Port role classification ───────────────────────────────
    let dm_read = device_manager.read().await;
    let switches = dm_read.get_switches();
    let switch_ids: Vec<String> = switches.iter().map(|d| d.record.id.clone()).collect();
    let router_id = dm_read
        .get_router()
        .map(|r| r.record.id.clone())
        .unwrap_or_else(|| "rb4011".to_string());
    drop(dm_read);

    // Fetch the router's bridge hosts so its local MACs enter the MAC table.
    // Without this, the router's port MACs (seen by switches on trunk ports)
    // would never be identified as switch-local and would leak into identities.
    match router_client.bridge_hosts().await {
        Ok(hosts) => {
            for host in &hosts {
                let on_iface = host.on_interface.as_deref().unwrap_or("");
                let is_local = host.local.unwrap_or(false);
                if let Err(e) = store
                    .upsert_mac_entry(
                        &router_id,
                        &host.mac_address,
                        on_iface,
                        &host.bridge,
                        None,
                        is_local,
                    )
                    .await
                {
                    tracing::warn!(mac = %host.mac_address, "router bridge host upsert: {e}");
                }
            }
        }
        Err(e) => tracing::warn!("correlation: router bridge_hosts fetch failed: {e}"),
    }

    let device_ids: Vec<String> = switch_ids.clone();

    for device_id in &device_ids {
        let mac_entries = store.get_mac_table(Some(device_id)).await?;
        let vlan_entries = store.get_vlan_membership(device_id).await?;

        // Count MACs per port (skip switch-local MACs — they're the switch's own port addresses)
        let mut mac_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for entry in &mac_entries {
            if entry.is_local {
                continue;
            }
            *mac_counts.entry(entry.port_name.clone()).or_default() += 1;
        }

        // Count VLANs per port
        let mut vlan_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for entry in &vlan_entries {
            *vlan_counts.entry(entry.port_name.clone()).or_default() += 1;
        }

        // Check LLDP neighbors per port
        let neighbors = store.get_neighbors(Some(device_id)).await?;
        let mut has_neighbor: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for nb in &neighbors {
            has_neighbor.insert(nb.interface.clone());
        }

        // Collect all known port names
        let mut all_ports: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        all_ports.extend(mac_counts.keys().cloned());
        all_ports.extend(vlan_counts.keys().cloned());

        for port_name in &all_ports {
            let mac_count = mac_counts.get(port_name).copied().unwrap_or(0);
            let vlan_count = vlan_counts.get(port_name).copied().unwrap_or(0);
            let has_lldp = has_neighbor.contains(port_name);

            let role = classify_port_role(mac_count, vlan_count, has_lldp);

            if let Err(e) = store
                .set_port_role(device_id, port_name, &role, vlan_count, mac_count, has_lldp)
                .await
            {
                tracing::warn!(device = %device_id, port = %port_name, "port role: {e}");
            }
        }
    }

    // ── 1b. Build switch-local MAC ranges ─────────────────────────
    // Manufacturers assign sequential MACs to switch/router ports. By collecting
    // all is_local=true MACs per device and computing [min, max], we can
    // identify the full block — catching infrastructure MACs even when they
    // appear from other data sources (ARP, DHCP, neighbor tables, or
    // other switches' MAC tables where they are NOT marked local).
    let mut all_infra_ids = device_ids.clone();
    all_infra_ids.push(router_id.clone());
    let switch_local_macs = build_switch_local_mac_set(store, &all_infra_ids).await;

    // Clean up any existing identities that we now recognise as infrastructure MACs.
    // These may have been created in earlier cycles before the range was computed.
    if !switch_local_macs.is_empty() {
        let existing = store.get_network_identities().await.unwrap_or_default();
        let mut purged = 0u32;
        for ident in &existing {
            if is_switch_local_mac(&ident.mac_address, &switch_local_macs) {
                if let Ok(true) = store.delete_network_identity(&ident.mac_address).await {
                    purged += 1;
                }
            }
        }
        if purged > 0 {
            tracing::info!(count = purged, "purged infrastructure MAC identities");
        }
    }

    // ── 2. Unified identity assembly ──────────────────────────────
    let all_macs = store.get_mac_table(None).await?;
    let all_neighbors = store.get_neighbors(None).await?;

    // ── 2a. Trunk port detection + peer resolution ──────────────
    // Identify trunk/uplink ports so we can deprioritise their MAC bindings.
    // MACs learned on a trunk port are *transiting*, not directly connected.
    let port_roles = store.get_port_roles(None).await.unwrap_or_default();
    let mut trunk_ports: HashSet<(String, String)> = port_roles
        .iter()
        .filter(|r| r.role == "trunk" || r.role == "uplink")
        .map(|r| (r.device_id.clone(), r.port_name.to_lowercase()))
        .collect();

    // Force backbone-linked ports to trunk role (fills in what LLDP would provide
    // for non-LLDP switches like SwOS devices).
    let backbone_links = store.get_backbone_links().await.unwrap_or_default();
    for link in &backbone_links {
        if let Some(ref port) = link.port_a {
            trunk_ports.insert((link.device_a.clone(), port.to_lowercase()));
            let _ = store.set_port_role(&link.device_a, port, "trunk", 0, 0, false).await;
        }
        if let Some(ref port) = link.port_b {
            trunk_ports.insert((link.device_b.clone(), port.to_lowercase()));
            let _ = store.set_port_role(&link.device_b, port, "trunk", 0, 0, false).await;
        }
    }

    // Build device resolution maps for LLDP identity → device_id
    let dm_read = device_manager.read().await;
    let mut lldp_identity_to_device: HashMap<String, String> = HashMap::new();
    let mut lldp_ip_to_device: HashMap<String, String> = HashMap::new();
    for entry in dm_read.all_devices() {
        lldp_identity_to_device.insert(entry.record.name.to_lowercase(), entry.record.id.clone());
        lldp_identity_to_device.insert(entry.record.id.to_lowercase(), entry.record.id.clone());
        lldp_ip_to_device.insert(entry.record.host.clone(), entry.record.id.clone());
    }
    drop(dm_read);

    // Build trunk peer map: (device_id, normalized_port) → peer_device_id.
    // When a MAC is only seen on a trunk port, we redirect it to the peer
    // device (e.g. router's trunk to CRS326 → attribute MAC to CRS326).
    let mut trunk_peer: HashMap<(String, String), String> = HashMap::new();
    for nb in &all_neighbors {
        let resolved = nb
            .identity
            .as_deref()
            .and_then(|id| lldp_identity_to_device.get(&id.to_lowercase()).cloned())
            .or_else(|| {
                nb.address
                    .as_deref()
                    .and_then(|addr| lldp_ip_to_device.get(addr).cloned())
            });
        if let Some(peer_id) = resolved {
            // Normalize LLDP interface: "1-sfp-sfpplus,B-VLANs" → "1-sfp-sfpplus"
            let port = nb.interface.split(',').next().unwrap_or(&nb.interface);
            trunk_peer.insert((nb.device_id.clone(), port.to_lowercase()), peer_id);
        }
    }

    // Add backbone links as trunk peers (don't overwrite LLDP-derived peers).
    for link in &backbone_links {
        if let Some(ref port) = link.port_a {
            trunk_peer.entry((link.device_a.clone(), port.to_lowercase()))
                .or_insert_with(|| link.device_b.clone());
        }
        if let Some(ref port) = link.port_b {
            trunk_peer.entry((link.device_b.clone(), port.to_lowercase()))
                .or_insert_with(|| link.device_a.clone());
        }
    }

    // Build wireless VLAN set for WAP attribution.
    let wireless_vlans: HashSet<u32> = vlan_configs
        .iter()
        .filter(|v| v.media_type == "wireless" || v.media_type == "mixed")
        .map(|v| v.vlan_id)
        .collect();

    // Compute switch depth from router via BFS over backbone + LLDP adjacency.
    // Deeper switches get higher priority scores — a MAC on a depth-2 switch
    // trunk is more specific than the same MAC on a depth-1 switch trunk.
    let switch_depths = compute_switch_depths(&backbone_links, &trunk_peer, &router_id);
    if !switch_depths.is_empty() {
        let depth_summary: Vec<String> = switch_depths
            .iter()
            .filter(|(id, _)| *id != &router_id)
            .map(|(id, d)| format!("{}={}", id, d))
            .collect();
        tracing::info!(router = %router_id, depths = ?depth_summary, "switch depth map");
    }

    // Build a map: MAC → best known info
    let mut identity_map: HashMap<String, IdentityBuilder> = HashMap::new();

    // From MAC table — priority-based binding.
    // Access port (directly connected) beats switch trunk (downstream aggregation)
    // which beats router trunk (sees everything via ARP gateway).
    for entry in &all_macs {
        if entry.is_local {
            continue;
        }
        if is_switch_local_mac(&entry.mac_address, &switch_local_macs) {
            continue;
        }

        let is_trunk = trunk_ports.contains(&(entry.device_id.clone(), entry.port_name.to_lowercase()));
        let is_router = entry.device_id == router_id;
        let depth = switch_depths.get(&entry.device_id).copied().unwrap_or(0);
        // Priority formula:
        //   Router:      100         — always lowest, sees every MAC via bridge
        //   Switch trunk: 200+depth*10 — deeper trunk = closer to device (correct)
        //   Access port:  400-depth*10 — shallower access = more trustworthy
        //
        // Why invert depth for access? A MAC can appear on "access" ports of
        // multiple switches when a deeper switch's uplink is misclassified
        // (e.g. SwOS port name doesn't match backbone link). The shallower
        // switch's access port is more likely the genuine connection.
        // Access always beats trunk (min 310 vs max ~240).
        let new_priority: u32 = if is_router {
            100
        } else if is_trunk {
            200 + depth * 10
        } else {
            400_u32.saturating_sub(depth * 10)
        };

        let builder = identity_map
            .entry(entry.mac_address.to_uppercase())
            .or_insert_with(IdentityBuilder::default);

        // Only update switch binding if new priority strictly dominates.
        // Equal priority → no change (eliminates flapping between same-class ports).
        if new_priority > builder.binding_priority {
            builder.switch_device_id = Some(entry.device_id.clone());
            builder.switch_port = Some(entry.port_name.clone());
            builder.binding_priority = new_priority;
            builder.binding_last_seen = entry.last_seen;
        }

        if entry.vlan_id.is_some() {
            builder.vlan_id = entry.vlan_id;
        }
    }

    // ── 2b. Trunk redirection (downstream only) ─────────────────
    // MACs still bound to a trunk port get redirected to the peer device on
    // that trunk, but ONLY if the peer is deeper (downstream). Redirecting
    // upstream (toward the router) would be wrong — a MAC on CRS326's uplink
    // should not be attributed to the router.
    {
        let mut redirected = 0u32;
        for builder in identity_map.values_mut() {
            let dev = builder.switch_device_id.clone();
            let port = builder.switch_port.clone();
            if let (Some(dev), Some(port)) = (dev, port) {
                if trunk_ports.contains(&(dev.clone(), port.to_lowercase())) {
                    let normalized = port.split(',').next().unwrap_or(&port).to_lowercase();
                    if let Some(peer_id) =
                        trunk_peer.get(&(dev.clone(), normalized))
                    {
                        let current_depth = switch_depths.get(&dev).copied().unwrap_or(0);
                        let peer_depth = switch_depths.get(peer_id.as_str()).copied().unwrap_or(0);
                        // Only redirect downstream — peer must be deeper than current
                        if peer_depth > current_depth {
                            builder.switch_device_id = Some(peer_id.clone());
                            builder.switch_port = None;
                            builder.binding_priority = 200 + peer_depth * 10;
                            redirected += 1;
                        }
                    }
                }
            }
        }
        if redirected > 0 {
            tracing::info!(count = redirected, "trunk port MACs redirected to downstream peer");
        }
    }

    // ── 2c. WAP attribution for wireless devices ──────────────────
    // Devices on wireless VLANs are attributed to WAPs instead of switches
    // when the switch has exactly one WAP child in the backbone links.
    {
        // Build WAP child map: switch_id → list of WAP identifiers
        let infra_identities = store.get_infrastructure_identities().await.unwrap_or_default();
        let wap_identifiers: HashSet<String> = infra_identities
            .iter()
            .filter(|i| {
                matches!(
                    i.device_type.as_deref(),
                    Some("access_point") | Some("wap")
                )
            })
            .filter_map(|i| i.hostname.clone().or(Some(i.mac_address.clone())))
            .collect();

        let wap_children = build_wap_children(&backbone_links, &wap_identifiers);
        let mut wap_attributed = 0u32;

        for builder in identity_map.values_mut() {
            // Only consider devices on wireless VLANs
            match builder.vlan_id {
                Some(v) if wireless_vlans.contains(&v) => {}
                _ => continue,
            };

            let switch_id = match &builder.switch_device_id {
                Some(id) => id.clone(),
                None => continue,
            };

            // If this switch has exactly one WAP child, attribute to that WAP
            if let Some(waps) = wap_children.get(&switch_id) {
                if waps.len() == 1 {
                    builder.switch_device_id = Some(waps[0].clone());
                    builder.switch_port = None;
                    wap_attributed += 1;
                }
            }
        }

        if wap_attributed > 0 {
            tracing::info!(count = wap_attributed, "wireless devices attributed to WAPs");
        }
    }

    // From neighbor discovery — skip infrastructure MACs
    for nb in &all_neighbors {
        let mac = match &nb.mac_address {
            Some(m) if !m.is_empty() => m.to_uppercase(),
            _ => continue,
        };
        if is_switch_local_mac(&mac, &switch_local_macs) {
            continue;
        }
        let builder = identity_map
            .entry(mac)
            .or_insert_with(IdentityBuilder::default);

        if let Some(ref addr) = nb.address {
            builder.best_ip = Some(addr.clone());
        }
        if let Some(ref identity) = nb.identity {
            builder.hostname = Some(identity.clone());
            builder.remote_identity = Some(identity.clone());
        }
        if let Some(ref platform) = nb.platform {
            builder.remote_platform = Some(platform.clone());
            // LLDP platform often reveals device type at high confidence
            let plat_lower = platform.to_lowercase();
            if plat_lower.contains("routeros") || plat_lower.contains("mikrotik") {
                if builder.device_type_confidence < 0.95 {
                    builder.device_type = Some("network_equipment".to_string());
                    builder.device_type_source = Some("lldp".to_string());
                    builder.device_type_confidence = 0.95;
                }
            }
        }
        builder.discovery_protocol = Some("LLDP/MNDP".to_string());
    }

    // From router ARP table — MAC→IP for every active device on the network
    match router_client.arp_table().await {
        Ok(arp_entries) => {
            for entry in &arp_entries {
                if let Some(ref mac) = entry.mac_address {
                    if is_switch_local_mac(mac, &switch_local_macs) {
                        continue;
                    }
                    let mac_upper = mac.to_uppercase();
                    let builder = identity_map
                        .entry(mac_upper)
                        .or_insert_with(IdentityBuilder::default);
                    if builder.best_ip.is_none() {
                        builder.best_ip = Some(entry.address.clone());
                    }
                }
            }
        }
        Err(e) => tracing::warn!("correlation: ARP fetch failed: {e}"),
    }

    // From router DHCP leases — MAC→IP + hostname for every lease
    match router_client.dhcp_leases().await {
        Ok(leases) => {
            for lease in &leases {
                if let Some(ref mac) = lease.mac_address {
                    if is_switch_local_mac(mac, &switch_local_macs) {
                        continue;
                    }
                    let mac_upper = mac.to_uppercase();
                    let builder = identity_map
                        .entry(mac_upper)
                        .or_insert_with(IdentityBuilder::default);
                    // DHCP address is authoritative — prefer over ARP
                    builder.best_ip = Some(lease.address.clone());
                    if let Some(ref hostname) = lease.host_name {
                        if !hostname.is_empty() && builder.hostname.is_none() {
                            builder.hostname = Some(hostname.clone());
                        }
                    }
                }
            }
        }
        Err(e) => tracing::warn!("correlation: DHCP fetch failed: {e}"),
    }

    // Reverse DNS (PTR) lookups against Technitium for devices with IP but no hostname.
    // This catches devices that have DNS records but don't advertise via DHCP or LLDP.
    let ips_needing_ptr: Vec<(String, String)> = identity_map
        .iter()
        .filter(|(_, b)| b.hostname.is_none() && b.best_ip.is_some())
        .map(|(mac, b)| (mac.clone(), b.best_ip.clone().unwrap()))
        .collect();

    if !ips_needing_ptr.is_empty() {
        match build_ptr_resolver() {
            Ok(resolver) => {
                let mut resolved = 0u32;
                for (mac, ip) in &ips_needing_ptr {
                    if let Ok(addr) = ip.parse::<IpAddr>() {
                        match tokio::time::timeout(
                            Duration::from_millis(500),
                            resolver.reverse_lookup(addr),
                        )
                        .await
                        {
                            Ok(Ok(lookup)) => {
                                if let Some(name) = lookup.iter().next() {
                                    let hostname = name.to_string().trim_end_matches('.').to_string();
                                    if !hostname.is_empty() {
                                        if let Some(builder) = identity_map.get_mut(mac) {
                                            builder.hostname = Some(hostname);
                                            resolved += 1;
                                        }
                                    }
                                }
                            }
                            Ok(Err(_)) => {} // no PTR record — that's fine
                            Err(_) => {}     // timeout — skip
                        }
                    }
                }
                if resolved > 0 {
                    tracing::debug!(resolved, total = ips_needing_ptr.len(), "PTR lookups");
                }
            }
            Err(e) => tracing::warn!("correlation: PTR resolver setup failed: {e}"),
        }
    }

    // Infer VLAN from IP when not already set.
    // In this environment the third octet of the IP maps to the VLAN ID:
    //   10.2.2.x → VLAN 2, 172.20.6.x → VLAN 6, 10.20.25.x → VLAN 25,
    //   192.168.90.x → VLAN 90, etc.
    for builder in identity_map.values_mut() {
        if builder.vlan_id.is_none() {
            if let Some(ref ip) = builder.best_ip {
                if let Some(vlan) = vlan_from_ip(ip, &vlan_subnets) {
                    builder.vlan_id = Some(vlan);
                }
            }
        }
    }

    // Enrich with OUI manufacturer + device type inference
    for (mac, builder) in &mut identity_map {
        if let Some(manufacturer) = oui_db.lookup(mac) {
            builder.manufacturer = Some(manufacturer.to_string());
            // Infer device type from manufacturer name
            if let Some((device_type, confidence)) =
                OuiDb::device_type_from_manufacturer(manufacturer)
            {
                builder.device_type = Some(device_type.to_string());
                builder.device_type_source = Some("oui".to_string());
                builder.device_type_confidence = confidence;
            }
        }
    }

    // Write all identities
    let mut upserted = 0u32;
    for (mac, builder) in &identity_map {
        // Compute a simple confidence score based on how many fields we have
        let confidence = builder.confidence_score();

        if let Err(e) = store
            .upsert_network_identity(
                mac,
                builder.best_ip.as_deref(),
                builder.hostname.as_deref(),
                builder.manufacturer.as_deref(),
                builder.switch_device_id.as_deref(),
                builder.switch_port.as_deref(),
                builder.vlan_id,
                builder.discovery_protocol.as_deref(),
                builder.remote_identity.as_deref(),
                builder.remote_platform.as_deref(),
                confidence,
                builder.device_type.as_deref(),
                builder.device_type_source.as_deref(),
                builder.device_type_confidence,
            )
            .await
        {
            tracing::warn!(mac = %mac, "identity upsert: {e}");
        } else {
            upserted += 1;
        }
    }

    // ── 5. Port binding enforcement ──────────────────────────────
    // For each MAC-to-port binding, compare expected MAC against actual.
    // Generate violations when mismatched; auto-resolve when correct.
    let bindings = store.get_port_bindings(None).await.unwrap_or_default();
    let mut violations_created = 0u32;
    let mut violations_resolved = 0u32;

    for binding in &bindings {
        // Find the actual MAC on this port from the MAC table
        let port_macs: Vec<&MacTableEntry> = all_macs
            .iter()
            .filter(|e| {
                e.device_id == binding.device_id
                    && e.port_name == binding.port_name
                    && !e.is_local
                    && !is_switch_local_mac(&e.mac_address, &switch_local_macs)
            })
            .collect();

        let expected_upper = binding.expected_mac.to_uppercase();

        if port_macs.is_empty() {
            // No MAC on this port → device missing
            if let Err(e) = store
                .upsert_port_violation(
                    &binding.device_id,
                    &binding.port_name,
                    &expected_upper,
                    None,
                    "device_missing",
                )
                .await
            {
                tracing::warn!(
                    device = %binding.device_id, port = %binding.port_name,
                    "port violation upsert: {e}"
                );
            } else {
                violations_created += 1;
            }
        } else {
            let actual_mac = port_macs[0].mac_address.to_uppercase();
            if actual_mac != expected_upper {
                // Wrong MAC on this port
                if let Err(e) = store
                    .upsert_port_violation(
                        &binding.device_id,
                        &binding.port_name,
                        &expected_upper,
                        Some(&actual_mac),
                        "mac_mismatch",
                    )
                    .await
                {
                    tracing::warn!(
                        device = %binding.device_id, port = %binding.port_name,
                        "port violation upsert: {e}"
                    );
                } else {
                    violations_created += 1;
                }
            } else {
                // Correct MAC — auto-resolve any existing violations
                match store
                    .auto_resolve_violations(&binding.device_id, &binding.port_name)
                    .await
                {
                    Ok(n) => violations_resolved += n as u32,
                    Err(e) => tracing::warn!(
                        device = %binding.device_id, port = %binding.port_name,
                        "auto-resolve violations: {e}"
                    ),
                }
            }
        }
    }

    if upserted > 0 || violations_created > 0 || violations_resolved > 0 {
        tracing::debug!(
            identities = upserted,
            switches = device_ids.len(),
            violations_new = violations_created,
            violations_resolved = violations_resolved,
            "correlation cycle complete"
        );
    }

    Ok(())
}

/// Classify a port's role based on MAC count, VLAN count, and LLDP neighbor presence.
fn classify_port_role(mac_count: u32, vlan_count: u32, has_lldp: bool) -> String {
    if vlan_count > 1 {
        "trunk".to_string()
    } else if has_lldp {
        "uplink".to_string()
    } else if mac_count > 10 {
        "uplink".to_string()
    } else if mac_count == 0 {
        "unused".to_string()
    } else {
        "access".to_string()
    }
}

/// Intermediate struct for building a network identity from multiple sources.
#[derive(Default)]
struct IdentityBuilder {
    best_ip: Option<String>,
    hostname: Option<String>,
    manufacturer: Option<String>,
    switch_device_id: Option<String>,
    switch_port: Option<String>,
    vlan_id: Option<u32>,
    discovery_protocol: Option<String>,
    remote_identity: Option<String>,
    remote_platform: Option<String>,
    device_type: Option<String>,
    device_type_source: Option<String>,
    device_type_confidence: f64,
    /// Priority of the current switch binding. Higher = closer to device.
    /// Router=100, trunk=200+depth*10, access=400-depth*10.
    binding_priority: u32,
    /// Timestamp of the MAC table entry that set the current binding.
    /// Used to break ties when multiple entries have the same priority.
    binding_last_seen: i64,
}

impl IdentityBuilder {
    /// Compute a confidence score (0.0 to 1.0) based on available data.
    fn confidence_score(&self) -> f64 {
        let mut score = 0.0;
        if self.best_ip.is_some() { score += 0.2; }
        if self.hostname.is_some() { score += 0.2; }
        if self.manufacturer.is_some() { score += 0.15; }
        if self.switch_port.is_some() { score += 0.15; }
        if self.discovery_protocol.is_some() { score += 0.15; }
        if self.vlan_id.is_some() { score += 0.15; }
        score
    }
}

/// Infer VLAN ID from an IP address using the vlan_config subnet data.
/// Falls back to third-octet heuristic for VLANs not yet in the DB.
fn vlan_from_ip(ip: &str, vlan_subnets: &[(u32, String)]) -> Option<u32> {
    let ip_addr: std::net::Ipv4Addr = ip.parse().ok()?;
    let ip_u32 = u32::from(ip_addr);

    // Try DB-sourced subnets first (exact CIDR match)
    for (vlan_id, cidr) in vlan_subnets {
        if let Some((net, mask_bits)) = parse_cidr(cidr) {
            let mask = if mask_bits == 0 { 0 } else { !0u32 << (32 - mask_bits) };
            if (ip_u32 & mask) == (net & mask) {
                return Some(*vlan_id);
            }
        }
    }

    // Fallback: third-octet heuristic for any VLANs not in DB yet
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let third: u32 = octets[2].parse().ok()?;
    match (octets[0], octets[1], third) {
        ("10", "2", 2) => Some(2),
        ("172", "20", 6) => Some(6),
        ("172", "20", 10) => Some(10),
        ("10", "20", 25) => Some(25),
        ("10", "20", 30) => Some(30),
        ("10", "20", 35) => Some(35),
        ("172", "20", 40) => Some(40),
        ("192", "168", 90) => Some(90),
        ("192", "168", 99) => Some(99),
        _ => None,
    }
}

/// Parse a CIDR string like "10.20.25.0/24" into (network_u32, mask_bits).
fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let addr: std::net::Ipv4Addr = parts[0].parse().ok()?;
    let bits: u32 = parts[1].parse().ok()?;
    Some((u32::from(addr), bits))
}

/// Parse a MAC address (colon or hyphen separated) into a u64 for range arithmetic.
fn mac_to_u64(mac: &str) -> Option<u64> {
    let hex: String = mac
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() != 12 {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

/// Convert a u64 back to a colon-separated MAC string.
fn u64_to_mac(val: u64) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        (val >> 40) & 0xFF,
        (val >> 32) & 0xFF,
        (val >> 24) & 0xFF,
        (val >> 16) & 0xFF,
        (val >> 8) & 0xFF,
        val & 0xFF,
    )
}

/// Build the set of all switch-local MAC addresses by computing sequential
/// ranges from the is_local=true entries on each managed switch.
///
/// Manufacturers assign MACs sequentially per switch (port 1 = base, port 2 =
/// base+1, etc.). By finding [min, max] of the local MACs per switch, we can
/// identify the full block — catching switch MACs even when they appear from
/// other data sources like ARP or DHCP.
async fn build_switch_local_mac_set(
    store: &SwitchStore,
    device_ids: &[String],
) -> HashSet<u64> {
    let mut local_macs = HashSet::new();

    for device_id in device_ids {
        let entries = match store.get_mac_table(Some(device_id)).await {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Collect all local MAC values for this switch
        let local_vals: Vec<u64> = entries
            .iter()
            .filter(|e| e.is_local)
            .filter_map(|e| mac_to_u64(&e.mac_address))
            .collect();

        if local_vals.is_empty() {
            continue;
        }

        let min_mac = *local_vals.iter().min().unwrap();
        let max_mac = *local_vals.iter().max().unwrap();

        // Sanity check: the range should be reasonable (< 128 addresses).
        // A 48-port switch uses ~48 MACs. If the range is absurdly large,
        // the MACs aren't sequential and we fall back to the exact set.
        let range_size = max_mac - min_mac + 1;
        if range_size <= 128 {
            for val in min_mac..=max_mac {
                local_macs.insert(val);
            }
            tracing::debug!(
                device = %device_id,
                range = %format!("{} — {}", u64_to_mac(min_mac), u64_to_mac(max_mac)),
                count = range_size,
                "switch-local MAC range"
            );
        } else {
            // Not sequential — just use the exact set
            for val in &local_vals {
                local_macs.insert(*val);
            }
            tracing::debug!(
                device = %device_id,
                count = local_vals.len(),
                "switch-local MACs (non-sequential, exact set)"
            );
        }
    }

    local_macs
}

/// Check if a MAC address falls within any switch-local MAC range.
fn is_switch_local_mac(mac: &str, local_set: &HashSet<u64>) -> bool {
    match mac_to_u64(mac) {
        Some(val) => local_set.contains(&val),
        None => false,
    }
}

/// Sync VLAN config from router VLAN interfaces + IP addresses.
/// Discovers VLANs, their names, subnets, and infers media type from naming conventions.
/// Only inserts missing VLANs — existing entries (including human edits) are preserved.
async fn sync_vlan_config_from_router(
    store: &SwitchStore,
    router_client: &MikrotikClient,
) -> anyhow::Result<()> {
    use mikrotik_core::switch_store::VlanConfig;

    let vlan_ifaces = router_client.vlan_interfaces().await?;
    let ip_addrs = router_client.ip_addresses().await?;

    // Build map: interface name → subnet CIDR
    let mut iface_subnet: HashMap<String, String> = HashMap::new();
    for addr in &ip_addrs {
        if !addr.disabled {
            // addr.address is "10.20.25.1/24", addr.network is "10.20.25.0"
            // Combine network + mask from address for proper CIDR
            if let Some(mask) = addr.address.split('/').nth(1) {
                iface_subnet.insert(
                    addr.interface.clone(),
                    format!("{}/{}", addr.network, mask),
                );
            }
        }
    }

    // Auto-assign colors by VLAN ID for a reasonable default palette
    fn auto_color(vlan_id: u32) -> &'static str {
        match vlan_id {
            2 => "#00f0ff",
            6 => "#888888",
            10 => "#ff4444",
            25 => "#00b4d8",
            30 => "#22cc88",
            35 => "#44ddaa",
            40 => "#ffaa00",
            90 => "#f97316",
            99 => "#7FFF00",
            _ => "#6b7280",
        }
    }

    let mut synced = 0u32;
    for vlan in &vlan_ifaces {
        if vlan.disabled {
            continue;
        }

        // Extract a human-friendly name from the interface name.
        // RouterOS names like "V-35-T-WiFi" → "T-WiFi", "V-6-Cambia" → "Cambia"
        // Pattern: "V-{id}-{rest}" — strip the "V-{id}-" prefix.
        let raw_name = &vlan.name;
        let friendly_name = raw_name
            .strip_prefix(&format!("V-{}-", vlan.vlan_id))
            .or_else(|| raw_name.strip_prefix(&format!("V-X-{}-", vlan.vlan_id)))
            .unwrap_or(raw_name)
            .to_string();

        // Infer media type from interface name keywords
        let name_lower = raw_name.to_lowercase();
        let media_type = if name_lower.contains("wifi") || name_lower.contains("wireless") {
            "wireless"
        } else {
            "wired"
        };

        let subnet = iface_subnet.get(raw_name).cloned();

        let config = VlanConfig {
            vlan_id: vlan.vlan_id,
            name: friendly_name,
            media_type: media_type.to_string(),
            subnet,
            color: Some(auto_color(vlan.vlan_id).to_string()),
        };

        match store.insert_vlan_config_if_missing(&config).await {
            Ok(true) => synced += 1,
            Ok(false) => {} // already exists
            Err(e) => tracing::warn!(vlan = vlan.vlan_id, "vlan config insert: {e}"),
        }
    }

    if synced > 0 {
        tracing::info!(count = synced, "VLAN configs synced from router");
    }

    Ok(())
}

/// Build a map of switch_id → list of WAP identifiers that are direct backbone children.
fn build_wap_children(
    backbone_links: &[BackboneLink],
    wap_identifiers: &HashSet<String>,
) -> HashMap<String, Vec<String>> {
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    for link in backbone_links {
        // Check if device_a or device_b is a WAP
        if wap_identifiers.contains(&link.device_a) {
            children.entry(link.device_b.clone()).or_default().push(link.device_a.clone());
        }
        if wap_identifiers.contains(&link.device_b) {
            children.entry(link.device_a.clone()).or_default().push(link.device_b.clone());
        }
    }
    children
}

/// Compute the BFS depth of each switch from the router through backbone links
/// AND LLDP trunk peers. Uses both data sources to build the adjacency graph:
/// - LLDP neighbors provide depth for managed switches automatically
/// - Backbone links fill in for non-LLDP devices (SwOS switches, WAPs)
///
/// Router is depth 0, directly connected switches are depth 1, etc.
/// Switches not reachable via either source get depth 0 (no bonus).
fn compute_switch_depths(
    backbone_links: &[BackboneLink],
    trunk_peer: &HashMap<(String, String), String>,
    router_id: &str,
) -> HashMap<String, u32> {
    // Build undirected adjacency set from both sources
    let mut adj: HashMap<String, HashSet<String>> = HashMap::new();

    // From backbone links
    for link in backbone_links {
        adj.entry(link.device_a.clone())
            .or_default()
            .insert(link.device_b.clone());
        adj.entry(link.device_b.clone())
            .or_default()
            .insert(link.device_a.clone());
    }

    // From LLDP trunk peers (already resolved to device IDs)
    for ((dev_id, _port), peer_id) in trunk_peer {
        adj.entry(dev_id.clone())
            .or_default()
            .insert(peer_id.clone());
        adj.entry(peer_id.clone())
            .or_default()
            .insert(dev_id.clone());
    }

    // BFS from router
    let mut depths: HashMap<String, u32> = HashMap::new();
    depths.insert(router_id.to_string(), 0);
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(router_id.to_string());

    while let Some(current) = queue.pop_front() {
        let current_depth = depths[&current];
        if let Some(neighbors) = adj.get(&current) {
            for neighbor in neighbors {
                if !depths.contains_key(neighbor) {
                    depths.insert(neighbor.clone(), current_depth + 1);
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }

    depths
}

/// Build an async DNS resolver pointing at Technitium for PTR lookups.
fn build_ptr_resolver() -> anyhow::Result<Resolver<TokioConnectionProvider>> {
    let ns_group = NameServerConfigGroup::from_ips_clear(&[DNS_SERVER], 53, true);
    let config = ResolverConfig::from_parts(None, Vec::new(), ns_group);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(500);
    opts.attempts = 1;
    let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(opts)
        .build();
    Ok(resolver)
}

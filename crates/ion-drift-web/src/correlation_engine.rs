use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use ion_drift_storage::SwitchStore;
use ion_drift_storage::switch::{BackboneLink, MacTableEntry, PortRoleProbability};
use crate::topology_inference::canonicalize_port_name;
use crate::topology_inference::graph::{DeviceResolutionMaps, InfrastructureGraph};
use crate::topology_inference::resolver::{self, InferenceMode};
use tokio::sync::RwLock;

use crate::device_manager::{DeviceManager, DeviceStatus};
use crate::device_resolution::{self, DeviceResolutionMaps as NewResolutionMaps};
use crate::dns::DnsResolver;
use crate::infrastructure_snapshot::{
    self, EvidenceAuthority, InfraNodeSource, InfrastructureSnapshotState,
    ResolvedEdge, ResolvedInfraNode, ResolvedInfrastructureSnapshot, ResolutionEvidence,
    ResolutionMethod, SnapshotStatus, SourceEpoch, EdgeSource, EdgeCorroboration,
    SNAPSHOT_SCHEMA_VERSION, push_evidence,
};
use crate::oui::OuiDb;
use crate::router_queue::{RouterQueue, Priority, QueuedRequest};
use crate::task_supervisor::TaskSupervisor;

/// Spawn the correlation engine on a configurable interval to:
/// 1. Classify port roles (access/trunk/uplink/unused)
/// 2. Build unified network identities from MAC/neighbor/OUI/ARP/DHCP data
pub fn spawn_correlation_engine(
    supervisor: &TaskSupervisor,
    switch_store: Arc<SwitchStore>,
    oui_db: Arc<OuiDb>,
    device_manager: Arc<RwLock<DeviceManager>>,
    router_queue: RouterQueue,
    dns_resolver: Arc<dyn DnsResolver>,
    snapshot_state: Arc<RwLock<InfrastructureSnapshotState>>,
    wan_interface: String,
    interval_secs: u64,
) {
    supervisor.spawn("correlation_engine", move || {
        let switch_store = switch_store.clone();
        let oui_db = oui_db.clone();
        let device_manager = device_manager.clone();
        let router_queue = router_queue.clone();
        let dns_resolver = dns_resolver.clone();
        let snapshot_state = snapshot_state.clone();
        let wan_interface = wan_interface.clone();
        Box::pin(async move {
        // 90-second startup delay — let switch pollers collect initial data
        tokio::time::sleep(Duration::from_secs(90)).await;
        tracing::info!(interval_secs, "correlation engine starting");

        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await;
        let mut cycle_number: u64 = 0;

        loop {
            interval.tick().await;
            cycle_number += 1;

            if let Err(e) = run_correlation(
                &switch_store,
                &oui_db,
                &device_manager,
                &router_queue,
                dns_resolver.as_ref(),
                &snapshot_state,
                cycle_number,
                interval_secs,
                &wan_interface,
            )
            .await
            {
                tracing::warn!("correlation engine error: {e}");
            }
        }
    })});
}

async fn run_correlation(
    store: &SwitchStore,
    oui_db: &OuiDb,
    device_manager: &Arc<RwLock<DeviceManager>>,
    router_queue: &RouterQueue,
    dns_resolver: &dyn DnsResolver,
    snapshot_state: &Arc<RwLock<InfrastructureSnapshotState>>,
    cycle_number: u64,
    interval_secs: u64,
    wan_interface: &str,
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

    // ── 0b. Fetch router data in a single batch ─────────────────
    // Bridge hosts, VLAN interfaces, IP addresses, ARP table, and DHCP leases
    // are all fetched together through the queue to minimize router load.
    let batch_results = router_queue.submit(
        "correlation_engine",
        Priority::Normal,
        vec![
            QueuedRequest::get("interface/bridge/host"),
            QueuedRequest::get("interface/vlan"),
            QueuedRequest::get("ip/address"),
            QueuedRequest::get("ip/arp"),
            QueuedRequest::get("ip/dhcp-server/lease"),
        ],
    ).await.map_err(|e| anyhow::anyhow!("correlation queue submit: {e}"))?;

    let mut batch_iter = batch_results.into_iter();
    let bridge_hosts_result = batch_iter.next().unwrap();
    let vlan_ifaces_result = batch_iter.next().unwrap();
    let ip_addrs_result = batch_iter.next().unwrap();
    let arp_result = batch_iter.next().unwrap();
    let dhcp_result = batch_iter.next().unwrap();

    // Sync VLAN config from the batch results.
    // Discovers VLANs, their names, subnets, and infers media type from naming conventions.
    // Only inserts new VLANs — never overwrites human edits.
    if let Err(e) = sync_vlan_config_from_batch(store, &vlan_ifaces_result, &ip_addrs_result).await {
        tracing::warn!("VLAN config sync: {e}");
    }

    // Load VLAN configs for use throughout correlation (subnet matching, wireless detection)
    let vlan_configs = store.get_vlan_configs().await.unwrap_or_default();

    // Build subnet list for VLAN-from-IP inference
    let vlan_subnets: Vec<(u32, String)> = vlan_configs
        .iter()
        .filter_map(|c| c.subnet.as_ref().filter(|s| !s.is_empty()).map(|s| (c.vlan_id, s.clone())))
        .collect();

    // Build wireless VLAN set early — needed for both port role probabilities and identity assembly.
    let wireless_vlans: HashSet<u32> = vlan_configs
        .iter()
        .filter(|v| v.media_type == "wireless" || v.media_type == "mixed")
        .map(|v| v.vlan_id)
        .collect();

    // ── 1. Port role classification ───────────────────────────────
    let dm_read = device_manager.read().await;
    let mut switch_ids: Vec<String> = dm_read
        .get_switches()
        .iter()
        .map(|d| d.record.id.clone())
        .collect();
    // Include SNMP and SwOS switches — they also have MAC/VLAN data to classify
    for d in dm_read.get_snmp_switches() {
        switch_ids.push(d.record.id.clone());
    }
    for d in dm_read.get_swos_switches() {
        switch_ids.push(d.record.id.clone());
    }
    let router_id = match dm_read.get_router() {
        Some(r) => r.record.id.clone(),
        None => {
            tracing::warn!("no primary router in device manager, skipping correlation cycle");
            return Ok(());
        }
    };
    drop(dm_read);

    // Process bridge hosts so the router's local MACs enter the MAC table.
    // Without this, the router's port MACs (seen by switches on trunk ports)
    // would never be identified as switch-local and would leak into identities.
    match bridge_hosts_result.and_then(|v| {
        serde_json::from_value::<Vec<mikrotik_core::BridgeHost>>(v)
            .map_err(|e| mikrotik_core::MikrotikError::Deserialize(e.to_string()))
    }) {
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

    // Include the router in device_ids — its ports need role probability
    // computation so the inference engine can suppress router candidates
    // (e.g. rb4011:1-sfp-sfpplus sees all MACs via ARP gateway).
    let mut device_ids: Vec<String> = switch_ids.clone();
    if !device_ids.contains(&router_id) {
        device_ids.push(router_id.clone());
    }

    // Load backbone links early — needed for port role probability computation.
    let backbone_links = store.get_backbone_links().await.unwrap_or_default();

    // Build a set of backbone port pairs for quick lookup during probability computation.
    // Uses canonical port names to match aggregated evidence.
    let mut backbone_port_set: HashSet<(String, String)> = HashSet::new();
    for link in &backbone_links {
        if let Some(ref port) = link.port_a {
            backbone_port_set.insert((link.device_a.clone(), canonicalize_port_name(port)));
        }
        if let Some(ref port) = link.port_b {
            backbone_port_set.insert((link.device_b.clone(), canonicalize_port_name(port)));
        }
    }

    let mut all_role_probs: Vec<PortRoleProbability> = Vec::new();

    for device_id in &device_ids {
        let mac_entries = store.get_mac_table(Some(device_id)).await?;
        let vlan_entries = store.get_vlan_membership(device_id).await?;

        // Count MACs per canonical port name (skip switch-local MACs).
        // Canonicalization merges SNMP aliases (e.g. mg5/port5/twopointfivegigabitethernet5)
        // so evidence aggregates on the real physical port.
        let mut mac_counts: HashMap<String, u32> = HashMap::new();
        for entry in &mac_entries {
            if entry.is_local {
                continue;
            }
            let canonical = canonicalize_port_name(&entry.port_name);
            *mac_counts.entry(canonical).or_default() += 1;
        }

        // Count VLANs per canonical port
        let mut vlan_counts: HashMap<String, u32> = HashMap::new();
        for entry in &vlan_entries {
            let canonical = canonicalize_port_name(&entry.port_name);
            *vlan_counts.entry(canonical).or_default() += 1;
        }

        // Track which VLAN IDs are on each canonical port (for wireless detection)
        let mut port_vlan_ids: HashMap<String, Vec<u32>> = HashMap::new();
        for entry in &vlan_entries {
            let canonical = canonicalize_port_name(&entry.port_name);
            port_vlan_ids.entry(canonical).or_default().push(entry.vlan_id);
        }

        // Deduplicate VLAN IDs per port (aliases may have contributed duplicates)
        for vids in port_vlan_ids.values_mut() {
            vids.sort_unstable();
            vids.dedup();
        }

        // Check LLDP neighbors per canonical port
        let neighbors = store.get_neighbors(Some(device_id)).await?;
        let mut has_neighbor: HashSet<String> = HashSet::new();
        for nb in &neighbors {
            has_neighbor.insert(canonicalize_port_name(&nb.interface));
        }

        // Collect all known canonical port names
        let mut all_ports: HashSet<String> = HashSet::new();
        all_ports.extend(mac_counts.keys().cloned());
        all_ports.extend(vlan_counts.keys().cloned());

        for port_name in &all_ports {
            let mac_count = mac_counts.get(port_name).copied().unwrap_or(0);
            let vlan_count = vlan_counts.get(port_name).copied().unwrap_or(0);
            let has_lldp = has_neighbor.contains(port_name);
            let is_backbone = backbone_port_set.contains(
                &(device_id.clone(), port_name.clone())
            );

            // Discrete role (stored under canonical name)
            let role = classify_port_role(mac_count, vlan_count, has_lldp);

            if let Err(e) = store
                .set_port_role(device_id, port_name, &role, vlan_count, mac_count, has_lldp)
                .await
            {
                tracing::warn!(device = %device_id, port = %port_name, "port role: {e}");
            }

            // Probabilistic role (new — additive model)
            let port_vlans = port_vlan_ids.get(port_name.as_str()).map(|v| v.as_slice()).unwrap_or(&[]);
            let probs = compute_port_role_probabilities(mac_count, vlan_count, has_lldp, is_backbone, port_vlans, &wireless_vlans);
            all_role_probs.push(PortRoleProbability {
                device_id: device_id.clone(),
                port_name: port_name.clone(),
                trunk_prob: probs.0,
                uplink_prob: probs.1,
                access_prob: probs.2,
                wireless_prob: probs.3,
                computed_at: 0, // filled by store
            });
        }
    }

    // Batch-store all port role probabilities
    if !all_role_probs.is_empty() {
        if let Err(e) = store.set_port_role_probabilities_batch(&all_role_probs).await {
            tracing::warn!("port role probabilities batch store: {e}");
        }
    }

    // ── 1b. Build switch-local MAC set ────────────────────────────
    let mut all_infra_device_ids = device_ids.clone();
    all_infra_device_ids.push(router_id.clone());
    let switch_local_macs = build_switch_local_mac_set(store, &all_infra_device_ids).await;

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

    // ── 2a. Build infrastructure graph ──────────────────────────
    // The InfrastructureGraph consolidates trunk detection, peer resolution,
    // and BFS depth — used by both legacy binding and new inference engine.
    let port_roles = store.get_port_roles(None).await.unwrap_or_default();

    let dm_read = device_manager.read().await;
    let resolution = DeviceResolutionMaps {
        identity_to_device: {
            let mut m = HashMap::new();
            for entry in dm_read.all_devices() {
                m.insert(entry.record.name.to_lowercase(), entry.record.id.clone());
                m.insert(entry.record.id.to_lowercase(), entry.record.id.clone());
            }
            m
        },
        ip_to_device: {
            let mut m = HashMap::new();
            for entry in dm_read.all_devices() {
                m.insert(entry.record.host.clone(), entry.record.id.clone());
            }
            m
        },
    };
    drop(dm_read);

    let port_role_tuples: Vec<(String, String, String)> = port_roles
        .iter()
        .map(|r| (r.device_id.clone(), r.port_name.clone(), r.role.clone()))
        .collect();

    let infra_graph = InfrastructureGraph::build(
        &all_infra_device_ids,
        &router_id,
        &all_neighbors,
        &backbone_links,
        &port_role_tuples,
        &resolution,
    );

    // Force backbone-linked ports to trunk role in the store
    for link in &backbone_links {
        if let Some(ref port) = link.port_a {
            let _ = store.set_port_role(&link.device_a, port, "trunk", 0, 0, false).await;
        }
        if let Some(ref port) = link.port_b {
            let _ = store.set_port_role(&link.device_b, port, "trunk", 0, 0, false).await;
        }
    }

    // Derive legacy variables from the graph for backward compat
    let trunk_ports = &infra_graph.trunk_ports;
    let trunk_peer = &infra_graph.trunk_peers;
    let switch_depths = &infra_graph.depth;

    if infra_graph.depth.len() > 1 {
        let depth_summary: Vec<String> = infra_graph.depth
            .iter()
            .filter(|(id, _)| *id != &router_id)
            .map(|(id, d)| format!("{}={}", id, d))
            .collect();
        tracing::info!(router = %router_id, depths = ?depth_summary, "switch depth map");
    }

    // ── 2b. Record MAC observations for topology inference ──────
    // Build a role probability lookup from the batch we just computed.
    let role_prob_map: HashMap<(String, String), &PortRoleProbability> = all_role_probs
        .iter()
        .map(|p| ((p.device_id.clone(), p.port_name.clone()), p))
        .collect();

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut pending_observations: Vec<ion_drift_storage::switch::MacObservation> = Vec::new();

    // Deduplicate MAC table entries per (device_id, mac_address) to avoid
    // double-counting from SNMP port alias duplication (e.g. Netgear returns
    // the same MAC on both "mg5" and "port5" in the same poll).
    // Keep the first port name seen — typically the one with role data.
    let mut seen_mac_device: HashSet<(String, String)> = HashSet::new();

    for entry in &all_macs {
        if entry.is_local {
            continue;
        }
        if is_switch_local_mac(&entry.mac_address, &switch_local_macs) {
            continue;
        }

        let mac_upper = entry.mac_address.to_uppercase();
        let dedup_key = (entry.device_id.clone(), mac_upper.clone());
        if !seen_mac_device.insert(dedup_key) {
            continue; // Already recorded an observation for this MAC on this device
        }

        let canonical_port = canonicalize_port_name(&entry.port_name);
        let key = (entry.device_id.clone(), canonical_port.clone());

        // Look up role probabilities for this port (using canonical name)
        let (obs_confidence, edge_lk, transit_lk) = if let Some(probs) = role_prob_map.get(&key) {
            // Observation confidence: high for access, medium for wireless, low for trunk/uplink
            let confidence = probs.access_prob * 0.9
                + probs.wireless_prob * 0.7
                + probs.uplink_prob * 0.2
                + probs.trunk_prob * 0.1;
            let edge = probs.access_prob + probs.wireless_prob * 0.8;
            let transit = probs.trunk_prob + probs.uplink_prob * 0.7;
            (confidence.clamp(0.0, 1.0), edge.clamp(0.0, 1.0), transit.clamp(0.0, 1.0))
        } else {
            // No role data — use neutral defaults
            (0.5, 0.5, 0.5)
        };

        pending_observations.push(ion_drift_storage::switch::MacObservation {
            id: 0, // auto-assigned by DB
            mac_address: mac_upper,
            device_id: entry.device_id.clone(),
            port_name: canonical_port,
            vlan_id: entry.vlan_id,
            timestamp: now_ts,
            observation_confidence: obs_confidence,
            edge_likelihood: edge_lk,
            transit_likelihood: transit_lk,
        });
    }

    if !pending_observations.is_empty() {
        if let Err(e) = store.insert_mac_observations(&pending_observations).await {
            tracing::warn!(count = pending_observations.len(), "MAC observation insert: {e}");
        }
    }

    // Prune observations older than 20 minutes (retention window)
    match store.prune_old_observations(1200).await {
        Ok(n) if n > 0 => tracing::debug!(count = n, "pruned old MAC observations"),
        Err(e) => tracing::warn!("prune MAC observations: {e}"),
        _ => {}
    }

    // ── 2c. Run topology inference engine ─────────────────────────
    let inference_mode = InferenceMode::from_env();
    if inference_mode != InferenceMode::Legacy {
        // Build AP feeder map for wireless attribution
        let infra_identities_for_map = store.get_infrastructure_identities().await.unwrap_or_default();
        let wap_ids_for_map = crate::topology_inference::build_wap_identifier_set(&infra_identities_for_map);
        let ap_feeder_map = crate::topology_inference::build_ap_feeder_map(&backbone_links, &wap_ids_for_map);

        let results = resolver::run_inference_cycle(
            store, &infra_graph, &wireless_vlans, &ap_feeder_map, now_ts,
        ).await;

        if !results.is_empty() {
            let changed = results.iter().filter(|r| r.binding_changed).count();
            let total = results.len();

            if inference_mode == InferenceMode::Shadow {
                // Shadow mode: log divergences between old and new binding
                let mut divergences = 0u32;
                for r in &results {
                    if let Some(ref winner) = r.winner {
                        let identities = store.get_network_identities().await.unwrap_or_default();
                        if let Some(ident) = identities.iter().find(|i| i.mac_address.eq_ignore_ascii_case(&r.mac)) {
                            let old_dev = ident.switch_device_id.as_deref().unwrap_or("");
                            let old_port = ident.switch_port.as_deref().unwrap_or("");
                            if old_dev != winner.device_id || old_port != winner.port_name {
                                divergences += 1;
                                tracing::debug!(
                                    mac = %r.mac,
                                    old_dev = %old_dev, old_port = %old_port,
                                    new_dev = %winner.device_id, new_port = %winner.port_name,
                                    score = %format!("{:.2}", winner.score),
                                    confidence = %format!("{:.2}", r.confidence),
                                    state = %r.state.state.as_str(),
                                    "inference divergence (shadow)"
                                );
                            }
                        }
                    }
                }
                tracing::info!(
                    mode = "shadow", total = total, changed = changed,
                    divergences = divergences, "inference cycle"
                );
            } else {
                // Active mode: write back binding changes to identity store
                let mut written = 0u32;
                let mut router_skipped = 0u32;
                for r in &results {
                    if r.binding_changed && r.confidence > 0.5 {
                        if let Some(ref winner) = r.winner {
                            // Gate: never write router bindings back
                            if infra_graph.nodes.get(&winner.device_id)
                                .map(|n| n.is_router)
                                .unwrap_or(false)
                            {
                                tracing::debug!(
                                    mac = %r.mac,
                                    "inference: skipping router binding writeback"
                                );
                                router_skipped += 1;
                                continue;
                            }
                            match store
                                .update_identity_binding(
                                    &r.mac,
                                    &winner.device_id,
                                    &winner.port_name,
                                    "inference",
                                )
                                .await
                            {
                                Ok(true) => written += 1,
                                Ok(false) => {} // human-confirmed, skipped
                                Err(e) => tracing::warn!(
                                    mac = %r.mac,
                                    "inference binding writeback: {e}"
                                ),
                            }
                        }
                    }
                }
                tracing::info!(
                    mode = "active", total = total, changed = changed,
                    written = written, router_skipped = router_skipped,
                    "inference cycle"
                );
            }
        }
    }

    // Collect MACs where inference is authoritative (Active mode with successful binding).
    // Legacy binding below will skip these to avoid overwriting inference results.
    let inference_bound_macs: HashSet<String> = if inference_mode == InferenceMode::Active {
        store.get_all_attachment_states().await.unwrap_or_default()
            .into_iter()
            .filter(|s| {
                s.current_device_id.is_some()
                    && s.confidence > 0.3
                    && s.state != "unknown"
            })
            .map(|s| s.mac_address.to_uppercase())
            .collect()
    } else {
        HashSet::new()
    };

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

        let canonical_port = canonicalize_port_name(&entry.port_name);
        let is_trunk = trunk_ports.contains(&(entry.device_id.clone(), canonical_port.clone()));
        let is_router = entry.device_id == router_id;
        let known_depth = switch_depths.get(&entry.device_id).copied();
        // Priority formula:
        //   Router:       100         — always lowest, sees every MAC via bridge
        //   Switch trunk: 200+depth*10 — deeper trunk = closer to device (correct)
        //   Access port:  400-depth*10 — shallower access = more trustworthy
        //   Unknown depth: 250        — switches not in topology get neutral priority
        //
        // Why invert depth for access? A MAC can appear on "access" ports of
        // multiple switches when a deeper switch's uplink is misclassified
        // (e.g. SwOS port name doesn't match backbone link). The shallower
        // switch's access port is more likely the genuine connection.
        // Access always beats trunk (min 310 vs max ~240).
        //
        // Unknown-depth switches (not reachable from router via backbone/LLDP)
        // get a neutral score of 250 — lower than any known access port (min 310)
        // but higher than trunk ports at depth <=4. This prevents unregistered
        // switches from stealing MACs from known topology positions.
        let new_priority: u32 = if is_router {
            100
        } else if let Some(depth) = known_depth {
            if is_trunk {
                200 + depth * 10
            } else {
                400_u32.saturating_sub(depth * 10)
            }
        } else {
            // Switch not in backbone topology — use neutral priority
            250
        };

        let builder = identity_map
            .entry(entry.mac_address.to_uppercase())
            .or_insert_with(IdentityBuilder::default);

        // Skip switch binding for MACs where inference is authoritative
        let mac_upper = entry.mac_address.to_uppercase();
        let inference_owns = inference_bound_macs.contains(&mac_upper);

        // Only update switch binding if new priority strictly dominates.
        // Equal priority → no change (eliminates flapping between same-class ports).
        // Inference-bound MACs keep their inference binding — legacy only updates VLAN.
        if !inference_owns && new_priority > builder.binding_priority {
            builder.switch_device_id = Some(entry.device_id.clone());
            builder.switch_port = Some(canonical_port);
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
        for (mac_key, builder) in identity_map.iter_mut() {
            if inference_bound_macs.contains(mac_key) { continue; }
            let dev = builder.switch_device_id.clone();
            let port = builder.switch_port.clone();
            if let (Some(dev), Some(port)) = (dev, port) {
                if trunk_ports.contains(&(dev.clone(), canonicalize_port_name(&port))) {
                    let canonical = canonicalize_port_name(port.split(',').next().unwrap_or(&port));
                    if let Some(peer_id) =
                        trunk_peer.get(&(dev.clone(), canonical))
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
    // Devices on wireless VLANs are attributed to WAPs. For each wireless
    // device: if its current switch has WAP children (via backbone links),
    // round-robin among those WAPs. Otherwise, round-robin among ALL known
    // WAPs. This ensures every wireless device gets a WAP parent — the user
    // can manually correct via the identity manager.
    {
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
        // Sorted list of all WAPs for deterministic round-robin
        let mut all_waps: Vec<String> = wap_identifiers.iter().cloned().collect();
        all_waps.sort();

        if all_waps.is_empty() {
            tracing::debug!("no WAPs found, skipping wireless attribution");
        } else {
            // Per-WAP round-robin counters (keyed by WAP list identity)
            let mut global_rr = 0usize;
            let mut switch_rr: HashMap<String, usize> = HashMap::new();
            let mut wap_attributed = 0u32;

            // Collect wireless MAC keys first, then iterate — avoids borrow issues
            let wireless_macs: Vec<String> = identity_map
                .iter()
                .filter_map(|(mac, b)| {
                    if inference_bound_macs.contains(mac) { return None; }
                    match b.vlan_id {
                        Some(v) if wireless_vlans.contains(&v) => Some(mac.clone()),
                        _ => None,
                    }
                })
                .collect();

            for mac in &wireless_macs {
                let builder = identity_map.get_mut(mac).unwrap();
                let switch_id = match &builder.switch_device_id {
                    Some(id) => id.clone(),
                    None => continue,
                };

                // Prefer switch-specific WAPs if available, else all WAPs
                let wap_list = wap_children.get(&switch_id).unwrap_or(&all_waps);
                if wap_list.is_empty() {
                    continue;
                }

                let idx = if wap_list.len() == all_waps.len() {
                    let i = global_rr;
                    global_rr += 1;
                    i
                } else {
                    let i = switch_rr.entry(switch_id.clone()).or_insert(0);
                    let idx = *i;
                    *i += 1;
                    idx
                };

                builder.switch_device_id = Some(wap_list[idx % wap_list.len()].clone());
                builder.switch_port = None;
                wap_attributed += 1;
            }

            if wap_attributed > 0 {
                tracing::info!(
                    count = wap_attributed,
                    waps = all_waps.len(),
                    "wireless devices attributed to WAPs (round-robin)"
                );
            }
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
    match arp_result.and_then(|v| {
        serde_json::from_value::<Vec<mikrotik_core::resources::ip::ArpEntry>>(v)
            .map_err(|e| mikrotik_core::MikrotikError::Deserialize(e.to_string()))
    }) {
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
    match dhcp_result.and_then(|v| {
        serde_json::from_value::<Vec<mikrotik_core::resources::ip::DhcpLease>>(v)
            .map_err(|e| mikrotik_core::MikrotikError::Deserialize(e.to_string()))
    }) {
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
        .filter_map(|(mac, b)| b.best_ip.clone().map(|ip| (mac.clone(), ip)))
        .collect();

    if !ips_needing_ptr.is_empty() {
        let mut resolved = 0u32;
        for (mac, ip) in &ips_needing_ptr {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                if let Some(hostname) = dns_resolver.reverse_lookup(addr).await {
                    if !hostname.is_empty() {
                        if let Some(builder) = identity_map.get_mut(mac) {
                            builder.hostname = Some(hostname);
                            resolved += 1;
                        }
                    }
                }
            }
        }
        if resolved > 0 {
            tracing::debug!(resolved, total = ips_needing_ptr.len(), "PTR lookups");
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

    // ── 4. Build and publish resolved infrastructure snapshot ────
    {
        let snapshot_start = std::time::Instant::now();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Build new-style resolution maps from device manager
        let dm = device_manager.read().await;
        let mut new_resolution = NewResolutionMaps::build(&dm, None);
        drop(dm);

        // Populate MAC→device from neighbor records
        new_resolution.populate_mac_from_neighbors(&all_neighbors);

        // Resolve all LLDP neighbors and build infrastructure nodes + edges
        let mut infra_nodes: Vec<ResolvedInfraNode> = Vec::new();
        let mut edges: Vec<ResolvedEdge> = Vec::new();
        let mut seen_device_ids: HashSet<String> = HashSet::new();
        let mut wan_neighbor_count: u32 = 0;

        // Add registered devices as infrastructure nodes
        let dm = device_manager.read().await;
        for entry in dm.all_devices() {
            let id = entry.record.id.clone();
            seen_device_ids.insert(id.clone());

            let authority = if entry.record.device_type == "router" {
                EvidenceAuthority::RouterPrimary
            } else {
                match &entry.client {
                    crate::device_manager::DeviceClient::RouterOs(_) => EvidenceAuthority::RouterOsSwitch,
                    crate::device_manager::DeviceClient::Snmp(_) => EvidenceAuthority::ManagedSwitchSnmp,
                    crate::device_manager::DeviceClient::SwOs(_) => EvidenceAuthority::ManagedSwitchSnmp,
                }
            };

            infra_nodes.push(ResolvedInfraNode {
                device_id: id.clone(),
                label: entry.record.name.clone(),
                source: InfraNodeSource::Registered,
                device_type: Some(entry.record.device_type.clone()),
                mac: None,
                ip: Some(entry.record.host.clone()),
                manufacturer: None,
                vlan_membership: Vec::new(),
                confidence: 1.0,
                resolution_method: ResolutionMethod::Authoritative,
                evidence: vec![ResolutionEvidence {
                    authority,
                    source: format!("device_manager:{}", id),
                    observation: format!("Registered device '{}'", entry.record.name),
                    observed_at: now_secs,
                }],
                conflict: None,
                first_seen: None,
                last_seen: None,
            });
        }
        drop(dm);

        // Pre-load network identities for identity_overrides_lldp checks.
        // If a MAC has a NetworkIdentity that says it's NOT infrastructure
        // (e.g., a workstation broadcasting MNDP), skip creating an infra node.
        let existing_identities = store.get_network_identities().await.unwrap_or_default();
        let identity_by_mac: HashMap<String, &ion_drift_storage::switch::NetworkIdentity> =
            existing_identities.iter().map(|i| (i.mac_address.to_uppercase(), i)).collect();

        // Load neighbor aliases — "hide" entries suppress ISP/unwanted LLDP neighbors
        let aliases = store.get_neighbor_aliases().await.unwrap_or_default();
        let mut hidden_macs: HashSet<String> = HashSet::new();
        let mut hidden_identities: HashSet<String> = HashSet::new();
        for alias in &aliases {
            if alias.action == "hide" {
                match alias.match_type.as_str() {
                    "mac" => { hidden_macs.insert(alias.match_value.to_uppercase()); }
                    "identity" => { hidden_identities.insert(alias.match_value.to_lowercase()); }
                    _ => {}
                }
            }
        }

        // Resolve LLDP neighbors → infrastructure nodes + trunk edges
        // Track MAC→node_id for dedup (same device seen from multiple switches)
        let mut infra_mac_to_id: HashMap<String, String> = HashMap::new();

        // Pre-seed MAC→device from neighbors that resolve to registered devices.
        // This enables the MAC fallback in the unresolved path below to catch
        // devices seen with a generic identity (e.g., "MikroTik") from one switch
        // but a real identity from another.
        for nb in &all_neighbors {
            if let Some(ref mac) = nb.mac_address {
                if let Some(resolved) = new_resolution.resolve_neighbor(nb) {
                    infra_mac_to_id.insert(mac.to_uppercase(), resolved.device_id);
                }
            }
        }

        // Find the router device_id for WAN neighbor filtering.
        // Topology filters WAN neighbors by checking source_port == wan_interface.
        // We match that: neighbors from the router on the WAN port are ISP equipment.
        let router_device_id = {
            let dm = device_manager.read().await;
            dm.all_devices().into_iter()
                .find(|d| d.record.device_type == "router")
                .map(|r| r.record.id.clone())
        };

        for nb in &all_neighbors {
            // Skip WAN-facing neighbors: same logic as topology.rs — neighbors
            // reported by the router on the WAN interface are ISP/external equipment.
            if let Some(ref rid) = router_device_id {
                if nb.device_id == *rid && nb.interface == wan_interface {
                    wan_neighbor_count += 1;
                    continue;
                }
            }

            // Skip neighbors hidden via neighbor aliases
            if let Some(ref mac) = nb.mac_address {
                if hidden_macs.contains(&mac.to_uppercase()) { continue; }
            }
            if let Some(ref ident) = nb.identity {
                if hidden_identities.contains(&ident.to_lowercase()) { continue; }
            }

            let source_device = nb.device_id.clone();

            // Try to resolve this neighbor to a known device
            if let Some(resolved) = new_resolution.resolve_neighbor(nb) {
                // Known device — create trunk edge
                if !seen_device_ids.contains(&resolved.device_id) {
                    // Shouldn't happen for registered devices, but defensive
                    seen_device_ids.insert(resolved.device_id.clone());
                }

                let edge = ResolvedEdge {
                    source_device: source_device.clone(),
                    target_device: resolved.device_id.clone(),
                    source_port: Some(nb.interface.clone()),
                    target_port: None,
                    vlans: Vec::new(),
                    speed_mbps: None,
                    traffic_bps: None,
                    edge_source: EdgeSource::LldpObserved,
                    corroboration: None,
                    confidence: resolved.confidence,
                    evidence: vec![ResolutionEvidence {
                        authority: resolved.authority,
                        source: format!("neighbor:{}:{}", source_device, nb.interface),
                        observation: format!(
                            "LLDP neighbor '{}' resolved via {:?}",
                            nb.identity.as_deref().unwrap_or("?"),
                            resolved.method,
                        ),
                        observed_at: now_secs,
                    }],
                };
                edges.push(edge);

                // Learn this resolution for future cycles
                new_resolution.learn(nb, &resolved, now_secs);
            } else {
                // Unresolved neighbor — try additional resolution before creating an inferred node.

                // Check if identity says NOT infrastructure (workstations, phones, cameras)
                if let Some(ref mac) = nb.mac_address {
                    if let Some(ident) = identity_by_mac.get(&mac.to_uppercase()) {
                        if identity_overrides_lldp(ident) {
                            continue;
                        }
                    }
                }

                // Skip neighbors with empty identity AND no platform — these are
                // endpoints that happen to show up in the neighbor table, not infrastructure.
                let has_identity = nb.identity.as_deref().map_or(false, |s| !s.is_empty());
                if !has_identity {
                    // No identity at all — only keep if we can identify it via MAC
                    // as a known infrastructure device from identities
                    let is_known_infra = nb.mac_address.as_deref().map_or(false, |mac| {
                        identity_by_mac.get(&mac.to_uppercase()).map_or(false, |ident| {
                            ident.is_infrastructure == Some(true)
                                || is_infrastructure_type(ident.device_type.as_deref())
                        })
                    });
                    if !is_known_infra {
                        continue;
                    }
                }

                // Last-chance resolution: try to match by MAC against registered infra MACs
                // that we've already collected. Also try IP match against identity store.
                if let Some(ref mac) = nb.mac_address {
                    if let Some(existing) = infra_mac_to_id.get(&mac.to_uppercase()) {
                        // Already have an infra node for this MAC — just add edge
                        edges.push(ResolvedEdge {
                            source_device: source_device.clone(),
                            target_device: existing.clone(),
                            source_port: Some(nb.interface.clone()),
                            target_port: None,
                            vlans: Vec::new(),
                            speed_mbps: None,
                            traffic_bps: None,
                            edge_source: EdgeSource::LldpObserved,
                            corroboration: None,
                            confidence: 0.60,
                            evidence: vec![ResolutionEvidence {
                                authority: EvidenceAuthority::LldpObserved,
                                source: format!("neighbor:{}:{}", source_device, nb.interface),
                                observation: format!("Matched via MAC to existing infra node {}", existing),
                                observed_at: now_secs,
                            }],
                        });
                        continue;
                    }
                }

                // Try IP match against network identities — catches devices on
                // management VLANs whose VLAN IP differs from the registered host IP
                if let Some(ref addr) = nb.address {
                    if !addr.starts_with("fe80") {
                        let ip_match = existing_identities.iter().find(|ident| {
                            ident.best_ip.as_deref() == Some(addr.as_str())
                                && ident.switch_device_id.is_some()
                        });
                        if let Some(ident) = ip_match {
                            if let Some(ref dev_id) = ident.switch_device_id {
                                if seen_device_ids.contains(dev_id) {
                                    edges.push(ResolvedEdge {
                                        source_device: source_device.clone(),
                                        target_device: dev_id.clone(),
                                        source_port: Some(nb.interface.clone()),
                                        target_port: None,
                                        vlans: Vec::new(),
                                        speed_mbps: None,
                                        traffic_bps: None,
                                        edge_source: EdgeSource::LldpObserved,
                                        corroboration: None,
                                        confidence: 0.65,
                                        evidence: vec![ResolutionEvidence {
                                            authority: EvidenceAuthority::LldpObserved,
                                            source: format!("neighbor:{}:{}", source_device, nb.interface),
                                            observation: format!("Matched via IP {} to identity {}", addr, dev_id),
                                            observed_at: now_secs,
                                        }],
                                    });
                                    continue;
                                }
                            }
                        }
                    }
                }

                tracing::debug!(
                    source = %nb.device_id,
                    interface = %nb.interface,
                    identity = ?nb.identity,
                    address = ?nb.address,
                    mac = ?nb.mac_address,
                    "snapshot: creating inferred infrastructure node"
                );

                // Create inferred infrastructure node.
                // Preserve original case for the ID to match topology's behavior.
                let inferred_id = match (nb.identity.as_deref(), nb.mac_address.as_deref()) {
                    (Some(id), _) if !id.is_empty() => id.to_string(),
                    (_, Some(mac)) if !mac.is_empty() => format!("unknown-{}", mac.to_uppercase()),
                    _ => continue,
                };

                // MAC-based dedup: if we've already created a node for this MAC, reuse it
                if let Some(ref mac) = nb.mac_address {
                    let mac_upper = mac.to_uppercase();
                    if let Some(existing_id) = infra_mac_to_id.get(&mac_upper) {
                        // Just add an edge to the existing node
                        edges.push(ResolvedEdge {
                            source_device: source_device.clone(),
                            target_device: existing_id.clone(),
                            source_port: Some(nb.interface.clone()),
                            target_port: None,
                            vlans: Vec::new(),
                            speed_mbps: None,
                            traffic_bps: None,
                            edge_source: EdgeSource::LldpObserved,
                            corroboration: None,
                            confidence: 0.50,
                            evidence: vec![ResolutionEvidence {
                                authority: EvidenceAuthority::LldpObserved,
                                source: format!("neighbor:{}:{}", source_device, nb.interface),
                                observation: format!("Unresolved LLDP neighbor (dedup via MAC {})", mac_upper),
                                observed_at: now_secs,
                            }],
                        });
                        continue;
                    }
                    infra_mac_to_id.insert(mac_upper, inferred_id.clone());
                }

                if !seen_device_ids.contains(&inferred_id) {
                    seen_device_ids.insert(inferred_id.clone());

                    infra_nodes.push(ResolvedInfraNode {
                        device_id: inferred_id.clone(),
                        label: nb.identity.clone().unwrap_or_else(|| inferred_id.clone()),
                        source: InfraNodeSource::InferredLldp,
                        device_type: None,
                        mac: nb.mac_address.clone(),
                        ip: nb.address.clone(),
                        manufacturer: nb.mac_address.as_deref().and_then(|m| oui_db.lookup(m).map(|s| s.to_string())),
                        vlan_membership: Vec::new(),
                        confidence: 0.50,
                        resolution_method: ResolutionMethod::ManualDefinition,
                        evidence: vec![ResolutionEvidence {
                            authority: EvidenceAuthority::LldpObserved,
                            source: format!("neighbor:{}:{}", source_device, nb.interface),
                            observation: format!(
                                "Unresolved LLDP neighbor '{}'",
                                nb.identity.as_deref().unwrap_or("?"),
                            ),
                            observed_at: now_secs,
                        }],
                        conflict: None,
                        first_seen: Some(nb.first_seen),
                        last_seen: Some(nb.last_seen),
                    });
                }

                edges.push(ResolvedEdge {
                    source_device: source_device.clone(),
                    target_device: inferred_id,
                    source_port: Some(nb.interface.clone()),
                    target_port: None,
                    vlans: Vec::new(),
                    speed_mbps: None,
                    traffic_bps: None,
                    edge_source: EdgeSource::LldpObserved,
                    corroboration: None,
                    confidence: 0.50,
                    evidence: vec![ResolutionEvidence {
                        authority: EvidenceAuthority::LldpObserved,
                        source: format!("neighbor:{}:{}", source_device, nb.interface),
                        observation: "Inferred infrastructure from LLDP".to_string(),
                        observed_at: now_secs,
                    }],
                });
            }
        }

        // Backbone links → edges + auto-create missing nodes
        for link in &backbone_links {
            // Check corroboration: does an LLDP-observed edge already exist between these devices?
            let corroborated = edges.iter().any(|e| {
                (e.source_device == link.device_a && e.target_device == link.device_b)
                    || (e.source_device == link.device_b && e.target_device == link.device_a)
            });

            let (edge_source, corroboration) = if corroborated {
                (
                    EdgeSource::BackboneCorroborated,
                    Some(EdgeCorroboration::Corroborated {
                        evidence: "LLDP neighbor observation confirms this link".to_string(),
                    }),
                )
            } else {
                (
                    EdgeSource::BackboneDefined,
                    Some(EdgeCorroboration::Unobserved),
                )
            };

            // Auto-create infrastructure nodes for backbone endpoints not yet in the snapshot
            for device_id in [&link.device_a, &link.device_b] {
                if !seen_device_ids.contains(device_id.as_str()) {
                    seen_device_ids.insert(device_id.clone());

                    // Try to get metadata from infrastructure identities
                    let infra_identities = store.get_infrastructure_identities().await.unwrap_or_default();
                    let ident = infra_identities.iter().find(|i| {
                        i.hostname.as_deref() == Some(device_id.as_str())
                            || i.mac_address == *device_id
                    });

                    infra_nodes.push(ResolvedInfraNode {
                        device_id: device_id.clone(),
                        label: ident
                            .and_then(|i| i.hostname.clone())
                            .unwrap_or_else(|| device_id.clone()),
                        source: InfraNodeSource::BackboneLink,
                        device_type: ident.and_then(|i| i.device_type.clone()),
                        mac: ident.map(|i| i.mac_address.clone()),
                        ip: ident.and_then(|i| i.best_ip.clone()),
                        manufacturer: ident.and_then(|i| i.manufacturer.clone()),
                        vlan_membership: Vec::new(),
                        confidence: 0.70,
                        resolution_method: ResolutionMethod::ManualDefinition,
                        evidence: vec![ResolutionEvidence {
                            authority: EvidenceAuthority::ManualBackbone,
                            source: format!("backbone_link:{}", link.id),
                            observation: format!(
                                "Backbone link {} ↔ {}",
                                link.device_a, link.device_b,
                            ),
                            observed_at: now_secs,
                        }],
                        conflict: None,
                        first_seen: None,
                        last_seen: None,
                    });
                }
            }

            edges.push(ResolvedEdge {
                source_device: link.device_a.clone(),
                target_device: link.device_b.clone(),
                source_port: link.port_a.clone(),
                target_port: link.port_b.clone(),
                vlans: Vec::new(),
                speed_mbps: link.speed_mbps,
                traffic_bps: None,
                edge_source,
                corroboration,
                confidence: if corroborated { 0.95 } else { 0.70 },
                evidence: vec![ResolutionEvidence {
                    authority: EvidenceAuthority::ManualBackbone,
                    source: format!("backbone_link:{}", link.id),
                    observation: format!(
                        "Backbone: {} ↔ {} ({})",
                        link.device_a,
                        link.device_b,
                        if corroborated { "corroborated" } else { "unobserved" },
                    ),
                    observed_at: now_secs,
                }],
            });
        }

        // Deduplicate bidirectional edges (A→B + B→A → single edge with both ports)
        let edges = dedup_bidirectional_edges(edges);

        // Read the just-written identities for the snapshot
        let identities = store.get_network_identities().await.unwrap_or_default();

        // Build and publish the snapshot
        let generation = {
            let state = snapshot_state.read().await;
            state.next_generation()
        };

        let snapshot = ResolvedInfrastructureSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            generation,
            computed_at: now_secs,
            source_epoch: SourceEpoch {
                window_start: now_secs - (interval_secs as i64),
                window_end: now_secs,
                cycle_number,
            },
            status: SnapshotStatus::Complete,
            infrastructure: infra_nodes,
            edges,
            wan_neighbor_count,
            identities,
        };

        let infra_count = snapshot.infrastructure.len();
        let edge_count = snapshot.edges.len();

        {
            let mut state = snapshot_state.write().await;
            state.publish(snapshot);
        }

        let elapsed = snapshot_start.elapsed();
        tracing::info!(
            generation,
            infra_nodes = infra_count,
            edges = edge_count,
            wan = wan_neighbor_count,
            elapsed_ms = elapsed.as_millis() as u64,
            "infrastructure snapshot published"
        );
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

/// Compute port role probabilities using an additive evidence model.
///
/// Returns (trunk_prob, uplink_prob, access_prob, wireless_prob) normalized
/// so the values sum to ~1.0. Each signal contributes additive weight to
/// the relevant role, then soft-max normalization distributes the mass.
fn compute_port_role_probabilities(
    mac_count: u32,
    vlan_count: u32,
    has_lldp: bool,
    is_backbone: bool,
    port_vlans: &[u32],
    wireless_vlans: &HashSet<u32>,
) -> (f64, f64, f64, f64) {
    let mut trunk = 0.0_f64;
    let mut uplink = 0.0_f64;
    let mut access = 0.0_f64;
    let mut wireless = 0.0_f64;

    // ── Backbone signal (strongest trunk indicator) ──────────
    if is_backbone {
        trunk += 0.75;
    }

    // ── Trunk signals ────────────────────────────────────────
    if vlan_count > 3 {
        trunk += 0.9;
    } else if vlan_count > 1 {
        trunk += 0.6;
    }

    // ── Uplink signals ───────────────────────────────────────
    if has_lldp {
        uplink += 0.7;
    }
    if mac_count > 20 {
        uplink += 0.5;
    } else if mac_count > 10 {
        uplink += 0.3;
    }

    // ── Access signals ───────────────────────────────────────
    if mac_count >= 1 && mac_count <= 3 && !has_lldp && vlan_count <= 1 {
        access += 0.8;
    } else if mac_count >= 1 && mac_count <= 10 && !has_lldp {
        access += 0.5;
    }

    // ── Wireless signals ─────────────────────────────────────
    // Port carries at least one wireless/mixed VLAN
    let wireless_vlan_count = port_vlans.iter().filter(|v| wireless_vlans.contains(v)).count();
    if wireless_vlan_count > 0 {
        wireless += 0.4;
        // If majority of VLANs are wireless, stronger signal
        if !port_vlans.is_empty() && wireless_vlan_count * 2 > port_vlans.len() {
            wireless += 0.3;
        }
    }

    // ── Unused baseline ──────────────────────────────────────
    // If no evidence at all, all probabilities are low (effectively unused)
    if mac_count == 0 && !has_lldp && vlan_count == 0 {
        // Leave all at 0 — the normalization will produce equal small values
        // (or the caller can interpret all-zeros as "unused")
        return (0.0, 0.0, 0.0, 0.0);
    }

    // ── Normalize ────────────────────────────────────────────
    let total = trunk + uplink + access + wireless;
    if total < 0.001 {
        return (0.0, 0.0, 0.0, 0.0);
    }
    (trunk / total, uplink / total, access / total, wireless / total)
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
fn vlan_from_ip(ip: &str, vlan_subnets: &[(u32, String)]) -> Option<u32> {
    let ip_addr: std::net::Ipv4Addr = ip.parse().ok()?;
    let ip_u32 = u32::from(ip_addr);

    // Match against DB-sourced subnets (exact CIDR match)
    for (vlan_id, cidr) in vlan_subnets {
        if let Some((net, mask_bits)) = parse_cidr(cidr) {
            let mask = if mask_bits == 0 { 0 } else { !0u32 << (32 - mask_bits) };
            if (ip_u32 & mask) == (net & mask) {
                return Some(*vlan_id);
            }
        }
    }

    None
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

/// Build the set of all switch-local MAC addresses using exact observed values.
///
/// Uses only the is_local=true MACs that switches explicitly report — no range
/// expansion. Range expansion assumed sequential OUI allocation and could
/// incorrectly flag non-infrastructure MACs that happened to fall within the
/// min/max range of a switch's local MACs.
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

        let mut count = 0u32;
        for entry in &entries {
            if entry.is_local {
                if let Some(val) = mac_to_u64(&entry.mac_address) {
                    local_macs.insert(val);
                    count += 1;
                }
            }
        }

        if count > 0 {
            tracing::debug!(
                device = %device_id,
                count = count,
                "switch-local MACs (exact set)"
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

/// Sync VLAN config from pre-fetched batch results (VLAN interfaces + IP addresses).
/// Discovers VLANs, their names, subnets, and infers media type from naming conventions.
/// Only inserts missing VLANs — existing entries (including human edits) are preserved.
async fn sync_vlan_config_from_batch(
    store: &SwitchStore,
    vlan_ifaces_result: &Result<serde_json::Value, mikrotik_core::MikrotikError>,
    ip_addrs_result: &Result<serde_json::Value, mikrotik_core::MikrotikError>,
) -> anyhow::Result<()> {
    use ion_drift_storage::switch::VlanConfig;

    let vlan_ifaces: Vec<mikrotik_core::resources::interface::VlanInterface> = match vlan_ifaces_result {
        Ok(v) => serde_json::from_value(v.clone())
            .map_err(|e| anyhow::anyhow!("deserialize vlan interfaces: {e}"))?,
        Err(e) => return Err(anyhow::anyhow!("vlan interfaces fetch failed: {e}")),
    };
    let ip_addrs: Vec<mikrotik_core::resources::ip::IpAddress> = match ip_addrs_result {
        Ok(v) => serde_json::from_value(v.clone())
            .map_err(|e| anyhow::anyhow!("deserialize ip addresses: {e}"))?,
        Err(e) => return Err(anyhow::anyhow!("ip addresses fetch failed: {e}")),
    };

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
            interface_name: Some(raw_name.clone()),
            media_type: media_type.to_string(),
            subnet,
            color: Some(auto_color(vlan.vlan_id).to_string()),
            sensitivity: "monitor".to_string(),
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

/// Returns true if the device type string represents network infrastructure.
fn is_infrastructure_type(dt: Option<&str>) -> bool {
    matches!(
        dt,
        Some("router" | "switch" | "network_equipment" | "access_point" | "wap")
    )
}

/// Check whether a network identity should block LLDP from creating an
/// infrastructure node for the same MAC. Returns true when the identity
/// data is authoritative enough to override LLDP inference.
///
/// Duplicated from topology.rs — will be consolidated in Phase 3.
fn identity_overrides_lldp(ident: &ion_drift_storage::switch::NetworkIdentity) -> bool {
    match ident.is_infrastructure {
        Some(false) => return true,
        Some(true) => return false,
        None => {}
    }
    if ident.human_confirmed && !is_infrastructure_type(ident.device_type.as_deref()) {
        return true;
    }
    if !ident.human_confirmed
        && !is_infrastructure_type(ident.device_type.as_deref())
        && ident.device_type.is_some()
        && ident.device_type_confidence >= 0.5
    {
        return true;
    }
    false
}

/// Deduplicate bidirectional edges: A→B and B→A become a single edge.
/// Keeps the first-seen edge and merges port info from the reverse.
fn dedup_bidirectional_edges(edges: Vec<ResolvedEdge>) -> Vec<ResolvedEdge> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut result: Vec<ResolvedEdge> = Vec::new();

    for mut edge in edges {
        // Normalize the pair: always use (min, max) as the canonical key
        let key = if edge.source_device <= edge.target_device {
            (edge.source_device.clone(), edge.target_device.clone())
        } else {
            (edge.target_device.clone(), edge.source_device.clone())
        };

        if seen.contains(&key) {
            // Reverse edge — try to fill in the target_port on the existing edge
            if let Some(existing) = result.iter_mut().find(|e| {
                let ek = if e.source_device <= e.target_device {
                    (e.source_device.clone(), e.target_device.clone())
                } else {
                    (e.target_device.clone(), e.source_device.clone())
                };
                ek == key
            }) {
                // The reverse edge's source_port is the original edge's target_port
                if existing.target_port.is_none() {
                    existing.target_port = edge.source_port.take();
                }
                // Keep the higher confidence
                if edge.confidence > existing.confidence {
                    existing.confidence = edge.confidence;
                }
                // Merge speed — backbone-defined speed overrides LLDP (which has None)
                if existing.speed_mbps.is_none() && edge.speed_mbps.is_some() {
                    existing.speed_mbps = edge.speed_mbps;
                }
                // Merge traffic
                if existing.traffic_bps.is_none() && edge.traffic_bps.is_some() {
                    existing.traffic_bps = edge.traffic_bps;
                }
                // Upgrade edge source if backbone corroborates LLDP
                if existing.edge_source == EdgeSource::LldpObserved
                    && edge.edge_source == EdgeSource::BackboneDefined
                {
                    existing.edge_source = EdgeSource::BackboneCorroborated;
                    existing.corroboration = Some(EdgeCorroboration::Corroborated {
                        evidence: "LLDP + backbone link both confirm this edge".to_string(),
                    });
                }
            }
        } else {
            seen.insert(key);
            result.push(edge);
        }
    }

    result
}

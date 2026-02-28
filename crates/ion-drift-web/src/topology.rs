//! Auto-generated network topology computation.
//!
//! Reads from `neighbor_discovery`, `network_identities`, `switch_port_roles`,
//! and the `DeviceManager` to build a hierarchical network graph with deterministic
//! layout. The result is cached in `AppState` and served via the topology API.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use mikrotik_core::switch_store::SwitchStore;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::device_manager::{DeviceManager, DeviceStatus};

// ── Data structures ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Router,
    ManagedSwitch,
    UnmanagedSwitch,
    AccessPoint,
    Server,
    Workstation,
    Camera,
    Printer,
    Phone,
    IoT,
    SmartHome,
    MediaPlayer,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Trunk,
    Access,
    Wireless,
    Uplink,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Online,
    Offline,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub kind: NodeKind,
    pub vlan_id: Option<u32>,
    pub vlans_served: Vec<u32>,
    pub device_type: Option<String>,
    pub manufacturer: Option<String>,
    pub is_infrastructure: bool,
    pub layer: u32,
    pub x: f64,
    pub y: f64,
    pub position_source: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub parent_id: Option<String>,
    pub switch_port: Option<String>,
    pub status: NodeStatus,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub kind: EdgeKind,
    pub source_port: Option<String>,
    pub target_port: Option<String>,
    pub vlans: Vec<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VlanGroup {
    pub vlan_id: u32,
    pub name: String,
    pub color: String,
    pub subnet: String,
    pub node_count: u32,
    pub bbox_x: f64,
    pub bbox_y: f64,
    pub bbox_w: f64,
    pub bbox_h: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkTopology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
    pub vlan_groups: Vec<VlanGroup>,
    pub computed_at: i64,
    pub node_count: usize,
    pub edge_count: usize,
    pub infrastructure_count: usize,
    pub endpoint_count: usize,
}

// ── VLAN config (matches frontend VLAN_CONFIG) ───────────────────

fn vlan_config(id: u32) -> (&'static str, &'static str, &'static str) {
    match id {
        2 => ("Network Mgmt", "#00f0ff", "10.2.2.0/24"),
        6 => ("Employer Isolated", "#888888", "172.20.6.0/24"),
        10 => ("Cyber Hive Security", "#ff4444", "172.20.10.0/24"),
        25 => ("Trusted Services", "#00b4d8", "10.20.25.0/24"),
        30 => ("Trusted Wired", "#22cc88", "10.20.30.0/24"),
        35 => ("Trusted Wireless", "#44ddaa", "10.20.35.0/24"),
        40 => ("Guest", "#ffaa00", "10.20.40.0/24"),
        90 => ("IoT Internet", "#666666", "192.168.90.0/24"),
        99 => ("IoT Restricted", "#444444", "192.168.99.0/24"),
        _ => ("Unknown", "#888888", ""),
    }
}

/// Sorted VLAN order for consistent horizontal layout.
const VLAN_ORDER: &[u32] = &[2, 6, 10, 25, 30, 35, 40, 90, 99];

// ── Layout constants ─────────────────────────────────────────────

const CANVAS_W: f64 = 4000.0;
const LAYER_SPACING: f64 = 300.0;
const VLAN_SECTOR_MIN_W: f64 = 350.0;
const NODE_SPACING: f64 = 60.0;
const TOP_MARGIN: f64 = 150.0;
const ENDPOINT_OFFSET: f64 = 200.0;
const SECTOR_PADDING: f64 = 40.0;

// ── Graph construction ───────────────────────────────────────────

pub async fn compute_topology(
    store: &SwitchStore,
    device_manager: &Arc<RwLock<DeviceManager>>,
) -> anyhow::Result<NetworkTopology> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut nodes: BTreeMap<String, TopologyNode> = BTreeMap::new();
    let mut edges: Vec<TopologyEdge> = Vec::new();
    let mut infra_ids: HashSet<String> = HashSet::new();

    // ── Layer 1: Infrastructure skeleton ─────────────────────────

    // 1a. Registered devices (router + managed switches)
    let dm = device_manager.read().await;
    let all_devices = dm.all_devices();

    let mut router_id: Option<String> = None;

    for entry in &all_devices {
        let id = entry.record.id.clone();
        let kind = if entry.record.device_type == "router" {
            router_id = Some(id.clone());
            NodeKind::Router
        } else {
            NodeKind::ManagedSwitch
        };

        let status = match &entry.status {
            DeviceStatus::Online { .. } => NodeStatus::Online,
            DeviceStatus::Offline { .. } => NodeStatus::Offline,
            DeviceStatus::Unknown => NodeStatus::Unknown,
        };

        infra_ids.insert(id.clone());
        nodes.insert(
            id.clone(),
            TopologyNode {
                id: id.clone(),
                label: entry.record.name.clone(),
                ip: Some(entry.record.host.clone()),
                mac: None,
                kind,
                vlan_id: None,
                vlans_served: Vec::new(),
                device_type: Some(entry.record.device_type.clone()),
                manufacturer: entry.record.model.clone(),
                is_infrastructure: true,
                layer: 0,
                x: 0.0,
                y: 0.0,
                position_source: "auto".to_string(),
                first_seen: entry.record.created_at,
                last_seen: now,
                parent_id: None,
                switch_port: None,
                status,
                confidence: 1.0,
            },
        );
    }
    drop(dm);

    // 1b. LLDP/MNDP neighbors → trunk edges + inferred infrastructure
    let neighbors = store.get_neighbors(None).await?;

    // Build mappings: identity/name/IP → registered device ID
    let dm = device_manager.read().await;
    let mut identity_to_device: HashMap<String, String> = HashMap::new();
    let mut ip_to_device: HashMap<String, String> = HashMap::new();
    for entry in dm.all_devices() {
        identity_to_device.insert(entry.record.name.to_lowercase(), entry.record.id.clone());
        identity_to_device.insert(entry.record.id.to_lowercase(), entry.record.id.clone());
        ip_to_device.insert(entry.record.host.clone(), entry.record.id.clone());
    }
    drop(dm);

    // Track edges we've already created (both directions)
    let mut edge_set: HashSet<(String, String)> = HashSet::new();

    for nb in &neighbors {
        let source_device = nb.device_id.clone();
        let source_port = nb.interface.clone();

        // Try to match neighbor to a registered device (by identity name, then IP)
        let remote_id = nb
            .identity
            .as_deref()
            .and_then(|id| identity_to_device.get(&id.to_lowercase()).cloned())
            .or_else(|| {
                nb.address
                    .as_deref()
                    .and_then(|addr| ip_to_device.get(addr).cloned())
            });

        if let Some(ref target_id) = remote_id {
            // Known registered device — trunk edge
            let pair = if source_device < *target_id {
                (source_device.clone(), target_id.clone())
            } else {
                (target_id.clone(), source_device.clone())
            };

            if edge_set.insert(pair) {
                edges.push(TopologyEdge {
                    source: source_device.clone(),
                    target: target_id.clone(),
                    kind: EdgeKind::Trunk,
                    source_port: Some(source_port.clone()),
                    target_port: None, // Will be filled if we find the reverse neighbor
                    vlans: Vec::new(),
                });
            }
        } else if let Some(ref platform) = nb.platform {
            // Unregistered neighbor — create inferred infrastructure node
            let plat_lower = platform.to_lowercase();
            let is_mikrotik = plat_lower.contains("routeros")
                || plat_lower.contains("mikrotik")
                || plat_lower.contains("swos");
            let is_ap = plat_lower.contains("cap")
                || plat_lower.contains("wap")
                || plat_lower.contains("wireless");

            let inferred_id = nb
                .identity
                .clone()
                .unwrap_or_else(|| {
                    nb.mac_address
                        .clone()
                        .unwrap_or_else(|| format!("unknown-{}-{}", nb.device_id, nb.interface))
                });

            if !infra_ids.contains(&inferred_id) && !nodes.contains_key(&inferred_id) {
                let kind = if is_ap {
                    NodeKind::AccessPoint
                } else if is_mikrotik {
                    NodeKind::UnmanagedSwitch
                } else {
                    NodeKind::UnmanagedSwitch
                };

                infra_ids.insert(inferred_id.clone());
                nodes.insert(
                    inferred_id.clone(),
                    TopologyNode {
                        id: inferred_id.clone(),
                        label: nb.identity.clone().unwrap_or_else(|| "Unknown Switch".to_string()),
                        ip: nb.address.clone(),
                        mac: nb.mac_address.clone(),
                        kind,
                        vlan_id: None,
                        vlans_served: Vec::new(),
                        device_type: Some("network_equipment".to_string()),
                        manufacturer: nb.board.clone(),
                        is_infrastructure: true,
                        layer: 0,
                        x: 0.0,
                        y: 0.0,
                        position_source: "auto".to_string(),
                        first_seen: nb.first_seen,
                        last_seen: nb.last_seen,
                        parent_id: None,
                        switch_port: None,
                        status: NodeStatus::Unknown,
                        confidence: 0.7,
                    },
                );
            }

            // Edge from managed device to inferred node
            let pair = if source_device < inferred_id {
                (source_device.clone(), inferred_id.clone())
            } else {
                (inferred_id.clone(), source_device.clone())
            };
            if edge_set.insert(pair) {
                edges.push(TopologyEdge {
                    source: source_device.clone(),
                    target: inferred_id,
                    kind: EdgeKind::Trunk,
                    source_port: Some(source_port),
                    target_port: None,
                    vlans: Vec::new(),
                });
            }
        }
    }

    // Fill in reverse port labels on trunk edges
    for edge in &mut edges {
        if edge.target_port.is_none() && edge.kind == EdgeKind::Trunk {
            // Find reverse neighbor entry
            for nb in &neighbors {
                let remote_match = nb
                    .identity
                    .as_deref()
                    .map(|id| identity_to_device.get(&id.to_lowercase()).cloned())
                    .flatten();

                if nb.device_id == edge.target
                    && remote_match.as_deref() == Some(edge.source.as_str())
                {
                    edge.target_port = Some(nb.interface.clone());
                    break;
                }
            }
        }
    }

    // 1c. BFS layer assignment from router
    if let Some(ref rid) = router_id {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, u32)> = VecDeque::new();
        queue.push_back((rid.clone(), 0));
        visited.insert(rid.clone());

        while let Some((node_id, layer)) = queue.pop_front() {
            if let Some(node) = nodes.get_mut(&node_id) {
                node.layer = layer;
            }

            // Find connected infrastructure nodes via trunk edges
            for edge in &edges {
                if edge.kind != EdgeKind::Trunk {
                    continue;
                }
                let neighbor = if edge.source == node_id {
                    &edge.target
                } else if edge.target == node_id {
                    &edge.source
                } else {
                    continue;
                };

                if !visited.contains(neighbor) && infra_ids.contains(neighbor) {
                    visited.insert(neighbor.clone());
                    queue.push_back((neighbor.clone(), layer + 1));
                }
            }
        }

        // Any unvisited infrastructure gets max_layer + 1
        let max_layer = nodes
            .values()
            .filter(|n| n.is_infrastructure)
            .map(|n| n.layer)
            .max()
            .unwrap_or(0);
        for node in nodes.values_mut() {
            if node.is_infrastructure && !visited.contains(&node.id) {
                node.layer = max_layer + 1;
            }
        }
    }

    // Compute VLANs served by each infrastructure node (from VLAN membership)
    for infra_id in &infra_ids {
        let memberships = store.get_vlan_membership(infra_id).await.unwrap_or_default();
        let mut vlans: HashSet<u32> = HashSet::new();
        for m in &memberships {
            vlans.insert(m.vlan_id);
        }
        let mut vlan_list: Vec<u32> = vlans.into_iter().collect();
        vlan_list.sort();
        if let Some(node) = nodes.get_mut(infra_id) {
            node.vlans_served = vlan_list;
        }
    }

    // ── Layer 2: Endpoint placement ─────────────────────────────

    let identities = store.get_network_identities().await?;
    let endpoint_layer = nodes
        .values()
        .filter(|n| n.is_infrastructure)
        .map(|n| n.layer)
        .max()
        .unwrap_or(0)
        + 1;

    // Build MAC → infra_id mapping for infrastructure nodes
    let mut infra_macs: HashSet<String> = HashSet::new();
    for nb in &neighbors {
        if let Some(ref mac) = nb.mac_address {
            // If this neighbor MAC is associated with a registered device, skip as endpoint
            if let Some(ref ident) = nb.identity {
                if identity_to_device.contains_key(&ident.to_lowercase()) {
                    infra_macs.insert(mac.to_uppercase());
                }
            }
        }
    }
    // Also add any MAC that appears as an infra node's mac field
    for node in nodes.values() {
        if node.is_infrastructure {
            if let Some(ref mac) = node.mac {
                infra_macs.insert(mac.to_uppercase());
            }
        }
    }

    for identity in &identities {
        let mac = identity.mac_address.to_uppercase();

        // Skip infrastructure MACs
        if infra_macs.contains(&mac) {
            continue;
        }
        // Skip if already in nodes (e.g., inferred infrastructure)
        if nodes.contains_key(&mac) {
            continue;
        }

        let kind = map_device_type(identity.device_type.as_deref());

        let label = identity
            .human_label
            .as_deref()
            .or(identity.hostname.as_deref())
            .or(identity.manufacturer.as_deref())
            .unwrap_or(&mac)
            .to_string();

        let parent_id = identity.switch_device_id.clone();

        nodes.insert(
            mac.clone(),
            TopologyNode {
                id: mac.clone(),
                label,
                ip: identity.best_ip.clone(),
                mac: Some(mac.clone()),
                kind,
                vlan_id: identity.vlan_id,
                vlans_served: Vec::new(),
                device_type: identity.device_type.clone(),
                manufacturer: identity.manufacturer.clone(),
                is_infrastructure: false,
                layer: endpoint_layer,
                x: 0.0,
                y: 0.0,
                position_source: "auto".to_string(),
                first_seen: identity.first_seen,
                last_seen: identity.last_seen,
                parent_id: parent_id.clone(),
                switch_port: identity.switch_port.clone(),
                status: NodeStatus::Unknown,
                confidence: identity.confidence,
            },
        );

        // Create access edge from switch to endpoint
        if let Some(ref switch_id) = parent_id {
            if nodes.contains_key(switch_id) {
                edges.push(TopologyEdge {
                    source: switch_id.clone(),
                    target: mac,
                    kind: EdgeKind::Access,
                    source_port: identity.switch_port.clone(),
                    target_port: None,
                    vlans: identity.vlan_id.map(|v| vec![v]).unwrap_or_default(),
                });
            }
        }
    }

    // ── Layer 3: Orphan handling ─────────────────────────────────
    // Orphans (no switch_device_id) get layer = endpoint_layer + 1
    let orphan_layer = endpoint_layer + 1;
    for node in nodes.values_mut() {
        if !node.is_infrastructure && node.parent_id.is_none() {
            node.layer = orphan_layer;
        }
    }

    // ── Layout computation ───────────────────────────────────────
    compute_layout(&mut nodes, &edges);

    // ── Position override merging ────────────────────────────────
    let positions = store.get_topology_positions().await.unwrap_or_default();
    for pos in &positions {
        if pos.source == "human" {
            if let Some(node) = nodes.get_mut(&pos.node_id) {
                node.x = pos.x;
                node.y = pos.y;
                node.position_source = "human".to_string();
            }
        }
    }

    // ── VLAN group computation ───────────────────────────────────
    let mut vlan_nodes: BTreeMap<u32, Vec<&TopologyNode>> = BTreeMap::new();
    for node in nodes.values() {
        if let Some(vlan_id) = node.vlan_id {
            vlan_nodes.entry(vlan_id).or_default().push(node);
        }
    }

    let mut vlan_groups: Vec<VlanGroup> = Vec::new();
    for (&vlan_id, group_nodes) in &vlan_nodes {
        if group_nodes.is_empty() {
            continue;
        }
        let (name, color, subnet) = vlan_config(vlan_id);
        let min_x = group_nodes.iter().map(|n| n.x).fold(f64::INFINITY, f64::min);
        let max_x = group_nodes.iter().map(|n| n.x).fold(f64::NEG_INFINITY, f64::max);
        let min_y = group_nodes.iter().map(|n| n.y).fold(f64::INFINITY, f64::min);
        let max_y = group_nodes.iter().map(|n| n.y).fold(f64::NEG_INFINITY, f64::max);

        vlan_groups.push(VlanGroup {
            vlan_id,
            name: name.to_string(),
            color: color.to_string(),
            subnet: subnet.to_string(),
            node_count: group_nodes.len() as u32,
            bbox_x: min_x - SECTOR_PADDING,
            bbox_y: min_y - SECTOR_PADDING,
            bbox_w: (max_x - min_x) + SECTOR_PADDING * 2.0,
            bbox_h: (max_y - min_y) + SECTOR_PADDING * 2.0,
        });
    }

    // ── Assemble result ──────────────────────────────────────────
    let infra_count = nodes.values().filter(|n| n.is_infrastructure).count();
    let endpoint_count = nodes.values().filter(|n| !n.is_infrastructure).count();
    let node_list: Vec<TopologyNode> = nodes.into_values().collect();
    let edge_count = edges.len();
    let node_count = node_list.len();

    Ok(NetworkTopology {
        nodes: node_list,
        edges,
        vlan_groups,
        computed_at: now,
        node_count,
        edge_count,
        infrastructure_count: infra_count,
        endpoint_count,
    })
}

// ── Deterministic hierarchical layout ────────────────────────────

fn compute_layout(nodes: &mut BTreeMap<String, TopologyNode>, edges: &[TopologyEdge]) {
    // Group nodes by layer
    let mut layers: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for (id, node) in nodes.iter() {
        layers.entry(node.layer).or_default().push(id.clone());
    }

    // Build VLAN → sector X mapping
    let mut active_vlans: Vec<u32> = Vec::new();
    for vlan_id in VLAN_ORDER {
        let has_nodes = nodes.values().any(|n| n.vlan_id == Some(*vlan_id) && !n.is_infrastructure);
        let served = nodes.values().any(|n| n.vlans_served.contains(vlan_id));
        if has_nodes || served {
            active_vlans.push(*vlan_id);
        }
    }
    // Also include any VLANs not in VLAN_ORDER
    for node in nodes.values() {
        if let Some(vid) = node.vlan_id {
            if !active_vlans.contains(&vid) {
                active_vlans.push(vid);
            }
        }
    }

    let sector_count = active_vlans.len().max(1);
    let sector_w = (CANVAS_W / sector_count as f64).max(VLAN_SECTOR_MIN_W);
    let total_w = sector_w * sector_count as f64;
    let x_offset = (CANVAS_W - total_w) / 2.0;

    let vlan_center_x: HashMap<u32, f64> = active_vlans
        .iter()
        .enumerate()
        .map(|(i, &vid)| (vid, x_offset + sector_w * i as f64 + sector_w / 2.0))
        .collect();

    // ── Position infrastructure nodes ────────────────────────────
    // Infrastructure nodes that serve multiple VLANs: center across those sectors
    // Infrastructure with no VLANs served: center of canvas

    for (_layer, ids) in &layers {
        let mut infra_in_layer: Vec<String> = ids
            .iter()
            .filter(|id| nodes.get(*id).map(|n| n.is_infrastructure).unwrap_or(false))
            .cloned()
            .collect();
        infra_in_layer.sort(); // deterministic

        for (i, id) in infra_in_layer.iter().enumerate() {
            if let Some(node) = nodes.get_mut(id) {
                let y = TOP_MARGIN + node.layer as f64 * LAYER_SPACING;

                let x = if !node.vlans_served.is_empty() {
                    // Average X of all VLAN sectors this node serves
                    let sum: f64 = node
                        .vlans_served
                        .iter()
                        .filter_map(|v| vlan_center_x.get(v))
                        .sum();
                    let count = node
                        .vlans_served
                        .iter()
                        .filter(|v| vlan_center_x.contains_key(v))
                        .count()
                        .max(1);
                    sum / count as f64 + (i as f64 * NODE_SPACING * 0.5)
                } else {
                    // Center of canvas with offset
                    CANVAS_W / 2.0 + (i as f64 - infra_in_layer.len() as f64 / 2.0) * NODE_SPACING
                };

                node.x = x;
                node.y = y;
            }
        }
    }

    // ── Position endpoint nodes ──────────────────────────────────
    // Group endpoints by (parent_switch, vlan_id)
    let mut groups: BTreeMap<(Option<String>, Option<u32>), Vec<String>> = BTreeMap::new();
    for (id, node) in nodes.iter() {
        if !node.is_infrastructure {
            groups
                .entry((node.parent_id.clone(), node.vlan_id))
                .or_default()
                .push(id.clone());
        }
    }

    for ((parent, vlan), mut endpoint_ids) in groups {
        endpoint_ids.sort(); // deterministic

        // Determine the base X from VLAN sector
        let base_x = vlan
            .and_then(|v| vlan_center_x.get(&v))
            .copied()
            .unwrap_or(CANVAS_W / 2.0);

        // Determine the base Y: below the parent switch, or at endpoint layer
        let parent_y = parent
            .as_deref()
            .and_then(|pid| nodes.get(pid))
            .map(|n| n.y)
            .unwrap_or(TOP_MARGIN + 2.0 * LAYER_SPACING);

        let base_y = parent_y + ENDPOINT_OFFSET;

        // Arrange in a grid
        let cols = (endpoint_ids.len() as f64).sqrt().ceil() as usize;
        let cols = cols.max(1);

        for (i, id) in endpoint_ids.iter().enumerate() {
            let col = i % cols;
            let row = i / cols;
            let grid_w = (cols as f64 - 1.0) * NODE_SPACING;

            if let Some(node) = nodes.get_mut(id) {
                node.x = base_x - grid_w / 2.0 + col as f64 * NODE_SPACING;
                node.y = base_y + row as f64 * NODE_SPACING;
            }
        }
    }
}

// ── Device type mapping ──────────────────────────────────────────

fn map_device_type(dt: Option<&str>) -> NodeKind {
    match dt {
        Some("router") => NodeKind::Router,
        Some("switch") | Some("network_equipment") => NodeKind::ManagedSwitch,
        Some("access_point") | Some("wap") => NodeKind::AccessPoint,
        Some("server") => NodeKind::Server,
        Some("computer") | Some("workstation") | Some("laptop") | Some("desktop") => {
            NodeKind::Workstation
        }
        Some("camera") => NodeKind::Camera,
        Some("printer") => NodeKind::Printer,
        Some("phone") | Some("mobile") => NodeKind::Phone,
        Some("smart_home") => NodeKind::SmartHome,
        Some("media_player") | Some("media_server") => NodeKind::MediaPlayer,
        Some("gaming") | Some("iot") | Some("storage") => NodeKind::IoT,
        _ => NodeKind::Unknown,
    }
}

// ── Background task ──────────────────────────────────────────────

pub fn spawn_topology_updater(
    switch_store: Arc<SwitchStore>,
    device_manager: Arc<RwLock<DeviceManager>>,
    cache: Arc<RwLock<Option<NetworkTopology>>>,
) {
    tokio::spawn(async move {
        // Wait for correlation engine to populate data
        tokio::time::sleep(Duration::from_secs(120)).await;
        tracing::info!("topology updater starting (120s interval)");

        let mut interval = tokio::time::interval(Duration::from_secs(120));

        loop {
            match compute_topology(&switch_store, &device_manager).await {
                Ok(topo) => {
                    tracing::info!(
                        nodes = topo.node_count,
                        edges = topo.edge_count,
                        infra = topo.infrastructure_count,
                        endpoints = topo.endpoint_count,
                        "topology recomputed"
                    );
                    let mut w = cache.write().await;
                    *w = Some(topo);
                }
                Err(e) => {
                    tracing::warn!("topology computation failed: {e}");
                }
            }
            interval.tick().await;
        }
    });
}

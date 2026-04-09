//! Auto-generated network topology computation.
//!
//! Consumes a `ResolvedInfrastructureSnapshot` (produced by the correlation engine)
//! for infrastructure nodes and edges, then adds endpoint placement, BFS layout,
//! VLAN grouping, and sector positioning.
//!
//! **Rule:** No LLDP resolution, no neighbor matching, no infrastructure dedup
//! happens here. Topology is a pure consumer of resolved truth.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use ion_drift_storage::switch::{NetworkIdentity, SectorPosition, SwitchStore};
use crate::identity_utils::{identity_overrides_lldp, is_infrastructure_type};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::device_manager::DeviceManager;
use crate::infrastructure_snapshot::{
    InfraNodeSource, InfrastructureSnapshotState, ResolvedInfrastructureSnapshot,
};
use crate::task_supervisor::TaskSupervisor;
use ion_drift_storage::behavior::BehaviorStore;

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
    pub disposition: String,
    pub baseline_status: Option<String>,
    pub binding_source: String,
    pub binding_tier: Option<String>,
    pub attachment_state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub kind: EdgeKind,
    pub source_port: Option<String>,
    pub target_port: Option<String>,
    pub vlans: Vec<u32>,
    pub speed_mbps: Option<u32>,
    pub traffic_bps: Option<u64>,
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
    pub position_source: String,
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

// ── VLAN config ─────────────────────────────────────────────────

/// Generic fallback when DB has no entry for a VLAN.
fn vlan_config_fallback(id: u32) -> (String, &'static str, &'static str) {
    (format!("VLAN {id}"), "#888888", "")
}

use ion_drift_storage::switch::VlanConfig;

/// Resolve VLAN metadata from DB config map, falling back to hardcoded defaults.
fn resolve_vlan_config(
    id: u32,
    db_configs: &HashMap<u32, VlanConfig>,
) -> (String, String, String) {
    if let Some(cfg) = db_configs.get(&id) {
        (
            cfg.name.clone(),
            cfg.color.clone().unwrap_or_else(|| "#888888".to_string()),
            cfg.subnet.clone().unwrap_or_default(),
        )
    } else {
        let (n, c, s) = vlan_config_fallback(id);
        (n, c.to_string(), s.to_string())
    }
}

/// Sorted VLAN order for consistent horizontal layout.
// VLAN_ORDER removed — now derived from database VlanConfig at runtime.

// ── Layout constants ─────────────────────────────────────────────

const CANVAS_W: f64 = 4000.0;
const LAYER_SPACING: f64 = 300.0;
const VLAN_SECTOR_MIN_W: f64 = 200.0;
const VLAN_SECTOR_EMPTY_W: f64 = 150.0;
const NODE_SPACING: f64 = 120.0;
const TOP_MARGIN: f64 = 150.0;
const ENDPOINT_OFFSET: f64 = 200.0;
const SECTOR_PADDING: f64 = 40.0;

// WAN_INTERFACES removed — now passed as parameter from config.router.wan_interface

// ── Graph construction ───────────────────────────────────────────

pub async fn compute_topology(
    store: &SwitchStore,
    behavior_store: &BehaviorStore,
    snapshot: &ResolvedInfrastructureSnapshot,
    wan_interface: &str,
) -> anyhow::Result<NetworkTopology> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Load DB-backed VLAN configs for name/color/subnet resolution
    let vlan_config_list = store.get_vlan_configs().await.unwrap_or_default();
    let vlan_config_map: HashMap<u32, VlanConfig> = vlan_config_list
        .into_iter()
        .map(|c| (c.vlan_id, c))
        .collect();

    let mut nodes: BTreeMap<String, TopologyNode> = BTreeMap::new();
    let mut edges: Vec<TopologyEdge> = Vec::new();
    let mut infra_ids: HashSet<String> = HashSet::new();

    // ── Layer 1: Infrastructure from snapshot ─────────────────────
    //
    // The correlation engine has already resolved all LLDP neighbors,
    // built infrastructure nodes, and deduped edges. We just render them.

    let mut router_id: Option<String> = None;

    // Build infrastructure nodes from the resolved snapshot.
    // No LLDP resolution, no neighbor matching, no dedup — the correlation
    // engine has already done all of that.
    for infra_node in &snapshot.infrastructure {
        let id = infra_node.device_id.clone();
        let kind = match infra_node.device_type.as_deref() {
            Some("router") => {
                router_id = Some(id.clone());
                NodeKind::Router
            }
            Some("access_point") | Some("wap") => NodeKind::AccessPoint,
            Some("switch") | Some("network_equipment") => {
                if infra_node.source == InfraNodeSource::Registered {
                    NodeKind::ManagedSwitch
                } else {
                    NodeKind::UnmanagedSwitch
                }
            }
            _ => {
                if infra_node.source == InfraNodeSource::Registered {
                    NodeKind::ManagedSwitch
                } else {
                    NodeKind::UnmanagedSwitch
                }
            }
        };

        let status = if infra_node.source == InfraNodeSource::Registered {
            // Registered devices have live status — check via confidence as proxy
            // (correlation sets confidence=1.0 for online registered devices)
            if infra_node.confidence >= 1.0 {
                NodeStatus::Online
            } else {
                NodeStatus::Unknown
            }
        } else {
            NodeStatus::Unknown
        };

        let (binding_source, binding_tier) = match infra_node.source {
            InfraNodeSource::Registered => {
                let tier = if kind == NodeKind::Router { "router" } else { "ros_switch" };
                ("authoritative".to_string(), Some(tier.to_string()))
            }
            _ => ("observed".to_string(), None),
        };

        let disposition = match infra_node.source {
            InfraNodeSource::Registered => "my_device".to_string(),
            _ => "unknown".to_string(),
        };

        infra_ids.insert(id.clone());
        nodes.insert(
            id.clone(),
            TopologyNode {
                id: id.clone(),
                label: infra_node.label.clone(),
                ip: infra_node.ip.clone(),
                mac: infra_node.mac.clone(),
                kind,
                vlan_id: None,
                vlans_served: Vec::new(),
                device_type: infra_node.device_type.clone(),
                manufacturer: infra_node.manufacturer.clone(),
                is_infrastructure: true,
                layer: 0,
                x: 0.0,
                y: 0.0,
                position_source: "auto".to_string(),
                first_seen: infra_node.first_seen.unwrap_or(now),
                last_seen: infra_node.last_seen.unwrap_or(now),
                parent_id: None,
                switch_port: None,
                status,
                confidence: infra_node.confidence as f64,
                disposition,
                baseline_status: None,
                binding_source,
                binding_tier,
                attachment_state: None,
            },
        );
    }

    // Build trunk edges from snapshot
    for snap_edge in &snapshot.edges {
        edges.push(TopologyEdge {
            source: snap_edge.source_device.clone(),
            target: snap_edge.target_device.clone(),
            kind: EdgeKind::Trunk,
            source_port: snap_edge.source_port.clone(),
            target_port: snap_edge.target_port.clone(),
            vlans: snap_edge.vlans.clone(),
            speed_mbps: snap_edge.speed_mbps,
            traffic_bps: snap_edge.traffic_bps,
        });
    }

    // WAN placeholder from snapshot
    if snapshot.wan_neighbor_count > 0 {
        if let Some(ref rid) = router_id {
            let wan_id = "WAN".to_string();
            infra_ids.insert(wan_id.clone());
            nodes.insert(
                wan_id.clone(),
                TopologyNode {
                    id: wan_id.clone(),
                    label: format!("WAN / ISP ({})", snapshot.wan_neighbor_count),
                    ip: None,
                    mac: None,
                    kind: NodeKind::Router,
                    vlan_id: None,
                    vlans_served: Vec::new(),
                    device_type: Some("wan_gateway".to_string()),
                    manufacturer: None,
                    is_infrastructure: true,
                    layer: 0,
                    x: 0.0,
                    y: 0.0,
                    position_source: "auto".to_string(),
                    first_seen: now,
                    last_seen: now,
                    parent_id: None,
                    switch_port: None,
                    status: NodeStatus::Unknown,
                    confidence: 1.0,
                    disposition: "external".to_string(),
                    baseline_status: None,
                    binding_source: "authoritative".to_string(),
                    binding_tier: Some("router".to_string()),
                    attachment_state: None,
                },
            );
            edges.push(TopologyEdge {
                source: rid.clone(),
                target: wan_id,
                kind: EdgeKind::Uplink,
                source_port: Some(wan_interface.to_string()),
                target_port: None,
                vlans: Vec::new(),
                speed_mbps: Some(1000),
                traffic_bps: None,
            });
        }
    }

    // ── Resolve edge speeds from port metrics ─────────────────────
    {
        let mut device_ids_with_edges: HashSet<String> = HashSet::new();
        for edge in &edges {
            if edge.source_port.is_some() {
                device_ids_with_edges.insert(edge.source.clone());
            }
            if edge.target_port.is_some() {
                device_ids_with_edges.insert(edge.target.clone());
            }
        }
        let mut speed_map: HashMap<String, HashMap<String, u32>> = HashMap::new();
        for dev_id in &device_ids_with_edges {
            if let Ok(speeds) = store.get_port_speeds(dev_id).await {
                if !speeds.is_empty() {
                    speed_map.insert(dev_id.clone(), speeds);
                }
            }
        }
        for edge in &mut edges {
            if edge.speed_mbps.is_some() { continue; }
            let src_speed = edge.source_port.as_deref()
                .and_then(|p| speed_map.get(&edge.source).and_then(|m| m.get(&p.to_lowercase())))
                .copied();
            let tgt_speed = edge.target_port.as_deref()
                .and_then(|p| speed_map.get(&edge.target).and_then(|m| m.get(&p.to_lowercase())))
                .copied();
            edge.speed_mbps = match (src_speed, tgt_speed) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
        }
    }

    // ── Resolve traffic rates on edges ────────────────────────────
    {
        let mut traffic_map: HashMap<String, HashMap<String, u64>> = HashMap::new();
        let mut device_ids_with_edges: HashSet<String> = HashSet::new();
        for edge in &edges {
            if edge.source_port.is_some() { device_ids_with_edges.insert(edge.source.clone()); }
            if edge.target_port.is_some() { device_ids_with_edges.insert(edge.target.clone()); }
        }
        for dev_id in &device_ids_with_edges {
            if let Ok(traffic) = store.get_port_traffic_bps(dev_id).await {
                if !traffic.is_empty() { traffic_map.insert(dev_id.clone(), traffic); }
            }
        }
        for edge in &mut edges {
            let src_bps = edge.source_port.as_deref()
                .and_then(|p| traffic_map.get(&edge.source).and_then(|m| m.get(&p.to_lowercase()))).copied();
            let tgt_bps = edge.target_port.as_deref()
                .and_then(|p| traffic_map.get(&edge.target).and_then(|m| m.get(&p.to_lowercase()))).copied();
            edge.traffic_bps = match (src_bps, tgt_bps) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
        }
    }

    // ── BFS layer assignment from router ──────────────────────────
    if let Some(ref rid) = router_id {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, u32)> = VecDeque::new();
        queue.push_back((rid.clone(), 0));
        visited.insert(rid.clone());
        while let Some((node_id, layer)) = queue.pop_front() {
            if let Some(node) = nodes.get_mut(&node_id) { node.layer = layer; }
            for edge in &edges {
                if edge.kind != EdgeKind::Trunk { continue; }
                let neighbor = if edge.source == node_id { &edge.target }
                    else if edge.target == node_id { &edge.source }
                    else { continue };
                if !visited.contains(neighbor) && infra_ids.contains(neighbor) {
                    visited.insert(neighbor.clone());
                    queue.push_back((neighbor.clone(), layer + 1));
                }
            }
        }
        let max_layer = nodes.values().filter(|n| n.is_infrastructure).map(|n| n.layer).max().unwrap_or(0);
        for node in nodes.values_mut() {
            if node.is_infrastructure && !visited.contains(&node.id) { node.layer = max_layer + 1; }
        }
    }
    if let Some(wan) = nodes.get_mut("WAN") { wan.layer = 0; }

    // Compute VLANs served by each infrastructure node
    for infra_id in &infra_ids {
        let memberships = store.get_vlan_membership(infra_id).await.unwrap_or_default();
        let mut vlan_list: Vec<u32> = memberships.iter().map(|m| m.vlan_id).collect();
        vlan_list.sort();
        vlan_list.dedup();
        if let Some(node) = nodes.get_mut(infra_id) { node.vlans_served = vlan_list; }
    }

    // Derive helper maps for endpoint placement from snapshot data
    let identities = &snapshot.identities;
    let identity_by_mac: HashMap<String, &NetworkIdentity> = identities
        .iter()
        .map(|id| (id.mac_address.to_uppercase(), id))
        .collect();

    // Build ip_to_device and mac_to_device from infra nodes for endpoint filtering
    let mut ip_to_device: HashMap<String, String> = HashMap::new();
    let mut mac_to_device: HashMap<String, String> = HashMap::new();
    for infra_node in &snapshot.infrastructure {
        if let Some(ref ip) = infra_node.ip {
            ip_to_device.insert(ip.clone(), infra_node.device_id.clone());
        }
        if let Some(ref mac) = infra_node.mac {
            mac_to_device.insert(mac.to_uppercase(), infra_node.device_id.clone());
        }
    }

    // ── Layer 2: Endpoint placement ─────────────────────────────

    let endpoint_layer = nodes
        .values()
        .filter(|n| n.is_infrastructure)
        .map(|n| n.layer)
        .max()
        .unwrap_or(0)
        + 1;

    // Build infra MAC set from snapshot infrastructure nodes
    let mut infra_macs: HashSet<String> = HashSet::new();
    for infra_node in &snapshot.infrastructure {
        if let Some(ref mac) = infra_node.mac {
            infra_macs.insert(mac.to_uppercase());
        }
    }
    // Also add any MAC from the rendered infra nodes
    for node in nodes.values() {
        if node.is_infrastructure {
            if let Some(ref mac) = node.mac {
                infra_macs.insert(mac.to_uppercase());
            }
        }
    }
    // Add switch-local MACs (the switch's own interface MACs). These appear
    // in other switches' MAC tables as regular learned MACs but should never
    // become endpoint nodes. Without this, CRS310's sfp and bridge MACs
    // show up as phantom "Routerboardcom" endpoints.
    let local_macs = store.get_local_macs().await.unwrap_or_default();
    for mac in &local_macs {
        infra_macs.insert(mac.to_uppercase());
    }
    // Remove human-confirmed non-infrastructure MACs from infra_macs
    infra_macs.retain(|mac| {
        if let Some(ident) = identity_by_mac.get(mac.as_str()) {
            !identity_overrides_lldp(ident)
        } else {
            true
        }
    });

    for identity in identities {
        let mac = identity.mac_address.to_uppercase();

        // Skip infrastructure MACs
        if infra_macs.contains(&mac) {
            continue;
        }
        // Skip if already in nodes (e.g., inferred infrastructure)
        if nodes.contains_key(&mac) {
            continue;
        }
        // Skip if this identity's IP matches a registered device (catches router
        // gateway IPs that leak through ARP/DHCP into network_identities)
        if let Some(ref ip) = identity.best_ip {
            if ip_to_device.contains_key(ip) {
                continue;
            }
        }
        // Skip if this identity's MAC matches a known infrastructure device
        if mac_to_device.contains_key(&mac) {
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
                disposition: identity.disposition.clone(),
                baseline_status: None,
                binding_source: match identity.switch_binding_source.as_str() {
                    "human" => "authoritative",
                    "inference" => "inferred",
                    _ => "observed",
                }.to_string(),
                binding_tier: match identity.switch_binding_source.as_str() {
                    "human" => Some("admin".to_string()),
                    "inference" => Some("multi_signal".to_string()),
                    _ => None,
                },
                attachment_state: None, // stamped in Phase 2
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
                    speed_mbps: None,
                    traffic_bps: None,
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

    // ── Stamp baseline status from behavior profiles ─────────────
    {
        let macs: Vec<&str> = nodes.values()
            .filter_map(|n| n.mac.as_deref())
            .collect();
        if !macs.is_empty() {
            if let Ok(profiles) = behavior_store.get_profiles_bulk(&macs).await {
                for node in nodes.values_mut() {
                    if let Some(mac) = &node.mac {
                        if let Some(profile) = profiles.get(mac) {
                            node.baseline_status = Some(profile.baseline_status.clone());
                        }
                    }
                }
            }
        }
    }

    // ── Stamp attachment state from inference engine ──────────────
    {
        let attachment_rows = store.get_all_attachment_states().await.unwrap_or_default();
        let attachment_by_mac: std::collections::HashMap<String, _> = attachment_rows
            .into_iter()
            .map(|r| (r.mac_address.to_uppercase(), r))
            .collect();
        for node in nodes.values_mut() {
            if let Some(mac) = &node.mac {
                if let Some(att) = attachment_by_mac.get(&mac.to_uppercase()) {
                    node.attachment_state = Some(att.state.clone());
                    if att.confidence > node.confidence {
                        node.confidence = att.confidence;
                    }
                    // If inference has an active binding, override binding_source.
                    // This ensures topology reflects inference ownership even if the
                    // DB identity still shows "auto" from pre-SoA correlation cycles.
                    if att.current_device_id.is_some()
                        && att.state != "unknown"
                        && att.confidence > 0.3
                    {
                        node.binding_source = "inferred".to_string();
                        node.binding_tier = Some("multi_signal".to_string());
                    }
                }
            }
        }
    }

    // ── Assign primary VLAN to single-VLAN infrastructure ───────
    for node in nodes.values_mut() {
        if node.is_infrastructure && node.vlan_id.is_none() && node.vlans_served.len() == 1 {
            node.vlan_id = Some(node.vlans_served[0]);
        }
    }

    // ── Layout computation ───────────────────────────────────────
    // Returns (left_x, top_y, width, height) per VLAN sector
    // Build ordered VLAN list from database config (sorted by VLAN ID)
    let configured_vlans: Vec<u32> = {
        let mut ids: Vec<u32> = vlan_config_map.keys().copied().collect();
        ids.sort();
        ids
    };
    let sector_geometry = compute_layout(&mut nodes, &edges, &configured_vlans);

    // Position WAN node to the left of the router
    if let Some(router_pos) = router_id
        .as_ref()
        .and_then(|rid| nodes.get(rid))
        .map(|n| (n.x, n.y))
    {
        if let Some(wan) = nodes.get_mut("WAN") {
            wan.x = router_pos.0 - 300.0;
            wan.y = router_pos.1;
        }
    }

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

    // Load human sector position overrides
    let sector_positions = store.get_sector_positions().await.unwrap_or_default();
    let sector_overrides: HashMap<u32, &SectorPosition> = sector_positions
        .iter()
        .filter(|sp| sp.source == "human")
        .map(|sp| (sp.vlan_id, sp))
        .collect();

    let mut vlan_groups: Vec<VlanGroup> = Vec::new();
    for (&vlan_id, &(left_x, top_y, width, height)) in &sector_geometry {
        let group_nodes = vlan_nodes.get(&vlan_id);
        let (name, color, subnet) = resolve_vlan_config(vlan_id, &vlan_config_map);

        // Check for human override
        if let Some(sp) = sector_overrides.get(&vlan_id) {
            let node_count = group_nodes.map(|gn| gn.len() as u32).unwrap_or(0);
            let w = sp.width.unwrap_or(width);
            let h = sp.height.unwrap_or(height);
            vlan_groups.push(VlanGroup {
                vlan_id,
                name,
                color,
                subnet,
                node_count,
                bbox_x: sp.x,
                bbox_y: sp.y,
                bbox_w: w,
                bbox_h: h,
                position_source: "human".to_string(),
            });
            continue;
        }

        let node_count = group_nodes.map(|gn| gn.len() as u32).unwrap_or(0);

        vlan_groups.push(VlanGroup {
            vlan_id,
            name,
            color,
            subnet,
            node_count,
            bbox_x: left_x,
            bbox_y: top_y,
            bbox_w: width,
            bbox_h: height,
            position_source: "auto".to_string(),
        });
    }

    // ── Validate edges have valid endpoints ─────────────────────
    let valid_node_ids: HashSet<&String> = nodes.keys().collect();
    for edge in &edges {
        if !valid_node_ids.contains(&edge.source) {
            tracing::warn!(
                source = %edge.source, target = %edge.target, kind = ?edge.kind,
                "edge references non-existent source node — will not render"
            );
        }
        if !valid_node_ids.contains(&edge.target) {
            tracing::warn!(
                source = %edge.source, target = %edge.target, kind = ?edge.kind,
                "edge references non-existent target node — will not render"
            );
        }
    }

    // Log infrastructure nodes for debugging
    for node in nodes.values().filter(|n| n.is_infrastructure) {
        tracing::debug!(
            id = %node.id, label = %node.label, kind = ?node.kind,
            layer = node.layer, x = node.x, y = node.y,
            "infrastructure node"
        );
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

// ── Center-spine layout ─────────────────────────────────────────
//
// VLAN 2 (Management) renders as a vertical spine down the center.
// All other VLAN sectors stack in two columns (left/right) flanking it.
// Heights are proportional to device count; columns are balanced by
// total device count using a greedy assignment algorithm.

const SPINE_WIDTH: f64 = 300.0;
const COLUMN_GAP: f64 = 60.0;
const SECTOR_V_GAP: f64 = 30.0;
const MIN_SECTOR_H: f64 = 100.0;
const SECTOR_HEADER_H: f64 = 50.0;

/// Returns a map of vlan_id → (left_x, top_y, width, height) for sector geometry.
fn compute_layout(
    nodes: &mut BTreeMap<String, TopologyNode>,
    _edges: &[TopologyEdge],
    configured_vlans: &[u32],
) -> BTreeMap<u32, (f64, f64, f64, f64)> {
    // ── Collect VLANs and device counts ──────────────────────────
    let mut active_vlans: Vec<u32> = configured_vlans.to_vec();
    for node in nodes.values() {
        if let Some(vid) = node.vlan_id {
            if !active_vlans.contains(&vid) {
                active_vlans.push(vid);
            }
        }
    }

    let mut vlan_endpoint_counts: HashMap<u32, usize> = HashMap::new();
    for node in nodes.values() {
        // Count endpoints AND single-VLAN infrastructure (APs, single-VLAN switches)
        // so their VLAN sectors are sized correctly
        let in_sector = !node.is_infrastructure
            || (node.is_infrastructure && node.vlans_served.len() <= 1 && node.vlan_id.is_some());
        if in_sector {
            if let Some(vid) = node.vlan_id {
                *vlan_endpoint_counts.entry(vid).or_default() += 1;
            }
        }
    }

    // ── Balance VLANs across left/right columns ─────────────────
    // All VLANs get sectors — the spine is reserved for multi-VLAN infrastructure only
    let side_vlans: Vec<u32> = active_vlans.clone();

    // Sort by device count descending for greedy balancing
    let mut sorted_by_count: Vec<(u32, usize)> = side_vlans
        .iter()
        .map(|&v| (v, vlan_endpoint_counts.get(&v).copied().unwrap_or(0)))
        .collect();
    sorted_by_count.sort_by(|a, b| b.1.cmp(&a.1));

    let (mut left_vlans, mut right_vlans) = (Vec::new(), Vec::new());
    let (mut left_total, mut right_total) = (0usize, 0usize);

    for &(vid, count) in &sorted_by_count {
        let weight = count.max(1);
        if left_total <= right_total {
            left_vlans.push(vid);
            left_total += weight;
        } else {
            right_vlans.push(vid);
            right_total += weight;
        }
    }

    // Sort within columns by VLAN ID for consistency
    left_vlans.sort();
    right_vlans.sort();

    // ── Compute column widths (uniform per column) ──────────────
    fn col_width(vlans: &[u32], counts: &HashMap<u32, usize>) -> f64 {
        if vlans.is_empty() {
            return VLAN_SECTOR_MIN_W;
        }
        vlans
            .iter()
            .map(|&v| {
                let count = counts.get(&v).copied().unwrap_or(0);
                if count == 0 {
                    return VLAN_SECTOR_EMPTY_W;
                }
                let cols = (count as f64).sqrt().ceil().max(1.0);
                (cols * NODE_SPACING + 2.0 * SECTOR_PADDING).max(VLAN_SECTOR_MIN_W)
            })
            .fold(VLAN_SECTOR_MIN_W, f64::max)
    }

    let left_w = col_width(&left_vlans, &vlan_endpoint_counts);
    let right_w = col_width(&right_vlans, &vlan_endpoint_counts);

    // ── Compute sector heights ──────────────────────────────────
    fn sector_height(count: usize, sector_width: f64) -> f64 {
        if count == 0 {
            return MIN_SECTOR_H;
        }
        let usable_w = (sector_width - 2.0 * SECTOR_PADDING).max(NODE_SPACING);
        let cols = (usable_w / NODE_SPACING).floor().max(1.0) as usize;
        let rows = (count + cols - 1) / cols;
        let grid_h = rows as f64 * NODE_SPACING;
        (grid_h + SECTOR_HEADER_H + 2.0 * SECTOR_PADDING).max(MIN_SECTOR_H)
    }

    // ── Position sectors ────────────────────────────────────────
    let canvas_center = CANVAS_W / 2.0;
    let spine_left = canvas_center - SPINE_WIDTH / 2.0;
    let spine_right = canvas_center + SPINE_WIDTH / 2.0;

    let left_right_edge = spine_left - COLUMN_GAP;
    let left_left_edge = left_right_edge - left_w;
    let right_left_edge = spine_right + COLUMN_GAP;

    let mut sector_geom: BTreeMap<u32, (f64, f64, f64, f64)> = BTreeMap::new();

    // Stack left column
    let mut cursor_y = TOP_MARGIN;
    for &vid in &left_vlans {
        let count = vlan_endpoint_counts.get(&vid).copied().unwrap_or(0);
        let h = sector_height(count, left_w);
        sector_geom.insert(vid, (left_left_edge, cursor_y, left_w, h));
        cursor_y += h + SECTOR_V_GAP;
    }
    let left_total_h = if left_vlans.is_empty() {
        0.0
    } else {
        cursor_y - SECTOR_V_GAP - TOP_MARGIN
    };

    // Stack right column
    cursor_y = TOP_MARGIN;
    for &vid in &right_vlans {
        let count = vlan_endpoint_counts.get(&vid).copied().unwrap_or(0);
        let h = sector_height(count, right_w);
        sector_geom.insert(vid, (right_left_edge, cursor_y, right_w, h));
        cursor_y += h + SECTOR_V_GAP;
    }
    let right_total_h = if right_vlans.is_empty() {
        0.0
    } else {
        cursor_y - SECTOR_V_GAP - TOP_MARGIN
    };

    // Spine region — spans the full height, used for multi-VLAN infrastructure only
    let max_infra_layer = nodes
        .values()
        .filter(|n| n.is_infrastructure)
        .map(|n| n.layer)
        .max()
        .unwrap_or(0);
    let infra_bottom = TOP_MARGIN + max_infra_layer as f64 * LAYER_SPACING + LAYER_SPACING;
    let _spine_h = left_total_h
        .max(right_total_h)
        .max(infra_bottom - TOP_MARGIN)
        .max(MIN_SECTOR_H);

    // ── Position infrastructure nodes (in center spine) ─────────
    // Only multi-VLAN infrastructure goes on the spine; single-VLAN infra
    // (e.g., APs serving one VLAN) goes in their VLAN sector below.
    let mut layers: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for (id, node) in nodes.iter() {
        if node.is_infrastructure && (node.vlan_id.is_none() || node.vlans_served.len() > 1) {
            layers.entry(node.layer).or_default().push(id.clone());
        }
    }

    for (_layer, ids) in &layers {
        let mut infra_ids = ids.clone();
        infra_ids.sort();

        let count = infra_ids.len();
        for (i, id) in infra_ids.iter().enumerate() {
            if let Some(node) = nodes.get_mut(id) {
                node.y = TOP_MARGIN + node.layer as f64 * LAYER_SPACING;
                // Spread evenly within spine width
                let slot_w = SPINE_WIDTH / (count + 1) as f64;
                node.x = spine_left + slot_w * (i + 1) as f64;
            }
        }
    }

    // ── Position endpoint nodes (within their VLAN sector) ──────
    // Includes endpoints AND single-VLAN infrastructure (APs, etc.)
    let mut vlan_endpoints: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for (id, node) in nodes.iter() {
        let in_sector = !node.is_infrastructure
            || (node.is_infrastructure && node.vlans_served.len() <= 1 && node.vlan_id.is_some());
        if in_sector {
            if let Some(vid) = node.vlan_id {
                vlan_endpoints.entry(vid).or_default().push(id.clone());
            }
        }
    }

    for (vid, mut ep_ids) in vlan_endpoints {
        ep_ids.sort();

        if let Some(&(lx, ty, w, _h)) = sector_geom.get(&vid) {
            let usable_w = (w - 2.0 * SECTOR_PADDING).max(NODE_SPACING);
            let cols = (usable_w / NODE_SPACING).floor().max(1.0) as usize;

            let grid_start_y = ty + SECTOR_HEADER_H + SECTOR_PADDING;

            let grid_start_x = lx + SECTOR_PADDING + NODE_SPACING / 2.0;

            for (i, id) in ep_ids.iter().enumerate() {
                let col = i % cols;
                let row = i / cols;
                if let Some(node) = nodes.get_mut(id) {
                    node.x = grid_start_x + col as f64 * NODE_SPACING;
                    node.y = grid_start_y + row as f64 * NODE_SPACING;
                }
            }
        }
    }

    sector_geom
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

/// Strip punctuation/whitespace and lowercase for fuzzy identity matching.
/// e.g. "MT-4011-R-Office" → "mt4011roffice" matches "MT4011ROffice".
fn normalize_identity(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | ' '))
        .collect::<String>()
        .to_lowercase()
}

// ── Background task ──────────────────────────────────────────────

pub fn spawn_topology_updater(
    supervisor: &TaskSupervisor,
    switch_store: Arc<SwitchStore>,
    behavior_store: Arc<BehaviorStore>,
    cache: Arc<RwLock<Option<NetworkTopology>>>,
    snapshot_state: Arc<tokio::sync::RwLock<InfrastructureSnapshotState>>,
    wan_interface: String,
) {
    supervisor.spawn("topology_updater", move || {
        let switch_store = switch_store.clone();
        let behavior_store = behavior_store.clone();
        let cache = cache.clone();
        let snapshot_state = snapshot_state.clone();
        let wan_interface = wan_interface.clone();
        Box::pin(async move {
        tracing::info!("topology updater starting (120s interval, snapshot-driven)");

        let mut interval = tokio::time::interval(Duration::from_secs(120));

        loop {
            interval.tick().await;

            // Read the best available snapshot — no snapshot means no topology yet
            let snapshot = {
                let state = snapshot_state.read().await;
                match state.best_available() {
                    Some(s) => s.clone(),
                    None => {
                        tracing::debug!("topology: no snapshot available yet, skipping");
                        continue;
                    }
                }
            };

            match compute_topology(&switch_store, &behavior_store, &snapshot, &wan_interface).await {
                Ok(topo) => {
                    tracing::info!(
                        snapshot_gen = snapshot.generation,
                        nodes = topo.node_count,
                        edges = topo.edge_count,
                        infra = topo.infrastructure_count,
                        endpoints = topo.endpoint_count,
                        "topology recomputed from snapshot"
                    );
                    let mut w = cache.write().await;
                    *w = Some(topo);
                }
                Err(e) => {
                    tracing::warn!("topology computation failed: {e}");
                }
            }
        }
    })});
}


//! Auto-generated network topology computation.
//!
//! Reads from `neighbor_discovery`, `network_identities`, `switch_port_roles`,
//! and the `DeviceManager` to build a hierarchical network graph with deterministic
//! layout. The result is cached in `AppState` and served via the topology API.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use ion_drift_storage::switch::{NetworkIdentity, SectorPosition, SwitchStore};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::device_manager::{DeviceManager, DeviceStatus};
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
    device_manager: &Arc<RwLock<DeviceManager>>,
    behavior_store: &BehaviorStore,
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
    // MAC → node_id map for infrastructure dedup (prevents same physical device
    // from appearing under different keys like LLDP identity vs device name)
    let mut infra_mac_to_node_id: HashMap<String, String> = HashMap::new();

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

        let tier = if kind == NodeKind::Router { "router" } else { "ros_switch" };
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
                disposition: "my_device".to_string(),
                baseline_status: None,
                binding_source: "authoritative".to_string(),
                binding_tier: Some(tier.to_string()),
                attachment_state: None,
            },
        );
    }
    drop(dm);

    // ── Pre-load network identities for identity-first decisions ──
    // Loaded early so LLDP neighbor processing can check whether a MAC
    // has an authoritative identity before creating infrastructure nodes.
    let identities = store.get_network_identities().await?;
    let identity_by_mac: HashMap<String, &NetworkIdentity> = identities
        .iter()
        .map(|id| (id.mac_address.to_uppercase(), id))
        .collect();

    // 1b. LLDP/MNDP neighbors → trunk edges + inferred infrastructure
    let neighbors = store.get_neighbors(None).await?;

    // Build mappings: identity/name/IP/MAC → registered device ID
    // Multiple keys can map to the same device to handle LLDP reporting
    // alternate names (e.g. RouterOS identity vs registered name).
    let dm = device_manager.read().await;
    let mut identity_to_device: HashMap<String, String> = HashMap::new();
    let mut ip_to_device: HashMap<String, String> = HashMap::new();
    let mut mac_to_device: HashMap<String, String> = HashMap::new();
    for entry in dm.all_devices() {
        // Existing exact-match keys
        identity_to_device.insert(entry.record.name.to_lowercase(), entry.record.id.clone());
        identity_to_device.insert(entry.record.id.to_lowercase(), entry.record.id.clone());
        ip_to_device.insert(entry.record.host.clone(), entry.record.id.clone());
        // NEW: actual RouterOS identity from health check (exact MNDP broadcast string)
        if let DeviceStatus::Online { ref identity } = entry.status {
            identity_to_device.insert(identity.to_lowercase(), entry.record.id.clone());
            identity_to_device.insert(normalize_identity(identity), entry.record.id.clone());
        }
        // NEW: normalized fuzzy keys for name/id
        identity_to_device.insert(normalize_identity(&entry.record.name), entry.record.id.clone());
        identity_to_device.insert(normalize_identity(&entry.record.id), entry.record.id.clone());
    }
    drop(dm);

    // Also build MAC → device from neighbor records: if a neighbor was seen
    // FROM a device and matches a registered device, record the neighbor MAC
    // so we can dedup later even when identity names don't match.
    for nb in &neighbors {
        if let Some(ref mac) = nb.mac_address {
            // If this neighbor's identity or IP resolves to a registered device,
            // associate its MAC with that device too.
            let resolved = nb
                .identity
                .as_deref()
                .and_then(|id| identity_to_device.get(&id.to_lowercase()).cloned())
                .or_else(|| {
                    nb.address
                        .as_deref()
                        .and_then(|addr| ip_to_device.get(addr).cloned())
                });
            if let Some(dev_id) = resolved {
                mac_to_device.insert(mac.to_uppercase(), dev_id);
            }
        }
    }

    // ── Load neighbor aliases (alias → inject into maps, hide → skip set) ──
    let aliases = store.get_neighbor_aliases().await.unwrap_or_default();
    let mut hidden_macs: HashSet<String> = HashSet::new();
    let mut hidden_identities: HashSet<String> = HashSet::new();

    for alias in &aliases {
        match alias.action.as_str() {
            "alias" => {
                if let Some(ref target) = alias.target_device_id {
                    match alias.match_type.as_str() {
                        "mac" => {
                            mac_to_device.insert(alias.match_value.to_uppercase(), target.clone());
                        }
                        "identity" => {
                            identity_to_device.insert(alias.match_value.to_lowercase(), target.clone());
                            identity_to_device.insert(normalize_identity(&alias.match_value), target.clone());
                        }
                        _ => {}
                    }
                }
            }
            "hide" => {
                match alias.match_type.as_str() {
                    "mac" => { hidden_macs.insert(alias.match_value.to_uppercase()); }
                    "identity" => { hidden_identities.insert(alias.match_value.to_lowercase()); }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Seed infra MAC dedup from mac_to_device (registered devices' neighbor MACs)
    for (mac, dev_id) in &mac_to_device {
        infra_mac_to_node_id.insert(mac.clone(), dev_id.clone());
    }

    // Track edges we've already created (both directions)
    let mut edge_set: HashSet<(String, String)> = HashSet::new();
    let mut wan_neighbor_count = 0u32;

    for nb in &neighbors {
        let source_device = nb.device_id.clone();
        let source_port = nb.interface.clone();

        // Skip WAN-facing neighbors on the router — they are ISP/external equipment
        // and will be collapsed into a single "WAN / ISP" node below.
        if Some(&source_device) == router_id.as_ref()
            && source_port == wan_interface
        {
            wan_neighbor_count += 1;
            continue;
        }

        // Skip neighbors that are explicitly hidden via neighbor aliases
        if let Some(ref mac) = nb.mac_address {
            if hidden_macs.contains(&mac.to_uppercase()) { continue; }
        }
        if let Some(ref ident) = nb.identity {
            if hidden_identities.contains(&ident.to_lowercase()) { continue; }
        }

        // Try to match neighbor to a registered device:
        //   1. By LLDP identity name (exact lowercase, then fuzzy normalized)
        //   2. By IP address (skip fe80:: link-local — useless for matching)
        //   3. By MAC address (catches routers whose LLDP identity differs from registered name)
        let remote_id = nb
            .identity
            .as_deref()
            .and_then(|id| {
                identity_to_device.get(&id.to_lowercase()).cloned()
                    .or_else(|| identity_to_device.get(&normalize_identity(id)).cloned())
            })
            .or_else(|| {
                nb.address
                    .as_deref()
                    .filter(|addr| !addr.starts_with("fe80:"))
                    .and_then(|addr| ip_to_device.get(addr).cloned())
            })
            .or_else(|| {
                nb.mac_address
                    .as_deref()
                    .and_then(|mac| mac_to_device.get(&mac.to_uppercase()).cloned())
            });

        // When we DO match, learn the identity name → device mapping so future
        // lookups from other switches also match (e.g., "MT-4011-R-Office" → "rb4011").
        if let Some(ref matched_id) = remote_id {
            if let Some(ref ident) = nb.identity {
                identity_to_device
                    .entry(ident.to_lowercase())
                    .or_insert_with(|| matched_id.clone());
            }
            if let Some(ref mac) = nb.mac_address {
                mac_to_device
                    .entry(mac.to_uppercase())
                    .or_insert_with(|| matched_id.clone());
            }
        }

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
                    speed_mbps: None,
                    traffic_bps: None,
                });
            }
        } else if let Some(ref platform) = nb.platform {
            // Unregistered neighbor — create inferred infrastructure node,
            // BUT only if network_identities doesn't override this MAC.
            let neighbor_mac_upper = nb.mac_address.as_deref().map(|m| m.to_uppercase());

            // Identity-first check: if this MAC has an authoritative identity
            // that says it's NOT infrastructure, skip creating an infra node.
            // Layer 2 (endpoint placement) will handle it correctly.
            if let Some(ident) = neighbor_mac_upper
                .as_deref()
                .and_then(|mac| identity_by_mac.get(mac))
            {
                if identity_overrides_lldp(ident) {
                    continue;
                }
            }

            let plat_lower = platform.to_lowercase();
            let is_mikrotik = plat_lower.contains("routeros")
                || plat_lower.contains("mikrotik")
                || plat_lower.contains("swos");
            let is_ap = plat_lower.contains("cap")
                || plat_lower.contains("wap")
                || plat_lower.contains("wireless");

            // MAC-based dedup: if this neighbor's MAC resolves to a registered device,
            // create a trunk edge to that device instead of a duplicate inferred node.
            if let Some(resolved_dev) = neighbor_mac_upper
                .as_deref()
                .and_then(|mac| mac_to_device.get(mac))
            {
                let pair = if source_device < *resolved_dev {
                    (source_device.clone(), resolved_dev.clone())
                } else {
                    (resolved_dev.clone(), source_device.clone())
                };
                if edge_set.insert(pair) {
                    edges.push(TopologyEdge {
                        source: source_device.clone(),
                        target: resolved_dev.clone(),
                        kind: EdgeKind::Trunk,
                        source_port: Some(source_port.clone()),
                        target_port: None,
                        vlans: Vec::new(),
                        speed_mbps: None,
                        traffic_bps: None,
                    });
                }
                continue;
            }

            let inferred_id = nb
                .identity
                .clone()
                .unwrap_or_else(|| {
                    nb.mac_address
                        .clone()
                        .unwrap_or_else(|| format!("unknown-{}-{}", nb.device_id, nb.interface))
                });

            // MAC-based dedup: if this MAC already has an infra node, create edge to it instead
            if let Some(ref mac) = nb.mac_address {
                let mac_upper = mac.to_uppercase();
                if let Some(existing_node) = infra_mac_to_node_id.get(&mac_upper).cloned() {
                    let pair = if source_device < existing_node {
                        (source_device.clone(), existing_node.clone())
                    } else {
                        (existing_node.clone(), source_device.clone())
                    };
                    if edge_set.insert(pair) {
                        edges.push(TopologyEdge {
                            source: source_device.clone(),
                            target: existing_node,
                            kind: EdgeKind::Trunk,
                            source_port: Some(source_port.clone()),
                            target_port: None,
                            vlans: Vec::new(),
                            speed_mbps: None,
                            traffic_bps: None,
                        });
                    }
                    continue;
                }
            }

            if !infra_ids.contains(&inferred_id) && !nodes.contains_key(&inferred_id) {
                let kind = if is_ap {
                    NodeKind::AccessPoint
                } else if is_mikrotik {
                    NodeKind::UnmanagedSwitch
                } else {
                    NodeKind::UnmanagedSwitch
                };

                tracing::info!(
                    inferred_id = %inferred_id,
                    identity = ?nb.identity,
                    mac = ?nb.mac_address,
                    platform = %platform,
                    seen_by = %source_device,
                    port = %source_port,
                    "creating inferred infrastructure node from LLDP neighbor"
                );

                infra_ids.insert(inferred_id.clone());
                nodes.insert(
                    inferred_id.clone(),
                    TopologyNode {
                        id: inferred_id.clone(),
                        label: nb.identity.clone()
                            .filter(|s| !s.is_empty() && s != "?")
                            .or_else(|| nb.board.clone())
                            .or_else(|| nb.address.clone())
                            .or_else(|| nb.mac_address.clone())
                            .unwrap_or_else(|| "Unknown Switch".to_string()),
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
                        disposition: "unknown".to_string(),
                baseline_status: None,
                binding_source: "observed".to_string(),
                binding_tier: None,
                attachment_state: None,
                    },
                );

                // Register MAC for dedup against future LLDP/backbone entries
                if let Some(ref mac) = nb.mac_address {
                    infra_mac_to_node_id.insert(mac.to_uppercase(), inferred_id.clone());
                }
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
                    speed_mbps: None,
                    traffic_bps: None,
                });
            }
        }
    }

    // ── Backbone links → trunk edges + auto-create missing nodes ──
    // Manual switch-to-switch connections for non-LLDP devices.
    // If a backbone link references a device that doesn't have a node yet
    // (e.g. WAPs, SwOS switches without LLDP), create an infrastructure
    // node so the edge renders in the topology.
    let backbone_links = store.get_backbone_links().await.unwrap_or_default();
    let infra_identities = store.get_infrastructure_identities().await.unwrap_or_default();
    let infra_by_id: HashMap<String, &ion_drift_storage::switch::NetworkIdentity> = infra_identities
        .iter()
        .filter_map(|i| {
            let key = i.hostname.clone().unwrap_or_else(|| i.mac_address.clone());
            Some((key, i))
        })
        .collect();

    for link in &backbone_links {
        // Auto-create nodes for backbone link endpoints that don't exist yet
        for device_id in [&link.device_a, &link.device_b] {
            if nodes.contains_key(device_id) || infra_ids.contains(device_id) {
                continue;
            }

            // MAC-based dedup for backbone endpoints
            let ident = infra_by_id.get(device_id);
            if let Some(mac) = ident.map(|i| i.mac_address.to_uppercase()) {
                if let Some(existing) = infra_mac_to_node_id.get(&mac).cloned() {
                    // This backbone device is already in topology under a different key
                    infra_ids.insert(device_id.clone());
                    // Alias this device_id to the existing node for edge creation
                    infra_mac_to_node_id.insert(device_id.clone(), existing);
                    continue;
                }
            }

            // Look up from infrastructure identities for metadata
            let kind = match ident.and_then(|i| i.device_type.as_deref()) {
                Some("access_point") | Some("wap") => NodeKind::AccessPoint,
                _ => NodeKind::UnmanagedSwitch,
            };
            let label = ident
                .and_then(|i| {
                    i.human_label.clone()
                        .or(i.hostname.clone())
                        .or(i.best_ip.clone())
                        .or(i.manufacturer.as_ref().map(|m| {
                            let short_mac = &i.mac_address[i.mac_address.len().saturating_sub(8)..];
                            format!("{m} ({short_mac})")
                        }))
                })
                .unwrap_or_else(|| device_id.clone());

            infra_ids.insert(device_id.clone());
            nodes.insert(
                device_id.clone(),
                TopologyNode {
                    id: device_id.clone(),
                    label,
                    ip: ident.and_then(|i| i.best_ip.clone()),
                    mac: ident.map(|i| i.mac_address.clone()),
                    kind,
                    vlan_id: None,
                    vlans_served: Vec::new(),
                    device_type: ident.and_then(|i| i.device_type.clone()),
                    manufacturer: ident.and_then(|i| i.manufacturer.clone()),
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
                    confidence: 0.8,
                    disposition: "unknown".to_string(),
                baseline_status: None,
                binding_source: "observed".to_string(),
                binding_tier: None,
                attachment_state: None,
                },
            );
            tracing::debug!(device = %device_id, "created node from backbone link reference");
            // Register MAC for dedup
            if let Some(mac) = ident.map(|i| i.mac_address.to_uppercase()) {
                infra_mac_to_node_id.insert(mac, device_id.clone());
            }
        }

        let pair = if link.device_a < link.device_b {
            (link.device_a.clone(), link.device_b.clone())
        } else {
            (link.device_b.clone(), link.device_a.clone())
        };
        if edge_set.insert(pair.clone()) {
            // New edge — create it
            edges.push(TopologyEdge {
                source: link.device_a.clone(),
                target: link.device_b.clone(),
                kind: EdgeKind::Trunk,
                source_port: link.port_a.clone(),
                target_port: link.port_b.clone(),
                vlans: Vec::new(),
                speed_mbps: link.speed_mbps,
                traffic_bps: None,
            });
        } else {
            // Edge already exists (from LLDP) — merge backbone link data into it.
            // Backbone ports and speed override LLDP-discovered values.
            if let Some(existing) = edges.iter_mut().find(|e| {
                let ep = if e.source < e.target {
                    (&e.source, &e.target)
                } else {
                    (&e.target, &e.source)
                };
                ep == (&pair.0, &pair.1)
            }) {
                if link.port_a.is_some() {
                    // Figure out which direction the existing edge uses
                    if existing.source == link.device_a {
                        existing.source_port = link.port_a.clone();
                        existing.target_port = existing.target_port.clone().or(link.port_b.clone());
                    } else {
                        existing.target_port = link.port_a.clone();
                        existing.source_port = existing.source_port.clone().or(link.port_b.clone());
                    }
                }
                if link.speed_mbps.is_some() {
                    existing.speed_mbps = link.speed_mbps;
                }
            }
        }
    }

    // Create a single WAN/ISP placeholder if any WAN-facing neighbors were seen
    if wan_neighbor_count > 0 {
        if let Some(ref rid) = router_id {
            let wan_id = "WAN".to_string();
            infra_ids.insert(wan_id.clone());
            nodes.insert(
                wan_id.clone(),
                TopologyNode {
                    id: wan_id.clone(),
                    label: format!("WAN / ISP ({})", wan_neighbor_count),
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
                speed_mbps: Some(1000), // WAN — 1Gbps fiber
                traffic_bps: None,
            });
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

    // ── Resolve edge speeds from port metrics ─────────────────────
    // Collect all device IDs that have edges with ports, then batch-query speeds.
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

        // Build a map of device_id → (port_name → speed_mbps)
        let mut speed_map: HashMap<String, HashMap<String, u32>> = HashMap::new();
        for dev_id in &device_ids_with_edges {
            if let Ok(speeds) = store.get_port_speeds(dev_id).await {
                if !speeds.is_empty() {
                    tracing::debug!(device = %dev_id, ports = ?speeds, "port speeds loaded");
                    speed_map.insert(dev_id.clone(), speeds);
                } else {
                    tracing::debug!(device = %dev_id, "no port speed data available");
                }
            }
        }

        // Fill in speed_mbps on edges that don't already have one (manual override takes priority)
        // Port names in speed_map are lowercased for case-insensitive matching.
        for edge in &mut edges {
            if edge.speed_mbps.is_some() {
                tracing::debug!(
                    src = %edge.source, tgt = %edge.target,
                    speed = ?edge.speed_mbps,
                    "edge already has speed (manual override)"
                );
                continue;
            }
            let src_speed = edge
                .source_port
                .as_deref()
                .and_then(|p| speed_map.get(&edge.source).and_then(|m| m.get(&p.to_lowercase())))
                .copied();
            let tgt_speed = edge
                .target_port
                .as_deref()
                .and_then(|p| speed_map.get(&edge.target).and_then(|m| m.get(&p.to_lowercase())))
                .copied();
            edge.speed_mbps = match (src_speed, tgt_speed) {
                (Some(a), Some(b)) => Some(a.min(b)), // bottleneck speed
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            tracing::debug!(
                src = %edge.source, tgt = %edge.target,
                src_port = ?edge.source_port, tgt_port = ?edge.target_port,
                src_speed = ?src_speed, tgt_speed = ?tgt_speed,
                resolved = ?edge.speed_mbps,
                "edge speed resolution"
            );
        }
    }

    // 1b-2. Resolve traffic rates on edges from port metrics
    {
        let mut traffic_map: HashMap<String, HashMap<String, u64>> = HashMap::new();
        let mut device_ids_with_edges: HashSet<String> = HashSet::new();
        for edge in &edges {
            if edge.source_port.is_some() {
                device_ids_with_edges.insert(edge.source.clone());
            }
            if edge.target_port.is_some() {
                device_ids_with_edges.insert(edge.target.clone());
            }
        }
        for dev_id in &device_ids_with_edges {
            if let Ok(traffic) = store.get_port_traffic_bps(dev_id).await {
                if !traffic.is_empty() {
                    traffic_map.insert(dev_id.clone(), traffic);
                }
            }
        }
        for edge in &mut edges {
            let src_bps = edge
                .source_port
                .as_deref()
                .and_then(|p| traffic_map.get(&edge.source).and_then(|m| m.get(&p.to_lowercase())))
                .copied();
            let tgt_bps = edge
                .target_port
                .as_deref()
                .and_then(|p| traffic_map.get(&edge.target).and_then(|m| m.get(&p.to_lowercase())))
                .copied();
            // Use the higher of the two (same traffic seen from both sides)
            edge.traffic_bps = match (src_bps, tgt_bps) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
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

    // WAN node sits alongside the router at layer 0 (BFS doesn't traverse Uplink edges)
    if let Some(wan) = nodes.get_mut("WAN") {
        wan.layer = 0;
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
    // (identities already loaded above for identity-first LLDP decisions)

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
            let mac_upper = mac.to_uppercase();
            // If this neighbor MAC is associated with a registered device, skip as endpoint
            if let Some(ref ident) = nb.identity {
                if identity_to_device.contains_key(&ident.to_lowercase()) {
                    infra_macs.insert(mac_upper);
                    continue;
                }
            }
            // Also mark as infra if the neighbor created an infra node above
            if let Some(ref ident) = nb.identity {
                if infra_ids.contains(ident) {
                    infra_macs.insert(mac_upper);
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
    // Remove human-confirmed non-infrastructure MACs from infra_macs.
    // This prevents Layer 2 from skipping them — identity overrides LLDP.
    infra_macs.retain(|mac| {
        if let Some(ident) = identity_by_mac.get(mac.as_str()) {
            !identity_overrides_lldp(ident)
        } else {
            true
        }
    });

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

// ── Identity helpers ─────────────────────────────────────────────

/// Returns true if the device type string represents network infrastructure.
fn is_infrastructure_type(dt: Option<&str>) -> bool {
    matches!(
        dt,
        Some("router" | "switch" | "network_equipment" | "access_point" | "wap")
    )
}

/// Check whether a network identity should block LLDP from creating an
/// infrastructure node for the same MAC.  Returns true when the identity
/// data is authoritative enough to override LLDP inference.
fn identity_overrides_lldp(ident: &NetworkIdentity) -> bool {
    // Explicit is_infrastructure override takes absolute priority
    match ident.is_infrastructure {
        Some(false) => return true,  // Human says NOT infrastructure
        Some(true) => return false,  // Human says IS infrastructure — let LLDP proceed
        None => {}                   // Auto-detect — fall through to heuristics
    }
    // Human-confirmed non-infrastructure device → always wins
    if ident.human_confirmed && !is_infrastructure_type(ident.device_type.as_deref()) {
        return true;
    }
    // High-confidence auto-detection as non-infrastructure → wins over MNDP
    if !ident.human_confirmed
        && !is_infrastructure_type(ident.device_type.as_deref())
        && ident.device_type.is_some()
        && ident.device_type_confidence >= 0.8
    {
        return true;
    }
    false
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
    device_manager: Arc<RwLock<DeviceManager>>,
    behavior_store: Arc<BehaviorStore>,
    cache: Arc<RwLock<Option<NetworkTopology>>>,
    wan_interface: String,
) {
    supervisor.spawn("topology_updater", move || {
        let switch_store = switch_store.clone();
        let device_manager = device_manager.clone();
        let behavior_store = behavior_store.clone();
        let cache = cache.clone();
        let wan_interface = wan_interface.clone();
        Box::pin(async move {
        // Wait for correlation engine to populate data
        tokio::time::sleep(Duration::from_secs(120)).await;
        tracing::info!("topology updater starting (120s interval)");

        let mut interval = tokio::time::interval(Duration::from_secs(120));

        loop {
            match compute_topology(&switch_store, &device_manager, &behavior_store, &wan_interface).await {
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
    })});
}

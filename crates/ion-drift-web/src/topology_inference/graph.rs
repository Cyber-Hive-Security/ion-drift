//! Infrastructure graph — the physical switch/router topology used for
//! upstream suppression, depth scoring, and candidate pruning.

use std::collections::{HashMap, HashSet, VecDeque};

use ion_drift_storage::switch::{BackboneLink, NeighborEntry};
use serde::Serialize;

use super::canonicalize_port_name;

/// A node in the infrastructure graph (a managed switch or router).
#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub device_id: String,
    pub is_router: bool,
}

/// The infrastructure graph: rooted tree of managed network devices.
///
/// Built from backbone links + LLDP neighbor discovery. The router is
/// always the root (depth 0). Depth increases toward leaf switches.
#[derive(Debug, Clone, Default)]
pub struct InfrastructureGraph {
    /// All nodes keyed by device_id.
    pub nodes: HashMap<String, GraphNode>,
    /// Undirected adjacency: device_id → set of neighbor device_ids.
    pub adjacency: HashMap<String, HashSet<String>>,
    /// BFS depth from router (router = 0).
    pub depth: HashMap<String, u32>,
    /// Parent in the BFS tree (router has no parent).
    pub parent: HashMap<String, String>,
    /// Children in the BFS tree.
    pub children: HashMap<String, Vec<String>>,
    /// Trunk ports: (device_id, port_name_lowercase).
    pub trunk_ports: HashSet<(String, String)>,
    /// Trunk peer map: (device_id, port_name_lowercase) → peer_device_id.
    pub trunk_peers: HashMap<(String, String), String>,
    /// The router device ID (root of the tree).
    pub router_id: String,
    /// Maximum depth in the graph (for normalization).
    pub max_depth: u32,
}

/// Device identity resolution maps, used to match LLDP neighbors to device IDs.
pub struct DeviceResolutionMaps {
    /// LLDP identity (lowercase) → device_id
    pub identity_to_device: HashMap<String, String>,
    /// IP address → device_id
    pub ip_to_device: HashMap<String, String>,
}

impl InfrastructureGraph {
    /// Build the infrastructure graph from available data sources.
    ///
    /// This consolidates the trunk port detection, peer resolution, and BFS
    /// depth computation that was previously scattered through the correlation engine.
    pub fn build(
        device_ids: &[String],
        router_id: &str,
        neighbors: &[NeighborEntry],
        backbone_links: &[BackboneLink],
        port_roles: &[(String, String, String)], // (device_id, port_name, role)
        resolution: &DeviceResolutionMaps,
    ) -> Self {
        let mut graph = Self {
            router_id: router_id.to_string(),
            ..Default::default()
        };

        // Add all devices as nodes
        for id in device_ids {
            graph.nodes.insert(id.clone(), GraphNode {
                device_id: id.clone(),
                is_router: id == router_id,
            });
        }
        // Ensure router is always present
        if !graph.nodes.contains_key(router_id) {
            graph.nodes.insert(router_id.to_string(), GraphNode {
                device_id: router_id.to_string(),
                is_router: true,
            });
        }

        // Trunk ports from discrete role classification
        for (dev_id, port_name, role) in port_roles {
            if role == "trunk" || role == "uplink" {
                graph.trunk_ports.insert((dev_id.clone(), canonicalize_port_name(port_name)));
            }
        }

        // Force backbone-linked ports to trunk
        for link in backbone_links {
            if let Some(ref port) = link.port_a {
                graph.trunk_ports.insert((link.device_a.clone(), canonicalize_port_name(port)));
            }
            if let Some(ref port) = link.port_b {
                graph.trunk_ports.insert((link.device_b.clone(), canonicalize_port_name(port)));
            }
        }

        // Build trunk peer map from LLDP neighbors
        for nb in neighbors {
            let resolved = nb
                .identity
                .as_deref()
                .and_then(|id| resolution.identity_to_device.get(&id.to_lowercase()).cloned())
                .or_else(|| {
                    nb.address
                        .as_deref()
                        .and_then(|addr| resolution.ip_to_device.get(addr).cloned())
                });
            if let Some(peer_id) = resolved {
                let port = nb.interface.split(',').next().unwrap_or(&nb.interface);
                graph.trunk_peers.insert(
                    (nb.device_id.clone(), canonicalize_port_name(port)),
                    peer_id,
                );
            }
        }

        // Add backbone links as trunk peers (don't overwrite LLDP-derived peers)
        for link in backbone_links {
            if let Some(ref port) = link.port_a {
                graph.trunk_peers
                    .entry((link.device_a.clone(), canonicalize_port_name(port)))
                    .or_insert_with(|| link.device_b.clone());
            }
            if let Some(ref port) = link.port_b {
                graph.trunk_peers
                    .entry((link.device_b.clone(), canonicalize_port_name(port)))
                    .or_insert_with(|| link.device_a.clone());
            }
        }

        // Build undirected adjacency from backbone links + trunk peers
        for link in backbone_links {
            graph.adjacency.entry(link.device_a.clone()).or_default().insert(link.device_b.clone());
            graph.adjacency.entry(link.device_b.clone()).or_default().insert(link.device_a.clone());
        }
        for ((dev_id, _port), peer_id) in &graph.trunk_peers {
            graph.adjacency.entry(dev_id.clone()).or_default().insert(peer_id.clone());
            graph.adjacency.entry(peer_id.clone()).or_default().insert(dev_id.clone());
        }

        // BFS from router to compute depth + parent/child maps
        graph.depth.insert(router_id.to_string(), 0);
        let mut queue = VecDeque::new();
        queue.push_back(router_id.to_string());

        while let Some(current) = queue.pop_front() {
            let current_depth = graph.depth[&current];
            if let Some(neighbors) = graph.adjacency.get(&current) {
                for neighbor in neighbors {
                    if !graph.depth.contains_key(neighbor) {
                        let new_depth = current_depth + 1;
                        graph.depth.insert(neighbor.clone(), new_depth);
                        graph.parent.insert(neighbor.clone(), current.clone());
                        graph.children.entry(current.clone()).or_default().push(neighbor.clone());
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }

        graph.max_depth = graph.depth.values().copied().max().unwrap_or(0);

        graph
    }

    /// Get the BFS depth of a device (0 = router).
    pub fn depth_of(&self, device_id: &str) -> Option<u32> {
        self.depth.get(device_id).copied()
    }

    /// Check if `child` is a descendant of `ancestor` in the BFS tree.
    pub fn is_descendant_of(&self, child: &str, ancestor: &str) -> bool {
        let mut current = child;
        while let Some(parent) = self.parent.get(current) {
            if parent == ancestor {
                return true;
            }
            current = parent;
        }
        false
    }

    /// Check if a (device_id, port_name) pair is a trunk port.
    pub fn is_trunk_port(&self, device_id: &str, port_name: &str) -> bool {
        self.trunk_ports.contains(&(device_id.to_string(), canonicalize_port_name(port_name)))
    }

    /// Normalized depth score for a device (0.0 = router, 1.0 = deepest).
    pub fn normalized_depth(&self, device_id: &str) -> f64 {
        if self.max_depth == 0 {
            return 0.0;
        }
        self.depth_of(device_id)
            .map(|d| d as f64 / self.max_depth as f64)
            .unwrap_or(0.0)
    }
}

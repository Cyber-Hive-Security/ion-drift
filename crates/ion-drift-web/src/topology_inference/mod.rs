//! Topology inference engine — probabilistic MAC attachment resolution.
//!
//! Replaces the deterministic priority-based MAC binding with a weighted
//! candidate scoring pipeline over a constrained infrastructure graph.

use std::collections::{HashMap, HashSet};

use ion_drift_storage::switch::BackboneLink;

pub mod graph;
pub mod candidates;
pub mod scoring;
pub mod state;
pub mod resolver;

/// Map from (switch_device_id, canonical_port) → list of WAP device_ids fed by that port.
pub type ApFeederMap = HashMap<(String, String), Vec<String>>;

/// Build the AP feeder map: for each backbone link where one side is a WAP,
/// map the OTHER side's (device_id, canonical_port) → vec of WAP device_ids.
pub fn build_ap_feeder_map(
    backbone_links: &[BackboneLink],
    wap_identifiers: &HashSet<String>,
) -> ApFeederMap {
    let mut map: ApFeederMap = HashMap::new();

    for link in backbone_links {
        let a_is_wap = wap_identifiers.contains(&link.device_a);
        let b_is_wap = wap_identifiers.contains(&link.device_b);

        // If device_a is a WAP, the feeder port is on device_b
        if a_is_wap && !b_is_wap {
            if let Some(ref port) = link.port_b {
                let key = (link.device_b.clone(), canonicalize_port_name(port));
                map.entry(key).or_default().push(link.device_a.clone());
            }
        }

        // If device_b is a WAP, the feeder port is on device_a
        if b_is_wap && !a_is_wap {
            if let Some(ref port) = link.port_a {
                let key = (link.device_a.clone(), canonicalize_port_name(port));
                map.entry(key).or_default().push(link.device_b.clone());
            }
        }
    }

    map
}

/// Extract WAP identifiers from infrastructure identities.
///
/// Identifies devices with device_type "access_point" or "wap" and returns
/// their hostname (preferred) or MAC address as identifiers.
pub fn build_wap_identifier_set(
    infrastructure_identities: &[ion_drift_storage::switch::NetworkIdentity],
) -> HashSet<String> {
    infrastructure_identities
        .iter()
        .filter(|i| {
            matches!(
                i.device_type.as_deref(),
                Some("access_point") | Some("wap")
            )
        })
        .filter_map(|i| i.hostname.clone().or(Some(i.mac_address.clone())))
        .collect()
}

/// Check if a (device_id, port_name) feeds any WAPs.
pub fn port_feeds_ap(map: &ApFeederMap, device_id: &str, port_name: &str) -> bool {
    let key = (device_id.to_string(), canonicalize_port_name(port_name));
    map.contains_key(&key)
}

/// Get the list of WAP device_ids fed by a given (device_id, port_name).
pub fn fed_waps<'a>(map: &'a ApFeederMap, device_id: &str, port_name: &str) -> &'a [String] {
    let key = (device_id.to_string(), canonicalize_port_name(port_name));
    map.get(&key).map(|v| v.as_slice()).unwrap_or(&[])
}

/// Canonicalize SNMP port names that refer to the same physical port.
///
/// Some SNMP agents (notably Netgear MS510TXPP) expose the same physical port
/// under multiple MIB trees with different naming conventions:
///   mg5, twopointfivegigabitethernet5, port5  → all physical port 5
///   xg10, tengigabitethernet10, port10        → all physical port 10
///
/// We normalize to the `portN` canonical form so MAC counts, VLAN counts,
/// and role probabilities aggregate correctly.
///
/// Port names that don't match any known SNMP alias pattern are returned
/// lowercase, unchanged (safe for Mikrotik, SwOS, and any other device).
pub fn canonicalize_port_name(name: &str) -> String {
    let lower = name.to_lowercase();

    // Already canonical: "port5", "port10", etc.
    if lower.starts_with("port") && lower[4..].chars().all(|c| c.is_ascii_digit()) && lower.len() > 4 {
        return lower;
    }

    // Extract trailing digits from known SNMP naming patterns.
    // Patterns: g1, mg5, xg10, xmg9, gigabitethernet2, twopointfivegigabitethernet5,
    //           fivegigabitethernet7, tengigabitethernet10
    let prefixes = [
        "twopointfivegigabitethernet",
        "tengigabitethernet",
        "fivegigabitethernet",
        "gigabitethernet",
        "xmg",
        "xg",
        "mg",
        "g",
    ];

    for prefix in prefixes {
        if let Some(suffix) = lower.strip_prefix(prefix) {
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return format!("port{suffix}");
            }
        }
    }

    // Not a recognized alias pattern — return lowercase as-is
    lower
}

//! Per-manufacturer SNMP interface classification profiles.
//!
//! Different switch vendors use different conventions for interface naming,
//! numbering, and logical/physical interface types. This module provides a
//! data-driven profile system so each vendor's rules are isolated — changes
//! to Netgear don't affect Cisco, and vice versa.
//!
//! # Adding a new vendor
//!
//! 1. Define a `static VENDOR_PROFILE: SnmpProfile` with the vendor's rules
//! 2. Add a detection pattern in `detect_profile()` matching `sysDescr`
//! 3. Implement a `friendly_name_fn` if the vendor needs custom name logic

use serde::Serialize;

use crate::snmp_client::SnmpInterface;

// ─── Types ───────────────────────────────────────────────────────

/// Classification of an SNMP interface by its role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceClass {
    /// Physical copper/fiber port — shown in port table and grid
    Physical,
    /// Link aggregation group (port-channel, etherchannel)
    Lag,
    /// VLAN sub-interface (L2 or L3)
    Vlan,
    /// Management or loopback interface
    Management,
    /// Internal/hidden — tunnels, stack ports, virtual interfaces
    Internal,
}

/// Per-manufacturer SNMP behavior profile.
///
/// Each profile defines how to classify and name interfaces for a specific
/// vendor or device family. The `friendly_name_fn` allows per-vendor name
/// derivation without trait objects.
pub struct SnmpProfile {
    /// Human-readable vendor name (e.g., "Netgear", "Cisco")
    pub vendor: &'static str,

    /// IANA ifType values that represent physical ports (typically `[6]`
    /// for ethernetCsmacd). Only these appear in port metrics.
    pub physical_if_types: &'static [u32],

    /// IANA ifType values that represent LAG/port-channel interfaces.
    /// Classified but not shown in port metrics by default.
    pub lag_if_types: &'static [u32],

    /// ifIndex ranges to always hide (inclusive). Vendors often use high
    /// index ranges for internal/virtual interfaces.
    pub hidden_index_ranges: &'static [(u32, u32)],

    /// Whether to prefer ifName (true) or ifDescr (false) as the base
    /// for canonical name derivation.
    pub prefer_if_name: bool,

    /// Derive a display-friendly name from interface metadata.
    /// Arguments: (ifIndex, ifName, ifDescr, ifType)
    pub friendly_name_fn: fn(u32, &str, &str, u32) -> String,
}

/// An SNMP interface after profile-based classification.
///
/// Produced by [`classify_interfaces`] — carries both the canonical
/// display name and the raw SNMP names for internal lookups.
#[derive(Debug, Clone, Serialize)]
pub struct ClassifiedInterface {
    /// Hardware ifIndex from SNMP
    pub index: u32,
    /// Friendly display name derived by the profile
    pub canonical_name: String,
    /// Original ifName from SNMP (used for bridge port resolution)
    pub raw_name: String,
    /// Original ifDescr from SNMP
    pub descr: String,
    /// Interface classification
    pub class: InterfaceClass,
    /// IANA ifType value
    pub if_type: u32,
    /// Operational status (link up/down)
    pub oper_status: bool,
    /// Administrative status (enabled/disabled)
    pub admin_status: bool,
    /// Negotiated speed in Mbps
    pub speed_mbps: u64,
    /// Interface MAC address
    pub mac_address: Option<String>,
    /// 64-bit receive byte counter
    pub rx_bytes: u64,
    /// 64-bit transmit byte counter
    pub tx_bytes: u64,
    /// 64-bit receive packet counter
    pub rx_packets: u64,
    /// 64-bit transmit packet counter
    pub tx_packets: u64,
}

// ─── Detection ───────────────────────────────────────────────────

/// Detect the appropriate SNMP profile from the device's sysDescr string.
///
/// Called once per poll cycle. Falls back to [`GENERIC_PROFILE`] for
/// unrecognized vendors.
pub fn detect_profile(sys_descr: &str) -> &'static SnmpProfile {
    let lower = sys_descr.to_ascii_lowercase();

    if lower.contains("netgear") || lower.contains("prosafe") {
        return &NETGEAR_PROFILE;
    }

    // Future vendor profiles:
    // if lower.contains("cisco") || lower.contains("ios") { return &CISCO_PROFILE; }
    // if lower.contains("tp-link") || lower.contains("tplink") { return &TPLINK_PROFILE; }
    // if lower.contains("d-link") || lower.contains("dgs-") { return &DLINK_PROFILE; }

    &GENERIC_PROFILE
}

// ─── Classification ──────────────────────────────────────────────

/// Classify raw SNMP interfaces using a vendor profile.
///
/// Filters out hidden index ranges, assigns [`InterfaceClass`], and derives
/// canonical display names. The resulting list is suitable for port metric
/// recording and frontend display.
pub fn classify_interfaces(
    raw: &[SnmpInterface],
    profile: &SnmpProfile,
) -> Vec<ClassifiedInterface> {
    raw.iter()
        .filter_map(|iface| {
            // Skip interfaces in hidden index ranges
            for &(lo, hi) in profile.hidden_index_ranges {
                if iface.index >= lo && iface.index <= hi {
                    return None;
                }
            }

            let class = if profile.physical_if_types.contains(&iface.if_type) {
                InterfaceClass::Physical
            } else if profile.lag_if_types.contains(&iface.if_type) {
                InterfaceClass::Lag
            } else if iface.if_type == 135 {
                // l2vlan — common across vendors
                InterfaceClass::Vlan
            } else if iface.if_type == 24 {
                // softwareLoopback
                InterfaceClass::Management
            } else {
                InterfaceClass::Internal
            };

            let canonical_name = (profile.friendly_name_fn)(
                iface.index,
                &iface.name,
                &iface.descr,
                iface.if_type,
            );

            Some(ClassifiedInterface {
                index: iface.index,
                canonical_name,
                raw_name: iface.name.clone(),
                descr: iface.descr.clone(),
                class,
                if_type: iface.if_type,
                oper_status: iface.oper_status,
                admin_status: iface.admin_status,
                speed_mbps: iface.speed_mbps,
                mac_address: iface.mac_address.clone(),
                rx_bytes: iface.rx_bytes,
                tx_bytes: iface.tx_bytes,
                rx_packets: iface.rx_packets,
                tx_packets: iface.tx_packets,
            })
        })
        .collect()
}

// ─── Generic Profile ─────────────────────────────────────────────

/// Fallback profile for unrecognized vendors.
///
/// Uses standard SNMP conventions that work for most managed switches:
/// - ifType 6 (ethernetCsmacd) as physical ports
/// - ifName preferred over ifDescr
/// - No hidden index ranges
pub static GENERIC_PROFILE: SnmpProfile = SnmpProfile {
    vendor: "Generic",
    physical_if_types: &[6],
    lag_if_types: &[136, 161],
    hidden_index_ranges: &[],
    prefer_if_name: true,
    friendly_name_fn: generic_friendly_name,
};

fn generic_friendly_name(_idx: u32, if_name: &str, if_descr: &str, _if_type: u32) -> String {
    if !if_name.is_empty() {
        if_name.to_string()
    } else {
        if_descr.to_string()
    }
}

// ─── Netgear Profile ─────────────────────────────────────────────

/// Profile for Netgear managed switches (ProSafe, MS series, GS series).
///
/// Netgear uses short ifName values (g1, mg5, xmg9, xg10) alongside
/// verbose ifDescr values (GigabitEthernet1, TwoPointFiveGigabitEthernet5).
/// Port-channels are ifType 161 with ifName ch1-ch8.
/// High ifIndex ranges (3000+) are tunnels and internal interfaces.
pub static NETGEAR_PROFILE: SnmpProfile = SnmpProfile {
    vendor: "Netgear",
    physical_if_types: &[6],
    lag_if_types: &[161],
    hidden_index_ranges: &[
        (3000, 3999),   // tunnel interfaces
        (7000, 7999),   // loopback
        (9000, 9999),   // stack port
        (20000, u32::MAX), // internal logical interfaces
    ],
    prefer_if_name: true,
    friendly_name_fn: netgear_friendly_name,
};

fn netgear_friendly_name(_idx: u32, if_name: &str, if_descr: &str, _if_type: u32) -> String {
    // Netgear ifName is already short and friendly: g1, mg5, xmg9, xg10, ch1
    if !if_name.is_empty() {
        if_name.to_string()
    } else {
        if_descr.to_string()
    }
}

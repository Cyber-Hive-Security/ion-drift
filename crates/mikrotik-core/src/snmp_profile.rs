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

// ─── IANA ifType Constants (RFC 2863) ────────────────────────────

const IFTYPE_ETHERNET_CSMACD: u32 = 6;
const IFTYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IFTYPE_L2_VLAN: u32 = 135;
const IFTYPE_IEEE8023AD_LAG: u32 = 136;
const IFTYPE_PORT_CHANNEL: u32 = 161;

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
        tracing::debug!(vendor = "Netgear", "SNMP profile matched");
        return &NETGEAR_PROFILE;
    }

    if lower.contains("aruba") || lower.contains("jl356") || lower.contains("jl354")
        || lower.contains("jl355") || lower.contains("jl357")
        || (lower.contains("2540") && lower.contains("switch"))
    {
        tracing::debug!(vendor = "Aruba", sys_descr = %sys_descr, "SNMP profile matched");
        return &ARUBA_PROFILE;
    }

    if lower.contains("sg550") || lower.contains("sg350") || lower.contains("sg250")
        || lower.contains("sg500") || lower.contains("sf500")
        || (lower.contains("cisco") && lower.contains("stackable managed switch"))
    {
        tracing::debug!(vendor = "Cisco SMB", sys_descr = %sys_descr, "SNMP profile matched");
        return &CISCO_SMB_PROFILE;
    }

    tracing::debug!(sys_descr = %sys_descr, "no SNMP profile matched, using Generic");
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
            } else if iface.if_type == IFTYPE_L2_VLAN {
                InterfaceClass::Vlan
            } else if iface.if_type == IFTYPE_SOFTWARE_LOOPBACK {
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
    physical_if_types: &[IFTYPE_ETHERNET_CSMACD],
    lag_if_types: &[IFTYPE_IEEE8023AD_LAG, IFTYPE_PORT_CHANNEL],
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
    physical_if_types: &[IFTYPE_ETHERNET_CSMACD],
    lag_if_types: &[IFTYPE_PORT_CHANNEL],
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

// ─── Aruba Profile ──────────────────────────────────────────────

/// Profile for HPE/Aruba 2540, 2530, and similar managed switches.
///
/// Aruba uses bare numeric ifName/ifDescr ("1", "2", ..., "28") for physical
/// ports. SFP+ ports (25-28) report ifHighSpeed 10000. VLAN interfaces use
/// ifType 53 (propVirtual) at index 584+. Loopback interfaces (lo0-lo7) are
/// at indices 4807-4814 with ifType 24.
///
/// OUI: 88:3A:30 (HP/Aruba)
/// sysDescr: "Aruba JL356A 2540-24G-PoE+-4SFP+ Switch"
/// Entity MIB: JL356A
pub static ARUBA_PROFILE: SnmpProfile = SnmpProfile {
    vendor: "Aruba",
    physical_if_types: &[IFTYPE_ETHERNET_CSMACD],
    lag_if_types: &[IFTYPE_IEEE8023AD_LAG, IFTYPE_PORT_CHANNEL],
    hidden_index_ranges: &[
        (584, 999),      // VLAN interfaces (DEFAULT_VLAN etc.)
        (4807, 4814),    // loopback lo0-lo7
    ],
    prefer_if_name: true,
    friendly_name_fn: aruba_friendly_name,
};

fn aruba_friendly_name(idx: u32, if_name: &str, if_descr: &str, if_type: u32) -> String {
    // Aruba uses bare numbers for ifName ("1", "2", ..., "28").
    // Prefix with "Port " for clarity in the UI.
    // SFP+ ports (typically indices 25-28 on 24-port models) get "SFP+" prefix.
    let base = if !if_name.is_empty() { if_name } else { if_descr };

    if if_type == IFTYPE_ETHERNET_CSMACD {
        // Check if it's a bare number
        if base.chars().all(|c| c.is_ascii_digit()) {
            let port_num: u32 = base.parse().unwrap_or(idx);
            // On 24G+4SFP+ models, ports 25-28 are SFP+
            // We can't know the model from here, so just use "Port N"
            return format!("Port {port_num}");
        }
    }

    if if_type == IFTYPE_SOFTWARE_LOOPBACK {
        return format!("lo{}", idx.saturating_sub(4807));
    }

    tracing::trace!(idx, if_name, if_descr, if_type, vendor = "Aruba", "unclassified interface name");
    base.to_string()
}

// ─── Cisco SMB Profile ──────────────────────────────────────────

/// Profile for Cisco Small Business switches (SG550X, SG350X, SG250X, etc.).
///
/// These use Cisco IOS-style naming with stack notation: gi{unit}/0/{port},
/// te{unit}/0/{port}. Port-Channels are ifType 161 at indices 1000-1031.
/// Tunnels are ifType 131 at 3000-3015. The switch pre-allocates interfaces
/// for up to 8 stack units even if only 1 is present, resulting in hundreds
/// of virtual (ifOperStatus=6 "notPresent") interfaces.
///
/// OUI: 40:A6:E8 (Cisco)
/// sysDescr: "SG550X-24MP 24-Port Gigabit PoE Stackable Managed Switch"
/// Entity MIB: SG550X-24MP-K9
pub static CISCO_SMB_PROFILE: SnmpProfile = SnmpProfile {
    vendor: "Cisco SMB",
    physical_if_types: &[IFTYPE_ETHERNET_CSMACD],
    lag_if_types: &[IFTYPE_PORT_CHANNEL],
    hidden_index_ranges: &[
        (1000, 1031),    // Port-Channel1-32 (LAGs — classified separately)
        (3000, 3015),    // tunnel1-16
        (7000, 7999),    // loopback
        (8000, 8999),    // user-defined ports
        (9000, 9999),    // stack-port
        (20000, 20999),  // logical internal interfaces
        (100000, u32::MAX), // management VLAN / internal
    ],
    prefer_if_name: true,
    friendly_name_fn: cisco_smb_friendly_name,
};

fn cisco_smb_friendly_name(_idx: u32, if_name: &str, if_descr: &str, if_type: u32) -> String {
    // Cisco SMB ifName uses short notation: gi1/0/1, te1/0/1, Po1
    // ifDescr uses long form: GigabitEthernet1/0/1, TenGigabitEthernet1/0/1
    // We prefer the short ifName form for display.
    let base = if !if_name.is_empty() { if_name } else { if_descr };

    if if_type == IFTYPE_PORT_CHANNEL {
        // Port-Channel: ifName is "Po1", ifDescr is "Port-Channel1"
        // Normalize to "Po1" format
        if base.starts_with("Po") || base.starts_with("po") {
            return base.to_string();
        }
        if let Some(num) = base.strip_prefix("Port-Channel") {
            return format!("Po{num}");
        }
    }

    if if_type == IFTYPE_ETHERNET_CSMACD {
        // Already short: gi1/0/1, te1/0/1
        if base.starts_with("gi") || base.starts_with("te") {
            return base.to_string();
        }
        // Long form from ifDescr: extract unit/slot/port
        if let Some(rest) = base.strip_prefix("GigabitEthernet") {
            return format!("gi{rest}");
        }
        if let Some(rest) = base.strip_prefix("TenGigabitEthernet") {
            return format!("te{rest}");
        }
    }

    tracing::trace!(_idx, if_name, if_descr, if_type, vendor = "Cisco SMB", "unclassified interface name");
    base.to_string()
}

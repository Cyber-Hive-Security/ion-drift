//! Shared identity helper functions used by the correlation engine and
//! topology builder.

use ion_drift_storage::switch::NetworkIdentity;

/// Returns true if the device type string represents network infrastructure.
pub fn is_infrastructure_type(dt: Option<&str>) -> bool {
    matches!(
        dt,
        Some("router" | "switch" | "network_equipment" | "access_point" | "wap")
    )
}

/// Check whether a network identity should block LLDP from creating an
/// infrastructure node for the same MAC.  Returns true when the identity
/// data is authoritative enough to override LLDP inference.
pub fn identity_overrides_lldp(ident: &NetworkIdentity) -> bool {
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
    // Auto-detection as non-infrastructure → wins over MNDP/LLDP.
    // Threshold lowered to 0.5: any reasonable signal that a device is an
    // endpoint (workstation, phone, camera, etc.) should prevent it from
    // being promoted to infrastructure by LLDP discovery.
    if !ident.human_confirmed
        && !is_infrastructure_type(ident.device_type.as_deref())
        && ident.device_type.is_some()
        && ident.device_type_confidence >= 0.5
    {
        return true;
    }
    false
}

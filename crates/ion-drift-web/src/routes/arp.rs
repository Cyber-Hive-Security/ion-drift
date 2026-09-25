use axum::extract::State;
use axum::response::{Json, Response};
use serde::Serialize;

use crate::middleware::RequireAuth;
use crate::routes::network_map_status::DeviceStatus;
use crate::state::AppState;
use super::{iso_from_unix_secs, live_or_degrade, Degradable, LiveOr};

#[derive(Serialize)]
pub struct ArpEntryResponse {
    pub id: String,
    pub address: String,
    pub mac_address: Option<String>,
    pub interface: Option<String>,
    pub dynamic: Option<bool>,
    pub complete: Option<bool>,
    pub disabled: Option<bool>,
    pub comment: Option<String>,
    pub manufacturer: Option<String>,
}

/// GET /api/ip/arp
///
/// Degrades to ARP entries from the last cached network-map snapshot when the
/// router is unreachable, instead of 502ing (DRIFT P3). Snapshot rows lack the
/// live `interface`/`dynamic`/`complete`/`disabled`/`comment` fields, which are
/// left `None` rather than fabricated.
pub async fn list(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Degradable<ArpEntryResponse>>, Response> {
    match live_or_degrade(state.mikrotik.arp_table().await) {
        LiveOr::Live(entries) => {
            let result: Vec<ArpEntryResponse> = entries
                .into_iter()
                .map(|e| {
                    let manufacturer = e
                        .mac_address
                        .as_deref()
                        .and_then(|mac| state.oui_db.lookup(mac))
                        .map(String::from);

                    ArpEntryResponse {
                        id: e.id,
                        address: e.address,
                        mac_address: e.mac_address,
                        interface: e.interface,
                        dynamic: e.dynamic,
                        complete: e.complete,
                        disabled: e.disabled,
                        comment: e.comment,
                        manufacturer,
                    }
                })
                .collect();
            Ok(Json(Degradable::live(result)))
        }
        LiveOr::Degraded => {
            let (items, as_of) = arp_from_cache(&state).await;
            Ok(Json(Degradable::degraded(items, as_of)))
        }
    }
}

#[derive(Serialize)]
pub struct MergedLeaseArp {
    // DHCP lease fields
    pub id: String,
    pub address: String,
    pub mac_address: Option<String>,
    pub host_name: Option<String>,
    pub server: Option<String>,
    pub status: Option<String>,
    pub expires_after: Option<String>,
    pub last_seen: Option<String>,
    pub dynamic: Option<bool>,
    pub disabled: Option<bool>,
    pub comment: Option<String>,
    pub manufacturer: Option<String>,
    // Cross-reference fields
    pub arp_status: String,
}

/// GET /api/ip/dhcp-leases-status
/// Returns DHCP leases merged with ARP table status.
///
/// Degrades to the last cached network-map snapshot when the router is
/// unreachable (DRIFT P3).
pub async fn dhcp_leases_status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Degradable<MergedLeaseArp>>, Response> {
    match live_or_degrade(tokio::try_join!(
        async { state.mikrotik.dhcp_leases().await },
        async { state.mikrotik.arp_table().await },
    )) {
        LiveOr::Live((leases, arp_entries)) => {
            // Build set of IPs present in ARP table
            let arp_ips: std::collections::HashSet<String> = arp_entries
                .iter()
                .map(|a| a.address.clone())
                .collect();

            let result: Vec<MergedLeaseArp> = leases
                .into_iter()
                .map(|l| {
                    let in_arp = arp_ips.contains(&l.address);
                    let is_waiting = l.status.as_deref() == Some("waiting");

                    let arp_status = if in_arp {
                        "active".to_string()
                    } else if is_waiting {
                        "stale".to_string()
                    } else {
                        "offline".to_string()
                    };

                    let manufacturer = l
                        .mac_address
                        .as_deref()
                        .and_then(|mac| state.oui_db.lookup(mac))
                        .map(String::from);

                    MergedLeaseArp {
                        id: l.id,
                        address: l.address,
                        mac_address: l.mac_address,
                        host_name: l.host_name,
                        server: l.server,
                        status: l.status,
                        expires_after: l.expires_after,
                        last_seen: l.last_seen,
                        dynamic: l.dynamic,
                        disabled: l.disabled,
                        comment: l.comment,
                        manufacturer,
                        arp_status,
                    }
                })
                .collect();

            Ok(Json(Degradable::live(result)))
        }
        LiveOr::Degraded => {
            let (items, as_of) = dhcp_status_from_cache(&state).await;
            Ok(Json(Degradable::degraded(items, as_of)))
        }
    }
}

#[derive(Serialize)]
pub struct PoolUtilizationResponse {
    pub name: String,
    pub interface: String,
    pub pool_name: String,
    pub total_ips: usize,
    pub bound_count: usize,
    pub active_on_network: usize,
    pub pct: u8,
}

/// GET /api/ip/pool-utilization
/// Returns pool utilization with ARP-based active counts.
///
/// Pool/server configuration is not held in any in-memory cache, so when the
/// router is unreachable this degrades to an empty set (live_available:false)
/// rather than fabricating utilization figures (DRIFT P3).
pub async fn pool_utilization(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Degradable<PoolUtilizationResponse>>, Response> {
    match live_or_degrade(tokio::try_join!(
        async { state.mikrotik.ip_pools().await },
        async { state.mikrotik.dhcp_servers().await },
        async { state.mikrotik.dhcp_leases().await },
        async { state.mikrotik.arp_table().await },
    )) {
        LiveOr::Live((pools, servers, leases, arp_entries)) => {
            let arp_ips: std::collections::HashSet<String> = arp_entries
                .iter()
                .map(|a| a.address.clone())
                .collect();

            let result: Vec<PoolUtilizationResponse> = servers
                .iter()
                .filter(|s| !(s.disabled.unwrap_or(false)))
                .map(|server| {
                    let pool = pools.iter().find(|p| Some(&p.name) == server.address_pool.as_ref());
                    let total_ips = pool.map(|p| parse_pool_size(&p.ranges)).unwrap_or(0);
                    let server_leases: Vec<_> = leases
                        .iter()
                        .filter(|l| l.server.as_deref() == Some(&server.name) && l.status.as_deref() == Some("bound"))
                        .collect();
                    let bound_count = server_leases.len();
                    let active_on_network = server_leases
                        .iter()
                        .filter(|l| arp_ips.contains(&l.address))
                        .count();
                    let pct = if total_ips > 0 {
                        ((bound_count as f64 / total_ips as f64) * 100.0).round() as u8
                    } else {
                        0
                    };

                    PoolUtilizationResponse {
                        name: server.name.clone(),
                        interface: server.interface.clone(),
                        pool_name: server.address_pool.clone().unwrap_or_else(|| "\u{2014}".into()),
                        total_ips,
                        bound_count,
                        active_on_network,
                        pct,
                    }
                })
                .collect();

            Ok(Json(Degradable::live(result)))
        }
        LiveOr::Degraded => Ok(Json(Degradable::degraded(Vec::new(), None))),
    }
}

// ── Graceful-degradation fallbacks (DRIFT P3) ────────────────────

/// Build ARP entries from a cached network-map snapshot (pure — unit-testable).
/// Only devices actually seen in ARP are included; live-only ARP fields are
/// `None`, and the device IP doubles as a stable row id.
fn arp_items_from_devices(devices: &[DeviceStatus]) -> Vec<ArpEntryResponse> {
    devices
        .iter()
        .filter(|d| d.in_arp)
        .map(|d| ArpEntryResponse {
            id: d.ip.clone(),
            address: d.ip.clone(),
            mac_address: d.mac.clone(),
            interface: None,
            dynamic: None,
            complete: None,
            disabled: None,
            comment: None,
            manufacturer: d.manufacturer.clone(),
        })
        .collect()
}

/// Build merged DHCP-lease/ARP rows from a cached snapshot (pure — testable).
/// Only DHCP-known devices are included; `arp_status` is derived from the
/// snapshot's `in_arp`/`dhcp_status`.
fn dhcp_status_items_from_devices(devices: &[DeviceStatus]) -> Vec<MergedLeaseArp> {
    devices
        .iter()
        .filter(|d| d.dhcp_status.is_some())
        .map(|d| {
            let arp_status = if d.in_arp {
                "active"
            } else if d.dhcp_status.as_deref() == Some("waiting") {
                "stale"
            } else {
                "offline"
            }
            .to_string();

            MergedLeaseArp {
                id: d.ip.clone(),
                address: d.ip.clone(),
                mac_address: d.mac.clone(),
                host_name: d.hostname.clone(),
                server: d.dhcp_server.clone(),
                status: d.dhcp_status.clone(),
                expires_after: d.expires_after.clone(),
                last_seen: d.last_seen.clone(),
                dynamic: None,
                disabled: None,
                comment: None,
                manufacturer: d.manufacturer.clone(),
                arp_status,
            }
        })
        .collect()
}

/// Read ARP fallback + `as_of` from the network-map cache.
async fn arp_from_cache(state: &AppState) -> (Vec<ArpEntryResponse>, Option<String>) {
    let cache = state.network_map_cache.read().await;
    match *cache {
        Some(ref c) => (
            arp_items_from_devices(&c.data.devices),
            iso_from_unix_secs(c.data.timestamp),
        ),
        None => (Vec::new(), None),
    }
}

/// Read DHCP-lease-status fallback + `as_of` from the network-map cache.
async fn dhcp_status_from_cache(state: &AppState) -> (Vec<MergedLeaseArp>, Option<String>) {
    let cache = state.network_map_cache.read().await;
    match *cache {
        Some(ref c) => (
            dhcp_status_items_from_devices(&c.data.devices),
            iso_from_unix_secs(c.data.timestamp),
        ),
        None => (Vec::new(), None),
    }
}

fn parse_pool_size(ranges: &str) -> usize {
    let mut total = 0usize;
    for range in ranges.split(',') {
        let trimmed = range.trim();
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() == 2 {
            total += ip_to_num(parts[1]).saturating_sub(ip_to_num(parts[0])) as usize + 1;
        } else {
            total += 1;
        }
    }
    total
}

fn ip_to_num(ip: &str) -> u32 {
    ip.trim()
        .split('.')
        .fold(0u32, |acc, p| acc * 256 + p.parse::<u32>().unwrap_or(0))
}

#[cfg(test)]
mod degradation_tests {
    use super::*;
    use crate::routes::{live_or_degrade, LiveOr};
    use mikrotik_core::MikrotikError;

    fn device(ip: &str, in_arp: bool, dhcp_status: Option<&str>) -> DeviceStatus {
        DeviceStatus {
            ip: ip.into(),
            mac: Some("AA:BB:CC:DD:EE:FF".into()),
            hostname: Some("host".into()),
            manufacturer: Some("Acme".into()),
            in_arp,
            dhcp_status: dhcp_status.map(|s| s.to_string()),
            dhcp_server: Some("dhcp1".into()),
            expires_after: Some("1h".into()),
            last_seen: Some("2026-09-24T00:00:00Z".into()),
            hop_count: Some(1),
            internet_path: None,
        }
    }

    #[test]
    fn arp_items_only_include_in_arp_devices() {
        let devices = vec![
            device("10.0.0.1", true, Some("bound")),
            device("10.0.0.2", false, None),
        ];
        let items = arp_items_from_devices(&devices);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].address, "10.0.0.1");
        assert_eq!(items[0].manufacturer.as_deref(), Some("Acme"));
        assert!(items[0].interface.is_none());
    }

    #[test]
    fn dhcp_items_only_include_dhcp_devices_and_map_arp_status() {
        let devices = vec![
            device("10.0.0.1", true, Some("bound")),
            device("10.0.0.2", false, Some("waiting")),
            device("10.0.0.3", false, Some("bound")),
            device("10.0.0.9", true, None), // ARP-only, no DHCP -> excluded
        ];
        let items = dhcp_status_items_from_devices(&devices);
        assert_eq!(items.len(), 3);
        let by_ip = |ip: &str| items.iter().find(|i| i.address == ip).unwrap();
        assert_eq!(by_ip("10.0.0.1").arp_status, "active");
        assert_eq!(by_ip("10.0.0.2").arp_status, "stale");
        assert_eq!(by_ip("10.0.0.3").arp_status, "offline");
    }

    #[test]
    fn empty_devices_degrade_to_empty() {
        assert!(arp_items_from_devices(&[]).is_empty());
        assert!(dhcp_status_items_from_devices(&[]).is_empty());
    }

    #[test]
    fn erroring_call_maps_to_degraded() {
        let r: Result<Vec<()>, MikrotikError> = Err(MikrotikError::AuthFailed);
        assert!(matches!(live_or_degrade(r), LiveOr::Degraded));
    }
}

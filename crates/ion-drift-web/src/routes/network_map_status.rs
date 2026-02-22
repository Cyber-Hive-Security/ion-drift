use std::collections::{HashMap, HashSet};

use axum::extract::State;
use axum::response::{Json, Response};
use serde::Serialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::api_error;

#[derive(Serialize, Clone)]
pub struct DeviceStatus {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub manufacturer: Option<String>,
    pub in_arp: bool,
    pub dhcp_status: Option<String>,
    pub dhcp_server: Option<String>,
    pub expires_after: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct InterfaceStatus {
    pub name: String,
    pub running: bool,
    pub rx_byte: u64,
    pub tx_byte: u64,
    pub disabled: bool,
}

#[derive(Serialize, Clone)]
pub struct NetworkMapStatusResponse {
    pub devices: Vec<DeviceStatus>,
    pub interfaces: Vec<InterfaceStatus>,
    pub timestamp: i64,
}

#[derive(Clone)]
pub struct NetworkMapStatusCache {
    pub data: NetworkMapStatusResponse,
    pub cached_at: std::time::Instant,
}

/// GET /api/network-map/status
/// Returns merged device status (DHCP + ARP) and interface status.
/// Cached server-side for 5 seconds to avoid hammering the router.
pub async fn status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<NetworkMapStatusResponse>, Response> {
    // Check cache
    {
        let cache = state.network_map_cache.read().await;
        if let Some(ref cached) = *cache {
            if cached.cached_at.elapsed().as_secs() < 5 {
                return Ok(Json(cached.data.clone()));
            }
        }
    }

    // Fetch all three concurrently
    let (leases, arp_entries, ifaces) = tokio::try_join!(
        async { state.mikrotik.dhcp_leases().await.map_err(api_error) },
        async { state.mikrotik.arp_table().await.map_err(api_error) },
        async { state.mikrotik.interfaces().await.map_err(api_error) },
    )?;

    // Build ARP IP set
    let arp_ips: HashSet<&str> = arp_entries.iter().map(|a| a.address.as_str()).collect();

    // Start with DHCP leases (keyed by IP to deduplicate)
    let mut device_map: HashMap<String, DeviceStatus> = HashMap::new();

    for lease in &leases {
        let mac = lease.mac_address.clone();
        let manufacturer = mac
            .as_deref()
            .and_then(|m| state.oui_db.lookup(m))
            .map(String::from);

        device_map.insert(
            lease.address.clone(),
            DeviceStatus {
                ip: lease.address.clone(),
                mac,
                hostname: lease.host_name.clone(),
                manufacturer,
                in_arp: arp_ips.contains(lease.address.as_str()),
                dhcp_status: lease.status.clone(),
                dhcp_server: lease.server.clone(),
                expires_after: lease.expires_after.clone(),
                last_seen: lease.last_seen.clone(),
            },
        );
    }

    // Add ARP-only entries (static IPs not in DHCP)
    for arp in &arp_entries {
        if !device_map.contains_key(&arp.address) {
            let mac = arp.mac_address.clone();
            let manufacturer = mac
                .as_deref()
                .and_then(|m| state.oui_db.lookup(m))
                .map(String::from);

            device_map.insert(
                arp.address.clone(),
                DeviceStatus {
                    ip: arp.address.clone(),
                    mac,
                    hostname: None,
                    manufacturer,
                    in_arp: true,
                    dhcp_status: None,
                    dhcp_server: None,
                    expires_after: None,
                    last_seen: None,
                },
            );
        }
    }

    let devices: Vec<DeviceStatus> = device_map.into_values().collect();

    let interfaces: Vec<InterfaceStatus> = ifaces
        .iter()
        .map(|i| InterfaceStatus {
            name: i.name.clone(),
            running: i.running,
            rx_byte: i.rx_byte.unwrap_or(0),
            tx_byte: i.tx_byte.unwrap_or(0),
            disabled: i.disabled,
        })
        .collect();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let response = NetworkMapStatusResponse {
        devices,
        interfaces,
        timestamp,
    };

    // Update cache
    {
        let mut cache = state.network_map_cache.write().await;
        *cache = Some(NetworkMapStatusCache {
            data: response.clone(),
            cached_at: std::time::Instant::now(),
        });
    }

    Ok(Json(response))
}

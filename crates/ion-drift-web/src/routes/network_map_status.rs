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
    pub hop_count: Option<u8>,
    pub internet_path: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct InterfaceStatus {
    pub name: String,
    pub running: bool,
    pub rx_byte: u64,
    pub tx_byte: u64,
    pub rx_rate_bps: u64,
    pub tx_rate_bps: u64,
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
    /// Previous poll byte counters for rate computation: name → (rx_byte, tx_byte)
    pub prev_bytes: HashMap<String, (u64, u64)>,
}

/// Compute hop count and internet path for a device IP.
/// - Router IP (from config): 0 hops, direct ISP connection
/// - VLAN 99 (192.168.99.0/24): blocked by firewall policy
/// - All other VLANs: 1 hop through the router
fn compute_hops(ip: &str, router_host: &str) -> (Option<u8>, Option<String>) {
    let parts: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
    if parts.len() != 4 {
        return (None, None);
    }

    // Router itself (compare against configured router host)
    if ip == router_host {
        return (Some(0), Some("\u{2192} ISP (direct)".into()));
    }

    // VLAN 99 — IoT No-Internet (firewall blocks WAN access)
    if parts[0] == 192 && parts[1] == 168 && parts[2] == 99 {
        return (None, Some("blocked by policy".into()));
    }

    // All other internal VLANs route through the router
    if parts[0] == 10
        || (parts[0] == 172 && (16..=31).contains(&parts[1]))
        || (parts[0] == 192 && parts[1] == 168)
    {
        return (Some(1), Some("\u{2192} Router \u{2192} ISP".into()));
    }

    (None, None)
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
    let router_host = state.config.router.host.as_str();

    // Start with DHCP leases (keyed by IP to deduplicate)
    let mut device_map: HashMap<String, DeviceStatus> = HashMap::new();

    for lease in &leases {
        let mac = lease.mac_address.clone();
        let manufacturer = mac
            .as_deref()
            .and_then(|m| state.oui_db.lookup(m))
            .map(String::from);

        let (hop_count, internet_path) = compute_hops(&lease.address, router_host);
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
                hop_count,
                internet_path,
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

            let (hop_count, internet_path) = compute_hops(&arp.address, router_host);
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
                    hop_count,
                    internet_path,
                },
            );
        }
    }

    let devices: Vec<DeviceStatus> = device_map.into_values().collect();

    // Read previous byte counters and timestamp from cache for rate computation
    let (prev_bytes, prev_time) = {
        let cache = state.network_map_cache.read().await;
        match *cache {
            Some(ref c) => (c.prev_bytes.clone(), Some(c.cached_at)),
            None => (HashMap::new(), None),
        }
    };

    let now = std::time::Instant::now();
    let elapsed_secs = prev_time
        .map(|t| now.duration_since(t).as_secs_f64())
        .unwrap_or(0.0);

    // Build current byte counters and compute rates
    let mut current_bytes: HashMap<String, (u64, u64)> = HashMap::new();
    let interfaces: Vec<InterfaceStatus> = ifaces
        .iter()
        .map(|i| {
            let rx = i.rx_byte.unwrap_or(0);
            let tx = i.tx_byte.unwrap_or(0);
            current_bytes.insert(i.name.clone(), (rx, tx));

            let (rx_rate, tx_rate) = if elapsed_secs > 0.5 {
                if let Some(&(prev_rx, prev_tx)) = prev_bytes.get(&i.name) {
                    // Counters can wrap or reset — treat decrease as zero
                    let drx = rx.saturating_sub(prev_rx);
                    let dtx = tx.saturating_sub(prev_tx);
                    (
                        ((drx as f64 * 8.0) / elapsed_secs) as u64,
                        ((dtx as f64 * 8.0) / elapsed_secs) as u64,
                    )
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };

            InterfaceStatus {
                name: i.name.clone(),
                running: i.running,
                rx_byte: rx,
                tx_byte: tx,
                rx_rate_bps: rx_rate,
                tx_rate_bps: tx_rate,
                disabled: i.disabled,
            }
        })
        .collect();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
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
            cached_at: now,
            prev_bytes: current_bytes,
        });
    }

    Ok(Json(response))
}

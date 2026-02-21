use axum::extract::State;
use axum::response::{Json, Response};
use serde::Serialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::api_error;

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
pub async fn list(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<ArpEntryResponse>>, Response> {
    let entries = state.mikrotik.arp_table().await.map_err(api_error)?;

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

    Ok(Json(result))
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
pub async fn dhcp_leases_status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<MergedLeaseArp>>, Response> {
    let (leases, arp_entries) = tokio::try_join!(
        async { state.mikrotik.dhcp_leases().await.map_err(api_error) },
        async { state.mikrotik.arp_table().await.map_err(api_error) },
    )?;

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

    Ok(Json(result))
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
pub async fn pool_utilization(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<PoolUtilizationResponse>>, Response> {
    let (pools, servers, leases, arp_entries) = tokio::try_join!(
        async { state.mikrotik.ip_pools().await.map_err(api_error) },
        async { state.mikrotik.dhcp_servers().await.map_err(api_error) },
        async { state.mikrotik.dhcp_leases().await.map_err(api_error) },
        async { state.mikrotik.arp_table().await.map_err(api_error) },
    )?;

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
                pool_name: server.address_pool.clone().unwrap_or_else(|| "—".into()),
                total_ips,
                bound_count,
                active_on_network,
                pct,
            }
        })
        .collect();

    Ok(Json(result))
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

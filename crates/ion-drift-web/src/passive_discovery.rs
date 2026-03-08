//! Passive service discovery via router connection tracking.
//!
//! Instead of active nmap scanning (which requires raw sockets and elevated
//! privileges), this module passively analyzes the Mikrotik router's connection
//! tracking table (`/ip/firewall/connection`). Since the router is the gateway
//! for all VLANs, every inter-VLAN connection passes through it.
//!
//! When we see a connection where `dst_address` is an internal IP with
//! `seen_reply=true`, the `dst_port` is a listening (open) port on that device.
//! This gives us the same information as nmap's port scan, but:
//! - No raw sockets or elevated privileges needed
//! - Continuous monitoring (not point-in-time snapshots)
//! - Zero additional network traffic
//! - Works across all VLANs simultaneously
//!
//! Trade-off: only detects ports with active traffic. Idle services that no one
//! connects to won't be discovered. In practice, services that matter (web, SSH,
//! DNS, SMTP, etc.) always have active connections.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use mikrotik_core::MikrotikClient;
use ion_drift_storage::SwitchStore;
use crate::task_supervisor::TaskSupervisor;

/// Background task interval (seconds).
const POLL_INTERVAL_SECS: u64 = 120;

/// Startup delay to let the correlation engine populate identities first.
const STARTUP_DELAY_SECS: u64 = 150;

/// Services not seen in 7 days are pruned.
const SERVICE_MAX_AGE_SECS: i64 = 7 * 86400;

/// Spawn the passive service discovery background task.
pub fn spawn_passive_discovery(
    supervisor: &TaskSupervisor,
    switch_store: Arc<SwitchStore>,
    router_client: MikrotikClient,
) {
    supervisor.spawn("passive_discovery", move || {
        let switch_store = switch_store.clone();
        let router_client = router_client.clone();
        Box::pin(async move {
        tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_SECS)).await;
        tracing::info!("passive service discovery starting ({POLL_INTERVAL_SECS}s interval)");

        let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
        interval.tick().await;

        loop {
            interval.tick().await;

            if let Err(e) = run_passive_discovery(&switch_store, &router_client).await {
                tracing::warn!("passive discovery error: {e}");
            }

            // Prune stale services periodically
            if let Err(e) = switch_store.prune_observed_services(SERVICE_MAX_AGE_SECS).await {
                tracing::warn!("passive discovery: prune error: {e}");
            }
        }
    })});
}

/// One cycle of passive discovery.
async fn run_passive_discovery(
    store: &SwitchStore,
    router: &MikrotikClient,
) -> anyhow::Result<()> {
    // Fetch NAT and filter rules to discover which high ports are legitimate services.
    // dst-nat rules reveal port forwards; filter accept rules on specific dst-ports
    // reveal services the firewall explicitly allows.
    let nat_ports = extract_nat_service_ports(router).await;

    // Fetch all active connections from the router
    let connections = router.firewall_connections_full().await?;

    // Build a map: internal IP → set of (port, protocol) where it's the destination
    // (i.e., ports it's listening on).
    let mut listening_ports: HashMap<String, HashMap<(u32, String), u32>> = HashMap::new();

    for conn in &connections {
        // We need dst_address to be internal and seen_reply=true
        let seen_reply = conn.seen_reply.unwrap_or(false);
        if !seen_reply {
            continue;
        }

        let (dst_ip, dst_port_from_addr) = match &conn.dst_address {
            Some(addr) => parse_ip_port(addr),
            None => continue,
        };

        if !is_internal_ip(&dst_ip) {
            continue;
        }

        // Get the destination port — prefer the dedicated field, fall back to parsed from address
        let dst_port: u32 = conn
            .dst_port
            .as_ref()
            .and_then(|p| p.parse().ok())
            .or(dst_port_from_addr)
            .unwrap_or(0);

        if dst_port == 0 {
            continue;
        }

        // Skip ephemeral ports (>= IANA dynamic range start) unless the port
        // appears in NAT/firewall rules as a legitimate service port.
        if dst_port >= 49152 && !nat_ports.contains(&dst_port) {
            continue;
        }

        let protocol = conn
            .protocol
            .as_deref()
            .unwrap_or("tcp")
            .to_lowercase();

        // Only track TCP and UDP
        if protocol != "tcp" && protocol != "udp" {
            continue;
        }

        let entry = listening_ports
            .entry(dst_ip)
            .or_default();
        *entry.entry((dst_port, protocol)).or_default() += 1;
    }

    // Now store each observed service and infer device types
    let mut total_services = 0u32;
    let mut total_ips = 0u32;

    for (ip, ports) in &listening_ports {
        total_ips += 1;

        for ((port, protocol), _count) in ports {
            let service_name = port_to_service_name(*port, protocol);
            if let Err(e) = store
                .upsert_observed_service(ip, *port, protocol, service_name)
                .await
            {
                tracing::warn!(ip = %ip, port = %port, "observed service upsert: {e}");
            }
            total_services += 1;
        }

        // Infer device type from service profile
        let port_set: Vec<(u32, &str)> = ports
            .keys()
            .map(|(p, proto)| (*p, proto.as_str()))
            .collect();

        if let Some((device_type, confidence)) = infer_device_type_from_services(&port_set) {
            // Find the MAC address for this IP via network_identities
            if let Ok(identities) = store.get_network_identities().await {
                if let Some(identity) = identities.iter().find(|i| {
                    i.best_ip.as_deref() == Some(ip.as_str())
                }) {
                    // Only update if passive confidence beats current confidence
                    // and the identity isn't human-confirmed
                    if !identity.human_confirmed
                        && confidence > identity.device_type_confidence
                    {
                        if let Err(e) = store
                            .upsert_network_identity(
                                &identity.mac_address,
                                Some(ip),
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                identity.confidence, // preserve existing confidence
                                Some(device_type),
                                Some("conntrack"),
                                confidence,
                            )
                            .await
                        {
                            tracing::warn!(mac = %identity.mac_address, "failed to upsert network identity from passive discovery: {e}");
                        }
                    }
                }
            }
        }
    }

    if total_services > 0 {
        tracing::debug!(
            services = total_services,
            ips = total_ips,
            connections = connections.len(),
            "passive discovery cycle complete"
        );
    }

    Ok(())
}

/// Parse an IP address that may contain an embedded port (e.g. "10.20.25.8:443").
/// Returns (ip, Option<port>).
fn parse_ip_port(addr: &str) -> (String, Option<u32>) {
    if let Some(colon_pos) = addr.rfind(':') {
        let ip_part = &addr[..colon_pos];
        let port_part = &addr[colon_pos + 1..];
        // Verify the IP part looks like an IPv4 address (contains dots)
        if ip_part.contains('.') {
            if let Ok(port) = port_part.parse::<u32>() {
                return (ip_part.to_string(), Some(port));
            }
        }
    }
    (addr.to_string(), None)
}

/// Check if an IP is in RFC 1918 private ranges.
/// Delegates to the canonical implementation in mikrotik-core.
fn is_internal_ip(ip: &str) -> bool {
    ion_drift_storage::behavior::is_internal_ip(ip)
}

/// Extract service ports from router NAT and filter rules.
///
/// - dst-nat rules with `to-ports` or `dst-port` reveal port forwards
/// - filter accept rules with explicit `dst-port` reveal allowed services
///
/// Returns a set of port numbers that are known to be legitimate services,
/// even if they fall in the IANA ephemeral range (>= 49152).
async fn extract_nat_service_ports(router: &MikrotikClient) -> HashSet<u32> {
    let mut ports = HashSet::new();

    // Extract ports from NAT dst-nat rules (port forwards)
    if let Ok(nat_rules) = router.firewall_nat_rules().await {
        for rule in &nat_rules {
            if rule.action != "dst-nat" {
                continue;
            }
            if rule.disabled == Some(true) {
                continue;
            }
            // to-ports is the internal port the traffic is forwarded to
            if let Some(ref to_ports) = rule.to_ports {
                for p in parse_port_spec(to_ports) {
                    ports.insert(p);
                }
            }
            // dst-port is the external-facing port (also useful for service detection)
            if let Some(ref dst_port) = rule.dst_port {
                for p in parse_port_spec(dst_port) {
                    ports.insert(p);
                }
            }
        }
    }

    // Extract ports from filter accept rules with explicit dst-port
    if let Ok(filter_rules) = router.firewall_filter_rules().await {
        for rule in &filter_rules {
            if rule.action != "accept" {
                continue;
            }
            if rule.disabled == Some(true) {
                continue;
            }
            if let Some(ref dst_port) = rule.dst_port {
                for p in parse_port_spec(dst_port) {
                    ports.insert(p);
                }
            }
        }
    }

    if !ports.is_empty() {
        tracing::debug!(count = ports.len(), "discovered service ports from firewall rules");
    }

    ports
}

/// Parse a RouterOS port specification into individual port numbers.
/// Supports: single port ("443"), comma-separated ("80,443"), ranges ("8080-8090").
fn parse_port_spec(spec: &str) -> Vec<u32> {
    let mut result = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.trim().parse::<u32>(), end.trim().parse::<u32>()) {
                for p in s..=e.min(s + 100) {
                    result.push(p);
                }
            }
        } else if let Ok(p) = part.parse::<u32>() {
            result.push(p);
        }
    }
    result
}

/// Map a port number to a human-readable service name.
fn port_to_service_name(port: u32, protocol: &str) -> Option<&'static str> {
    match (port, protocol) {
        (22, "tcp") => Some("ssh"),
        (25, "tcp") => Some("smtp"),
        (53, _) => Some("dns"),
        (80, "tcp") => Some("http"),
        (110, "tcp") => Some("pop3"),
        (123, "udp") => Some("ntp"),
        (143, "tcp") => Some("imap"),
        (161, "udp") => Some("snmp"),
        (389, "tcp") => Some("ldap"),
        (443, "tcp") => Some("https"),
        (445, "tcp") => Some("smb"),
        (465, "tcp") => Some("submissions"),
        (514, "udp") => Some("syslog"),
        (554, "tcp") => Some("rtsp"),
        (587, "tcp") => Some("submission"),
        (631, "tcp") => Some("ipp"),
        (636, "tcp") => Some("ldaps"),
        (993, "tcp") => Some("imaps"),
        (995, "tcp") => Some("pop3s"),
        (1194, _) => Some("openvpn"),
        (1883, "tcp") => Some("mqtt"),
        (2222, "tcp") => Some("ssh-alt"),
        (3000, "tcp") => Some("web-app"),
        (3001, "tcp") => Some("web-app"),
        (3012, "tcp") => Some("websocket"),
        (3306, "tcp") => Some("mysql"),
        (3389, "tcp") => Some("rdp"),
        (4050, "tcp") => Some("certwarden"),
        (5055, "tcp") => Some("certwarden-client"),
        (5432, "tcp") => Some("postgresql"),
        (5514, "udp") => Some("syslog-alt"),
        (5900, "tcp") => Some("vnc"),
        (6379, "tcp") => Some("redis"),
        (6875, "tcp") => Some("bookstack"),
        (7575, "tcp") => Some("homarr"),
        (8006, "tcp") => Some("proxmox"),
        (8043, "tcp") => Some("omada-https"),
        (8080, "tcp") => Some("http-alt"),
        (8081, "tcp") => Some("http-alt"),
        (8082, "tcp") => Some("http-alt"),
        (8083, "tcp") => Some("http-alt"),
        (8084, "tcp") => Some("http-alt"),
        (8085, "tcp") => Some("http-alt"),
        (8088, "tcp") => Some("http-alt"),
        (8443, "tcp") => Some("https-alt"),
        (8883, "tcp") => Some("mqtts"),
        (8998, "tcp") => Some("web-app"),
        (9001, "tcp") => Some("portainer-agent"),
        (9100, "tcp") => Some("jetdirect"),
        (9443, "tcp") => Some("https-alt"),
        (32400, "tcp") => Some("plex"),
        _ => None,
    }
}

/// Infer device type from observed listening ports.
/// Returns (device_type, confidence) or None if insufficient data.
fn infer_device_type_from_services(ports: &[(u32, &str)]) -> Option<(&'static str, f64)> {
    let has = |p: u32| ports.iter().any(|(port, _)| *port == p);
    let has_any = |ps: &[u32]| ps.iter().any(|p| has(*p));

    // Camera / NVR — RTSP is very strong signal
    if has(554) {
        return Some(("camera", 0.90));
    }

    // Printer — JetDirect or IPP
    if has(9100) || has(631) {
        return Some(("printer", 0.90));
    }

    // Media server — Plex
    if has(32400) {
        return Some(("media_server", 0.85));
    }

    // Proxmox hypervisor
    if has(8006) {
        return Some(("server", 0.80));
    }

    // DNS server
    if has(53) && !has_any(&[80, 443, 8080]) {
        return Some(("dns_server", 0.80));
    }

    // Mail server — SMTP + IMAP combination
    if has_any(&[25, 587]) && has_any(&[143, 993]) {
        return Some(("mail_server", 0.85));
    }

    // Directory / LDAP server
    if has_any(&[389, 636]) {
        return Some(("server", 0.80));
    }

    // Network equipment — RouterOS HTTPS API or SNMP
    if has(8443) || (has(161) && !has_any(&[80, 443])) {
        return Some(("network_equipment", 0.75));
    }

    // Web server with SSH — likely a server
    if has_any(&[80, 443]) && has(22) {
        return Some(("server", 0.70));
    }

    // Any web-serving device without SSH
    if has_any(&[80, 443, 8080, 8443, 9443]) {
        // Could be IoT, could be server — lower confidence
        return Some(("server", 0.50));
    }

    // SSH only — could be server or network equipment
    if has(22) && ports.len() <= 2 {
        return Some(("server", 0.40));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_port() {
        assert_eq!(parse_ip_port("192.168.1.1:443"), ("192.168.1.1".to_string(), Some(443)));
        assert_eq!(parse_ip_port("192.168.1.1"), ("192.168.1.1".to_string(), None));
        assert_eq!(parse_ip_port("192.168.90.7:554"), ("192.168.90.7".to_string(), Some(554)));
    }

    #[test]
    fn test_is_internal_ip() {
        assert!(is_internal_ip("192.168.1.1"));
        assert!(is_internal_ip("172.16.0.1"));
        assert!(is_internal_ip("192.168.90.7"));
        assert!(!is_internal_ip("8.8.8.8"));
        assert!(!is_internal_ip("1.1.1.1"));
    }

    #[test]
    fn test_port_to_service() {
        assert_eq!(port_to_service_name(22, "tcp"), Some("ssh"));
        assert_eq!(port_to_service_name(443, "tcp"), Some("https"));
        assert_eq!(port_to_service_name(32400, "tcp"), Some("plex"));
        assert_eq!(port_to_service_name(12345, "tcp"), None);
    }

    #[test]
    fn test_device_type_inference() {
        // Camera
        assert_eq!(
            infer_device_type_from_services(&[(554, "tcp"), (80, "tcp")]),
            Some(("camera", 0.90))
        );
        // Plex
        assert_eq!(
            infer_device_type_from_services(&[(32400, "tcp"), (443, "tcp")]),
            Some(("media_server", 0.85))
        );
        // Mail server
        assert_eq!(
            infer_device_type_from_services(&[(25, "tcp"), (587, "tcp"), (993, "tcp"), (443, "tcp")]),
            Some(("mail_server", 0.85))
        );
        // Web + SSH = server
        assert_eq!(
            infer_device_type_from_services(&[(80, "tcp"), (443, "tcp"), (22, "tcp")]),
            Some(("server", 0.70))
        );
    }
}

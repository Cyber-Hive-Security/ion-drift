use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;
use crate::serde_helpers::*;

/// IP address — `/ip/address`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct IpAddress {
    #[serde(rename = ".id")]
    pub id: String,
    pub address: String,
    pub network: String,
    pub interface: String,
    #[serde(default)]
    pub actual_interface: Option<String>,
    #[serde(deserialize_with = "ros_bool")]
    pub disabled: bool,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub invalid: Option<bool>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// IP route — `/ip/route`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Route {
    #[serde(rename = ".id")]
    pub id: String,
    pub dst_address: String,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub distance: Option<u32>,
    #[serde(default)]
    pub routing_table: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub active: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// DHCP lease — `/ip/dhcp-server/lease`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DhcpLease {
    #[serde(rename = ".id")]
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub host_name: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub active_address: Option<String>,
    #[serde(default)]
    pub active_mac_address: Option<String>,
    #[serde(default)]
    pub expires_after: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// DNS static entry — `/ip/dns/static`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsStaticEntry {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub ttl: Option<u32>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// DNS cache entry — `/ip/dns/cache`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsCacheEntry {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    /// Resolved payload: an IP for A/AAAA, a target name for CNAME.
    #[serde(default)]
    pub data: Option<String>,
    #[serde(rename = "type", default)]
    pub record_type: Option<String>,
    /// RouterOS duration string, e.g. "23h59m59s".
    #[serde(default)]
    pub ttl: Option<String>,
    #[serde(rename = "static", default, deserialize_with = "ros_bool_opt")]
    pub is_static: Option<bool>,
}

/// IP pool — `/ip/pool`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct IpPool {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    pub ranges: String,
    #[serde(default)]
    pub comment: Option<String>,
}

/// DHCP server — `/ip/dhcp-server`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DhcpServer {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    pub interface: String,
    #[serde(default)]
    pub address_pool: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// ARP entry — `/ip/arp`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ArpEntry {
    #[serde(rename = ".id")]
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub complete: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// DHCP server network — `/ip/dhcp-server/network`
/// Contains per-pool options like DNS, NTP, gateway.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DhcpNetwork {
    #[serde(rename = ".id")]
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns_server: Option<String>,
    #[serde(default)]
    pub ntp_server: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// DNS server configuration — `/ip/dns`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    #[serde(default)]
    pub servers: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub allow_remote_requests: Option<bool>,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub cache_size: Option<u32>,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub cache_max_ttl: Option<u32>,
}

/// IP service — `/ip/service` (api, api-ssl, ssh, telnet, ftp, www, www-ssl, winbox).
///
/// `address` is the service's own source restriction: empty means any address
/// that can reach the router may connect.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct IpService {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub port: Option<u32>,
    #[serde(deserialize_with = "ros_bool")]
    pub disabled: bool,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub invalid: Option<bool>,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// List all IP addresses.
    pub async fn ip_addresses(&self) -> Result<Vec<IpAddress>, MikrotikError> {
        self.get("ip/address").await
    }

    /// List all routes.
    pub async fn ip_routes(&self) -> Result<Vec<Route>, MikrotikError> {
        self.get("ip/route").await
    }

    /// List DHCP server leases.
    pub async fn dhcp_leases(&self) -> Result<Vec<DhcpLease>, MikrotikError> {
        self.get("ip/dhcp-server/lease").await
    }

    /// List DNS static entries.
    pub async fn dns_static_entries(&self) -> Result<Vec<DnsStaticEntry>, MikrotikError> {
        self.get("ip/dns/static").await
    }

    /// List the DNS cache — every name the router has resolved recently.
    pub async fn dns_cache(&self) -> Result<Vec<DnsCacheEntry>, MikrotikError> {
        self.get("ip/dns/cache").await
    }

    /// List IP address pools.
    pub async fn ip_pools(&self) -> Result<Vec<IpPool>, MikrotikError> {
        self.get("ip/pool").await
    }

    /// List DHCP servers.
    pub async fn dhcp_servers(&self) -> Result<Vec<DhcpServer>, MikrotikError> {
        self.get("ip/dhcp-server").await
    }

    /// List ARP table entries.
    pub async fn arp_table(&self) -> Result<Vec<ArpEntry>, MikrotikError> {
        self.get("ip/arp").await
    }

    /// List DHCP server network configurations.
    pub async fn dhcp_networks(&self) -> Result<Vec<DhcpNetwork>, MikrotikError> {
        self.get("ip/dhcp-server/network").await
    }

    /// Get DNS server configuration.
    pub async fn dns_config(&self) -> Result<DnsConfig, MikrotikError> {
        self.get("ip/dns").await
    }

    /// `/ip/service` — management services and their source restrictions.
    pub async fn ip_services(&self) -> Result<Vec<IpService>, MikrotikError> {
        self.get("ip/service").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_cache_entry_deserializes_router_payload() {
        let payload = serde_json::json!([{
            ".id": "*1",
            "name": "paypa1.com",
            "data": "203.0.113.9",
            "type": "A",
            "ttl": "23h59m59s",
            "static": "false"
        }]);
        let entries: Vec<DnsCacheEntry> = serde_json::from_value(payload).unwrap();
        assert_eq!(entries[0].name, "paypa1.com");
        assert_eq!(entries[0].data.as_deref(), Some("203.0.113.9"));
        assert_eq!(entries[0].record_type.as_deref(), Some("A"));
        assert_eq!(entries[0].ttl.as_deref(), Some("23h59m59s"));
        assert_eq!(entries[0].is_static, Some(false));
    }

    #[test]
    fn dns_cache_entry_tolerates_missing_optionals() {
        // CNAME rows and stripped payloads: only `.id` and `name` are certain.
        let payload = serde_json::json!([{ ".id": "*2", "name": "example.com" }]);
        let entries: Vec<DnsCacheEntry> = serde_json::from_value(payload).unwrap();
        assert_eq!(entries[0].name, "example.com");
        assert!(entries[0].data.is_none());
        assert!(entries[0].is_static.is_none());
    }

    #[test]
    fn ip_service_deserializes_router_payload() {
        let payload = serde_json::json!([
            { ".id": "*8", "address": "", "certificate": "none", "disabled": "false",
              "invalid": "false", "name": "api-ssl", "port": "8729", "tls-version": "any", "vrf": "main" },
            { ".id": "*3", "address": "192.168.1.17/32", "disabled": "true", "name": "api", "port": "8728" }
        ]);
        let svcs: Vec<IpService> = serde_json::from_value(payload).unwrap();
        assert_eq!(svcs[0].name, "api-ssl");
        assert_eq!(svcs[0].port, Some(8729));
        assert!(!svcs[0].disabled);
        assert_eq!(svcs[0].address.as_deref(), Some(""));
        assert_eq!(svcs[1].address.as_deref(), Some("192.168.1.17/32"));
        assert!(svcs[1].disabled);
    }

    #[test]
    fn ip_service_tolerates_missing_optionals() {
        let payload = serde_json::json!([{ ".id": "*1", "name": "ssh", "disabled": "false" }]);
        let svcs: Vec<IpService> = serde_json::from_value(payload).unwrap();
        assert!(svcs[0].port.is_none());
        assert!(svcs[0].address.is_none());
        assert!(svcs[0].invalid.is_none());
    }
}

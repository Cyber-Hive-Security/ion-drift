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
}

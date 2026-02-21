use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;
use crate::serde_helpers::*;

/// Firewall filter rule — `/ip/firewall/filter`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FilterRule {
    #[serde(rename = ".id")]
    pub id: String,
    pub chain: String,
    pub action: String,
    #[serde(default)]
    pub src_address: Option<String>,
    #[serde(default)]
    pub dst_address: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub src_port: Option<String>,
    #[serde(default)]
    pub dst_port: Option<String>,
    #[serde(default)]
    pub in_interface: Option<String>,
    #[serde(default)]
    pub out_interface: Option<String>,
    #[serde(default)]
    pub in_interface_list: Option<String>,
    #[serde(default)]
    pub out_interface_list: Option<String>,
    #[serde(default)]
    pub src_address_list: Option<String>,
    #[serde(default)]
    pub dst_address_list: Option<String>,
    #[serde(default)]
    pub connection_state: Option<String>,
    #[serde(default)]
    pub connection_nat_state: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub bytes: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub packets: Option<u64>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub log: Option<String>,
    #[serde(default)]
    pub log_prefix: Option<String>,
}

/// NAT rule — `/ip/firewall/nat`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NatRule {
    #[serde(rename = ".id")]
    pub id: String,
    pub chain: String,
    pub action: String,
    #[serde(default)]
    pub src_address: Option<String>,
    #[serde(default)]
    pub dst_address: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub src_port: Option<String>,
    #[serde(default)]
    pub dst_port: Option<String>,
    #[serde(default)]
    pub in_interface: Option<String>,
    #[serde(default)]
    pub out_interface: Option<String>,
    #[serde(default)]
    pub in_interface_list: Option<String>,
    #[serde(default)]
    pub out_interface_list: Option<String>,
    #[serde(default)]
    pub to_addresses: Option<String>,
    #[serde(default)]
    pub to_ports: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub bytes: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub packets: Option<u64>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Mangle rule — `/ip/firewall/mangle`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MangleRule {
    #[serde(rename = ".id")]
    pub id: String,
    pub chain: String,
    pub action: String,
    #[serde(default)]
    pub src_address: Option<String>,
    #[serde(default)]
    pub dst_address: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub src_port: Option<String>,
    #[serde(default)]
    pub dst_port: Option<String>,
    #[serde(default)]
    pub in_interface: Option<String>,
    #[serde(default)]
    pub out_interface: Option<String>,
    #[serde(default)]
    pub passthrough: Option<String>,
    #[serde(default)]
    pub new_packet_mark: Option<String>,
    #[serde(default)]
    pub new_connection_mark: Option<String>,
    #[serde(default)]
    pub new_routing_mark: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub bytes: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub packets: Option<u64>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Body for creating a mangle rule via `PUT /rest/ip/firewall/mangle`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CreateMangleRule {
    pub chain: String,
    pub action: String,
    pub in_interface: String,
    pub out_interface: String,
    pub comment: String,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// List firewall filter rules.
    pub async fn firewall_filter_rules(&self) -> Result<Vec<FilterRule>, MikrotikError> {
        self.get("ip/firewall/filter").await
    }

    /// List firewall NAT rules.
    pub async fn firewall_nat_rules(&self) -> Result<Vec<NatRule>, MikrotikError> {
        self.get("ip/firewall/nat").await
    }

    /// List firewall mangle rules.
    pub async fn firewall_mangle_rules(&self) -> Result<Vec<MangleRule>, MikrotikError> {
        self.get("ip/firewall/mangle").await
    }

    /// Create a new mangle rule.
    pub async fn create_mangle_rule(&self, rule: &CreateMangleRule) -> Result<MangleRule, MikrotikError> {
        self.put("ip/firewall/mangle", rule).await
    }
}

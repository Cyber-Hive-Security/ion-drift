use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;
use crate::serde_helpers::*;

/// Network interface — `/interface`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Interface {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub default_name: Option<String>,
    #[serde(rename = "type")]
    pub iface_type: String,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub mtu: Option<u32>,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub actual_mtu: Option<u32>,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(deserialize_with = "ros_bool")]
    pub running: bool,
    #[serde(deserialize_with = "ros_bool")]
    pub disabled: bool,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub rx_byte: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub tx_byte: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub rx_packet: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub tx_packet: Option<u64>,
    #[serde(default)]
    pub last_link_up_time: Option<String>,
}

/// VLAN interface — `/interface/vlan`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct VlanInterface {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    #[serde(deserialize_with = "ros_u32")]
    pub vlan_id: u32,
    pub interface: String,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub mtu: Option<u32>,
    #[serde(deserialize_with = "ros_bool")]
    pub running: bool,
    #[serde(deserialize_with = "ros_bool")]
    pub disabled: bool,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub mac_address: Option<String>,
}

/// Bridge interface — `/interface/bridge`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BridgeInterface {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(deserialize_with = "ros_bool")]
    pub running: bool,
    #[serde(deserialize_with = "ros_bool")]
    pub disabled: bool,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub protocol_mode: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub vlan_filtering: Option<bool>,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// List all interfaces.
    pub async fn interfaces(&self) -> Result<Vec<Interface>, MikrotikError> {
        self.get("interface").await
    }

    /// List VLAN interfaces.
    pub async fn vlan_interfaces(&self) -> Result<Vec<VlanInterface>, MikrotikError> {
        self.get("interface/vlan").await
    }

    /// List bridge interfaces.
    pub async fn bridge_interfaces(&self) -> Result<Vec<BridgeInterface>, MikrotikError> {
        self.get("interface/bridge").await
    }
}

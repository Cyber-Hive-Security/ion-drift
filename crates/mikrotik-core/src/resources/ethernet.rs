use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;
use crate::serde_helpers::*;

/// Ethernet interface — `/interface/ethernet`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EthernetInterface {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub default_name: Option<String>,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub orig_mac_address: Option<String>,
    #[serde(default)]
    pub speed: Option<String>,
    #[serde(default)]
    pub advertise: Option<String>,
    #[serde(deserialize_with = "ros_bool")]
    pub running: bool,
    #[serde(deserialize_with = "ros_bool")]
    pub disabled: bool,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub auto_negotiation: Option<bool>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub rx_byte: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub tx_byte: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub rx_packet: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub tx_packet: Option<u64>,
    #[serde(default)]
    pub poe_out: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub switch: Option<String>,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// List ethernet interfaces with hardware details.
    pub async fn ethernet_interfaces(&self) -> Result<Vec<EthernetInterface>, MikrotikError> {
        self.get("interface/ethernet").await
    }
}

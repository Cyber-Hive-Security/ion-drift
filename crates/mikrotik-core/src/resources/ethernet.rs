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
    pub rx_bytes: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub tx_bytes: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub rx_packets: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub tx_packets: Option<u64>,
    #[serde(default)]
    pub poe_out: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub switch: Option<String>,
}

/// Real-time monitor entry from `/interface/ethernet/monitor`.
/// Contains actual negotiated link speed (vs. configured speed).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EthernetMonitorEntry {
    pub name: String,
    #[serde(default)]
    pub rate: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub full_duplex: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// List ethernet interfaces with hardware details.
    pub async fn ethernet_interfaces(&self) -> Result<Vec<EthernetInterface>, MikrotikError> {
        self.get("interface/ethernet").await
    }

    /// Monitor all ethernet interfaces (single snapshot).
    /// Returns actual negotiated link speed in the `rate` field.
    pub async fn monitor_ethernet(&self) -> Result<Vec<EthernetMonitorEntry>, MikrotikError> {
        self.post("interface/ethernet/monitor", &serde_json::json!({
            ".id": "*",
            "once": ""
        })).await
    }
}

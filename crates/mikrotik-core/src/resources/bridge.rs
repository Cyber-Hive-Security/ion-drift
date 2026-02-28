use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;
use crate::serde_helpers::*;

/// Bridge host entry (MAC address table) — `/interface/bridge/host`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BridgeHost {
    #[serde(rename = ".id")]
    pub id: String,
    pub mac_address: String,
    pub bridge: String,
    #[serde(default)]
    pub on_interface: Option<String>,
    #[serde(default)]
    pub age: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub local: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub external: Option<bool>,
}

/// Bridge port configuration — `/interface/bridge/port`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BridgePort {
    #[serde(rename = ".id")]
    pub id: String,
    pub bridge: String,
    pub interface: String,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub hw: Option<bool>,
    #[serde(default, deserialize_with = "ros_u32_opt")]
    pub pvid: Option<u32>,
    #[serde(default)]
    pub frame_types: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub ingress_filtering: Option<bool>,
    #[serde(default)]
    pub edge: Option<String>,
    #[serde(default)]
    pub point_to_point: Option<String>,
    #[serde(deserialize_with = "ros_bool")]
    pub disabled: bool,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub trusted: Option<bool>,
}

/// Bridge VLAN table entry — `/interface/bridge/vlan`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BridgeVlan {
    #[serde(rename = ".id")]
    pub id: String,
    pub bridge: String,
    pub vlan_ids: String,
    #[serde(default)]
    pub tagged: Option<String>,
    #[serde(default)]
    pub untagged: Option<String>,
    #[serde(default)]
    pub current_tagged: Option<String>,
    #[serde(default)]
    pub current_untagged: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dynamic: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub disabled: Option<bool>,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// List bridge host entries (MAC address table).
    pub async fn bridge_hosts(&self) -> Result<Vec<BridgeHost>, MikrotikError> {
        self.get("interface/bridge/host").await
    }

    /// List bridge port configurations.
    pub async fn bridge_ports(&self) -> Result<Vec<BridgePort>, MikrotikError> {
        self.get("interface/bridge/port").await
    }

    /// List bridge VLAN table entries.
    pub async fn bridge_vlans(&self) -> Result<Vec<BridgeVlan>, MikrotikError> {
        self.get("interface/bridge/vlan").await
    }
}

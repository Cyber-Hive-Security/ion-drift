use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;
use crate::serde_helpers::*;

/// Minimal connection entry — `/ip/firewall/connection` (for summary counts).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnectionEntry {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub protocol: Option<String>,
}

/// Full connection entry — `/ip/firewall/connection` (all fields).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FullConnectionEntry {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub src_address: Option<String>,
    #[serde(default)]
    pub dst_address: Option<String>,
    #[serde(default)]
    pub src_port: Option<String>,
    #[serde(default)]
    pub dst_port: Option<String>,
    #[serde(default)]
    pub tcp_state: Option<String>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub orig_bytes: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub repl_bytes: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub orig_packets: Option<u64>,
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub repl_packets: Option<u64>,
    #[serde(default)]
    pub connection_mark: Option<String>,
    #[serde(default)]
    pub connection_state: Option<String>,
    #[serde(default)]
    pub connection_type: Option<String>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub assured: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub seen_reply: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub fasttrack: Option<bool>,
    #[serde(default, deserialize_with = "ros_bool_opt")]
    pub dying: Option<bool>,
}

/// Connection tracking settings — `/ip/firewall/connection/tracking`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnectionTracking {
    #[serde(default, deserialize_with = "ros_u64_opt")]
    pub max_entries: Option<u64>,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// List firewall connections (minimal fields for summary counts).
    pub async fn firewall_connections(&self, proplist: &str) -> Result<Vec<ConnectionEntry>, MikrotikError> {
        let path = format!("ip/firewall/connection?.proplist={proplist}");
        self.get(&path).await
    }

    /// List all firewall connections with full details.
    pub async fn firewall_connections_full(&self) -> Result<Vec<FullConnectionEntry>, MikrotikError> {
        self.get("ip/firewall/connection").await
    }

    /// Get connection tracking settings.
    pub async fn connection_tracking(&self) -> Result<ConnectionTracking, MikrotikError> {
        self.get("ip/firewall/connection/tracking").await
    }
}

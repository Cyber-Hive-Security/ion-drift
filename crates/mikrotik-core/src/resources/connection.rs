use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;
use crate::serde_helpers::*;

/// Minimal connection entry — `/ip/firewall/connection`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnectionEntry {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub protocol: Option<String>,
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
    /// List firewall connections (use `.proplist` query param to limit fields).
    pub async fn firewall_connections(&self, proplist: &str) -> Result<Vec<ConnectionEntry>, MikrotikError> {
        let path = format!("ip/firewall/connection?.proplist={proplist}");
        self.get(&path).await
    }

    /// Get connection tracking settings.
    pub async fn connection_tracking(&self) -> Result<ConnectionTracking, MikrotikError> {
        self.get("ip/firewall/connection/tracking").await
    }
}

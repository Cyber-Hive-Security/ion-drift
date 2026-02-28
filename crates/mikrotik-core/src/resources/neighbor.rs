use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;

/// IP neighbor entry (LLDP/MNDP/CDP discovery) — `/ip/neighbor`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct IpNeighbor {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub address4: Option<String>,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub board: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub system_description: Option<String>,
    #[serde(default)]
    pub uptime: Option<String>,
    #[serde(default)]
    pub software_id: Option<String>,
    #[serde(default)]
    pub unpack: Option<String>,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// List IP neighbor entries (LLDP/MNDP/CDP discovery table).
    pub async fn ip_neighbors(&self) -> Result<Vec<IpNeighbor>, MikrotikError> {
        self.get("ip/neighbor").await
    }
}

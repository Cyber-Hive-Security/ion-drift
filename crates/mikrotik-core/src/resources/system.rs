use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;
use crate::serde_helpers::*;

/// System resource usage — `/system/resource`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SystemResource {
    #[serde(rename = ".id", default)]
    pub id: Option<String>,
    pub uptime: String,
    pub version: String,
    #[serde(default)]
    pub build_time: Option<String>,
    #[serde(default)]
    pub factory_software: Option<String>,
    #[serde(deserialize_with = "ros_u64")]
    pub free_memory: u64,
    #[serde(deserialize_with = "ros_u64")]
    pub total_memory: u64,
    pub cpu: String,
    #[serde(deserialize_with = "ros_u32")]
    pub cpu_count: u32,
    #[serde(deserialize_with = "ros_u32")]
    pub cpu_frequency: u32,
    #[serde(deserialize_with = "ros_u32")]
    pub cpu_load: u32,
    #[serde(deserialize_with = "ros_u64")]
    pub free_hdd_space: u64,
    #[serde(deserialize_with = "ros_u64")]
    pub total_hdd_space: u64,
    #[serde(default)]
    pub architecture_name: Option<String>,
    pub board_name: String,
    pub platform: String,
}

impl SystemResource {
    /// Memory usage as a percentage (0.0–100.0).
    pub fn memory_usage_percent(&self) -> f64 {
        if self.total_memory == 0 {
            return 0.0;
        }
        let used = self.total_memory - self.free_memory;
        (used as f64 / self.total_memory as f64) * 100.0
    }

    /// HDD usage as a percentage (0.0–100.0).
    pub fn hdd_usage_percent(&self) -> f64 {
        if self.total_hdd_space == 0 {
            return 0.0;
        }
        let used = self.total_hdd_space - self.free_hdd_space;
        (used as f64 / self.total_hdd_space as f64) * 100.0
    }
}

/// System identity — `/system/identity`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemIdentity {
    pub name: String,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// Fetch system resource usage.
    pub async fn system_resources(&self) -> Result<SystemResource, MikrotikError> {
        self.get("system/resource").await
    }

    /// Fetch system identity (router name).
    pub async fn system_identity(&self) -> Result<SystemIdentity, MikrotikError> {
        self.get("system/identity").await
    }
}

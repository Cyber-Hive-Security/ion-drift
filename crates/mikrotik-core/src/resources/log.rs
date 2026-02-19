use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;

/// System log entry — `/log`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogEntry {
    #[serde(rename = ".id")]
    pub id: String,
    pub time: String,
    #[serde(default)]
    pub topics: Option<String>,
    pub message: String,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// Fetch system log entries.
    pub async fn log_entries(&self) -> Result<Vec<LogEntry>, MikrotikError> {
        self.get("log").await
    }
}

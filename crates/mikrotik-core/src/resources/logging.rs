use serde::{Deserialize, Serialize};

use crate::MikrotikClient;
use crate::MikrotikError;

/// Logging action — `/system/logging/action`
///
/// Defines where log messages are sent (memory, disk, echo, remote).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LoggingAction {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    pub target: String,
    #[serde(default)]
    pub remote: Option<String>,
    #[serde(default)]
    pub remote_port: Option<u16>,
    #[serde(default)]
    pub src_address: Option<String>,
    #[serde(default)]
    pub bsd_syslog: Option<String>,
    #[serde(default)]
    pub syslog_facility: Option<String>,
    #[serde(default)]
    pub syslog_severity: Option<String>,
    #[serde(default, rename = "default")]
    pub is_default: Option<String>,
}

/// Body for creating a remote logging action.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CreateLoggingAction {
    pub name: String,
    pub target: String,
    pub remote: String,
    pub remote_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bsd_syslog: Option<String>,
}

/// Logging rule — `/system/logging`
///
/// Maps log topics to logging actions.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LoggingRule {
    #[serde(rename = ".id")]
    pub id: String,
    pub topics: String,
    pub action: String,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub disabled: Option<String>,
}

/// Body for creating a logging rule.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CreateLoggingRule {
    pub topics: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// Body for creating a firewall filter rule (used for adding log rules).
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CreateFilterRule {
    pub chain: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_interface_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_before: Option<String>,
}

/// Body for updating an existing filter rule (enable logging).
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct UpdateFilterRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_prefix: Option<String>,
}

// ── Client methods ─────────────────────────────────────────────

impl MikrotikClient {
    /// List all logging actions (memory, disk, echo, remote).
    pub async fn system_logging_actions(&self) -> Result<Vec<LoggingAction>, MikrotikError> {
        self.get("system/logging/action").await
    }

    /// Create a new logging action.
    pub async fn create_logging_action(
        &self,
        action: &CreateLoggingAction,
    ) -> Result<LoggingAction, MikrotikError> {
        self.put("system/logging/action", action).await
    }

    /// List all logging rules.
    pub async fn system_logging_rules(&self) -> Result<Vec<LoggingRule>, MikrotikError> {
        self.get("system/logging").await
    }

    /// Create a new logging rule.
    pub async fn create_logging_rule(
        &self,
        rule: &CreateLoggingRule,
    ) -> Result<LoggingRule, MikrotikError> {
        self.put("system/logging", rule).await
    }

    /// Create a new firewall filter rule.
    pub async fn create_filter_rule(
        &self,
        rule: &CreateFilterRule,
    ) -> Result<serde_json::Value, MikrotikError> {
        self.put("ip/firewall/filter", rule).await
    }

    /// Enable logging on an existing firewall filter rule.
    pub async fn update_filter_rule(
        &self,
        id: &str,
        update: &UpdateFilterRule,
    ) -> Result<(), MikrotikError> {
        self.patch("ip/firewall/filter", id, update).await
    }
}

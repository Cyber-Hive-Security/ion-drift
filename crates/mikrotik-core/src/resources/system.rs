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

/// RouterOS user — `/user`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouterUser {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    pub group: String,
    #[serde(default)]
    pub disabled: Option<String>,
}

/// RouterOS user group — `/user/group`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouterUserGroup {
    #[serde(rename = ".id")]
    pub id: String,
    pub name: String,
    pub policy: String,
}

/// Result of a provisioning permission check.
#[derive(Debug, Clone, Serialize)]
pub struct ProvisionPermissionCheck {
    /// Whether the API user has write permission.
    pub has_write: bool,
    /// The API username.
    pub username: String,
    /// The user's group name.
    pub group: String,
    /// The group's full policy string.
    pub policy: String,
    /// Which required policies are missing.
    pub missing_policies: Vec<String>,
    /// Terminal commands to create a provisioning-capable user.
    pub setup_commands: Option<String>,
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

    /// List all router users.
    pub async fn users(&self) -> Result<Vec<RouterUser>, MikrotikError> {
        self.get("user").await
    }

    /// List all user groups.
    pub async fn user_groups(&self) -> Result<Vec<RouterUserGroup>, MikrotikError> {
        self.get("user/group").await
    }

    /// Check if the authenticated API user has the permissions required
    /// for provisioning (write, policy, api, rest-api).
    ///
    /// Returns a detailed check result with setup instructions if permissions
    /// are insufficient.
    pub async fn check_provision_permission(&self) -> Result<ProvisionPermissionCheck, MikrotikError> {
        let users: Vec<RouterUser> = self.users().await?;
        let groups: Vec<RouterUserGroup> = self.user_groups().await?;

        // Find the authenticated user by matching against the configured username
        let username = self.username();
        let user = users.iter().find(|u| u.name == username);

        let (group_name, policy_str) = match user {
            Some(u) => {
                let group = groups.iter().find(|g| g.name == u.group);
                match group {
                    Some(g) => (g.name.clone(), g.policy.clone()),
                    None => (u.group.clone(), String::new()),
                }
            }
            None => {
                // Can't find ourselves — likely permission issue reading /user
                return Ok(ProvisionPermissionCheck {
                    has_write: false,
                    username: username.to_string(),
                    group: "unknown".to_string(),
                    policy: String::new(),
                    missing_policies: vec!["write".to_string()],
                    setup_commands: Some(setup_commands_text(username)),
                });
            }
        };

        // Parse policy string: "read,write,api,!ftp,!ssh" → check for required
        let policies: Vec<&str> = policy_str.split(',').collect();
        let required = ["write", "read", "api", "rest-api"];
        let mut missing = Vec::new();
        for req in &required {
            let has = policies.iter().any(|p| p.trim() == *req);
            let denied = policies.iter().any(|p| p.trim() == format!("!{req}"));
            if !has || denied {
                missing.push(req.to_string());
            }
        }

        let has_write = missing.is_empty();

        Ok(ProvisionPermissionCheck {
            has_write,
            username: username.to_string(),
            group: group_name,
            policy: policy_str,
            missing_policies: missing,
            setup_commands: if has_write {
                None
            } else {
                Some(setup_commands_text(username))
            },
        })
    }
}

/// Generate RouterOS terminal commands for creating a provisioning-capable user/group.
fn setup_commands_text(current_user: &str) -> String {
    format!(
        r#"Option 1: Add write permission to your existing user's group:
  /user/group/set [find name=<YOUR_GROUP>] policy=read,write,api,rest-api

Option 2: Create a dedicated provisioning group and reassign your user:
  /user/group/add name=ion-drift-rw policy=read,write,api,rest-api
  /user/set [find name={current_user}] group=ion-drift-rw

Option 3: Create a separate provisioning user (recommended):
  /user/group/add name=ion-drift-rw policy=read,write,api,rest-api
  /user/add name=ion-drift-provision group=ion-drift-rw password=<SECURE_PASSWORD>

After provisioning is complete, you can remove write permission:
  /user/group/set [find name=<YOUR_GROUP>] policy=read,api,rest-api

Note: Write permission is only needed during provisioning. Normal
monitoring requires only read,api,rest-api."#
    )
}


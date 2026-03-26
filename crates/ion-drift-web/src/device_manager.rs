use std::collections::HashMap;
use std::path::PathBuf;

use mikrotik_core::{MikrotikClient, MikrotikConfig, SecretString, SnmpClient, SwosClient};
use secrecy::ExposeSecret;
use tokio::time::Instant;

use crate::config::ServerConfig;
use crate::secrets::{DeviceRecord, SecretsManager};

/// Legacy hardcoded device ID from pre-v0.3.5. Used for migration detection.
pub const LEGACY_DEVICE_ID: &str = "rb4011";

/// Generate a device ID by slugifying the router identity string.
/// Lowercase, non-alphanumeric replaced with `-`, trimmed, truncated to 64 chars.
/// Falls back to `"router-1"` if the identity is empty.
pub fn slugify_device_id(identity: &str) -> String {
    let slug: String = identity
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>()
        .replace("--", "-");
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "router-1".to_string()
    } else if slug.len() > 64 {
        slug[..64].trim_end_matches('-').to_string()
    } else {
        slug
    }
}

/// Status of a managed device.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "status")]
pub enum DeviceStatus {
    Online { identity: String },
    Offline { error: String },
    Unknown,
}

/// Client variant for different device types.
#[derive(Clone)]
pub enum DeviceClient {
    /// RouterOS REST API client (routers + RouterOS switches).
    RouterOs(MikrotikClient),
    /// SwOS HTTP API client.
    SwOs(SwosClient),
    /// SNMP client for generic managed switches.
    Snmp(SnmpClient),
}

impl DeviceClient {
    /// Test connectivity and return the device identity string.
    pub async fn test_connection(&self) -> Result<String, mikrotik_core::MikrotikError> {
        match self {
            DeviceClient::RouterOs(c) => c.test_connection().await,
            DeviceClient::SwOs(c) => c.test_connection().await,
            DeviceClient::Snmp(c) => c.test_connection().await,
        }
    }

    /// Get the RouterOS client, if this is a RouterOS device.
    pub fn as_routeros(&self) -> Option<&MikrotikClient> {
        match self {
            DeviceClient::RouterOs(c) => Some(c),
            _ => None,
        }
    }

    /// Get the SwOS client, if this is a SwOS device.
    pub fn as_swos(&self) -> Option<&SwosClient> {
        match self {
            DeviceClient::SwOs(c) => Some(c),
            _ => None,
        }
    }

    /// Get the SNMP client, if this is an SNMP device.
    pub fn as_snmp(&self) -> Option<&SnmpClient> {
        match self {
            DeviceClient::Snmp(c) => Some(c),
            _ => None,
        }
    }
}

/// A device entry with its client, record, and runtime status.
pub struct DeviceEntry {
    pub client: DeviceClient,
    pub record: DeviceRecord,
    pub status: DeviceStatus,
    pub last_poll: Option<Instant>,
    /// Hardware or firmware limitations discovered during polling.
    pub limitations: Vec<String>,
}

/// Manages all registered Mikrotik devices (router + switches).
pub struct DeviceManager {
    devices: HashMap<String, DeviceEntry>,
    /// Disabled devices are tracked separately so they appear in the API but
    /// are not polled and have no runtime client.
    disabled_devices: HashMap<String, DeviceRecord>,
}

impl DeviceManager {
    /// Load all devices from the secrets database and build clients.
    pub async fn load(
        secrets: &SecretsManager,
        default_ca_cert: Option<&str>,
    ) -> anyhow::Result<Self> {
        let records = secrets.list_devices().await?;
        let mut devices = HashMap::new();
        let mut disabled_devices = HashMap::new();

        for record in records {
            if !record.enabled {
                tracing::info!(id = %record.id, name = %record.name, "device disabled, skipping client creation");
                disabled_devices.insert(record.id.clone(), record);
                continue;
            }

            let creds = secrets.get_device_credentials(&record.id).await?;
            let (username, password) = match creds {
                Some((u, p)) => (u, p.expose_secret().to_string()),
                None => {
                    tracing::warn!(
                        id = %record.id,
                        "no credentials found for device, skipping"
                    );
                    continue;
                }
            };

            let client = if record.device_type == "snmp_switch" {
                // Check for SNMPv3 params
                let (priv_pw, auth_proto, priv_proto) =
                    secrets.get_snmp_v3_params(&record.id).await?;
                let snmp = if priv_pw.is_some() || auth_proto.is_some() {
                    // SNMPv3 AuthPriv
                    SnmpClient::new_v3(
                        record.host.clone(),
                        record.port,
                        username,
                        password,
                        auth_proto.unwrap_or_else(|| "SHA".into()),
                        priv_pw.unwrap_or_default(),
                        priv_proto.unwrap_or_else(|| "AES128".into()),
                    )
                } else {
                    // SNMPv2c (backward compat)
                    SnmpClient::new_v2c(record.host.clone(), record.port, password)
                };
                tracing::info!(
                    id = %record.id,
                    name = %record.name,
                    host = %record.host,
                    device_type = %record.device_type,
                    v3 = snmp.is_v3(),
                    "SNMP client created"
                );
                DeviceClient::Snmp(snmp)
            } else if record.device_type == "swos_switch" {
                // SwOS devices use HTTP (no TLS)
                match SwosClient::new(record.host.clone(), record.port, username, password) {
                    Ok(swos) => {
                        tracing::info!(
                            id = %record.id,
                            name = %record.name,
                            host = %record.host,
                            device_type = %record.device_type,
                            "SwOS client created"
                        );
                        DeviceClient::SwOs(swos)
                    }
                    Err(e) => {
                        tracing::error!(
                            id = %record.id,
                            name = %record.name,
                            error = %e,
                            "failed to create SwOS client"
                        );
                        continue;
                    }
                }
            } else {
                // RouterOS devices (router, switch)
                let ca_cert_path = record
                    .ca_cert_path
                    .as_deref()
                    .or(default_ca_cert)
                    .map(PathBuf::from);

                let config = MikrotikConfig {
                    host: record.host.clone(),
                    port: record.port,
                    tls: record.tls,
                    ca_cert_path,
                    username,
                    password: SecretString::from(password),
                };

                match MikrotikClient::new(config) {
                    Ok(c) => {
                        tracing::info!(
                            id = %record.id,
                            name = %record.name,
                            host = %record.host,
                            device_type = %record.device_type,
                            "device client created"
                        );
                        DeviceClient::RouterOs(c)
                    }
                    Err(e) => {
                        tracing::error!(
                            id = %record.id,
                            error = %e,
                            "failed to create client for device"
                        );
                        continue;
                    }
                }
            };

            devices.insert(
                record.id.clone(),
                DeviceEntry {
                    client,
                    record,
                    status: DeviceStatus::Unknown,
                    last_poll: None,
                    limitations: Vec::new(),
                },
            );
        }

        Ok(Self { devices, disabled_devices })
    }

    /// Build from legacy config (single router, no device registry).
    /// `device_id` and `device_name` are auto-generated from router identity.
    pub fn from_config(config: &ServerConfig, device_id: &str, device_name: &str, model: Option<&str>) -> anyhow::Result<Self> {
        let mikrotik_config = config.mikrotik_config();
        let client = MikrotikClient::new(mikrotik_config)?;

        let record = DeviceRecord {
            id: device_id.to_string(),
            name: device_name.to_string(),
            host: config.router.host.clone(),
            port: config.router.port,
            tls: config.router.tls,
            ca_cert_path: config.router.ca_cert_path.clone(),
            device_type: "router".to_string(),
            model: model.map(|m| m.to_string()),
            is_primary: true,
            enabled: true,
            poll_interval_secs: 60,
            created_at: 0,
            updated_at: 0,
        };

        let mut devices = HashMap::new();
        devices.insert(
            device_id.to_string(),
            DeviceEntry {
                client: DeviceClient::RouterOs(client),
                record,
                status: DeviceStatus::Unknown,
                last_poll: None,
                limitations: Vec::new(),
            },
        );

        Ok(Self { devices, disabled_devices: HashMap::new() })
    }

    /// Get a device by ID.
    pub fn get_device(&self, id: &str) -> Option<&DeviceEntry> {
        self.devices.get(id)
    }

    /// Get the primary router entry.
    pub fn get_router(&self) -> Option<&DeviceEntry> {
        self.devices
            .values()
            .find(|d| d.record.is_primary && d.record.device_type == "router")
    }

    /// Get the primary router's RouterOS client directly (backward compat).
    pub fn get_router_client(&self) -> Option<MikrotikClient> {
        self.get_router()
            .and_then(|d| d.client.as_routeros())
            .cloned()
    }

    /// Get all RouterOS switch entries.
    pub fn get_switches(&self) -> Vec<&DeviceEntry> {
        self.devices
            .values()
            .filter(|d| d.record.device_type == "switch")
            .collect()
    }

    /// Get all SwOS switch entries.
    pub fn get_swos_switches(&self) -> Vec<&DeviceEntry> {
        self.devices
            .values()
            .filter(|d| d.record.device_type == "swos_switch")
            .collect()
    }

    /// Get all SNMP switch entries.
    pub fn get_snmp_switches(&self) -> Vec<&DeviceEntry> {
        self.devices
            .values()
            .filter(|d| d.record.device_type == "snmp_switch")
            .collect()
    }

    /// Get all device entries.
    pub fn all_devices(&self) -> Vec<&DeviceEntry> {
        self.devices.values().collect()
    }

    /// Get all device entries as a list of records with status.
    ///
    /// Includes both active and disabled devices. Disabled devices are
    /// reported with [`DeviceStatus::Offline`].
    pub fn device_list(&self) -> Vec<DeviceInfo> {
        let mut list: Vec<DeviceInfo> = self.devices
            .values()
            .map(|d| DeviceInfo {
                record: d.record.clone(),
                status: d.status.clone(),
                limitations: d.limitations.clone(),
            })
            .collect();
        for record in self.disabled_devices.values() {
            list.push(DeviceInfo {
                record: record.clone(),
                status: DeviceStatus::Offline {
                    error: "device disabled".into(),
                },
                limitations: Vec::new(),
            });
        }
        list
    }

    /// Get a disabled device record by ID.
    pub fn get_disabled_device(&self, id: &str) -> Option<&DeviceRecord> {
        self.disabled_devices.get(id)
    }

    /// Add a device at runtime.
    pub fn add_device(&mut self, record: DeviceRecord, client: DeviceClient) {
        self.devices.insert(
            record.id.clone(),
            DeviceEntry {
                client,
                record,
                status: DeviceStatus::Unknown,
                last_poll: None,
                limitations: Vec::new(),
            },
        );
    }

    /// Remove a device at runtime (from both active and disabled maps).
    pub fn remove_device(&mut self, id: &str) -> Option<DeviceEntry> {
        self.disabled_devices.remove(id);
        self.devices.remove(id)
    }

    /// Update device status after a poll or health check.
    pub fn set_status(&mut self, id: &str, status: DeviceStatus) {
        if let Some(entry) = self.devices.get_mut(id) {
            entry.status = status;
            entry.last_poll = Some(Instant::now());
        }
    }

    /// Record a hardware/firmware limitation discovered during polling.
    /// Deduplicates — the same limitation string won't be added twice.
    pub fn add_limitation(&mut self, id: &str, limitation: String) {
        if let Some(entry) = self.devices.get_mut(id) {
            if !entry.limitations.contains(&limitation) {
                entry.limitations.push(limitation);
            }
        }
    }

    /// Update the device record (after DB update).
    pub fn update_record(&mut self, id: &str, record: DeviceRecord) {
        if let Some(entry) = self.devices.get_mut(id) {
            entry.record = record;
        }
    }

    /// Replace the runtime client and record after a device update.
    ///
    /// Handles enabled/disabled transitions: if the device is now disabled it
    /// moves to the disabled map; if re-enabled it moves back to active.
    pub fn update_runtime_device(&mut self, id: &str, record: DeviceRecord, client: DeviceClient) {
        if !record.enabled {
            // Move to disabled map (remove from active if present)
            self.devices.remove(id);
            self.disabled_devices.insert(id.to_string(), record);
        } else {
            // Ensure it's not in the disabled map
            self.disabled_devices.remove(id);
            if let Some(entry) = self.devices.get_mut(id) {
                entry.record = record;
                entry.client = client;
            } else {
                // Was disabled, now re-enabled — insert fresh
                self.devices.insert(id.to_string(), DeviceEntry {
                    client,
                    record,
                    status: DeviceStatus::Unknown,
                    last_poll: None,
                    limitations: Vec::new(),
                });
            }
        }
    }

    /// Check if any devices are registered.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

/// Device info returned from the API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceInfo {
    #[serde(flatten)]
    pub record: DeviceRecord,
    #[serde(flatten)]
    pub status: DeviceStatus,
    /// Hardware or firmware limitations discovered during polling.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

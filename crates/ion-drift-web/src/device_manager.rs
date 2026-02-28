use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use mikrotik_core::{MikrotikClient, MikrotikConfig};
use secrecy::ExposeSecret;
use tokio::time::Instant;

use crate::config::ServerConfig;
use crate::secrets::{DeviceRecord, SecretsManager};

/// Status of a managed device.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "status")]
pub enum DeviceStatus {
    Online { identity: String },
    Offline { error: String },
    Unknown,
}

/// A device entry with its client, record, and runtime status.
pub struct DeviceEntry {
    pub client: MikrotikClient,
    pub record: DeviceRecord,
    pub status: DeviceStatus,
    pub last_poll: Option<Instant>,
}

/// Manages all registered Mikrotik devices (router + switches).
pub struct DeviceManager {
    devices: HashMap<String, DeviceEntry>,
}

impl DeviceManager {
    /// Load all devices from the secrets database and build clients.
    pub async fn load(
        secrets: &SecretsManager,
        default_ca_cert: Option<&str>,
    ) -> anyhow::Result<Self> {
        let records = secrets.list_devices().await?;
        let mut devices = HashMap::new();

        for record in records {
            if !record.enabled {
                tracing::info!(id = %record.id, name = %record.name, "device disabled, skipping");
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
                password,
            };

            match MikrotikClient::new(config) {
                Ok(client) => {
                    tracing::info!(
                        id = %record.id,
                        name = %record.name,
                        host = %record.host,
                        device_type = %record.device_type,
                        "device client created"
                    );
                    devices.insert(
                        record.id.clone(),
                        DeviceEntry {
                            client,
                            record,
                            status: DeviceStatus::Unknown,
                            last_poll: None,
                        },
                    );
                }
                Err(e) => {
                    tracing::error!(
                        id = %record.id,
                        error = %e,
                        "failed to create client for device"
                    );
                }
            }
        }

        Ok(Self { devices })
    }

    /// Build from legacy config (single router, no device registry).
    pub fn from_config(config: &ServerConfig) -> anyhow::Result<Self> {
        let mikrotik_config = config.mikrotik_config();
        let client = MikrotikClient::new(mikrotik_config)?;

        let record = DeviceRecord {
            id: "rb4011".to_string(),
            name: "RB4011".to_string(),
            host: config.router.host.clone(),
            port: config.router.port,
            tls: config.router.tls,
            ca_cert_path: config.router.ca_cert_path.clone(),
            device_type: "router".to_string(),
            model: Some("RB4011iGS+".to_string()),
            is_primary: true,
            enabled: true,
            poll_interval_secs: 60,
            created_at: 0,
            updated_at: 0,
        };

        let mut devices = HashMap::new();
        devices.insert(
            "rb4011".to_string(),
            DeviceEntry {
                client,
                record,
                status: DeviceStatus::Unknown,
                last_poll: None,
            },
        );

        Ok(Self { devices })
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

    /// Get all switch entries.
    pub fn get_switches(&self) -> Vec<&DeviceEntry> {
        self.devices
            .values()
            .filter(|d| d.record.device_type == "switch")
            .collect()
    }

    /// Get all device entries.
    pub fn all_devices(&self) -> Vec<&DeviceEntry> {
        self.devices.values().collect()
    }

    /// Get all device entries as a list of records with status.
    pub fn device_list(&self) -> Vec<DeviceInfo> {
        self.devices
            .values()
            .map(|d| DeviceInfo {
                record: d.record.clone(),
                status: d.status.clone(),
            })
            .collect()
    }

    /// Add a device at runtime.
    pub fn add_device(&mut self, record: DeviceRecord, client: MikrotikClient) {
        self.devices.insert(
            record.id.clone(),
            DeviceEntry {
                client,
                record,
                status: DeviceStatus::Unknown,
                last_poll: None,
            },
        );
    }

    /// Remove a device at runtime.
    pub fn remove_device(&mut self, id: &str) -> Option<DeviceEntry> {
        self.devices.remove(id)
    }

    /// Update device status after a poll or health check.
    pub fn set_status(&mut self, id: &str, status: DeviceStatus) {
        if let Some(entry) = self.devices.get_mut(id) {
            entry.status = status;
            entry.last_poll = Some(Instant::now());
        }
    }

    /// Update the device record (after DB update).
    pub fn update_record(&mut self, id: &str, record: DeviceRecord) {
        if let Some(entry) = self.devices.get_mut(id) {
            entry.record = record;
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
}

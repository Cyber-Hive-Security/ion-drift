use std::path::{Path, PathBuf};

use mikrotik_core::MikrotikConfig;
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct CliConfig {
    #[serde(default)]
    pub router: RouterConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct RouterConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tls: Option<bool>,
    pub ca_cert_path: Option<String>,
    pub username: Option<String>,
}

impl CliConfig {
    /// Load config from a TOML file. Returns default config if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;
        toml::from_str(&contents)
            .map_err(|e| format!("failed to parse config {}: {e}", path.display()))
    }

    /// Default config file path: ~/.config/ion-drift/cli.toml
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("ion-drift")
            .join("cli.toml")
    }
}

/// Build a MikrotikConfig by layering: config file → env vars → CLI flags.
pub fn build_mikrotik_config(
    file_cfg: &CliConfig,
    host: Option<&str>,
    user: Option<&str>,
    password: Option<&str>,
    ca_cert: Option<&str>,
    port: Option<u16>,
) -> Result<MikrotikConfig, String> {
    // Host: CLI flag > env > config file > default
    let host = host
        .map(String::from)
        .or_else(|| std::env::var("HIVE_ROUTER_HOST").ok())
        .or_else(|| file_cfg.router.host.clone())
        .unwrap_or_else(|| "192.168.88.1".into());

    // Port: CLI flag > config file > default
    let port = port
        .or(file_cfg.router.port)
        .unwrap_or(443);

    // TLS: config file > default (true)
    let tls = file_cfg.router.tls.unwrap_or(true);

    // CA cert: CLI flag > env > config file
    let ca_cert_path = ca_cert
        .map(String::from)
        .or_else(|| std::env::var("HIVE_ROUTER_CA_CERT").ok())
        .or_else(|| file_cfg.router.ca_cert_path.clone())
        .map(PathBuf::from);

    // Username: CLI flag > env > config file > default
    let username = user
        .map(String::from)
        .or_else(|| std::env::var("HIVE_ROUTER_USER").ok())
        .or_else(|| file_cfg.router.username.clone())
        .unwrap_or_else(|| "admin".into());

    // Password: CLI flag > env var (required)
    let password = password
        .map(String::from)
        .or_else(|| std::env::var("HIVE_ROUTER_PASSWORD").ok())
        .ok_or("password required: use --password or set HIVE_ROUTER_PASSWORD")?;

    Ok(MikrotikConfig {
        host,
        port,
        tls,
        ca_cert_path,
        username,
        password,
    })
}

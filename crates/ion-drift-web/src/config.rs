use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Top-level server configuration, loaded from TOML then overlaid with env vars.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub router: RouterSection,
    pub oidc: OidcSection,
    #[serde(default)]
    pub session: SessionSection,
    #[serde(default)]
    pub data: DataSection,
    #[serde(default)]
    pub bootstrap: BootstrapSection,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BootstrapSection {
    /// Path to PEM-encoded TLS certificate (for mTLS to Keycloak).
    pub cert_path: Option<String>,
    /// Path to PEM-encoded TLS private key (for mTLS to Keycloak).
    pub key_path: Option<String>,
    /// Keycloak realm URL (e.g., https://holonetid.kaziik.xyz:8443/realms/TheHolonet).
    pub keycloak_url: Option<String>,
    /// Keycloak base URL for Admin API (e.g., https://holonetid.kaziik.xyz:8443).
    pub keycloak_base_url: Option<String>,
    /// Keycloak realm name.
    pub realm: Option<String>,
    /// Bootstrap client ID (e.g., ion-drift-bootstrap).
    pub client_id: Option<String>,
}

/// Resolved bootstrap config (all fields validated as present).
pub struct ResolvedBootstrap {
    pub cert_path: String,
    pub key_path: String,
    pub keycloak_url: String,
    pub keycloak_base_url: String,
    pub realm: String,
    pub client_id: String,
}

impl BootstrapSection {
    /// Validate and resolve all required bootstrap fields.
    /// Returns None if bootstrap is not configured (no cert_path).
    pub fn resolve(&self) -> anyhow::Result<Option<ResolvedBootstrap>> {
        let cert_path = match &self.cert_path {
            Some(p) => p.clone(),
            None => return Ok(None),
        };
        let key_path = self.key_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("bootstrap.key_path required when cert_path is set"))?
            .clone();
        let keycloak_url = self.keycloak_url.as_ref()
            .ok_or_else(|| anyhow::anyhow!("bootstrap.keycloak_url required"))?
            .clone();
        let keycloak_base_url = self.keycloak_base_url.as_ref()
            .ok_or_else(|| anyhow::anyhow!("bootstrap.keycloak_base_url required"))?
            .clone();
        let realm = self.realm.as_ref()
            .ok_or_else(|| anyhow::anyhow!("bootstrap.realm required"))?
            .clone();
        let client_id = self.client_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("bootstrap.client_id required"))?
            .clone();

        Ok(Some(ResolvedBootstrap {
            cert_path,
            key_path,
            keycloak_url,
            keycloak_base_url,
            realm,
            client_id,
        }))
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DataSection {
    /// Path to GeoLite2-Country.mmdb (optional — geo features disabled if absent).
    pub geoip_db_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSection {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouterSection {
    #[serde(default = "default_router_host")]
    pub host: String,
    #[serde(default = "default_router_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls: bool,
    pub ca_cert_path: Option<String>,
    #[serde(default = "default_username")]
    pub username: String,
    /// Loaded from `HIVE_ROUTER_PASSWORD` env var at runtime.
    #[serde(skip)]
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcSection {
    pub issuer_url: String,
    pub client_id: String,
    /// Loaded from `HIVE_ROUTER_OIDC_SECRET` env var at runtime.
    #[serde(skip)]
    pub client_secret: String,
    pub redirect_uri: String,
    pub ca_cert_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionSection {
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_max_age")]
    pub max_age_seconds: u64,
    #[serde(default = "default_true")]
    pub secure: bool,
    #[serde(default = "default_same_site")]
    pub same_site: String,
    /// Loaded from `HIVE_ROUTER_SESSION_SECRET` env var at runtime.
    #[serde(skip)]
    pub session_secret: String,
}

impl Default for SessionSection {
    fn default() -> Self {
        Self {
            cookie_name: default_cookie_name(),
            max_age_seconds: default_max_age(),
            secure: true,
            same_site: default_same_site(),
            session_secret: String::new(),
        }
    }
}

// ── Default value helpers ─────────────────────────────────────────

fn default_listen_addr() -> String {
    "0.0.0.0".into()
}

fn default_listen_port() -> u16 {
    3000
}

fn default_router_host() -> String {
    "10.20.25.1".into()
}

fn default_router_port() -> u16 {
    443
}

fn default_true() -> bool {
    true
}

fn default_username() -> String {
    "admin".into()
}

fn default_cookie_name() -> String {
    "ion_drift_session".into()
}

fn default_max_age() -> u64 {
    86400
}

fn default_same_site() -> String {
    "lax".into()
}

// ── Loading ───────────────────────────────────────────────────────

impl ServerConfig {
    /// Load config from a TOML file, then overlay secrets from env vars.
    /// If `bootstrap.cert_path` is set, env var secrets are optional (managed via SecretsManager).
    /// If `bootstrap.cert_path` is not set, env var secrets are required (legacy mode).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {}: {e}", path.display()))?;

        let mut config: ServerConfig = toml::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;

        if config.bootstrap.cert_path.is_some() {
            // Secrets-at-rest mode: env vars are optional fallbacks
            config.router.password = std::env::var("HIVE_ROUTER_PASSWORD").unwrap_or_default();
            config.oidc.client_secret = std::env::var("HIVE_ROUTER_OIDC_SECRET").unwrap_or_default();
            config.session.session_secret = std::env::var("HIVE_ROUTER_SESSION_SECRET").unwrap_or_default();
        } else {
            // Legacy mode: env vars are required
            config.router.password = std::env::var("HIVE_ROUTER_PASSWORD")
                .map_err(|_| anyhow::anyhow!("HIVE_ROUTER_PASSWORD env var is required"))?;

            config.oidc.client_secret = std::env::var("HIVE_ROUTER_OIDC_SECRET")
                .map_err(|_| anyhow::anyhow!("HIVE_ROUTER_OIDC_SECRET env var is required"))?;

            config.session.session_secret = std::env::var("HIVE_ROUTER_SESSION_SECRET")
                .unwrap_or_else(|_| {
                    tracing::warn!("HIVE_ROUTER_SESSION_SECRET not set, generating random secret");
                    uuid::Uuid::new_v4().to_string()
                });
        }

        // Allow env overrides for non-secret router fields
        if let Ok(host) = std::env::var("HIVE_ROUTER_HOST") {
            config.router.host = host;
        }
        if let Ok(user) = std::env::var("HIVE_ROUTER_USER") {
            config.router.username = user;
        }
        if let Ok(ca) = std::env::var("HIVE_ROUTER_CA_CERT") {
            config.router.ca_cert_path = Some(ca);
        }

        Ok(config)
    }

    /// Resolve the config file path from: CLI arg → env var → default.
    pub fn resolve_path(cli_path: Option<&str>) -> PathBuf {
        if let Some(p) = cli_path {
            return PathBuf::from(p);
        }
        if let Ok(p) = std::env::var("ION_DRIFT_CONFIG") {
            return PathBuf::from(p);
        }
        PathBuf::from("./server.toml")
    }

    /// Build a `MikrotikConfig` from the loaded server config.
    pub fn mikrotik_config(&self) -> mikrotik_core::MikrotikConfig {
        mikrotik_core::MikrotikConfig {
            host: self.router.host.clone(),
            port: self.router.port,
            tls: self.router.tls,
            ca_cert_path: self.router.ca_cert_path.as_ref().map(PathBuf::from),
            username: self.router.username.clone(),
            password: self.router.password.clone(),
        }
    }
}

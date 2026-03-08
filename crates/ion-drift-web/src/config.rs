use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Top-level server configuration, loaded from TOML then overlaid with env vars.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub router: RouterSection,
    pub oidc: OidcSection,
    #[serde(default)]
    pub session: SessionSection,
    #[serde(default)]
    pub data: DataSection,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default)]
    pub certwarden: CertWardenSection,
    #[serde(default)]
    pub syslog: SyslogSection,
}

// ── OIDC Bootstrap (nested under [oidc.bootstrap]) ──────────────

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct OidcBootstrapSection {
    /// Bootstrap client ID (e.g., "ion-drift-bootstrap").
    pub client_id: Option<String>,
    /// Full Keycloak token endpoint URL.
    pub token_url: Option<String>,
    /// Full Keycloak Admin API URL (e.g., .../admin/realms/TheHolonet).
    pub admin_url: Option<String>,
    /// Keycloak user attribute name for storing the KEK.
    #[serde(default = "default_kek_attribute")]
    pub kek_attribute: String,
}

fn default_kek_attribute() -> String {
    "ion_drift_kek".into()
}

/// Resolved bootstrap config (all fields validated as present).
pub struct ResolvedBootstrap {
    pub cert_path: String,
    pub key_path: String,
    pub client_id: String,
    pub token_url: String,
    pub admin_url: String,
    pub kek_attribute: String,
}

// ── TLS Section ─────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsSection {
    /// Path to PEM-encoded mTLS client certificate.
    #[serde(default = "default_client_cert_path")]
    pub client_cert: String,
    /// Path to PEM-encoded mTLS client key.
    #[serde(default = "default_client_key_path")]
    pub client_key: String,
}

impl Default for TlsSection {
    fn default() -> Self {
        Self {
            client_cert: default_client_cert_path(),
            client_key: default_client_key_path(),
        }
    }
}

fn default_client_cert_path() -> String {
    "/app/data/certs/client.crt".into()
}

fn default_client_key_path() -> String {
    "/app/data/certs/client.key".into()
}

// ── CertWarden Section ──────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CertWardenSection {
    /// CertWarden API base URL (e.g., https://certwarden.example.com:4051).
    pub base_url: Option<String>,
    /// Certificate name in CertWarden.
    pub cert_name: Option<String>,
    /// Days before expiry to trigger renewal.
    #[serde(default = "default_30")]
    pub renewal_threshold_days: u32,
    /// Hours between cert expiry checks.
    #[serde(default = "default_1")]
    pub check_interval_hours: u32,
}

fn default_30() -> u32 {
    30
}

fn default_1() -> u32 {
    1
}

/// Resolved CertWarden config (base_url and cert_name present).
#[derive(Clone)]
pub struct ResolvedCertWarden {
    pub base_url: String,
    pub cert_name: String,
    pub renewal_threshold_days: u32,
    pub check_interval_hours: u32,
}

impl CertWardenSection {
    pub fn resolve(&self) -> Option<ResolvedCertWarden> {
        let base_url = self.base_url.as_ref()?;
        let cert_name = self.cert_name.as_ref()?;
        Some(ResolvedCertWarden {
            base_url: base_url.clone(),
            cert_name: cert_name.clone(),
            renewal_threshold_days: self.renewal_threshold_days,
            check_interval_hours: self.check_interval_hours,
        })
    }
}

// ── Syslog Section ─────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyslogSection {
    /// UDP port to listen on for syslog messages from the router.
    #[serde(default = "default_syslog_port")]
    pub port: u16,
    /// Bind address for the syslog listener.
    #[serde(default = "default_syslog_bind")]
    pub bind_address: String,
    /// IP address of this server as seen by the router (for configuring remote logging).
    /// If not set, router syslog forwarding setup is skipped.
    pub target_ip: Option<String>,
}

impl Default for SyslogSection {
    fn default() -> Self {
        Self {
            port: default_syslog_port(),
            bind_address: default_syslog_bind(),
            target_ip: None,
        }
    }
}

fn default_syslog_port() -> u16 {
    5514
}

fn default_syslog_bind() -> String {
    "0.0.0.0".into()
}

// ── Other sections (unchanged) ──────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DataSection {}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerSection {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Home location longitude for the world map (e.g. -111.97). Optional.
    pub home_lon: Option<f64>,
    /// Home location latitude for the world map (e.g. 41.22). Optional.
    pub home_lat: Option<f64>,
    /// Home country ISO 3166-1 alpha-2 code (e.g. "US"). Optional.
    pub home_country: Option<String>,
    /// Countries flagged for security monitoring (ISO 3166-1 alpha-2 codes).
    /// Connections to these countries will be marked as flagged.
    /// Default: ["RU", "CN", "IR", "KP", "VE", "BY", "SY", "CU"]
    #[serde(default = "default_warning_countries")]
    pub warning_countries: Vec<String>,
}

fn default_warning_countries() -> Vec<String> {
    vec![
        "RU".into(), "CN".into(), "IR".into(), "KP".into(),
        "VE".into(), "BY".into(), "SY".into(), "CU".into(),
    ]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// WAN interface name for traffic tracking (default: "1-WAN").
    #[serde(default = "default_wan_interface")]
    pub wan_interface: String,
    /// Internal DNS server IP for PTR lookups. If not set, PTR lookups are skipped.
    pub dns_server: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcSection {
    pub issuer_url: String,
    pub client_id: String,
    /// Loaded from `HIVE_ROUTER_OIDC_SECRET` env var at runtime.
    #[serde(skip)]
    pub client_secret: String,
    pub redirect_uri: String,
    pub ca_cert_path: Option<String>,
    /// Nested bootstrap config for mTLS KEK retrieval.
    #[serde(default)]
    pub bootstrap: Option<OidcBootstrapSection>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    "192.168.88.1".into()
}

fn default_router_port() -> u16 {
    mikrotik_core::DEFAULT_ROUTER_PORT
}

fn default_true() -> bool {
    true
}

fn default_username() -> String {
    mikrotik_core::DEFAULT_ROUTER_USERNAME.into()
}

fn default_wan_interface() -> String {
    "1-WAN".into()
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

// ── Resolve bootstrap ───────────────────────────────────────────

impl ServerConfig {
    /// Check if OIDC bootstrap (mTLS KEK) is configured.
    /// Returns a ResolvedBootstrap if oidc.bootstrap has a client_id and
    /// TLS cert/key paths are configured.
    pub fn resolve_bootstrap(&self) -> anyhow::Result<Option<ResolvedBootstrap>> {
        let bootstrap = match &self.oidc.bootstrap {
            Some(b) => b,
            None => return Ok(None),
        };
        let client_id = match &bootstrap.client_id {
            Some(id) => id.clone(),
            None => return Ok(None),
        };
        let token_url = bootstrap.token_url.as_ref()
            .ok_or_else(|| anyhow::anyhow!("oidc.bootstrap.token_url required when client_id is set"))?
            .clone();
        let admin_url = bootstrap.admin_url.as_ref()
            .ok_or_else(|| anyhow::anyhow!("oidc.bootstrap.admin_url required"))?
            .clone();

        Ok(Some(ResolvedBootstrap {
            cert_path: self.tls.client_cert.clone(),
            key_path: self.tls.client_key.clone(),
            client_id,
            token_url,
            admin_url,
            kek_attribute: bootstrap.kek_attribute.clone(),
        }))
    }
}

// ── Loading ───────────────────────────────────────────────────────

impl ServerConfig {
    /// Load config from a TOML file, then overlay secrets from env vars.
    /// If `oidc.bootstrap` is configured, env var secrets are optional (managed via SecretsManager).
    /// If not configured, env var secrets are required (legacy mode).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {}: {e}", path.display()))?;

        let mut config: ServerConfig = toml::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;

        let has_bootstrap = config.oidc.bootstrap.as_ref()
            .and_then(|b| b.client_id.as_ref())
            .is_some();

        if has_bootstrap {
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
        if let Ok(dns) = std::env::var("HIVE_ROUTER_DNS_SERVER") {
            config.router.dns_server = Some(dns);
        }

        // Validate router host configuration
        config.validate_router()?;

        Ok(config)
    }

    /// Validate router-related configuration, emitting warnings for defaults.
    fn validate_router(&self) -> anyhow::Result<()> {
        if self.router.host.is_empty() {
            anyhow::bail!("router.host cannot be empty; set it in config or HIVE_ROUTER_HOST env var");
        }

        if self.router.host.trim().contains(' ') {
            anyhow::bail!("router.host contains whitespace: {:?}", self.router.host);
        }

        if self.router.host == mikrotik_core::DEFAULT_ROUTER_HOST {
            tracing::warn!(
                "router.host is set to Mikrotik factory default ({}); \
                 set router.host in config or HIVE_ROUTER_HOST for production",
                mikrotik_core::DEFAULT_ROUTER_HOST
            );
        }

        if self.router.port == 0 {
            anyhow::bail!("router.port cannot be 0");
        }

        Ok(())
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

    /// Render resolved config as TOML with secrets explicitly redacted.
    pub fn masked_toml(&self) -> anyhow::Result<String> {
        let mut value = toml::Value::try_from(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize config: {e}"))?;

        let Some(root) = value.as_table_mut() else {
            anyhow::bail!("unexpected config structure");
        };

        if let Some(router) = root.get_mut("router").and_then(|v| v.as_table_mut()) {
            router.insert("password".to_string(), toml::Value::String("[REDACTED]".to_string()));
        }
        if let Some(oidc) = root.get_mut("oidc").and_then(|v| v.as_table_mut()) {
            oidc.insert(
                "client_secret".to_string(),
                toml::Value::String("[REDACTED]".to_string()),
            );
        }
        if let Some(session) = root.get_mut("session").and_then(|v| v.as_table_mut()) {
            session.insert(
                "session_secret".to_string(),
                toml::Value::String("[REDACTED]".to_string()),
            );
        }

        toml::to_string_pretty(&value)
            .map_err(|e| anyhow::anyhow!("failed to format masked config: {e}"))
    }
}

use std::path::PathBuf;

use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{debug, trace};

use crate::error::{MikrotikError, RouterOsErrorResponse};

/// Default RouterOS REST API port (HTTPS).
pub const DEFAULT_ROUTER_PORT: u16 = 443;

/// Default RouterOS admin username.
pub const DEFAULT_ROUTER_USERNAME: &str = "admin";

/// Mikrotik factory-default IP address.
///
/// Used as a fallback when no router host is explicitly configured.
/// Production deployments should always set the router host explicitly
/// via config file or environment variable.
pub const DEFAULT_ROUTER_HOST: &str = "192.168.88.1";

/// Configuration for connecting to a RouterOS device.
#[derive(Clone)]
pub struct MikrotikConfig {
    /// Router address (IP or hostname), e.g. "192.168.88.1"
    pub host: String,
    /// REST API port (default 443 for HTTPS)
    pub port: u16,
    /// Use HTTPS
    pub tls: bool,
    /// Path to custom CA certificate for TLS verification
    pub ca_cert_path: Option<PathBuf>,
    /// RouterOS username
    pub username: String,
    /// RouterOS password (wrapped in Secret to prevent accidental logging)
    pub password: SecretString,
}

impl Default for MikrotikConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_ROUTER_HOST.into(),
            port: DEFAULT_ROUTER_PORT,
            tls: true,
            ca_cert_path: None,
            username: DEFAULT_ROUTER_USERNAME.into(),
            password: SecretString::from(String::new()),
        }
    }
}

impl std::fmt::Debug for MikrotikConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MikrotikConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("tls", &self.tls)
            .field("ca_cert_path", &self.ca_cert_path)
            .finish()
    }
}

impl MikrotikConfig {
    /// Validate the configuration, returning a list of warnings.
    ///
    /// Returns `Err` for fatal misconfigurations (empty host, empty password).
    /// Returns `Ok(warnings)` where warnings is a Vec of non-fatal issues
    /// (e.g., using factory-default host).
    pub fn validate(&self) -> Result<Vec<String>, MikrotikError> {
        let mut warnings = Vec::new();

        if self.host.is_empty() {
            return Err(MikrotikError::Config("router host cannot be empty".into()));
        }

        if self.password.expose_secret().is_empty() {
            return Err(MikrotikError::Config("router password cannot be empty".into()));
        }

        if self.host == DEFAULT_ROUTER_HOST {
            warnings.push(format!(
                "using Mikrotik factory-default host ({DEFAULT_ROUTER_HOST}); \
                 set router.host in config or DRIFT_ROUTER_HOST env var for production"
            ));
        }

        if self.port == 0 {
            return Err(MikrotikError::Config("router port cannot be 0".into()));
        }

        // Validate host is a plausible IP or hostname (not just whitespace)
        let trimmed = self.host.trim();
        if trimmed.is_empty() || trimmed.contains(' ') {
            return Err(MikrotikError::Config(format!(
                "invalid router host: {:?}",
                self.host
            )));
        }

        Ok(warnings)
    }
}

/// Client for the RouterOS v7 REST API.
///
/// Construct with [`MikrotikClient::new`], then call resource methods
/// (e.g. `client.system_resources()`) to interact with the router.
#[derive(Clone)]
pub struct MikrotikClient {
    http: Client,
    base_url: String,
    username: String,
    password: SecretString,
}

impl MikrotikClient {
    /// Build a new client from the given config.
    ///
    /// This does **not** make any network requests. Call [`test_connection`](Self::test_connection)
    /// to verify connectivity.
    pub fn new(config: MikrotikConfig) -> Result<Self, MikrotikError> {
        let scheme = if config.tls { "https" } else { "http" };
        let base_url = format!("{scheme}://{}:{}/rest", config.host, config.port);

        let mut builder = Client::builder();

        if let Some(ca_path) = &config.ca_cert_path {
            let pem = std::fs::read(ca_path).map_err(|e| {
                MikrotikError::TlsConfig(format!(
                    "failed to read CA cert {}: {e}",
                    ca_path.display()
                ))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                MikrotikError::TlsConfig(format!("invalid CA certificate: {e}"))
            })?;
            builder = builder.add_root_certificate(cert);
        }

        let http = builder
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| MikrotikError::TlsConfig(format!("failed to build HTTP client: {e}")))?;

        debug!(base_url, "mikrotik client created");

        Ok(Self {
            http,
            base_url,
            username: config.username,
            password: config.password,
        })
    }

    /// Verify connectivity by fetching the system identity.
    pub async fn test_connection(&self) -> Result<String, MikrotikError> {
        #[derive(serde::Deserialize)]
        struct Identity {
            name: String,
        }
        let id: Identity = self.get("system/identity").await?;
        Ok(id.name)
    }

    // ── HTTP primitives ───────────────────────────────────────────

    /// `GET /rest/{path}` — fetch a resource (single object or array).
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, MikrotikError> {
        let url = format!("{}/{path}", self.base_url);
        trace!(url, "GET");

        let resp = self
            .http
            .get(&url)
            .basic_auth(&self.username, Some(self.password.expose_secret()))
            .send()
            .await?;

        self.handle_response(resp).await
    }

    /// `POST /rest/{path}` — execute a command or filtered print.
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, MikrotikError> {
        let url = format!("{}/{path}", self.base_url);
        trace!(url, "POST");

        let resp = self
            .http
            .post(&url)
            .basic_auth(&self.username, Some(self.password.expose_secret()))
            .json(body)
            .send()
            .await?;

        self.handle_response(resp).await
    }

    /// `PUT /rest/{path}` — create a new record.
    pub async fn put<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, MikrotikError> {
        let url = format!("{}/{path}", self.base_url);
        trace!(url, "PUT");

        let resp = self
            .http
            .put(&url)
            .basic_auth(&self.username, Some(self.password.expose_secret()))
            .json(body)
            .send()
            .await?;

        self.handle_response(resp).await
    }

    /// `PATCH /rest/{path}/{id}` — update an existing record.
    pub async fn patch<B: Serialize>(
        &self,
        path: &str,
        id: &str,
        body: &B,
    ) -> Result<(), MikrotikError> {
        let url = format!("{}/{path}/{id}", self.base_url);
        trace!(url, "PATCH");

        let resp = self
            .http
            .patch(&url)
            .basic_auth(&self.username, Some(self.password.expose_secret()))
            .json(body)
            .send()
            .await?;

        self.handle_empty_response(resp).await
    }

    /// `DELETE /rest/{path}/{id}` — remove a record.
    pub async fn delete(&self, path: &str, id: &str) -> Result<(), MikrotikError> {
        let url = format!("{}/{path}/{id}", self.base_url);
        trace!(url, "DELETE");

        let resp = self
            .http
            .delete(&url)
            .basic_auth(&self.username, Some(self.password.expose_secret()))
            .send()
            .await?;

        self.handle_empty_response(resp).await
    }

    // ── Response handling ─────────────────────────────────────────

    async fn handle_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, MikrotikError> {
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(MikrotikError::AuthFailed);
        }

        if !status.is_success() {
            return Err(self.parse_error(status.as_u16(), resp).await);
        }

        let body = resp.text().await?;
        trace!(body_len = body.len(), "response received");

        serde_json::from_str::<T>(&body).map_err(|e| {
            let preview = if body.len() > 200 {
                format!("{}...", &body[..200])
            } else {
                body
            };
            MikrotikError::Deserialize(format!("{e}: {preview}"))
        })
    }

    async fn handle_empty_response(&self, resp: reqwest::Response) -> Result<(), MikrotikError> {
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(MikrotikError::AuthFailed);
        }

        if !status.is_success() {
            return Err(self.parse_error(status.as_u16(), resp).await);
        }

        Ok(())
    }

    async fn parse_error(&self, status: u16, resp: reqwest::Response) -> MikrotikError {
        let body = resp.text().await.unwrap_or_default();

        if let Ok(ros_err) = serde_json::from_str::<RouterOsErrorResponse>(&body) {
            return MikrotikError::RouterOs {
                status,
                message: ros_err.message.unwrap_or_else(|| "unknown error".into()),
                detail: ros_err.detail,
            };
        }

        MikrotikError::RouterOs {
            status,
            message: body,
            detail: None,
        }
    }
}

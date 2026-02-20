use std::fmt;

#[derive(thiserror::Error, Debug)]
pub enum MikrotikError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("RouterOS error: {message} (status {status})")]
    RouterOs {
        status: u16,
        message: String,
        detail: Option<String>,
    },

    #[error("Authentication failed")]
    AuthFailed,

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("Deserialization error: {0}")]
    Deserialize(String),

    #[error("Database error: {0}")]
    Database(String),
}

/// Raw error response from RouterOS REST API.
#[derive(serde::Deserialize, Debug)]
pub(crate) struct RouterOsErrorResponse {
    #[allow(dead_code)]
    pub error: Option<u16>,
    pub message: Option<String>,
    pub detail: Option<String>,
}

impl fmt::Display for RouterOsErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(msg) = &self.message {
            write!(f, "{msg}")?;
        }
        if let Some(detail) = &self.detail {
            write!(f, " ({detail})")?;
        }
        Ok(())
    }
}

//! CertWarden API client for fetching and managing TLS certificates.
//!
//! Fetches certs/keys from CertWarden's download API, checks X.509 expiry
//! with `x509-parser`, and writes PEM files to disk.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::config::ResolvedCertWarden;

/// Status information about a certificate on disk.
#[derive(Debug, Clone, Serialize)]
pub struct CertStatus {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub not_before: i64,
    pub not_after: i64,
    pub seconds_until_expiry: i64,
    pub serial: String,
}

/// CertWarden API client.
pub struct CertWardenClient {
    client: reqwest::Client,
    base_url: String,
    cert_name: String,
}

impl CertWardenClient {
    /// Build a CertWarden API client with the given CA cert for TLS verification.
    pub fn new(config: &ResolvedCertWarden, ca_cert_path: &str) -> anyhow::Result<Self> {
        let ca_pem = std::fs::read(ca_cert_path)
            .map_err(|e| anyhow::anyhow!("failed to read CA cert {ca_cert_path}: {e}"))?;
        let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
            .map_err(|e| anyhow::anyhow!("invalid CA certificate: {e}"))?;

        let client = reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build CertWarden client: {e}"))?;

        Ok(Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            cert_name: config.cert_name.clone(),
        })
    }

    /// Fetch the certificate PEM from CertWarden.
    pub async fn fetch_cert(&self, api_key: &str) -> anyhow::Result<String> {
        let url = format!(
            "{}/api/v1/download/certificates/{}",
            self.base_url, self.cert_name
        );
        let resp = self.client
            .get(&url)
            .header("X-API-Key", api_key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("CertWarden cert fetch failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "CertWarden cert download failed ({}): {}",
                status, body
            ));
        }

        resp.text()
            .await
            .map_err(|e| anyhow::anyhow!("failed to read cert response: {e}"))
    }

    /// Fetch the private key PEM from CertWarden.
    pub async fn fetch_key(&self, api_key: &str) -> anyhow::Result<String> {
        let url = format!(
            "{}/api/v1/download/privatekeys/{}",
            self.base_url, self.cert_name
        );
        let resp = self.client
            .get(&url)
            .header("X-API-Key", api_key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("CertWarden key fetch failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "CertWarden key download failed ({}): {}",
                status, body
            ));
        }

        resp.text()
            .await
            .map_err(|e| anyhow::anyhow!("failed to read key response: {e}"))
    }

    /// Fetch both certificate and private key PEM from CertWarden.
    pub async fn fetch_cert_and_key(
        &self,
        cert_api_key: &str,
        key_api_key: &str,
    ) -> anyhow::Result<(String, String)> {
        let (cert, key) = tokio::try_join!(
            self.fetch_cert(cert_api_key),
            self.fetch_key(key_api_key),
        )?;
        Ok((cert, key))
    }
}

/// Parse a PEM certificate file on disk and return its status.
pub fn check_cert_status(cert_path: &str) -> anyhow::Result<CertStatus> {
    let pem_data = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("failed to read cert {cert_path}: {e}"))?;

    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_data)
        .map_err(|e| anyhow::anyhow!("failed to parse PEM: {e}"))?;

    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("failed to parse X.509 certificate: {e}"))?;

    let subject_cn = cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let issuer_cn = cert.issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let seconds_until_expiry = not_after - now;

    let serial = cert.serial.to_str_radix(16);

    Ok(CertStatus {
        subject_cn,
        issuer_cn,
        not_before,
        not_after,
        seconds_until_expiry,
        serial,
    })
}

/// Write certificate and key PEM files to disk, creating parent dirs as needed.
/// Sets key file permissions to 0600.
pub fn write_cert_and_key(
    cert_path: &str,
    key_path: &str,
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<()> {
    // Create parent directories
    if let Some(parent) = Path::new(cert_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("failed to create cert dir {}: {e}", parent.display()))?;
    }
    if let Some(parent) = Path::new(key_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("failed to create key dir {}: {e}", parent.display()))?;
    }

    // Write cert
    std::fs::write(cert_path, cert_pem)
        .map_err(|e| anyhow::anyhow!("failed to write cert to {cert_path}: {e}"))?;

    // Write key
    std::fs::write(key_path, key_pem)
        .map_err(|e| anyhow::anyhow!("failed to write key to {key_path}: {e}"))?;

    // Set key permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(key_path, perms)
            .map_err(|e| anyhow::anyhow!("failed to set key permissions: {e}"))?;
    }

    tracing::info!("wrote cert to {cert_path} and key to {key_path}");
    Ok(())
}

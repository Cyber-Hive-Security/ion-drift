//! Keycloak mTLS bootstrap: retrieve or generate the KEK (Key Encryption Key)
//! from a Keycloak service account attribute via mutual TLS authentication.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::Identity;
use sha2::Digest;
use std::path::Path;
use std::time::Duration;

use crate::config::ResolvedBootstrap;
use crate::secrets::compute_fingerprint;

/// Exponential backoff schedule for Keycloak connection retries.
const BACKOFF_DELAYS: &[u64] = &[5, 10, 30, 60, 120, 300];

/// Result of the KEK bootstrap process.
pub struct BootstrapResult {
    pub kek: Key<Aes256Gcm>,
    pub fingerprint: String,
    pub was_generated: bool,
}

/// Build an mTLS-capable reqwest client for Keycloak bootstrap.
///
/// Reads the cert+key, concatenates them for `Identity::from_pem()`,
/// and adds the Smallstep root CA for server verification.
pub fn build_mtls_client(config: &ResolvedBootstrap, ca_cert_path: &str) -> anyhow::Result<reqwest::Client> {
    let cert_pem = std::fs::read(&config.cert_path)
        .map_err(|e| anyhow::anyhow!("failed to read bootstrap cert {}: {e}", config.cert_path))?;
    let key_pem = std::fs::read(&config.key_path)
        .map_err(|e| anyhow::anyhow!("failed to read bootstrap key {}: {e}", config.key_path))?;

    // reqwest Identity::from_pem wants key + cert concatenated
    let mut identity_pem = key_pem;
    identity_pem.extend_from_slice(&cert_pem);
    let identity = Identity::from_pem(&identity_pem)
        .map_err(|e| anyhow::anyhow!("failed to build mTLS identity: {e}"))?;

    let ca_pem = std::fs::read(ca_cert_path)
        .map_err(|e| anyhow::anyhow!("failed to read CA cert {ca_cert_path}: {e}"))?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
        .map_err(|e| anyhow::anyhow!("invalid CA certificate: {e}"))?;

    reqwest::Client::builder()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build mTLS client: {e}"))
}

/// Main bootstrap function: retrieve or generate KEK from Keycloak.
///
/// Retries with exponential backoff [5s, 10s, 30s, 60s, 120s, 300s] if Keycloak is unreachable.
/// On success, caches the KEK locally (encrypted with a cert-derived key).
/// If all retries fail, attempts to load from the local cache before giving up.
pub async fn fetch_or_generate_kek(
    client: &reqwest::Client,
    config: &ResolvedBootstrap,
    data_dir: &Path,
    cert_path: &str,
) -> anyhow::Result<BootstrapResult> {
    tracing::info!("authenticating to Keycloak via mTLS for KEK bootstrap");

    let max_attempts = BACKOFF_DELAYS.len() + 1;
    let mut last_err = None;

    for attempt in 1..=max_attempts {
        match try_bootstrap(client, config).await {
            Ok(result) => {
                // Cache KEK locally for resilience against future Keycloak outages
                if let Err(e) = cache_kek(data_dir, cert_path, &result.kek) {
                    tracing::warn!("failed to cache KEK locally: {e}");
                } else {
                    tracing::debug!("KEK cached locally for offline resilience");
                }
                return Ok(result);
            }
            Err(e) => {
                let delay_idx = attempt.saturating_sub(1).min(BACKOFF_DELAYS.len() - 1);
                let delay = BACKOFF_DELAYS[delay_idx];
                tracing::warn!(
                    attempt,
                    max = max_attempts,
                    next_retry_secs = delay,
                    "KEK bootstrap attempt failed: {e}"
                );
                last_err = Some(e);
                if attempt < max_attempts {
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
            }
        }
    }

    // All Keycloak attempts failed — try local cache
    tracing::warn!("Keycloak unreachable after {max_attempts} attempts, trying local KEK cache");
    if let Some(result) = load_cached_kek(data_dir, cert_path) {
        tracing::warn!(
            fingerprint = %result.fingerprint,
            "using CACHED KEK — Keycloak is unreachable. KEK may be stale if rotated remotely."
        );
        return Ok(result);
    }

    Err(anyhow::anyhow!(
        "Keycloak unreachable after {max_attempts} attempts and no local KEK cache available. \
         Ion-drift is sealed. Last error: {}",
        last_err.unwrap()
    ))
}

/// Single attempt at the bootstrap process.
async fn try_bootstrap(
    client: &reqwest::Client,
    config: &ResolvedBootstrap,
) -> anyhow::Result<BootstrapResult> {
    let token = get_token(client, config).await?;
    let user_id = get_service_account_user_id(client, config, &token).await?;

    // Try to read existing KEK
    if let Some(kek_bytes) = read_kek_attribute(client, config, &token, &user_id).await? {
        if kek_bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "KEK attribute has wrong length ({} bytes, expected 32)",
                kek_bytes.len()
            ));
        }
        let kek = *Key::<Aes256Gcm>::from_slice(&kek_bytes);
        let fingerprint = compute_fingerprint(&kek);
        tracing::info!(fingerprint = %fingerprint, "KEK retrieved from Keycloak");
        return Ok(BootstrapResult {
            kek,
            fingerprint,
            was_generated: false,
        });
    }

    // No KEK found — generate and store
    tracing::info!("no KEK found in Keycloak, generating new one");
    let kek_bytes: [u8; 32] = rand::random();

    write_kek_attribute(client, config, &token, &user_id, &kek_bytes).await?;

    let kek = *Key::<Aes256Gcm>::from_slice(&kek_bytes);
    let fingerprint = compute_fingerprint(&kek);
    tracing::info!(fingerprint = %fingerprint, "new KEK generated and stored in Keycloak");

    Ok(BootstrapResult {
        kek,
        fingerprint,
        was_generated: true,
    })
}

/// Authenticate to Keycloak via mTLS client_credentials grant.
async fn get_token(client: &reqwest::Client, config: &ResolvedBootstrap) -> anyhow::Result<String> {
    let resp = client
        .post(&config.token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &config.client_id),
        ])
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("bootstrap token request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "bootstrap token request failed ({}): {}",
            status,
            body
        ));
    }

    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
    }

    let token: TokenResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse token response: {e}"))?;

    Ok(token.access_token)
}

/// Get the service account user ID for the bootstrap client.
async fn get_service_account_user_id(
    client: &reqwest::Client,
    config: &ResolvedBootstrap,
    token: &str,
) -> anyhow::Result<String> {
    // Find the client UUID
    let clients_url = format!(
        "{}/clients?clientId={}",
        config.admin_url, config.client_id
    );

    let resp = client
        .get(&clients_url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to query clients: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("failed to query clients ({}): {}", status, body));
    }

    #[derive(serde::Deserialize)]
    struct ClientRepr {
        id: String,
    }

    let clients: Vec<ClientRepr> = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse clients response: {e}"))?;

    let client_uuid = clients
        .first()
        .ok_or_else(|| anyhow::anyhow!("client {} not found", config.client_id))?
        .id
        .clone();

    // Get service account user for this client
    let sa_url = format!(
        "{}/clients/{}/service-account-user",
        config.admin_url, client_uuid
    );

    let resp = client
        .get(&sa_url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to get service account user: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "failed to get service account user ({}): {}",
            status,
            body
        ));
    }

    #[derive(serde::Deserialize)]
    struct UserRepr {
        id: String,
    }

    let user: UserRepr = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse service account user: {e}"))?;

    Ok(user.id)
}

/// Read the KEK attribute from the service account user.
async fn read_kek_attribute(
    client: &reqwest::Client,
    config: &ResolvedBootstrap,
    token: &str,
    user_id: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let user_url = format!(
        "{}/users/{}",
        config.admin_url, user_id
    );

    let resp = client
        .get(&user_url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to get user: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("failed to get user ({}): {}", status, body));
    }

    #[derive(serde::Deserialize)]
    struct UserRepr {
        attributes: Option<std::collections::HashMap<String, Vec<String>>>,
    }

    let user: UserRepr = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse user: {e}"))?;

    if let Some(attrs) = user.attributes {
        if let Some(values) = attrs.get(&config.kek_attribute) {
            if let Some(b64_value) = values.first() {
                if b64_value.is_empty() {
                    return Ok(None);
                }
                let kek_bytes = BASE64
                    .decode(b64_value)
                    .map_err(|e| anyhow::anyhow!("failed to decode KEK attribute: {e}"))?;
                return Ok(Some(kek_bytes));
            }
        }
    }

    Ok(None)
}

// ── Local KEK cache ─────────────────────────────────────────────

const KEK_CACHE_AAD: &[u8] = b"ion-drift-kek-cache";
const KEK_CACHE_FILE: &str = "kek.cache";

/// Derive an AES-256 key from the mTLS certificate PEM bytes.
fn derive_cache_key(cert_path: &str) -> anyhow::Result<Key<Aes256Gcm>> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("failed to read cert for cache key derivation: {e}"))?;
    let hash = sha2::Sha256::digest(&cert_pem);
    Ok(*Key::<Aes256Gcm>::from_slice(&hash))
}

/// Cache the KEK to a local file, encrypted with a cert-derived key.
/// Non-fatal: logs warnings on failure.
fn cache_kek(data_dir: &Path, cert_path: &str, kek: &Key<Aes256Gcm>) -> anyhow::Result<()> {
    let cache_key = derive_cache_key(cert_path)?;
    let cipher = Aes256Gcm::new(&cache_key);

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: kek.as_slice(), aad: KEK_CACHE_AAD })
        .map_err(|e| anyhow::anyhow!("failed to encrypt KEK for cache: {e}"))?;

    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    let cache_path = data_dir.join(KEK_CACHE_FILE);
    std::fs::write(&cache_path, &blob)
        .map_err(|e| anyhow::anyhow!("failed to write KEK cache to {}: {e}", cache_path.display()))?;

    Ok(())
}

/// Try to load the KEK from the local cache file.
/// Returns None if cache is missing, corrupt, or encrypted with a different key.
fn load_cached_kek(data_dir: &Path, cert_path: &str) -> Option<BootstrapResult> {
    let cache_path = data_dir.join(KEK_CACHE_FILE);
    let blob = std::fs::read(&cache_path).ok()?;

    if blob.len() < 13 {
        tracing::debug!("KEK cache file too small, ignoring");
        return None;
    }

    let cache_key = derive_cache_key(cert_path).ok()?;
    let cipher = Aes256Gcm::new(&cache_key);

    let nonce = Nonce::from_slice(&blob[..12]);
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: &blob[12..], aad: KEK_CACHE_AAD })
        .ok()?;

    if plaintext.len() != 32 {
        tracing::debug!("cached KEK has wrong length ({}), ignoring", plaintext.len());
        return None;
    }

    let kek = *Key::<Aes256Gcm>::from_slice(&plaintext);
    let fingerprint = compute_fingerprint(&kek);

    Some(BootstrapResult {
        kek,
        fingerprint,
        was_generated: false,
    })
}

/// Write the KEK attribute to the service account user.
async fn write_kek_attribute(
    client: &reqwest::Client,
    config: &ResolvedBootstrap,
    token: &str,
    user_id: &str,
    kek_bytes: &[u8],
) -> anyhow::Result<()> {
    let user_url = format!(
        "{}/users/{}",
        config.admin_url, user_id
    );

    let b64_value = BASE64.encode(kek_bytes);

    let body = serde_json::json!({
        "attributes": {
            &config.kek_attribute: [b64_value]
        }
    });

    let resp = client
        .put(&user_url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to write KEK attribute: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "failed to store KEK in Keycloak ({}): {}",
            status,
            body
        ));
    }

    Ok(())
}

//! Keycloak mTLS bootstrap: retrieve or generate the KEK (Key Encryption Key)
//! from a Keycloak service account attribute via mutual TLS authentication.

use aes_gcm::{Aes256Gcm, Key};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::Identity;
use std::time::Duration;

use crate::config::ResolvedBootstrap;
use crate::secrets::compute_fingerprint;

/// The Keycloak user attribute name where the KEK is stored.
const KEK_ATTRIBUTE: &str = "ion_drift_kek";

/// Maximum number of retries when Keycloak is unreachable.
const MAX_RETRIES: u32 = 3;

/// Delay between retries.
const RETRY_DELAY: Duration = Duration::from_secs(5);

/// Result of the KEK bootstrap process.
pub struct BootstrapResult {
    pub kek: Key<Aes256Gcm>,
    pub fingerprint: String,
    pub was_generated: bool,
}

/// Build an mTLS-capable reqwest client for Keycloak bootstrap.
///
/// Reads the CertWarden cert+key, concatenates them for `Identity::from_pem()`,
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
/// Retries up to 3 times with 5s delay if Keycloak is unreachable.
pub async fn fetch_or_generate_kek(
    client: &reqwest::Client,
    config: &ResolvedBootstrap,
) -> anyhow::Result<BootstrapResult> {
    tracing::info!("authenticating to Keycloak via mTLS for KEK bootstrap");

    let mut last_err = None;
    for attempt in 1..=MAX_RETRIES {
        match try_bootstrap(client, config).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                tracing::warn!(
                    attempt,
                    max = MAX_RETRIES,
                    "KEK bootstrap attempt failed: {e}"
                );
                last_err = Some(e);
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Keycloak unreachable after {MAX_RETRIES} attempts — cannot retrieve encryption key. \
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
    let token_url = format!("{}/protocol/openid-connect/token", config.keycloak_url);

    let resp = client
        .post(&token_url)
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
        "{}/admin/realms/{}/clients?clientId={}",
        config.keycloak_base_url, config.realm, config.client_id
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
        .ok_or_else(|| anyhow::anyhow!("client {} not found in realm {}", config.client_id, config.realm))?
        .id
        .clone();

    // Get service account user for this client
    let sa_url = format!(
        "{}/admin/realms/{}/clients/{}/service-account-user",
        config.keycloak_base_url, config.realm, client_uuid
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
        "{}/admin/realms/{}/users/{}",
        config.keycloak_base_url, config.realm, user_id
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
        if let Some(values) = attrs.get(KEK_ATTRIBUTE) {
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

/// Write the KEK attribute to the service account user.
async fn write_kek_attribute(
    client: &reqwest::Client,
    config: &ResolvedBootstrap,
    token: &str,
    user_id: &str,
    kek_bytes: &[u8],
) -> anyhow::Result<()> {
    let user_url = format!(
        "{}/admin/realms/{}/users/{}",
        config.keycloak_base_url, config.realm, user_id
    );

    let b64_value = BASE64.encode(kek_bytes);

    let body = serde_json::json!({
        "attributes": {
            KEK_ATTRIBUTE: [b64_value]
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

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use tokio::sync::RwLock;

use crate::certwarden;
use crate::config;
use crate::secrets::{self, SecretsManager};

/// Background task: check cert expiry and renew from CertWarden when within threshold.
pub fn spawn_cert_rotation(
    sm: Arc<RwLock<SecretsManager>>,
    cw_config: config::ResolvedCertWarden,
    tls_config: config::TlsSection,
    ca_cert_path: String,
) {
    let interval_hours = cw_config.check_interval_hours.max(1) as u64;
    let threshold_secs = (cw_config.renewal_threshold_days as i64) * 86400;

    tokio::spawn(async move {
        // 5-minute initial delay before first check
        tokio::time::sleep(Duration::from_secs(300)).await;
        tracing::info!(
            "cert rotation task started: checking every {}h, renewing within {}d of expiry",
            interval_hours,
            cw_config.renewal_threshold_days
        );

        loop {
            // Check cert expiry
            match certwarden::check_cert_status(&tls_config.client_cert) {
                Ok(status) => {
                    tracing::debug!(
                        cn = %status.subject_cn,
                        days_until_expiry = status.seconds_until_expiry / 86400,
                        "cert expiry check"
                    );

                    if status.seconds_until_expiry <= threshold_secs {
                        tracing::info!(
                            days_remaining = status.seconds_until_expiry / 86400,
                            "cert within renewal threshold, attempting renewal"
                        );

                        // Decrypt CertWarden API keys
                        let sm_read = sm.read().await;
                        let cert_key = sm_read.decrypt_secret(secrets::SECRET_CW_CERT_API_KEY).await;
                        let key_key = sm_read.decrypt_secret(secrets::SECRET_CW_KEY_API_KEY).await;
                        drop(sm_read);

                        match (cert_key, key_key) {
                            (Ok(Some(cert_api_key)), Ok(Some(key_api_key))) => {
                                match certwarden::CertWardenClient::new(&cw_config, &ca_cert_path) {
                                    Ok(cw_client) => {
                                        match cw_client.fetch_cert_and_key(
                                            cert_api_key.expose_secret(),
                                            key_api_key.expose_secret(),
                                        ).await {
                                            Ok((cert_pem, key_pem)) => {
                                                match certwarden::write_cert_and_key(
                                                    &tls_config.client_cert,
                                                    &tls_config.client_key,
                                                    &cert_pem,
                                                    &key_pem,
                                                ) {
                                                    Ok(()) => tracing::info!("cert renewed successfully"),
                                                    Err(e) => tracing::warn!("cert write failed: {e}"),
                                                }
                                            }
                                            Err(e) => tracing::warn!("cert fetch from CertWarden failed: {e}"),
                                        }
                                    }
                                    Err(e) => tracing::warn!("failed to create CertWarden client: {e}"),
                                }
                            }
                            _ => tracing::warn!("CertWarden API keys not found in secrets DB, skipping renewal"),
                        }
                    }
                }
                Err(e) => tracing::warn!("cert status check failed: {e}"),
            }

            tokio::time::sleep(Duration::from_secs(interval_hours * 3600)).await;
        }
    });
}

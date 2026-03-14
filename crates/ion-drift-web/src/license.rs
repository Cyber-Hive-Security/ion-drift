//! License validation and management for Ion Drift.
//!
//! Ion Drift uses a two-layer licensing model:
//! - PolyForm Shield 1.0.0 (anti-competition)
//! - Cyber Hive Security Use Agreement (free personal home use, commercial license required otherwise)

use chrono::NaiveDate;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// CHS Ed25519 public key for license verification (hex-encoded, compiled in).
const LICENSE_PUBLIC_KEY_HEX: &str = "71839e29676e0f2dcad394ac6ea61ac0b1c524e026106bafd4db48f1f238a52d";

/// Days after first run before the license reminder appears.
const EVALUATION_DAYS: u32 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LicenseTier {
    Business,
    Education,
    Nonprofit,
    Government,
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseTier::Business => write!(f, "Business"),
            LicenseTier::Education => write!(f, "Education"),
            LicenseTier::Nonprofit => write!(f, "Nonprofit"),
            LicenseTier::Government => write!(f, "Government"),
        }
    }
}

/// The payload embedded in a signed license key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub licensee: String,
    pub tier: LicenseTier,
    pub device_limit: u32,
    pub issued: NaiveDate,
    pub expires: NaiveDate,
}

/// Current license state of this Ion Drift installation.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum LicenseMode {
    Evaluation { days_remaining: u32 },
    Community { acknowledged: bool },
    Licensed {
        licensee: String,
        tier: LicenseTier,
        expires: NaiveDate,
        device_limit: u32,
    },
}

impl LicenseMode {
    /// Whether the license reminder banner should be shown.
    pub fn should_show_banner(&self) -> bool {
        matches!(self, LicenseMode::Community { acknowledged: false })
    }
}

/// Validate a license key string.
///
/// Key format: base64url(json_payload) + "." + base64url(ed25519_signature)
/// The signature is over the raw JSON payload bytes.
pub fn validate_license_key(key: &str) -> Result<LicensePayload, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let (payload_b64, sig_b64) = key
        .split_once('.')
        .ok_or("invalid key format: missing separator")?;

    let payload_bytes = engine
        .decode(payload_b64)
        .map_err(|e| format!("invalid key format: bad payload encoding: {e}"))?;

    let sig_bytes = engine
        .decode(sig_b64)
        .map_err(|e| format!("invalid key format: bad signature encoding: {e}"))?;

    // Verify signature
    let pub_key_bytes = hex::decode(LICENSE_PUBLIC_KEY_HEX)
        .map_err(|_| "internal error: invalid compiled public key")?;

    let verifying_key = VerifyingKey::from_bytes(
        pub_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "internal error: invalid public key length")?,
    )
    .map_err(|e| format!("internal error: invalid public key: {e}"))?;

    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid key: wrong signature length")?,
    );

    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| "invalid license key: signature verification failed")?;

    // Parse payload
    let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("invalid license key: bad payload: {e}"))?;

    // Check expiration
    let today = chrono::Utc::now().date_naive();
    if payload.expires < today {
        return Err(format!("license expired on {}", payload.expires));
    }

    Ok(payload)
}

/// Determine the current license mode from stored state.
///
/// Checks in order:
/// 1. Valid license key in secrets.db -> Licensed
/// 2. Acknowledgment stored -> Community { acknowledged: true }
/// 3. Install age < 30 days -> Evaluation
/// 4. Install age >= 30 days -> Community { acknowledged: false }
pub async fn determine_license_mode(
    secrets: Option<&tokio::sync::RwLock<crate::secrets::SecretsManager>>,
) -> LicenseMode {
    if let Some(sm_lock) = secrets {
        let sm = sm_lock.read().await;

        // Check for valid license key
        if let Ok(Some(key)) = sm.decrypt_secret("license_key").await {
            use secrecy::ExposeSecret;
            match validate_license_key(key.expose_secret()) {
                Ok(payload) => {
                    return LicenseMode::Licensed {
                        licensee: payload.licensee,
                        tier: payload.tier,
                        expires: payload.expires,
                        device_limit: payload.device_limit,
                    };
                }
                Err(e) => {
                    tracing::warn!("stored license key invalid: {e}");
                }
            }
        }

        // Check for acknowledgment
        if let Ok(Some(ack)) = sm.decrypt_secret("license_acknowledged").await {
            use secrecy::ExposeSecret;
            if ack.expose_secret() == "true" {
                return LicenseMode::Community { acknowledged: true };
            }
        }

        // Check install age from the first secret's timestamp
        if let Ok(Some(install_date)) = sm.decrypt_secret("install_date").await {
            use secrecy::ExposeSecret;
            if let Ok(date) = install_date.expose_secret().parse::<NaiveDate>() {
                let today = chrono::Utc::now().date_naive();
                let days = (today - date).num_days();
                if days < EVALUATION_DAYS as i64 {
                    return LicenseMode::Evaluation {
                        days_remaining: (EVALUATION_DAYS as i64 - days) as u32,
                    };
                } else {
                    return LicenseMode::Community { acknowledged: false };
                }
            }
        }
    }

    // No secrets manager or no install date — treat as fresh evaluation
    LicenseMode::Evaluation {
        days_remaining: EVALUATION_DAYS,
    }
}

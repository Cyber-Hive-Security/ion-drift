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

/// Days before license expiry to start showing a renewal warning.
const EXPIRY_WARNING_DAYS: i64 = 30;

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
        /// Days until expiry; None if > EXPIRY_WARNING_DAYS away.
        expiry_warning_days: Option<u32>,
    },
    Expired {
        licensee: String,
        tier: LicenseTier,
        expired_on: NaiveDate,
    },
}

impl LicenseMode {
    /// Whether a banner should be shown (community nag, expiry warning, or expired).
    pub fn should_show_banner(&self) -> bool {
        match self {
            LicenseMode::Community { acknowledged: false } => true,
            LicenseMode::Licensed { expiry_warning_days: Some(_), .. } => true,
            LicenseMode::Expired { .. } => true,
            _ => false,
        }
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

    Ok(payload)
}

/// Validate a key and check if it's expired. Returns the payload and whether it's expired.
pub fn validate_license_key_with_expiry(key: &str) -> Result<(LicensePayload, bool), String> {
    let payload = validate_license_key(key)?;
    let today = chrono::Utc::now().date_naive();
    let expired = payload.expires < today;
    Ok((payload, expired))
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
                    let today = chrono::Utc::now().date_naive();
                    if payload.expires < today {
                        // Key is valid but expired — honor system, no lockout
                        return LicenseMode::Expired {
                            licensee: payload.licensee,
                            tier: payload.tier,
                            expired_on: payload.expires,
                        };
                    }
                    let days_until = (payload.expires - today).num_days();
                    let expiry_warning_days = if days_until <= EXPIRY_WARNING_DAYS {
                        Some(days_until as u32)
                    } else {
                        None
                    };
                    return LicenseMode::Licensed {
                        licensee: payload.licensee,
                        tier: payload.tier,
                        expires: payload.expires,
                        device_limit: payload.device_limit,
                        expiry_warning_days,
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

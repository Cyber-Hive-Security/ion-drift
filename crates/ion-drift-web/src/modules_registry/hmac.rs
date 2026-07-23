//! Shared HMAC sign/verify for the module API wire envelope.
//!
//! Both directions use the same scheme:
//! - Sender computes `HMAC-SHA256(secret, "<timestamp>.<body>")` and sends
//!   it as `X-IonDrift-Signature: t=<timestamp>,v1=<hex>`.
//! - Receiver parses the header, rejects if the timestamp is outside its
//!   skew window, then re-derives and constant-time compares.
//!
//! This module is the single source of truth for the algorithm so the
//! outbound dispatcher (`dispatcher.rs`) and the inbound publish endpoint
//! (`inbound.rs`) cannot drift apart.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HTTP header name carrying the signature on every signed envelope POST,
/// in either direction.
pub const SIGNATURE_HEADER: &str = "X-IonDrift-Signature";

/// HTTP header name carrying the unix timestamp the signature was made at.
/// Sent alongside `SIGNATURE_HEADER` for inbound publishes (the outbound
/// path packs the timestamp into the signature header itself for legacy
/// reasons; both forms are accepted on the inbound side).
pub const TIMESTAMP_HEADER: &str = "X-IonDrift-Timestamp";

/// Default acceptable absolute clock skew between sender and receiver.
/// 300 seconds matches Stripe's webhook recommendation and is a sensible
/// floor against replay attacks.
pub const DEFAULT_TIMESTAMP_SKEW_SECS: i64 = 300;

/// Stripe-style HMAC-SHA256 over `<timestamp>.<body>`. Returns lowercase
/// hex.
pub fn sign_bytes(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("hmac can take any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Reasons a signature/envelope failed verification. The caller maps these
/// onto opaque HTTP error codes — never echo the variant back to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Hex-decoded signature has the wrong number of bytes.
    MalformedSignature,
    /// The signature did not match the recomputed value.
    SignatureMismatch,
    /// The provided timestamp is too far from `now`.
    TimestampOutOfWindow,
}

/// Verify a signature against `<timestamp>.<body>` in constant time, and
/// reject timestamps outside the configured skew window.
pub fn verify_signature(
    secret: &str,
    timestamp: i64,
    body: &[u8],
    now_unix: i64,
    signature_hex: &str,
    skew_secs: i64,
) -> Result<(), VerifyError> {
    if (now_unix - timestamp).abs() > skew_secs {
        return Err(VerifyError::TimestampOutOfWindow);
    }
    let provided =
        hex::decode(signature_hex).map_err(|_| VerifyError::MalformedSignature)?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("hmac can take any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    // `verify_slice` is constant-time and length-checks for us.
    mac.verify_slice(&provided)
        .map_err(|_| VerifyError::SignatureMismatch)
}

/// Parsed components of a `t=<ts>,v1=<hex>` style signature header.
pub struct ParsedSigHeader<'a> {
    pub timestamp: i64,
    pub signature_hex: &'a str,
}

/// Parse `X-IonDrift-Signature: t=<unix>,v1=<hex>`. Order-independent;
/// extra fields are ignored. Returns `None` on any malformedness so the
/// caller can collapse all variants into a single opaque 401.
pub fn parse_sig_header(header: &str) -> Option<ParsedSigHeader<'_>> {
    let mut timestamp: Option<i64> = None;
    let mut signature: Option<&str> = None;
    for part in header.split(',') {
        let (k, v) = part.split_once('=')?;
        match k.trim() {
            "t" => timestamp = v.trim().parse().ok(),
            "v1" => signature = Some(v.trim()),
            _ => {}
        }
    }
    Some(ParsedSigHeader {
        timestamp: timestamp?,
        signature_hex: signature?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "shared-secret-at-least-32-chars-long-!";

    #[test]
    fn sign_is_deterministic() {
        let a = sign_bytes(SECRET, 100, b"abc");
        let b = sign_bytes(SECRET, 100, b"abc");
        assert_eq!(a, b);
    }

    #[test]
    fn sign_is_sensitive_to_inputs() {
        let base = sign_bytes(SECRET, 100, b"abc");
        assert_ne!(base, sign_bytes(SECRET, 101, b"abc"));
        assert_ne!(base, sign_bytes(SECRET, 100, b"abd"));
        assert_ne!(base, sign_bytes("different-secret-at-least-32-chars-long", 100, b"abc"));
    }

    #[test]
    fn verify_round_trip_succeeds() {
        let body = br#"{"kind":"finding"}"#;
        let ts = 1_700_000_000;
        let sig = sign_bytes(SECRET, ts, body);
        verify_signature(SECRET, ts, body, ts, &sig, DEFAULT_TIMESTAMP_SKEW_SECS).unwrap();
    }

    #[test]
    fn verify_rejects_skew() {
        let body = b"x";
        let sig = sign_bytes(SECRET, 100, body);
        let now = 100 + DEFAULT_TIMESTAMP_SKEW_SECS + 1;
        assert_eq!(
            verify_signature(SECRET, 100, body, now, &sig, DEFAULT_TIMESTAMP_SKEW_SECS),
            Err(VerifyError::TimestampOutOfWindow)
        );
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let sig = sign_bytes(SECRET, 100, b"original");
        assert_eq!(
            verify_signature(SECRET, 100, b"tampered", 100, &sig, DEFAULT_TIMESTAMP_SKEW_SECS),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_rejects_malformed_hex() {
        assert_eq!(
            verify_signature(SECRET, 100, b"x", 100, "not-hex!!", DEFAULT_TIMESTAMP_SKEW_SECS),
            Err(VerifyError::MalformedSignature)
        );
    }

    #[test]
    fn parse_header_round_trip() {
        let h = "t=1700000000,v1=deadbeef";
        let p = parse_sig_header(h).unwrap();
        assert_eq!(p.timestamp, 1_700_000_000);
        assert_eq!(p.signature_hex, "deadbeef");
    }

    #[test]
    fn parse_header_order_independent() {
        let p = parse_sig_header("v1=abc,t=42").unwrap();
        assert_eq!(p.timestamp, 42);
        assert_eq!(p.signature_hex, "abc");
    }

    #[test]
    fn parse_header_rejects_missing_fields() {
        assert!(parse_sig_header("t=100").is_none());
        assert!(parse_sig_header("v1=abc").is_none());
        assert!(parse_sig_header("garbage").is_none());
    }
}

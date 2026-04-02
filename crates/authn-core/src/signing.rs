//! Ed25519 request signing and verification.
//!
//! Pure functions for constructing canonical payloads, signing them with
//! Ed25519, and verifying signatures. No I/O — key loading is the caller's
//! responsibility.

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use ed25519_dalek::Verifier as _;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// KeyId
// ---------------------------------------------------------------------------

/// Non-empty identifier for a signing key, used for key rotation.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Returns the key ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KeyId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::InvalidKeyId);
        }
        Ok(Self(value))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

/// Unix timestamp in milliseconds, used for replay detection.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Create a timestamp from the current system time.
    pub fn from_system_time(time: std::time::SystemTime) -> Self {
        let millis = time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self(millis)
    }

    /// Create a timestamp from raw milliseconds.
    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Returns the underlying millisecond value.
    pub fn as_millis(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// SigningKey
// ---------------------------------------------------------------------------

/// Thin wrapper around `ed25519_dalek::SigningKey`.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Parse a PKCS#8 PEM-encoded private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;
        let key = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| Error::InvalidSigningKey(e.to_string()))?;
        Ok(Self(key))
    }

    /// Create from raw 32-byte seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(bytes))
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.0.verifying_key())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// VerifyingKey
// ---------------------------------------------------------------------------

/// Thin wrapper around `ed25519_dalek::VerifyingKey`.
#[derive(Debug, Clone)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Parse a SPKI PEM-encoded public key.
    pub fn from_public_key_pem(pem: &str) -> Result<Self> {
        use ed25519_dalek::pkcs8::DecodePublicKey as _;
        let key = ed25519_dalek::VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| Error::InvalidVerifyingKey(e.to_string()))?;
        Ok(Self(key))
    }

    /// Create from raw 32-byte public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|e| Error::InvalidVerifyingKey(e.to_string()))?;
        Ok(Self(key))
    }
}

impl From<&SigningKey> for VerifyingKey {
    fn from(sk: &SigningKey) -> Self {
        Self(sk.0.verifying_key())
    }
}

// ---------------------------------------------------------------------------
// CanonicalPayload
// ---------------------------------------------------------------------------

/// Deterministic byte payload for signing.
///
/// Format (v1):
/// ```text
/// forgeguard-sig-v1\n
/// trace-id:{uuid}\n
/// timestamp:{unix_millis}\n
/// {header-name}:{value}\n   (sorted lexicographically by name)
/// ```
pub struct CanonicalPayload(Vec<u8>);

impl CanonicalPayload {
    /// Build from a trace ID, timestamp, and identity headers.
    ///
    /// Headers are sorted lexicographically by name for determinism,
    /// regardless of insertion order.
    pub fn new(trace_id: &str, timestamp: Timestamp, headers: &[(String, String)]) -> Self {
        let mut sorted: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        sorted.sort_by_key(|(k, _)| *k);

        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"forgeguard-sig-v1\n");
        buf.extend_from_slice(format!("trace-id:{trace_id}\n").as_bytes());
        buf.extend_from_slice(format!("timestamp:{}\n", timestamp.as_millis()).as_bytes());
        for (name, value) in &sorted {
            buf.extend_from_slice(format!("{name}:{value}\n").as_bytes());
        }

        Self(buf)
    }

    /// The raw canonical bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// SignedPayload
// ---------------------------------------------------------------------------

/// Product of [`sign`] — carries everything needed to inject signature headers.
pub struct SignedPayload {
    key_id: KeyId,
    signature: ed25519_dalek::Signature,
    timestamp: Timestamp,
    trace_id: String,
}

impl SignedPayload {
    /// `X-ForgeGuard-Signature` header value: `v1:{base64}`.
    pub fn signature_header_value(&self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(self.signature.to_bytes());
        format!("v1:{b64}")
    }

    /// `X-ForgeGuard-Timestamp` header value.
    pub fn timestamp_header_value(&self) -> String {
        self.timestamp.to_string()
    }

    /// `X-ForgeGuard-Key-Id` header value.
    pub fn key_id_header_value(&self) -> String {
        self.key_id.as_str().to_string()
    }

    /// `X-ForgeGuard-Trace-Id` header value.
    pub fn trace_id_header_value(&self) -> &str {
        &self.trace_id
    }

    /// The raw signature bytes (for verification in tests).
    pub fn signature(&self) -> &ed25519_dalek::Signature {
        &self.signature
    }
}

// ---------------------------------------------------------------------------
// sign / verify
// ---------------------------------------------------------------------------

/// Sign a canonical payload. Pure — no I/O, no time, no randomness.
pub fn sign(
    key: &SigningKey,
    key_id: &KeyId,
    payload: &CanonicalPayload,
    timestamp: Timestamp,
    trace_id: String,
) -> SignedPayload {
    let signature = key.0.sign(payload.as_bytes());
    SignedPayload {
        key_id: key_id.clone(),
        signature,
        timestamp,
        trace_id,
    }
}

/// Verify a signature against a canonical payload. Pure.
pub fn verify(
    key: &VerifyingKey,
    payload: &CanonicalPayload,
    signature: &ed25519_dalek::Signature,
) -> Result<()> {
    key.0
        .verify(payload.as_bytes(), signature)
        .map_err(|_| Error::SignatureInvalid)
}

// ---------------------------------------------------------------------------
// TimestampValidator
// ---------------------------------------------------------------------------

/// Checks that a request timestamp falls within an acceptable drift window.
pub struct TimestampValidator {
    max_drift: Duration,
}

impl TimestampValidator {
    /// Create with the given maximum allowed drift.
    pub fn new(max_drift: Duration) -> Self {
        Self { max_drift }
    }

    /// Check that `request_ts` is within `max_drift` of `now`. Pure.
    pub fn check(&self, request_ts: Timestamp, now: Timestamp) -> Result<()> {
        let drift_ms = self.max_drift.as_millis() as u64;
        let req = request_ts.as_millis();
        let current = now.as_millis();

        let diff = req.abs_diff(current);

        if diff > drift_ms {
            return Err(Error::TimestampDrift(diff));
        }
        Ok(())
    }
}

/// Parse a `v1:{base64}` signature header value back into an Ed25519 signature.
pub fn parse_signature_header(value: &str) -> Result<ed25519_dalek::Signature> {
    let b64 = value
        .strip_prefix("v1:")
        .ok_or_else(|| Error::InvalidCredential("signature header must start with 'v1:'".into()))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| Error::InvalidCredential(format!("invalid base64 in signature: {e}")))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| Error::InvalidCredential("signature must be 64 bytes".into()))?;
    Ok(ed25519_dalek::Signature::from_bytes(&arr))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = VerifyingKey::from(&sk);
        (sk, vk)
    }

    fn sample_headers() -> Vec<(String, String)> {
        vec![
            ("x-forgeguard-user-id".into(), "alice".into()),
            ("x-forgeguard-tenant-id".into(), "acme-corp".into()),
            ("x-forgeguard-auth-provider".into(), "jwt".into()),
        ]
    }

    #[test]
    fn key_id_rejects_empty() {
        assert!(KeyId::try_from(String::new()).is_err());
    }

    #[test]
    fn key_id_accepts_non_empty() {
        let id = KeyId::try_from("proxy-prod-01".to_string()).unwrap();
        assert_eq!(id.as_str(), "proxy-prod-01");
    }

    #[test]
    fn canonical_payload_determinism() {
        let ts = Timestamp::from_millis(1_700_000_000_000);
        let trace = "abc-123";

        let headers_a = vec![
            ("x-forgeguard-user-id".into(), "alice".into()),
            ("x-forgeguard-auth-provider".into(), "jwt".into()),
        ];
        let headers_b = vec![
            ("x-forgeguard-auth-provider".into(), "jwt".into()),
            ("x-forgeguard-user-id".into(), "alice".into()),
        ];

        let payload_a = CanonicalPayload::new(trace, ts, &headers_a);
        let payload_b = CanonicalPayload::new(trace, ts, &headers_b);

        assert_eq!(payload_a.as_bytes(), payload_b.as_bytes());
    }

    #[test]
    fn canonical_payload_format() {
        let ts = Timestamp::from_millis(1_700_000_000_000);
        let trace = "trace-xyz";
        let headers = vec![
            ("x-forgeguard-user-id".into(), "alice".into()),
            ("x-forgeguard-auth-provider".into(), "jwt".into()),
        ];

        let payload = CanonicalPayload::new(trace, ts, &headers);
        let text = std::str::from_utf8(payload.as_bytes()).unwrap();

        assert!(text.starts_with("forgeguard-sig-v1\n"));
        assert!(text.contains("trace-id:trace-xyz\n"));
        assert!(text.contains("timestamp:1700000000000\n"));
        // auth-provider sorts before user-id
        let auth_pos = text.find("x-forgeguard-auth-provider").unwrap();
        let user_pos = text.find("x-forgeguard-user-id").unwrap();
        assert!(auth_pos < user_pos);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, vk) = test_keypair();
        let key_id = KeyId::try_from("test-key".to_string()).unwrap();
        let ts = Timestamp::from_millis(1_700_000_000_000);
        let headers = sample_headers();
        let payload = CanonicalPayload::new("trace-1", ts, &headers);

        let signed = sign(&sk, &key_id, &payload, ts, "trace-1".into());

        assert!(verify(&vk, &payload, signed.signature()).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, vk) = test_keypair();
        let key_id = KeyId::try_from("test-key".to_string()).unwrap();
        let ts = Timestamp::from_millis(1_700_000_000_000);
        let headers = sample_headers();
        let payload = CanonicalPayload::new("trace-1", ts, &headers);

        let signed = sign(&sk, &key_id, &payload, ts, "trace-1".into());

        // Tamper: different headers
        let tampered_headers = vec![("x-forgeguard-user-id".into(), "eve".into())];
        let tampered = CanonicalPayload::new("trace-1", ts, &tampered_headers);

        assert!(verify(&vk, &tampered, signed.signature()).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (sk, _vk) = test_keypair();
        let wrong_vk = VerifyingKey::from(&SigningKey::from_bytes(&[99u8; 32]));
        let key_id = KeyId::try_from("test-key".to_string()).unwrap();
        let ts = Timestamp::from_millis(1_700_000_000_000);
        let headers = sample_headers();
        let payload = CanonicalPayload::new("trace-1", ts, &headers);

        let signed = sign(&sk, &key_id, &payload, ts, "trace-1".into());

        assert!(verify(&wrong_vk, &payload, signed.signature()).is_err());
    }

    #[test]
    fn signed_payload_header_values() {
        let (sk, _vk) = test_keypair();
        let key_id = KeyId::try_from("my-key".to_string()).unwrap();
        let ts = Timestamp::from_millis(1_700_000_000_000);
        let headers = sample_headers();
        let payload = CanonicalPayload::new("trace-abc", ts, &headers);

        let signed = sign(&sk, &key_id, &payload, ts, "trace-abc".into());

        assert!(signed.signature_header_value().starts_with("v1:"));
        assert_eq!(signed.timestamp_header_value(), "1700000000000");
        assert_eq!(signed.key_id_header_value(), "my-key");
        assert_eq!(signed.trace_id_header_value(), "trace-abc");
    }

    #[test]
    fn parse_signature_header_roundtrip() {
        let (sk, vk) = test_keypair();
        let key_id = KeyId::try_from("test-key".to_string()).unwrap();
        let ts = Timestamp::from_millis(1_700_000_000_000);
        let headers = sample_headers();
        let payload = CanonicalPayload::new("trace-1", ts, &headers);

        let signed = sign(&sk, &key_id, &payload, ts, "trace-1".into());
        let header_value = signed.signature_header_value();

        let parsed_sig = parse_signature_header(&header_value).unwrap();
        assert!(verify(&vk, &payload, &parsed_sig).is_ok());
    }

    #[test]
    fn timestamp_validator_accepts_within_window() {
        let validator = TimestampValidator::new(Duration::from_secs(30));
        let now = Timestamp::from_millis(1_700_000_000_000);
        let req = Timestamp::from_millis(1_700_000_000_000 - 15_000); // 15s ago

        assert!(validator.check(req, now).is_ok());
    }

    #[test]
    fn timestamp_validator_rejects_outside_window() {
        let validator = TimestampValidator::new(Duration::from_secs(30));
        let now = Timestamp::from_millis(1_700_000_000_000);
        let req = Timestamp::from_millis(1_700_000_000_000 - 60_000); // 60s ago

        assert!(validator.check(req, now).is_err());
    }

    #[test]
    fn timestamp_validator_rejects_future() {
        let validator = TimestampValidator::new(Duration::from_secs(30));
        let now = Timestamp::from_millis(1_700_000_000_000);
        let req = Timestamp::from_millis(1_700_000_000_000 + 60_000); // 60s in future

        assert!(validator.check(req, now).is_err());
    }

    #[test]
    fn verifying_key_from_signing_key() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = VerifyingKey::from(&sk);

        // Sign with sk, verify with vk — should succeed
        let key_id = KeyId::try_from("k".to_string()).unwrap();
        let ts = Timestamp::from_millis(1);
        let payload = CanonicalPayload::new("t", ts, &[]);
        let signed = sign(&sk, &key_id, &payload, ts, "t".into());
        assert!(verify(&vk, &payload, signed.signature()).is_ok());
    }
}

//! Ed25519 request signing — inlined from `forgeguard_authn_core::signing`.
//!
//! xtask inlines this narrow surface to avoid a workspace path dependency on
//! `forgeguard_authn_core`, which would re-trigger xtask rebuilds on every edit
//! to the authn crate. A drift-prevention integration test at
//! `xtask/tests/signing_compat.rs` (added in Task α.C) verifies this copy stays
//! byte-compatible with the upstream.
//!
//! # Format
//!
//! Canonical payload byte layout is defined by `.claude/context/request-signing.md`.

use std::fmt;

use thiserror::Error;

/// Errors from the inlined signing module.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("key id must be non-empty")]
    InvalidKeyId,
    #[error("invalid Ed25519 signing key: {0}")]
    InvalidSigningKey(String),
}

pub type Result<T> = std::result::Result<T, SigningError>;

// ---------------------------------------------------------------------------
// KeyId
// ---------------------------------------------------------------------------

/// Non-empty identifier for a signing key, used for key rotation.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KeyId {
    type Error = SigningError;

    fn try_from(value: String) -> Result<Self> {
        if value.is_empty() {
            return Err(SigningError::InvalidKeyId);
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

/// Unix timestamp in milliseconds.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn from_system_time(time: std::time::SystemTime) -> Self {
        let millis = time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self(millis)
    }

    #[cfg(test)]
    pub(crate) fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

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

/// Thin wrapper around `ed25519_dalek::SigningKey`. Pure construction only.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;
        let key = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| SigningError::InvalidSigningKey(e.to_string()))?;
        Ok(Self(key))
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(bytes))
    }

    #[cfg(test)]
    pub(crate) fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
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
// CanonicalPayload
// ---------------------------------------------------------------------------

/// Deterministic byte payload for signing. See `.claude/context/request-signing.md`.
pub struct CanonicalPayload(Vec<u8>);

impl CanonicalPayload {
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
    pub fn signature_header_value(&self) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(self.signature.to_bytes());
        format!("v1:{b64}")
    }

    pub fn timestamp_header_value(&self) -> String {
        self.timestamp.to_string()
    }

    pub fn key_id_header_value(&self) -> String {
        self.key_id.as_str().to_string()
    }

    pub fn trace_id_header_value(&self) -> &str {
        &self.trace_id
    }

    #[cfg(test)]
    pub(crate) fn signature(&self) -> &ed25519_dalek::Signature {
        &self.signature
    }
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

/// Sign a canonical payload. Pure — no I/O, no time, no randomness.
pub fn sign(
    key: &SigningKey,
    key_id: &KeyId,
    payload: &CanonicalPayload,
    timestamp: Timestamp,
    trace_id: String,
) -> SignedPayload {
    use ed25519_dalek::Signer as _;
    let signature = key.0.sign(payload.as_bytes());
    SignedPayload {
        key_id: key_id.clone(),
        signature,
        timestamp,
        trace_id,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod key_id_tests {
    use super::*;

    #[test]
    fn rejects_empty_string() {
        let err = KeyId::try_from(String::new()).unwrap_err();
        assert!(matches!(err, SigningError::InvalidKeyId));
    }

    #[test]
    fn accepts_non_empty_string() {
        let id = KeyId::try_from("key-001".to_string()).unwrap();
        assert_eq!(id.as_str(), "key-001");
    }

    #[test]
    fn display_matches_inner() {
        let id = KeyId::try_from("k".to_string()).unwrap();
        assert_eq!(format!("{id}"), "k");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod timestamp_tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn from_millis_round_trip() {
        let ts = Timestamp::from_millis(1_700_000_000_000);
        assert_eq!(ts.as_millis(), 1_700_000_000_000);
    }

    #[test]
    fn from_system_time_matches_millis() {
        let t = UNIX_EPOCH + Duration::from_millis(1_234_567_890);
        let ts = Timestamp::from_system_time(t);
        assert_eq!(ts.as_millis(), 1_234_567_890);
    }

    #[test]
    fn from_system_time_before_epoch_is_zero() {
        let t = UNIX_EPOCH - Duration::from_millis(50);
        let ts = Timestamp::from_system_time(t);
        assert_eq!(ts.as_millis(), 0);
    }

    #[test]
    fn display_is_decimal_millis() {
        assert_eq!(format!("{}", Timestamp::from_millis(42)), "42");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod signing_key_tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn from_bytes_accepts_32_byte_seed() {
        let _key = SigningKey::from_bytes(&TEST_SEED);
    }

    #[test]
    fn from_pkcs8_pem_rejects_garbage() {
        let err = SigningKey::from_pkcs8_pem("not a pem").unwrap_err();
        assert!(matches!(err, SigningError::InvalidSigningKey(_)));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod canonical_payload_tests {
    use super::*;

    #[test]
    fn layout_matches_spec() {
        let ts = Timestamp::from_millis(1_700_000_000_000);
        let headers = vec![("x-forgeguard-org-id".to_string(), "org-123".to_string())];
        let payload = CanonicalPayload::new("trace-abc", ts, &headers);
        let expected = concat!(
            "forgeguard-sig-v1\n",
            "trace-id:trace-abc\n",
            "timestamp:1700000000000\n",
            "x-forgeguard-org-id:org-123\n",
        );
        assert_eq!(payload.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn headers_sorted_lexicographically() {
        let ts = Timestamp::from_millis(0);
        let headers = vec![
            ("b-header".to_string(), "2".to_string()),
            ("a-header".to_string(), "1".to_string()),
        ];
        let payload = CanonicalPayload::new("t", ts, &headers);
        let body = std::str::from_utf8(payload.as_bytes()).unwrap();
        let a_pos = body.find("a-header").unwrap();
        let b_pos = body.find("b-header").unwrap();
        assert!(a_pos < b_pos, "headers must sort lexicographically");
    }

    #[test]
    fn empty_headers_produce_prefix_only() {
        let ts = Timestamp::from_millis(7);
        let payload = CanonicalPayload::new("x", ts, &[]);
        assert_eq!(
            payload.as_bytes(),
            b"forgeguard-sig-v1\ntrace-id:x\ntimestamp:7\n"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod sign_tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [7u8; 32];

    fn fixture() -> (SigningKey, KeyId, Timestamp, CanonicalPayload, String) {
        let key = SigningKey::from_bytes(&TEST_SEED);
        let key_id = KeyId::try_from("k-1".to_string()).unwrap();
        let ts = Timestamp::from_millis(1_700_000_000_000);
        let headers = vec![("x-forgeguard-org-id".to_string(), "o".to_string())];
        let payload = CanonicalPayload::new("t-1", ts, &headers);
        (key, key_id, ts, payload, "t-1".to_string())
    }

    #[test]
    fn sign_is_deterministic() {
        let (k, kid, ts, p, tid) = fixture();
        let a = sign(&k, &kid, &p, ts, tid.clone());

        let (k2, kid2, ts2, p2, tid2) = fixture();
        let b = sign(&k2, &kid2, &p2, ts2, tid2);

        assert_eq!(a.signature().to_bytes(), b.signature().to_bytes());
    }

    #[test]
    fn signature_header_value_has_v1_prefix_and_base64() {
        let (k, kid, ts, p, tid) = fixture();
        let signed = sign(&k, &kid, &p, ts, tid);
        let header = signed.signature_header_value();
        assert!(header.starts_with("v1:"), "got {header}");
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header.trim_start_matches("v1:"))
            .expect("base64");
        assert_eq!(decoded.len(), 64, "Ed25519 signatures are 64 bytes");
    }

    #[test]
    fn timestamp_and_key_id_headers_surface_inputs() {
        let (k, kid, ts, p, tid) = fixture();
        let signed = sign(&k, &kid, &p, ts, tid);
        assert_eq!(signed.timestamp_header_value(), "1700000000000");
        assert_eq!(signed.key_id_header_value(), "k-1");
        assert_eq!(signed.trace_id_header_value(), "t-1");
    }

    #[test]
    fn signature_verifies_with_ed25519_dalek_directly() {
        let (k, kid, ts, p, tid) = fixture();
        let signed = sign(&k, &kid, &p, ts, tid);
        use ed25519_dalek::Verifier as _;
        let vk = k.verifying_key();
        vk.verify(p.as_bytes(), signed.signature()).unwrap();
    }
}

//! Drift prevention: xtask-inlined signing must produce signatures that
//! `forgeguard_authn_core::signing::verify` accepts. When someone edits one
//! format without updating the other, this test fails.

use std::time::SystemTime;

use forgeguard_authn_core::signing as upstream;
use xtask::signing as inlined;

#[test]
fn inlined_signature_verifies_via_authn_core() {
    let seed = [7u8; 32];
    let inlined_key =
        inlined::SigningKey::from_pkcs8_pem(&ed25519_pem_from_seed(&seed)).expect("valid PEM");
    let inlined_key_id = inlined::KeyId::try_from("k-1".to_string()).expect("non-empty");
    let inlined_ts = inlined::Timestamp::from_system_time(SystemTime::UNIX_EPOCH);
    let inlined_headers = vec![("x-forgeguard-org-id".to_string(), "o".to_string())];
    let inlined_payload = inlined::CanonicalPayload::new("t-1", inlined_ts, &inlined_headers);
    let inlined_signed = inlined::sign(
        &inlined_key,
        &inlined_key_id,
        &inlined_payload,
        inlined_ts,
        "t-1".to_string(),
    );

    // Parse signature bytes from the header value — round-tripping through the
    // public API rather than reaching into internals.
    let header = inlined_signed.signature_header_value();
    let b64 = header.strip_prefix("v1:").expect("v1: prefix");
    use base64::Engine as _;
    let sig_bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("base64")
        .try_into()
        .expect("64 bytes");
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    // Reconstruct the payload via upstream so verify can consume it.
    let upstream_ts = upstream::Timestamp::from_millis(inlined_ts.as_millis());
    let upstream_payload = upstream::CanonicalPayload::new("t-1", upstream_ts, &inlined_headers);

    let upstream_signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let upstream_verifying_key =
        upstream::VerifyingKey::from_bytes(&upstream_signing_key.verifying_key().to_bytes())
            .expect("verifying key");

    upstream::verify(&upstream_verifying_key, &upstream_payload, &signature)
        .expect("xtask-inlined signature must verify with upstream — drift detected");
}

/// Helper: encode a 32-byte Ed25519 seed as a PKCS#8 PEM private key, so the
/// test can exercise `SigningKey::from_pkcs8_pem` directly. This avoids
/// reaching into a `#[cfg(test)]` constructor that is not exposed by the lib.
fn ed25519_pem_from_seed(seed: &[u8; 32]) -> String {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    sk.to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("to_pkcs8_pem")
        .to_string()
}

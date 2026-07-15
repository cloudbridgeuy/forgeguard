//! Pure verification of served event envelopes against published public keys
//! (V4 / D8). No I/O — the shell (`verify_events.rs`) fetches JSON over HTTP
//! and hands parsed values in.

use std::collections::HashMap;
use std::fmt;

use base64::Engine as _;
use forgeguard_authn_core::signing::{verify_bytes, VerifyingKey};
use forgeguard_authz_core::{canonical_envelope_bytes, EventEnvelope};

/// Per-envelope verification verdict.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VerifyResult {
    /// Signature verifies against the published key.
    Ok,
    /// The envelope's `key_id` has no published public key.
    UnknownKey,
    /// The stored signature is not valid base64 / not 64 bytes.
    BadSignatureEncoding(String),
    /// The signature does not verify over the recomputed canonical bytes.
    Invalid,
}

impl VerifyResult {
    /// Whether the envelope verified successfully.
    pub(crate) fn is_ok(&self) -> bool {
        matches!(self, VerifyResult::Ok)
    }
}

impl fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyResult::Ok => write!(f, "OK"),
            VerifyResult::UnknownKey => write!(f, "FAIL (no published key)"),
            VerifyResult::BadSignatureEncoding(e) => write!(f, "FAIL (bad signature: {e})"),
            VerifyResult::Invalid => write!(f, "FAIL (signature invalid)"),
        }
    }
}

/// One envelope's outcome, carrying enough to print a per-event line.
pub(crate) struct Outcome {
    pub(crate) seq: u64,
    pub(crate) kind: String,
    pub(crate) key_id: String,
    pub(crate) result: VerifyResult,
}

/// Verify every envelope: recompute `forgeguard-event-v1` canonical bytes and
/// check the Ed25519 signature against the key published for its `key_id`.
pub(crate) fn verify_envelopes(
    org_id: &str,
    envelopes: &[EventEnvelope],
    keys: &HashMap<String, VerifyingKey>,
) -> Vec<Outcome> {
    envelopes
        .iter()
        .map(|envelope| {
            let seq = envelope.seq().value();
            let kind = envelope.kind().as_str().to_string();
            let key_id = envelope.key_id().to_string();
            let result = verify_one(org_id, envelope, keys);
            Outcome {
                seq,
                kind,
                key_id,
                result,
            }
        })
        .collect()
}

fn verify_one(
    org_id: &str,
    envelope: &EventEnvelope,
    keys: &HashMap<String, VerifyingKey>,
) -> VerifyResult {
    let Some(key) = keys.get(envelope.key_id()) else {
        return VerifyResult::UnknownKey;
    };
    let decoded = match base64::engine::general_purpose::STANDARD.decode(envelope.signature()) {
        Ok(bytes) => bytes,
        Err(e) => return VerifyResult::BadSignatureEncoding(e.to_string()),
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = decoded.try_into() else {
        return VerifyResult::BadSignatureEncoding("signature must be 64 bytes".into());
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let bytes = canonical_envelope_bytes(envelope, org_id);
    match verify_bytes(key, &bytes, &signature) {
        Ok(()) => VerifyResult::Ok,
        Err(_) => VerifyResult::Invalid,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use forgeguard_authn_core::signing::{sign_bytes, SigningKey};
    use forgeguard_authz_core::{
        canonical_event_bytes, Actor, EventDraft, EventDraftParams, EventId, EventKind, Revision,
    };

    fn signed_envelope(org_id: &str, sk: &SigningKey, key_id: &str) -> EventEnvelope {
        let draft = EventDraft::new(EventDraftParams {
            event_id: EventId::try_new("01J000000000000000000000".to_string()).unwrap(),
            seq: Revision::new(1),
            kind: EventKind::PrincipalUpserted,
            occurred_at: "2026-07-15T00:00:00Z".to_string(),
            actor: Actor::System,
            payload: serde_json::json!({"role": "admin"}),
        });
        let bytes = canonical_event_bytes(&draft, org_id);
        let sig = sign_bytes(sk, &bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        EventEnvelope::from_signed(draft, key_id.to_string(), sig_b64)
    }

    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = VerifyingKey::from(&sk);
        (sk, vk)
    }

    #[test]
    fn valid_envelope_is_ok() {
        let (sk, vk) = keypair();
        let envelope = signed_envelope("org-a", &sk, "key-1");
        let keys = HashMap::from([("key-1".to_string(), vk)]);

        let outcomes = verify_envelopes("org-a", &[envelope], &keys);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].result, VerifyResult::Ok);
        assert_eq!(outcomes[0].seq, 1);
    }

    #[test]
    fn wrong_org_id_is_invalid() {
        let (sk, vk) = keypair();
        let envelope = signed_envelope("org-a", &sk, "key-1");
        let keys = HashMap::from([("key-1".to_string(), vk)]);

        let outcomes = verify_envelopes("org-evil", &[envelope], &keys);
        assert_eq!(outcomes[0].result, VerifyResult::Invalid);
    }

    #[test]
    fn missing_key_is_unknown_key() {
        let (sk, _vk) = keypair();
        let envelope = signed_envelope("org-a", &sk, "key-1");

        let outcomes = verify_envelopes("org-a", &[envelope], &HashMap::new());
        assert_eq!(outcomes[0].result, VerifyResult::UnknownKey);
    }

    #[test]
    fn wrong_key_is_invalid() {
        let (sk, _) = keypair();
        let other_vk = VerifyingKey::from(&SigningKey::from_bytes(&[9u8; 32]));
        let envelope = signed_envelope("org-a", &sk, "key-1");
        let keys = HashMap::from([("key-1".to_string(), other_vk)]);

        let outcomes = verify_envelopes("org-a", &[envelope], &keys);
        assert_eq!(outcomes[0].result, VerifyResult::Invalid);
    }

    #[test]
    fn garbage_signature_is_bad_encoding() {
        let (sk, vk) = keypair();
        let good = signed_envelope("org-a", &sk, "key-1");
        // Rebuild with a garbage signature via JSON surgery (fields are private).
        let mut json = serde_json::to_value(&good).unwrap();
        json["signature"] = serde_json::json!("not-base64!!!");
        let bad: EventEnvelope = serde_json::from_value(json).unwrap();
        let keys = HashMap::from([("key-1".to_string(), vk)]);

        let outcomes = verify_envelopes("org-a", &[bad], &keys);
        assert!(matches!(
            outcomes[0].result,
            VerifyResult::BadSignatureEncoding(_)
        ));
    }

    #[test]
    fn is_ok_matches_only_the_ok_variant() {
        assert!(VerifyResult::Ok.is_ok());
        assert!(!VerifyResult::UnknownKey.is_ok());
        assert!(!VerifyResult::BadSignatureEncoding("x".to_string()).is_ok());
        assert!(!VerifyResult::Invalid.is_ok());
    }

    #[test]
    fn display_renders_expected_verdict_strings() {
        assert_eq!(VerifyResult::Ok.to_string(), "OK");
        assert_eq!(
            VerifyResult::UnknownKey.to_string(),
            "FAIL (no published key)"
        );
        assert_eq!(
            VerifyResult::BadSignatureEncoding("bad length".to_string()).to_string(),
            "FAIL (bad signature: bad length)"
        );
        assert_eq!(
            VerifyResult::Invalid.to_string(),
            "FAIL (signature invalid)"
        );
    }
}

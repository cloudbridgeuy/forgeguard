//! Canonical byte encoding of an [`EventDraft`], used as the signing input
//! (D8). Deterministic: the payload is hashed as the exact bytes the shell
//! will persist (`serde_json::to_vec`) — consumers hash stored bytes, never
//! re-serialize.

use sha2::{Digest, Sha256};

use crate::event::envelope::{EventDraft, EventEnvelope};

/// The envelope fields that enter the canonical byte encoding, borrowed from
/// either an unsigned [`EventDraft`] (signing side) or a stored
/// [`EventEnvelope`] (verification side).
struct CanonicalFields<'a> {
    seq: u64,
    event_id: &'a str,
    kind: &'a str,
    occurred_at: &'a str,
    narrowing: bool,
    schema_version: u32,
    payload: &'a serde_json::Value,
}

fn canonical_bytes(fields: &CanonicalFields<'_>, org_id: &str) -> Vec<u8> {
    // Unwrap: serializing a `serde_json::Value` never fails.
    let payload_bytes = serde_json::to_vec(fields.payload).unwrap_or_default();
    let payload_sha256 = hex::encode(Sha256::digest(&payload_bytes));

    format!(
        "forgeguard-event-v1\n\
         org:{org_id}\n\
         seq:{seq}\n\
         event_id:{event_id}\n\
         kind:{kind}\n\
         occurred_at:{occurred_at}\n\
         narrowing:{narrowing}\n\
         schema_version:{schema_version}\n\
         payload_sha256:{payload_sha256}\n",
        seq = fields.seq,
        event_id = fields.event_id,
        kind = fields.kind,
        occurred_at = fields.occurred_at,
        narrowing = fields.narrowing,
        schema_version = fields.schema_version,
    )
    .into_bytes()
}

/// Build the canonical byte representation of `draft` for organization
/// `org_id`, ready to be passed to a signing function.
pub fn canonical_event_bytes(draft: &EventDraft, org_id: &str) -> Vec<u8> {
    canonical_bytes(
        &CanonicalFields {
            seq: draft.seq().value(),
            event_id: draft.event_id().as_str(),
            kind: draft.kind().as_str(),
            occurred_at: draft.occurred_at(),
            narrowing: draft.narrowing(),
            schema_version: draft.schema_version(),
            payload: draft.payload(),
        },
        org_id,
    )
}

/// Reconstruct the canonical bytes of a stored [`EventEnvelope`] for external
/// verification (D8): consumers recompute these bytes from the served
/// envelope and check its Ed25519 signature against the org's published
/// public key.
pub fn canonical_envelope_bytes(envelope: &EventEnvelope, org_id: &str) -> Vec<u8> {
    canonical_bytes(
        &CanonicalFields {
            seq: envelope.seq().value(),
            event_id: envelope.event_id().as_str(),
            kind: envelope.kind().as_str(),
            occurred_at: envelope.occurred_at(),
            narrowing: envelope.narrowing(),
            schema_version: envelope.schema_version(),
            payload: envelope.payload(),
        },
        org_id,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::event::envelope::{Actor, EventDraftParams, EventId};
    use crate::event::kind::EventKind;
    use crate::store::Revision;
    use forgeguard_core::{Fgrn, NativeId, Segment};

    fn draft(payload: serde_json::Value) -> EventDraft {
        EventDraft::new(EventDraftParams {
            event_id: EventId::try_new("01J000000000000000000000".to_string()).unwrap(),
            seq: Revision::new(1),
            kind: EventKind::PrincipalUpserted,
            occurred_at: "2026-07-14T00:00:00Z".to_string(),
            actor: Actor::Principal(Fgrn::principal(
                &Segment::try_new("acme").unwrap(),
                &NativeId::try_new("usr_1").unwrap(),
            )),
            payload,
        })
    }

    #[test]
    fn matches_golden_string() {
        let d = draft(serde_json::json!({ "a": 1 }));
        let bytes = canonical_event_bytes(&d, "acme");

        // Independently pinned: sha256 hex digest of the UTF-8 bytes `{"a":1}`
        // (`serde_json::to_vec(json!({"a":1}))`), computed out-of-band so a
        // bug in the production hashing step can't cancel out against the
        // test's own hashing.
        let expected = "forgeguard-event-v1\n\
             org:acme\n\
             seq:1\n\
             event_id:01J000000000000000000000\n\
             kind:principal.upserted\n\
             occurred_at:2026-07-14T00:00:00Z\n\
             narrowing:false\n\
             schema_version:1\n\
             payload_sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862\n";
        assert_eq!(String::from_utf8(bytes).unwrap(), expected);
    }

    #[test]
    fn differing_payload_changes_hash_line() {
        let a = canonical_event_bytes(&draft(serde_json::json!({ "a": 1 })), "acme");
        let b = canonical_event_bytes(&draft(serde_json::json!({ "a": 2 })), "acme");
        assert_ne!(a, b);
    }

    #[test]
    fn envelope_bytes_match_draft_bytes() {
        // The verifier's reconstruction from a stored envelope must be
        // byte-identical to what was signed at append time.
        let d = draft(serde_json::json!({ "b": 2, "a": 1 }));
        let draft_bytes = canonical_event_bytes(&d, "acme");

        let envelope =
            crate::event::envelope::EventEnvelope::from_signed(d, "key-1".into(), "c2ln".into());
        let envelope_bytes = canonical_envelope_bytes(&envelope, "acme");

        assert_eq!(draft_bytes, envelope_bytes);
    }

    #[test]
    fn envelope_bytes_survive_json_round_trip() {
        // A consumer deserializes the envelope from the /events response —
        // the payload Value round-trips through JSON. Bytes must not change.
        let d = draft(serde_json::json!({ "z": [1, 2], "a": { "nested": true } }));
        let expected = canonical_event_bytes(&d, "acme");

        let envelope =
            crate::event::envelope::EventEnvelope::from_signed(d, "key-1".into(), "c2ln".into());
        let json = serde_json::to_string(&envelope).unwrap();
        let back: crate::event::envelope::EventEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(canonical_envelope_bytes(&back, "acme"), expected);
    }
}

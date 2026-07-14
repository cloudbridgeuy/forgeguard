//! Canonical byte encoding of an [`EventDraft`], used as the signing input
//! (D8). Deterministic: the payload is hashed as the exact bytes the shell
//! will persist (`serde_json::to_vec`) — consumers hash stored bytes, never
//! re-serialize.

use sha2::{Digest, Sha256};

use crate::event::envelope::EventDraft;

/// Build the canonical byte representation of `draft` for organization
/// `org_id`, ready to be passed to a signing function.
pub fn canonical_event_bytes(draft: &EventDraft, org_id: &str) -> Vec<u8> {
    // Unwrap: serializing a `serde_json::Value` never fails.
    let payload_bytes = serde_json::to_vec(draft.payload()).unwrap_or_default();
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
        seq = draft.seq(),
        event_id = draft.event_id().as_str(),
        kind = draft.kind().as_str(),
        occurred_at = draft.occurred_at(),
        narrowing = draft.narrowing(),
        schema_version = draft.schema_version(),
    )
    .into_bytes()
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
}

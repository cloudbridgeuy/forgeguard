//! V5 (N16): pure fold of a per-org event log prefix into entity state,
//! plus the `principal.upserted` payload builder that makes principal
//! events self-describing (subject identity travels in the payload).

use forgeguard_core::NativeId;

/// Build the `principal.upserted` event payload: the raw principal doc
/// wrapped with its subject identity, so a pure fold over served envelopes
/// can reconstruct *which* principal each event touched. The state item and
/// the D6 no-op compare keep the raw doc — only the event payload wraps.
pub fn principal_event_payload(
    native_id: &NativeId,
    principal: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "native_id": native_id.to_string(),
        "principal": principal,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn payload_wraps_doc_with_subject_identity() {
        let native_id = NativeId::try_new("usr_1").unwrap();
        let doc = serde_json::json!({ "role": "admin" });
        assert_eq!(
            principal_event_payload(&native_id, &doc),
            serde_json::json!({
                "native_id": "usr_1",
                "principal": { "role": "admin" },
            })
        );
    }
}

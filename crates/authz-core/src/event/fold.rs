//! V5 (N16): pure fold of a per-org event log prefix into entity state,
//! plus the `principal.upserted` payload builder that makes principal
//! events self-describing (subject identity travels in the payload).

use std::collections::BTreeMap;

use forgeguard_core::NativeId;

use crate::error::{Error, Result};
use crate::event::envelope::EventEnvelope;
use crate::event::kind::EventKind;
use crate::store::Revision;

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

/// Entity state reconstructed by folding an org's event log up to a
/// revision: the model-plane answer to "what did the world look like at N".
///
/// JSON-shaped by design (D9 amendment): principal docs are arbitrary JSON,
/// so no typed `EntitySlice` can be built from them. Fields are private —
/// state is only ever produced by [`fold_events`] / [`FoldedState::empty`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedState {
    revision: Revision,
    /// `native_id -> raw principal doc` (the doc, unwrapped).
    principals: BTreeMap<String, serde_json::Value>,
    /// `(resource_type, native_id) -> fgrn` for live promotions.
    promotions: BTreeMap<(String, String), String>,
    /// The latest `org.created`/`org.updated` payload, if any.
    org: Option<serde_json::Value>,
}

impl FoldedState {
    /// The state of an org whose log is empty: revision 0, no entities.
    pub fn empty() -> Self {
        Self {
            revision: Revision::new(0),
            principals: BTreeMap::new(),
            promotions: BTreeMap::new(),
            org: None,
        }
    }

    /// The revision this state is pinned to.
    pub fn revision(&self) -> Revision {
        self.revision
    }

    /// The principal doc stored under `native_id`, if any.
    pub fn principal(&self, native_id: &str) -> Option<&serde_json::Value> {
        self.principals.get(native_id)
    }

    /// All principals, ascending by `native_id`.
    pub fn principals(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.principals
    }

    /// The live promotion's FGRN for `(resource_type, native_id)`, if any.
    pub fn promotion(&self, resource_type: &str, native_id: &str) -> Option<&str> {
        self.promotions
            .get(&(resource_type.to_string(), native_id.to_string()))
            .map(String::as_str)
    }

    /// All live promotions, ascending by `(resource_type, native_id)`.
    pub fn promotions(&self) -> &BTreeMap<(String, String), String> {
        &self.promotions
    }

    /// The latest org payload folded so far, if any.
    pub fn org(&self) -> Option<&serde_json::Value> {
        self.org.as_ref()
    }
}

/// Build the `org.created`/`org.updated` event payload: the full
/// post-mutation `Organization` plus its `OrgConfig` (or `null` if
/// unconfigured). Signing keys never enter payloads — they're not on
/// `Organization`.
pub fn org_event_payload(
    organization: &serde_json::Value,
    config: Option<&serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "organization": organization,
        "config": config,
    })
}

/// The semantic view of an org payload used for no-op detection: identical
/// to the payload except `organization.updated_at` is stripped, since a
/// timestamp bump alone must not count as a change.
pub fn org_semantic_view(payload: &serde_json::Value) -> serde_json::Value {
    let mut view = payload.clone();
    if let Some(org) = view.get_mut("organization").and_then(|v| v.as_object_mut()) {
        org.remove("updated_at");
    }
    view
}

/// Fold `events` (the log prefix from seq 1, ascending, gap-free) into the
/// entity state as of revision `at` (N16). Events after `at` are ignored;
/// `at == 0` or `at > latest` is [`Error::UnknownRevision`] (MemoryStore
/// parity). Pure: no I/O, no clock.
pub fn fold_events(events: &[EventEnvelope], at: Revision) -> Result<FoldedState> {
    let latest = events.last().map(|e| e.seq().value()).unwrap_or(0);
    let requested = at.value();
    if requested == 0 || requested > latest {
        return Err(Error::UnknownRevision { requested, latest });
    }

    let mut state = FoldedState {
        revision: at,
        principals: BTreeMap::new(),
        promotions: BTreeMap::new(),
        org: None,
    };
    for (index, event) in events.iter().enumerate() {
        let seq = event.seq().value();
        let expected = index as u64 + 1;
        if seq != expected {
            return Err(Error::UnfoldableEvent {
                seq,
                reason: format!("event log gap: expected seq {expected}"),
            });
        }
        if seq > requested {
            break;
        }
        apply_event(event, &mut state)?;
    }
    Ok(state)
}

/// One fold step. Only the three kinds the control plane appends are
/// foldable; anything else (or a pre-V5 payload missing its identity
/// wrapper) is a typed error — silently skipping would fabricate history.
fn apply_event(event: &EventEnvelope, state: &mut FoldedState) -> Result<()> {
    let seq = event.seq().value();
    let unfoldable = |reason: String| Error::UnfoldableEvent { seq, reason };
    let payload_str = |field: &str| -> Result<String> {
        event.payload()[field]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                unfoldable(format!(
                    "{} payload missing string field {field}",
                    event.kind()
                ))
            })
    };

    match event.kind() {
        EventKind::PrincipalUpserted => {
            let native_id = payload_str("native_id").map_err(|_| {
                unfoldable(
                    "principal.upserted payload missing native_id (pre-V5 event)".to_string(),
                )
            })?;
            let doc = event.payload().get("principal").cloned().ok_or_else(|| {
                unfoldable(
                    "principal.upserted payload missing principal doc (pre-V5 event)".to_string(),
                )
            })?;
            state.principals.insert(native_id, doc);
        }
        EventKind::ResourcePromoted => {
            let fgrn = payload_str("fgrn")?;
            state.promotions.insert(
                (payload_str("resource_type")?, payload_str("native_id")?),
                fgrn,
            );
        }
        EventKind::ResourceTombstoned => {
            state
                .promotions
                .remove(&(payload_str("resource_type")?, payload_str("native_id")?));
        }
        EventKind::OrgCreated | EventKind::OrgUpdated => {
            if !event.payload()["organization"].is_object() {
                return Err(unfoldable(format!(
                    "{} payload missing object field organization",
                    event.kind()
                )));
            }
            state.org = Some(event.payload().clone());
        }
        other => {
            return Err(unfoldable(format!("no fold rule for kind {other}")));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::event::envelope::{Actor, EventDraft, EventDraftParams, EventEnvelope, EventId};
    use crate::event::kind::EventKind;
    use crate::store::Revision;
    use forgeguard_core::{Fgrn, Segment};

    fn envelope(seq: u64, kind: EventKind, payload: serde_json::Value) -> EventEnvelope {
        let draft = EventDraft::new(EventDraftParams {
            event_id: EventId::try_new(format!("01J{seq:022}")).unwrap(),
            seq: Revision::new(seq),
            kind,
            occurred_at: "2026-07-15T00:00:00Z".to_string(),
            actor: Actor::System,
            payload,
        });
        EventEnvelope::from_signed(draft, "key-1".to_string(), "sig".to_string())
    }

    fn upsert(seq: u64, native_id: &str, doc: &serde_json::Value) -> EventEnvelope {
        let native_id = NativeId::try_new(native_id).unwrap();
        envelope(
            seq,
            EventKind::PrincipalUpserted,
            principal_event_payload(&native_id, doc),
        )
    }

    fn promo_payload(native_id: &str) -> serde_json::Value {
        let org = Segment::try_new("acme").unwrap();
        let fgrn = Fgrn::resource(
            &org,
            &Segment::try_new("document").unwrap(),
            &NativeId::try_new(native_id).unwrap(),
        );
        serde_json::json!({
            "fgrn": fgrn.to_string(),
            "resource_type": "document",
            "native_id": native_id,
        })
    }

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

    /// The V5 demo, pure half: mutate at N+1, fold at N reproduces the
    /// pre-mutation state.
    #[test]
    fn fold_at_earlier_revision_reproduces_pre_mutation_state() {
        let events = vec![
            upsert(1, "usr_1", &serde_json::json!({ "role": "admin" })),
            upsert(2, "usr_1", &serde_json::json!({ "role": "viewer" })),
        ];

        let before = fold_events(&events, Revision::new(1)).unwrap();
        assert_eq!(before.revision(), Revision::new(1));
        assert_eq!(
            before.principal("usr_1"),
            Some(&serde_json::json!({ "role": "admin" }))
        );

        let after = fold_events(&events, Revision::new(2)).unwrap();
        assert_eq!(
            after.principal("usr_1"),
            Some(&serde_json::json!({ "role": "viewer" }))
        );
    }

    #[test]
    fn tombstone_removes_promotion_but_not_at_earlier_revisions() {
        let events = vec![
            envelope(1, EventKind::ResourcePromoted, promo_payload("doc_1")),
            envelope(2, EventKind::ResourceTombstoned, promo_payload("doc_1")),
        ];

        let promoted = fold_events(&events, Revision::new(1)).unwrap();
        assert_eq!(
            promoted.promotion("document", "doc_1"),
            Some("fgrn:acme:resource:document/doc_1")
        );

        let tombstoned = fold_events(&events, Revision::new(2)).unwrap();
        assert_eq!(tombstoned.promotion("document", "doc_1"), None);
        assert!(tombstoned.promotions().is_empty());
    }

    #[test]
    fn revision_zero_is_unknown() {
        let events = vec![upsert(1, "usr_1", &serde_json::json!({}))];
        let err = fold_events(&events, Revision::new(0)).unwrap_err();
        assert!(matches!(
            err,
            Error::UnknownRevision {
                requested: 0,
                latest: 1
            }
        ));
    }

    #[test]
    fn revision_past_latest_is_unknown() {
        let events = vec![upsert(1, "usr_1", &serde_json::json!({}))];
        let err = fold_events(&events, Revision::new(9)).unwrap_err();
        assert!(matches!(
            err,
            Error::UnknownRevision {
                requested: 9,
                latest: 1
            }
        ));
    }

    #[test]
    fn sequence_gap_is_unfoldable() {
        let events = vec![
            upsert(1, "usr_1", &serde_json::json!({})),
            upsert(3, "usr_2", &serde_json::json!({})),
        ];
        let err = fold_events(&events, Revision::new(3)).unwrap_err();
        assert!(matches!(err, Error::UnfoldableEvent { seq: 3, .. }));
        assert!(err.to_string().contains("event log gap"));
    }

    #[test]
    fn pre_v5_principal_payload_is_unfoldable() {
        // A V1-era event: raw doc, no identity wrapper.
        let events = vec![envelope(
            1,
            EventKind::PrincipalUpserted,
            serde_json::json!({ "role": "admin" }),
        )];
        let err = fold_events(&events, Revision::new(1)).unwrap_err();
        assert!(matches!(err, Error::UnfoldableEvent { seq: 1, .. }));
        assert!(err.to_string().contains("pre-V5 event"));
    }

    #[test]
    fn kind_without_fold_rule_is_unfoldable() {
        let events = vec![envelope(1, EventKind::GrantAdded, serde_json::json!({}))];
        let err = fold_events(&events, Revision::new(1)).unwrap_err();
        assert!(err
            .to_string()
            .contains("no fold rule for kind grant.added"));
    }

    #[test]
    fn events_after_the_target_are_ignored() {
        let events = vec![
            upsert(1, "usr_1", &serde_json::json!({ "role": "admin" })),
            envelope(2, EventKind::ResourcePromoted, promo_payload("doc_1")),
        ];
        let at_one = fold_events(&events, Revision::new(1)).unwrap();
        assert!(at_one.promotions().is_empty());
    }

    #[test]
    fn empty_state_is_revision_zero() {
        let state = FoldedState::empty();
        assert_eq!(state.revision(), Revision::new(0));
        assert!(state.principals().is_empty());
        assert!(state.promotions().is_empty());
        assert!(state.org().is_none());
    }

    #[test]
    fn org_created_then_updated_folds_to_latest() {
        let created = org_event_payload(&serde_json::json!({ "name": "Acme" }), None);
        let updated = org_event_payload(&serde_json::json!({ "name": "Acme Inc" }), None);
        let events = vec![
            envelope(1, EventKind::OrgCreated, created.clone()),
            envelope(2, EventKind::OrgUpdated, updated.clone()),
        ];

        let at_one = fold_events(&events, Revision::new(1)).unwrap();
        assert_eq!(at_one.org(), Some(&created));

        let at_two = fold_events(&events, Revision::new(2)).unwrap();
        assert_eq!(at_two.org(), Some(&updated));
    }

    #[test]
    fn org_payload_missing_organization_is_unfoldable() {
        let events = vec![envelope(1, EventKind::OrgCreated, serde_json::json!({}))];
        let err = fold_events(&events, Revision::new(1)).unwrap_err();
        assert!(matches!(err, Error::UnfoldableEvent { seq: 1, .. }));
        assert!(err
            .to_string()
            .contains("missing object field organization"));
    }

    #[test]
    fn org_semantic_view_ignores_updated_at() {
        let a = org_event_payload(
            &serde_json::json!({ "name": "Acme", "updated_at": "2026-01-01T00:00:00Z" }),
            None,
        );
        let b = org_event_payload(
            &serde_json::json!({ "name": "Acme", "updated_at": "2026-07-15T00:00:00Z" }),
            None,
        );
        assert_eq!(org_semantic_view(&a), org_semantic_view(&b));

        let c = org_event_payload(
            &serde_json::json!({ "name": "Acme Inc", "updated_at": "2026-01-01T00:00:00Z" }),
            None,
        );
        assert_ne!(org_semantic_view(&a), org_semantic_view(&c));
    }

    #[test]
    fn org_event_payload_shape() {
        let payload = org_event_payload(&serde_json::json!({ "name": "Acme" }), None);
        assert_eq!(
            payload,
            serde_json::json!({
                "organization": { "name": "Acme" },
                "config": null,
            })
        );
    }
}

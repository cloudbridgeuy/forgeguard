//! Promotion state item mapping (V3 / A7-D7): pure key, FGRN, and payload
//! builders for `PK=ORG#{org}, SK=PROMO#{type}#{native_id}` items. All I/O
//! (the transactional tombstone, the reconciliation Query) lives on the
//! `PrincipalEventStore` implementations in `principal_store.rs`.
//!
//! Wired up by `principal_store.rs` in Task 3; until then clippy sees this
//! module as dead code from the crate's perspective.
#![allow(dead_code)]

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_core::{Fgrn, NativeId, Segment};

use crate::dynamo_store::ORG_PREFIX;
use crate::error::{Error, Result};
use crate::event_log::StatePut;

pub(crate) const PROMO_PREFIX: &str = "PROMO#";

/// One row of a reconciliation page (U6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromotionEntry {
    pub(crate) fgrn: String,
    pub(crate) native_id: String,
}

/// `PROMO#{type}#{native_id}` — the promotion state item's sort key (S4).
pub(crate) fn promotion_sk(resource_type: &Segment, native_id: &NativeId) -> String {
    format!("{PROMO_PREFIX}{resource_type}#{native_id}")
}

/// Mint the resource FGRN for a promotion (`fgrn:{org}:resource:{type}/{id}`).
///
/// `org_id` re-parses as a `Segment` here because callers hold the raw path
/// value; an org id that fails segment parsing cannot own promotions.
pub(crate) fn promotion_fgrn(
    org_id: &str,
    resource_type: &Segment,
    native_id: &NativeId,
) -> Result<Fgrn> {
    let org = Segment::try_new(org_id)
        .map_err(|e| Error::Store(format!("org id is not a valid FGRN segment: {e}")))?;
    Ok(Fgrn::resource(&org, resource_type, native_id))
}

/// The D4 payload carried by both `resource.promoted` and
/// `resource.tombstoned` events: the identity of the (now present / now gone)
/// resource, enough for consumers to key idempotent upserts and cache drops.
pub(crate) fn promotion_event_payload(
    fgrn: &Fgrn,
    resource_type: &Segment,
    native_id: &NativeId,
) -> serde_json::Value {
    serde_json::json!({
        "fgrn": fgrn.to_string(),
        "resource_type": resource_type.to_string(),
        "native_id": native_id.to_string(),
    })
}

/// Params struct — pub fields are the documented carve-out
/// (see .claude/context/params-struct-rule.md).
#[derive(Clone, Copy)]
pub(crate) struct PromotionStatePutParams<'a> {
    pub(crate) org_id: &'a str,
    pub(crate) resource_type: &'a Segment,
    pub(crate) native_id: &'a NativeId,
    pub(crate) fgrn: &'a Fgrn,
    pub(crate) promoted_at: &'a str,
}

/// Build the `StatePut` for a promotion state item. `promoted_at` (RFC3339)
/// is minted by the caller — this function stays a pure mapping.
pub(crate) fn promotion_state_put(params: PromotionStatePutParams<'_>) -> StatePut {
    let mut attributes = HashMap::new();
    attributes.insert(
        "fgrn".to_string(),
        AttributeValue::S(params.fgrn.to_string()),
    );
    attributes.insert(
        "native_id".to_string(),
        AttributeValue::S(params.native_id.to_string()),
    );
    attributes.insert(
        "promoted_at".to_string(),
        AttributeValue::S(params.promoted_at.to_string()),
    );
    StatePut {
        pk: format!("{ORG_PREFIX}{}", params.org_id),
        sk: promotion_sk(params.resource_type, params.native_id),
        attributes,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn seg(s: &str) -> Segment {
        Segment::try_new(s).unwrap()
    }
    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    #[test]
    fn sk_is_promo_type_native_id() {
        assert_eq!(
            promotion_sk(&seg("document"), &nid("doc_1")),
            "PROMO#document#doc_1"
        );
    }

    #[test]
    fn fgrn_uses_resource_constructor() {
        let fgrn = promotion_fgrn("acme", &seg("document"), &nid("doc_1")).unwrap();
        assert_eq!(fgrn.to_string(), "fgrn:acme:resource:document/doc_1");
    }

    #[test]
    fn invalid_org_segment_errors() {
        assert!(promotion_fgrn("not a segment!", &seg("document"), &nid("doc_1")).is_err());
    }

    #[test]
    fn payload_carries_identity_triple() {
        let fgrn = promotion_fgrn("acme", &seg("document"), &nid("doc_1")).unwrap();
        let payload = promotion_event_payload(&fgrn, &seg("document"), &nid("doc_1"));
        assert_eq!(payload["fgrn"], "fgrn:acme:resource:document/doc_1");
        assert_eq!(payload["resource_type"], "document");
        assert_eq!(payload["native_id"], "doc_1");
    }

    #[test]
    fn state_put_lands_on_promo_key_with_fgrn_attr() {
        let fgrn = promotion_fgrn("acme", &seg("document"), &nid("doc_1")).unwrap();
        let put = promotion_state_put(PromotionStatePutParams {
            org_id: "acme",
            resource_type: &seg("document"),
            native_id: &nid("doc_1"),
            fgrn: &fgrn,
            promoted_at: "2026-07-15T00:00:00Z",
        });
        assert_eq!(put.pk, "ORG#acme");
        assert_eq!(put.sk, "PROMO#document#doc_1");
        assert_eq!(
            put.attributes.get("fgrn").unwrap().as_s().unwrap(),
            "fgrn:acme:resource:document/doc_1"
        );
    }
}

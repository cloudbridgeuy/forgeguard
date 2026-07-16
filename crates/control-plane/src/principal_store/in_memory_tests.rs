//! Unit tests for [`InMemoryPrincipalEventStore`]'s promotion methods — plain
//! `cargo xtask lint`, no `dynamodb-tests` feature required.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forgeguard_authz_core::{Actor, EventKind};
use forgeguard_core::Segment;

use super::*;

fn seg(s: &str) -> Segment {
    Segment::try_new(s).unwrap()
}
fn nid(s: &str) -> NativeId {
    NativeId::try_new(s).unwrap()
}

#[tokio::test]
async fn put_then_list_then_tombstone_roundtrip() {
    let store = InMemoryPrincipalEventStore::new();
    let doc_type = seg("document");

    let r1 = store
        .put_promotion("acme", &doc_type, &nid("doc_1"), Actor::System)
        .await
        .unwrap();
    let r2 = store
        .put_promotion("acme", &doc_type, &nid("doc_2"), Actor::System)
        .await
        .unwrap();
    assert_eq!(r1, Revision::new(1));
    assert_eq!(r2, Revision::new(2));

    let mut listed = store
        .list_promotions("acme", &doc_type, None, 100)
        .await
        .unwrap();
    listed.sort_by(|a, b| a.native_id.cmp(&b.native_id));
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].native_id, "doc_1");
    assert_eq!(listed[0].fgrn, "fgrn:acme:resource:document/doc_1");
    assert_eq!(listed[1].native_id, "doc_2");

    let tombstoned = store
        .tombstone_promotion("acme", &doc_type, &nid("doc_1"), Actor::System)
        .await
        .unwrap();
    assert_eq!(tombstoned, Some(Revision::new(3)));

    let remaining = store
        .list_promotions("acme", &doc_type, None, 100)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].native_id, "doc_2");

    let log = store.log_for("acme").unwrap();
    let events = EventLog::events_after(log.as_ref(), Revision::new(0), 100)
        .await
        .unwrap();
    let kinds: Vec<EventKind> = events.iter().map(EventEnvelope::kind).collect();
    assert_eq!(
        kinds,
        vec![
            EventKind::ResourcePromoted,
            EventKind::ResourcePromoted,
            EventKind::ResourceTombstoned,
        ]
    );
}

#[tokio::test]
async fn tombstone_absent_promotion_returns_none_and_appends_nothing() {
    let store = InMemoryPrincipalEventStore::new();
    let tombstoned = store
        .tombstone_promotion("acme", &seg("document"), &nid("doc_missing"), Actor::System)
        .await
        .unwrap();
    assert_eq!(tombstoned, None);
    let revision = store.latest_revision("acme").await.unwrap();
    assert_eq!(revision, Revision::new(0));
}

#[tokio::test]
async fn list_respects_after_cursor_and_limit() {
    let store = InMemoryPrincipalEventStore::new();
    let doc_type = seg("document");
    for id in ["doc_1", "doc_2", "doc_3"] {
        store
            .put_promotion("acme", &doc_type, &nid(id), Actor::System)
            .await
            .unwrap();
    }

    let page = store
        .list_promotions("acme", &doc_type, Some(&nid("doc_1")), 1)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].native_id, "doc_2");
}

#[tokio::test]
async fn list_is_scoped_to_org_and_type() {
    let store = InMemoryPrincipalEventStore::new();
    store
        .put_promotion("acme", &seg("document"), &nid("doc_1"), Actor::System)
        .await
        .unwrap();
    store
        .put_promotion("acme", &seg("folder"), &nid("f_1"), Actor::System)
        .await
        .unwrap();
    store
        .put_promotion("globex", &seg("document"), &nid("doc_9"), Actor::System)
        .await
        .unwrap();

    let listed = store
        .list_promotions("acme", &seg("document"), None, 100)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].native_id, "doc_1");
}

#[tokio::test]
async fn list_signing_keys_returns_in_memory_key() {
    let store = InMemoryPrincipalEventStore::new();
    let keys = store.list_signing_keys("org-a").await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id, "in-memory-test-key");
    assert!(keys[0].public_key_pem.contains("BEGIN PUBLIC KEY"));
}

#[tokio::test]
async fn in_memory_key_verifies_an_appended_event() {
    use base64::Engine as _;
    use forgeguard_authn_core::signing::{verify_bytes, VerifyingKey};
    use forgeguard_authz_core::canonical_envelope_bytes;

    let store = InMemoryPrincipalEventStore::new();
    let native_id = nid("usr_1");
    store
        .upsert_changed(
            "org-a",
            &native_id,
            Actor::System,
            serde_json::json!({"role": "admin"}),
        )
        .await
        .unwrap();

    let events = store
        .events_after("org-a", Revision::new(0), 10)
        .await
        .unwrap();
    let envelope = &events[0];
    let keys = store.list_signing_keys("org-a").await.unwrap();
    let key = keys.iter().find(|k| k.key_id == envelope.key_id()).unwrap();

    let vk = VerifyingKey::from_public_key_pem(&key.public_key_pem).unwrap();
    let sig_bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(envelope.signature())
        .unwrap()
        .try_into()
        .unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let bytes = canonical_envelope_bytes(envelope, "org-a");
    assert!(verify_bytes(&vk, &bytes, &sig).is_ok());
}

/// V5 demo: mutate at rev N+1, `fold_at(N)` reproduces the pre-mutation
/// state; `fold_at(None)` matches the state items; unknown revision errors.
#[tokio::test]
async fn fold_at_time_travels_over_the_org_log() {
    let store = InMemoryPrincipalEventStore::new();
    let usr = nid("usr_1");
    let doc_type = seg("document");
    let doc = nid("doc_1");

    // rev 1: usr_1 is admin
    store
        .upsert_changed(
            "acme",
            &usr,
            Actor::System,
            serde_json::json!({"role": "admin"}),
        )
        .await
        .unwrap();
    // rev 2: usr_1 becomes viewer
    store
        .upsert_changed(
            "acme",
            &usr,
            Actor::System,
            serde_json::json!({"role": "viewer"}),
        )
        .await
        .unwrap();
    // rev 3: doc_1 promoted; rev 4: tombstoned
    store
        .put_promotion("acme", &doc_type, &doc, Actor::System)
        .await
        .unwrap();
    store
        .tombstone_promotion("acme", &doc_type, &doc, Actor::System)
        .await
        .unwrap();

    // slice(at 1): pre-mutation principal, no promotions yet.
    let at_1 = store.fold_at("acme", Some(Revision::new(1))).await.unwrap();
    assert_eq!(at_1.revision(), Revision::new(1));
    assert_eq!(
        at_1.principal("usr_1"),
        Some(&serde_json::json!({"role": "admin"}))
    );
    assert!(at_1.promotions().is_empty());

    // slice(at 3): post-mutation principal, promotion live.
    let at_3 = store.fold_at("acme", Some(Revision::new(3))).await.unwrap();
    assert_eq!(
        at_3.principal("usr_1"),
        Some(&serde_json::json!({"role": "viewer"}))
    );
    assert_eq!(
        at_3.promotion("document", "doc_1"),
        Some("fgrn:acme:resource:document/doc_1")
    );

    // slice(latest): promotion tombstoned; principal matches the state item.
    let latest = store.fold_at("acme", None).await.unwrap();
    assert_eq!(latest.revision(), Revision::new(4));
    assert_eq!(latest.promotion("document", "doc_1"), None);
    let state_item = store.get_principal("acme", &usr).await.unwrap();
    assert_eq!(latest.principal("usr_1"), state_item.as_ref());

    // unknown revision errors.
    let err = store
        .fold_at("acme", Some(Revision::new(9)))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown revision 9"));
}

#[tokio::test]
async fn fold_at_on_empty_org_log() {
    let store = InMemoryPrincipalEventStore::new();

    let latest = store.fold_at("acme", None).await.unwrap();
    assert_eq!(latest.revision(), Revision::new(0));
    assert!(latest.principals().is_empty());

    let err = store
        .fold_at("acme", Some(Revision::new(1)))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown revision 1"));
}

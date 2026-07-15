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

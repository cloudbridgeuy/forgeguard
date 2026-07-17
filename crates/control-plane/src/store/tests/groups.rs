//! InMemory group store unit tests (Group C, Task C.4; rewritten for #113 V4
//! Task 6 — group writes now ride `ModelEventStore::{put_group,delete_group}`,
//! `OrgStore` only serves reads).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use forgeguard_authz_core::{Actor, RbacEntry};
use forgeguard_core::OrganizationId;

use crate::model_event_store::{GroupWriteOutcome, InMemoryModelEventStore, ModelEventStore};
use crate::store::{InMemoryOrgStore, OrgStore};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn org(id: &str) -> OrganizationId {
    OrganizationId::new(id).unwrap()
}

/// Build a minimal `RbacEntry` that will pass validation when there are no
/// existing groups (no cycle / unknown-inherit checks needed).
fn entry(name: &str) -> RbacEntry {
    RbacEntry {
        name: name.to_owned(),
        description: None,
        inherits: vec![],
        allow: vec!["cp:x:read".to_owned()],
        tenant_scoped: true,
    }
}

/// Build a `(OrgStore, ModelEventStore)` pair wired together the way
/// production does (one DynamoDB table) and dev-mode does (write-through
/// hook): writes go through `events`, and are mirrored into `org_store`'s
/// group read-model, which is what the `OrgStore` read methods under test
/// here (`get_group`, `list_groups`, ...) actually read from.
fn stores() -> (Arc<InMemoryOrgStore>, InMemoryModelEventStore) {
    let org_store = Arc::new(InMemoryOrgStore::new(BTreeMap::new()));
    let events =
        InMemoryModelEventStore::new_with_org_store(org_store.clone() as Arc<dyn OrgStore>);
    (org_store, events)
}

// ---------------------------------------------------------------------------
// C.4.1 — put_group create then get_group returns the same group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_group_create_then_get_returns_identical() {
    let (org_store, events) = stores();
    let oid = org("org-grp-get");

    let outcome = events
        .put_group(oid.as_str(), entry("member"), Actor::System, None)
        .await
        .unwrap();
    assert!(matches!(outcome, GroupWriteOutcome::Applied { .. }));

    let fetched = org_store.get_group(&oid, "member").await.unwrap().unwrap();
    assert_eq!(fetched.entry().name, "member");
    assert_eq!(fetched.entry().allow, vec!["cp:x:read".to_owned()]);
}

// ---------------------------------------------------------------------------
// C.4.4 — list_groups: sorted by name; empty when org has none
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_groups_empty_when_org_has_none() {
    let (org_store, _events) = stores();
    let oid = org("org-grp-empty-list");
    let result = org_store.list_groups(&oid).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn list_groups_returns_sorted_by_name() {
    let (org_store, events) = stores();
    let oid = org("org-grp-sorted");

    // Insert in reverse alphabetical order.
    for name in ["owner", "member", "admin"] {
        events
            .put_group(oid.as_str(), entry(name), Actor::System, None)
            .await
            .unwrap();
    }

    let result = org_store.list_groups(&oid).await.unwrap();
    let names: Vec<&str> = result.iter().map(|g| g.entry().name.as_str()).collect();
    assert_eq!(names, ["admin", "member", "owner"]);
}

#[tokio::test]
async fn list_groups_only_returns_groups_for_correct_org() {
    let (org_store, events) = stores();
    let oid1 = org("org-grp-a");
    let oid2 = org("org-grp-b");

    events
        .put_group(oid1.as_str(), entry("member"), Actor::System, None)
        .await
        .unwrap();
    events
        .put_group(oid2.as_str(), entry("admin"), Actor::System, None)
        .await
        .unwrap();

    let for_oid1 = org_store.list_groups(&oid1).await.unwrap();
    assert_eq!(for_oid1.len(), 1);
    assert_eq!(for_oid1[0].entry().name, "member");

    let for_oid2 = org_store.list_groups(&oid2).await.unwrap();
    assert_eq!(for_oid2.len(), 1);
    assert_eq!(for_oid2[0].entry().name, "admin");
}

// ---------------------------------------------------------------------------
// C.4.5 — delete_group removes the item; subsequent get_group → None
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_group_removes_group() {
    let (org_store, events) = stores();
    let oid = org("org-grp-del");

    events
        .put_group(oid.as_str(), entry("member"), Actor::System, None)
        .await
        .unwrap();

    let outcome = events
        .delete_group(oid.as_str(), "member", Actor::System, None)
        .await
        .unwrap();
    assert!(matches!(outcome, GroupWriteOutcome::Applied { .. }));

    let fetched = org_store.get_group(&oid, "member").await.unwrap();
    assert!(fetched.is_none());
}

// ---------------------------------------------------------------------------
// C.4.6b — delete_group on a non-existent group → NoOp (D6), no event
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_group_absent_is_noop() {
    let (_org_store, events) = stores();
    let oid = org("org-grp-del-missing");

    let outcome = events
        .delete_group(oid.as_str(), "ghost", Actor::System, None)
        .await
        .unwrap();
    assert!(
        matches!(outcome, GroupWriteOutcome::NoOp { .. }),
        "expected NoOp, got: {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// C.4.7 — list_inheritors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_inheritors_returns_direct_children_only() {
    let (org_store, events) = stores();
    let oid = org("org-grp-inheritors");

    // member (no inherits)
    events
        .put_group(oid.as_str(), entry("member"), Actor::System, None)
        .await
        .unwrap();

    // admin inherits member
    let admin_entry = RbacEntry {
        name: "admin".to_owned(),
        description: None,
        inherits: vec!["member".to_owned()],
        allow: vec!["cp:x:read".to_owned()],
        tenant_scoped: true,
    };
    events
        .put_group(oid.as_str(), admin_entry, Actor::System, None)
        .await
        .unwrap();

    // owner inherits admin
    let owner_entry = RbacEntry {
        name: "owner".to_owned(),
        description: None,
        inherits: vec!["admin".to_owned()],
        allow: vec!["cp:x:read".to_owned()],
        tenant_scoped: true,
    };
    events
        .put_group(oid.as_str(), owner_entry, Actor::System, None)
        .await
        .unwrap();

    let inheritors_of_member = org_store.list_inheritors(&oid, "member").await.unwrap();
    assert_eq!(inheritors_of_member, ["admin"]);

    let inheritors_of_admin = org_store.list_inheritors(&oid, "admin").await.unwrap();
    assert_eq!(inheritors_of_admin, ["owner"]);

    let inheritors_of_owner = org_store.list_inheritors(&oid, "owner").await.unwrap();
    assert!(inheritors_of_owner.is_empty());
}

// ---------------------------------------------------------------------------
// C.4.8 — count_memberships_for_group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn count_memberships_for_group_mirrors_per_user_counts() {
    let (org_store, events) = stores();
    let oid = org("org-grp-members");

    events
        .put_group(oid.as_str(), entry("member"), Actor::System, None)
        .await
        .unwrap();
    events
        .put_group(oid.as_str(), entry("admin"), Actor::System, None)
        .await
        .unwrap();

    // Seed the memberships map directly (V2 in-memory path; production
    // memberships live in DynamoDB only, via Group E).
    org_store
        .seed_membership(&oid, "user-alice", vec!["member".to_owned()])
        .await;
    org_store
        .seed_membership(
            &oid,
            "user-bob",
            vec!["member".to_owned(), "admin".to_owned()],
        )
        .await;

    let member_counts = org_store
        .count_memberships_for_group(&oid, "member")
        .await
        .unwrap();
    assert_eq!(member_counts.len(), 2, "alice and bob are both in member");
    assert_eq!(member_counts["user-alice"], 1);
    assert_eq!(member_counts["user-bob"], 1);

    let admin_counts = org_store
        .count_memberships_for_group(&oid, "admin")
        .await
        .unwrap();
    assert_eq!(admin_counts.len(), 1, "only bob is in admin");
    assert_eq!(admin_counts["user-bob"], 1);
}

// ---------------------------------------------------------------------------
// C.4.9 — is_declared_group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn is_declared_group_returns_true_for_written_group() {
    let (org_store, events) = stores();
    let oid = org("org-grp-declared");

    events
        .put_group(oid.as_str(), entry("member"), Actor::System, None)
        .await
        .unwrap();

    assert!(org_store.is_declared_group(&oid, "member").await.unwrap());
}

#[tokio::test]
async fn is_declared_group_returns_false_for_unknown_group() {
    let (org_store, _events) = stores();
    let oid = org("org-grp-undeclared");

    assert!(!org_store.is_declared_group(&oid, "ghost").await.unwrap());
}

#[tokio::test]
async fn is_declared_group_returns_false_for_unknown_org() {
    let (org_store, _events) = stores();
    let oid = org("org-grp-no-org");

    assert!(!org_store.is_declared_group(&oid, "member").await.unwrap());
}

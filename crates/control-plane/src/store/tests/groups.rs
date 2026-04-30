//! InMemory group store unit tests (Group C, Task C.4).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use forgeguard_authz_core::{validate_rbac_entry, RbacEntry};
use forgeguard_core::OrganizationId;

use crate::error::Error;
use crate::store::{InMemoryOrgStore, OrgStore};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn store() -> InMemoryOrgStore {
    InMemoryOrgStore::new(BTreeMap::new())
}

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

/// Validate `entry` against the minimal post-write state (create path, no
/// existing groups). The proposed entry itself must be in `all_after` so
/// `resolve_inherits` can find the target name.
fn validate(e: RbacEntry) -> forgeguard_authz_core::ValidatedRbacEntry {
    let all_after = vec![e.clone()];
    validate_rbac_entry(e, &all_after).unwrap()
}

/// Validate `entry` against a named set of existing groups (for inherits checks).
///
/// Builds minimal `RbacEntry` stubs for each name so `validate_rbac_entry`
/// can resolve the `inherits` graph without needing a store round-trip.
fn validate_with_existing(
    e: RbacEntry,
    existing: &[&str],
) -> forgeguard_authz_core::ValidatedRbacEntry {
    // `all_after` must include both the existing stubs and the proposed entry
    // (post-write state) so `resolve_inherits` can find every referenced name.
    let mut all_after: Vec<RbacEntry> = existing
        .iter()
        .map(|name| RbacEntry {
            name: name.to_string(),
            description: None,
            inherits: vec![],
            allow: vec!["cp:x:read".to_owned()],
            tenant_scoped: true,
        })
        .collect();
    all_after.push(e.clone());
    validate_rbac_entry(e, &all_after).unwrap()
}

// ---------------------------------------------------------------------------
// C.4.1 — put_group create then get_group returns identical EtagedGroup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_group_create_then_get_returns_identical() {
    let s = store();
    let oid = org("org-grp-get");
    let validated = validate(entry("member"));

    let created = s.put_group(&oid, validated, None).await.unwrap();

    let fetched = s.get_group(&oid, "member").await.unwrap().unwrap();
    assert_eq!(created.etag(), fetched.etag());
    assert_eq!(created.entry().name, fetched.entry().name);
    assert_eq!(created.entry().allow, fetched.entry().allow);
}

// ---------------------------------------------------------------------------
// C.4.2 — put_group with no expected_etag on existing key → Conflict
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_group_no_etag_on_existing_key_returns_conflict() {
    let s = store();
    let oid = org("org-grp-conflict");

    s.put_group(&oid, validate(entry("member")), None)
        .await
        .unwrap();

    let result = s.put_group(&oid, validate(entry("member")), None).await;

    assert!(
        matches!(result, Err(Error::Conflict(_))),
        "expected Conflict, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// C.4.3 — put_group with stale etag → PreconditionFailed { current_etag }
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_group_stale_etag_returns_precondition_failed() {
    let s = store();
    let oid = org("org-grp-stale");

    let created = s
        .put_group(&oid, validate(entry("member")), None)
        .await
        .unwrap();
    let current_etag = created.etag().to_string();

    let result = s
        .put_group(
            &oid,
            validate(entry("member")),
            Some("\"definitely-wrong-etag\""),
        )
        .await;

    match result {
        Err(Error::PreconditionFailed { current_etag: got }) => {
            assert_eq!(got, current_etag, "returned etag should match stored etag");
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// C.4.4 — list_groups: sorted by name; empty when org has none
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_groups_empty_when_org_has_none() {
    let s = store();
    let oid = org("org-grp-empty-list");
    let result = s.list_groups(&oid).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn list_groups_returns_sorted_by_name() {
    let s = store();
    let oid = org("org-grp-sorted");

    // Insert in reverse alphabetical order.
    s.put_group(&oid, validate(entry("owner")), None)
        .await
        .unwrap();
    s.put_group(&oid, validate(entry("member")), None)
        .await
        .unwrap();
    s.put_group(&oid, validate(entry("admin")), None)
        .await
        .unwrap();

    let result = s.list_groups(&oid).await.unwrap();
    let names: Vec<&str> = result.iter().map(|g| g.entry().name.as_str()).collect();
    assert_eq!(names, ["admin", "member", "owner"]);
}

#[tokio::test]
async fn list_groups_only_returns_groups_for_correct_org() {
    let s = store();
    let oid1 = org("org-grp-a");
    let oid2 = org("org-grp-b");

    s.put_group(&oid1, validate(entry("member")), None)
        .await
        .unwrap();
    s.put_group(&oid2, validate(entry("admin")), None)
        .await
        .unwrap();

    let for_oid1 = s.list_groups(&oid1).await.unwrap();
    assert_eq!(for_oid1.len(), 1);
    assert_eq!(for_oid1[0].entry().name, "member");

    let for_oid2 = s.list_groups(&oid2).await.unwrap();
    assert_eq!(for_oid2.len(), 1);
    assert_eq!(for_oid2[0].entry().name, "admin");
}

// ---------------------------------------------------------------------------
// C.4.5 — delete_group with matching etag → Ok; subsequent get → None
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_group_matching_etag_removes_group() {
    let s = store();
    let oid = org("org-grp-del");

    let created = s
        .put_group(&oid, validate(entry("member")), None)
        .await
        .unwrap();
    s.delete_group(&oid, "member", created.etag())
        .await
        .unwrap();

    let fetched = s.get_group(&oid, "member").await.unwrap();
    assert!(fetched.is_none());
}

// ---------------------------------------------------------------------------
// C.4.6 — delete_group with stale etag → PreconditionFailed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_group_stale_etag_returns_precondition_failed() {
    let s = store();
    let oid = org("org-grp-del-stale");

    let created = s
        .put_group(&oid, validate(entry("member")), None)
        .await
        .unwrap();

    let result = s.delete_group(&oid, "member", "\"wrong-etag\"").await;

    match result {
        Err(Error::PreconditionFailed { current_etag }) => {
            assert_eq!(
                current_etag,
                created.etag(),
                "should return the current stored etag"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// C.4.6b — delete_group on a non-existent group → NotFound
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_group_not_found_returns_not_found() {
    let s = store();
    let oid = org("org-grp-del-missing");

    let result = s.delete_group(&oid, "ghost", "\"any-etag\"").await;

    assert!(
        matches!(result, Err(Error::NotFound(_))),
        "expected NotFound, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// C.4.7 — list_inheritors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_inheritors_returns_direct_children_only() {
    let s = store();
    let oid = org("org-grp-inheritors");

    // member (no inherits)
    s.put_group(&oid, validate(entry("member")), None)
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
    s.put_group(&oid, validate_with_existing(admin_entry, &["member"]), None)
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
    s.put_group(
        &oid,
        validate_with_existing(owner_entry, &["member", "admin"]),
        None,
    )
    .await
    .unwrap();

    let inheritors_of_member = s.list_inheritors(&oid, "member").await.unwrap();
    assert_eq!(inheritors_of_member, ["admin"]);

    let inheritors_of_admin = s.list_inheritors(&oid, "admin").await.unwrap();
    assert_eq!(inheritors_of_admin, ["owner"]);

    let inheritors_of_owner = s.list_inheritors(&oid, "owner").await.unwrap();
    assert!(inheritors_of_owner.is_empty());
}

// ---------------------------------------------------------------------------
// C.4.8 — count_memberships_for_group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn count_memberships_for_group_mirrors_per_user_counts() {
    let s = store();
    let oid = org("org-grp-members");

    s.put_group(&oid, validate(entry("member")), None)
        .await
        .unwrap();
    s.put_group(&oid, validate(entry("admin")), None)
        .await
        .unwrap();

    // Seed the memberships map directly (V2 in-memory path).
    {
        let mut m = s.memberships_to_groups.write().await;
        m.insert(
            (oid.clone(), "user-alice".to_owned()),
            vec!["member".to_owned()],
        );
        m.insert(
            (oid.clone(), "user-bob".to_owned()),
            vec!["member".to_owned(), "admin".to_owned()],
        );
    }

    let member_counts = s.count_memberships_for_group(&oid, "member").await.unwrap();
    assert_eq!(member_counts.len(), 2, "alice and bob are both in member");
    assert_eq!(member_counts["user-alice"], 1);
    assert_eq!(member_counts["user-bob"], 1);

    let admin_counts = s.count_memberships_for_group(&oid, "admin").await.unwrap();
    assert_eq!(admin_counts.len(), 1, "only bob is in admin");
    assert_eq!(admin_counts["user-bob"], 1);
}

// ---------------------------------------------------------------------------
// C.4.9 — is_declared_group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn is_declared_group_returns_true_for_written_group() {
    let s = store();
    let oid = org("org-grp-declared");

    s.put_group(&oid, validate(entry("member")), None)
        .await
        .unwrap();

    assert!(s.is_declared_group(&oid, "member").await.unwrap());
}

#[tokio::test]
async fn is_declared_group_returns_false_for_unknown_group() {
    let s = store();
    let oid = org("org-grp-undeclared");

    assert!(!s.is_declared_group(&oid, "ghost").await.unwrap());
}

#[tokio::test]
async fn is_declared_group_returns_false_for_unknown_org() {
    let s = store();
    let oid = org("org-grp-no-org");

    assert!(!s.is_declared_group(&oid, "member").await.unwrap());
}

// ---------------------------------------------------------------------------
// Extra: conditional put with Some(etag) on non-existent row
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_group_etag_on_nonexistent_returns_precondition_failed_empty_current() {
    let s = store();
    let oid = org("org-grp-none-some");

    let result = s
        .put_group(&oid, validate(entry("member")), Some("\"any-etag\""))
        .await;

    match result {
        Err(Error::PreconditionFailed { current_etag }) => {
            assert!(
                current_etag.is_empty(),
                "current_etag should be empty for non-existent row, got: {current_etag:?}"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
}

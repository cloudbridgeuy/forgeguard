//! DynamoDB integration tests for the Groups V2 store methods.
//!
//! Each test provisions its own fresh table (via `unique_table_name` +
//! `create_test_table`) so tests are fully isolated and safe to run in
//! parallel.
//!
//! Run with: `cargo xtask control-plane test`

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_authz_core::{validate_rbac_entry, RbacEntry};
use forgeguard_core::OrganizationId;

use super::*;
use crate::store::OrgStore;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a minimal valid `RbacEntry` — one allow action, no inherits.
fn make_entry(name: &str, allow: &[&str]) -> RbacEntry {
    RbacEntry {
        name: name.to_owned(),
        description: None,
        inherits: Vec::new(),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        tenant_scoped: true,
    }
}

/// Build a `RbacEntry` with `inherits` populated.
fn make_entry_with_inherits(name: &str, allow: &[&str], inherits: &[&str]) -> RbacEntry {
    RbacEntry {
        name: name.to_owned(),
        description: None,
        inherits: inherits.iter().map(|s| s.to_string()).collect(),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        tenant_scoped: true,
    }
}

/// Validate and wrap an entry as `ValidatedRbacEntry` for single-group
/// operations where no peer context is needed (the entry is its own context).
fn validated_single(entry: RbacEntry) -> forgeguard_authz_core::ValidatedRbacEntry {
    let all = vec![entry.clone()];
    validate_rbac_entry(entry, &all).unwrap()
}

/// Provision a fresh store with one Draft org and return (store, org_id).
async fn fresh_store_with_draft_org(org_id_str: &str) -> (DynamoOrgStore, OrganizationId) {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;
    let store = DynamoOrgStore::new(client, table);
    let now = chrono::Utc::now();
    let org_id = OrganizationId::new(org_id_str).unwrap();
    let org = forgeguard_core::Organization::new(
        org_id.clone(),
        "Test Org".to_string(),
        forgeguard_core::OrgStatus::Draft,
        now,
    );
    store.create(org, None).await.unwrap();
    (store, org_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// POST group (create) then GET — confirms round-trip storage and etag stability.
#[tokio::test]
async fn dynamodb_create_then_get_group() {
    let (store, org_id) = fresh_store_with_draft_org("dg-create-get").await;

    let entry = make_entry("admin", &["cp:org:read"]);
    let validated = validated_single(entry);
    let created = store.put_group(&org_id, validated, None).await.unwrap();

    assert_eq!(created.entry().name, "admin");
    assert!(
        !created.etag().as_str().is_empty(),
        "etag must be non-empty"
    );
    assert!(
        created.etag().as_str().starts_with('"') && created.etag().as_str().ends_with('"'),
        "etag must be a quoted string, got: {}",
        created.etag()
    );

    // GET must return the same etag
    let fetched = store.get_group(&org_id, "admin").await.unwrap().unwrap();
    assert_eq!(fetched.entry().name, "admin");
    assert_eq!(
        fetched.etag(),
        created.etag(),
        "GET etag must match PUT etag"
    );
    assert_eq!(
        fetched.entry().allow,
        vec!["cp:org:read"],
        "allow list must round-trip"
    );
}

/// Second POST with the same name must return `Error::Conflict`.
#[tokio::test]
async fn dynamodb_create_duplicate_returns_conflict() {
    let (store, org_id) = fresh_store_with_draft_org("dg-dup").await;

    let entry1 = make_entry("admin", &["cp:org:read"]);
    store
        .put_group(&org_id, validated_single(entry1), None)
        .await
        .unwrap();

    let entry2 = make_entry("admin", &["cp:org:write"]);
    let result = store
        .put_group(&org_id, validated_single(entry2), None)
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), crate::error::Error::Conflict(_)),
        "second create must return Conflict"
    );
}

/// PUT with a stale `If-Match` must return `Error::PreconditionFailed` carrying
/// the current stored etag.
#[tokio::test]
async fn dynamodb_update_with_stale_etag_returns_precondition_failed() {
    let (store, org_id) = fresh_store_with_draft_org("dg-stale-etag").await;

    // Create the group
    let entry = make_entry("member", &["cp:org:read"]);
    let created = store
        .put_group(&org_id, validated_single(entry), None)
        .await
        .unwrap();
    let correct_etag = created.etag().clone();

    // Try to update with a wrong etag
    let update_entry = make_entry("member", &["cp:org:read", "cp:org:write"]);
    let all_after = vec![update_entry.clone()];
    let validated_update = validate_rbac_entry(update_entry, &all_after).unwrap();

    let result = store
        .put_group(&org_id, validated_update, Some("\"wrong-etag\""))
        .await;

    match result {
        Err(crate::error::Error::PreconditionFailed { current_etag }) => {
            assert_eq!(
                current_etag,
                Some(correct_etag),
                "recovered etag must match the stored one"
            );
        }
        other => panic!("expected PreconditionFailed, got {other:?}"),
    }
}

/// `list_groups` must return groups sorted ascending by name.
///
/// DynamoDB Query returns items sorted by SK (GROUP#{name}) which equals
/// ascending by group name after stripping the prefix — no client-side sort.
#[tokio::test]
async fn dynamodb_list_groups_returns_sorted() {
    let (store, org_id) = fresh_store_with_draft_org("dg-list-sorted").await;

    // Insert in non-alphabetical order
    for name in &["owner", "admin", "member"] {
        let entry = make_entry(name, &["cp:org:read"]);
        store
            .put_group(&org_id, validated_single(entry), None)
            .await
            .unwrap();
    }

    let groups = store.list_groups(&org_id).await.unwrap();
    let names: Vec<&str> = groups.iter().map(|g| g.entry().name.as_str()).collect();
    assert_eq!(
        names,
        vec!["admin", "member", "owner"],
        "list_groups must be sorted ascending by name, got: {names:?}"
    );
}

/// DELETE with the correct etag must succeed (return `Ok(())`), and a
/// subsequent GET must return `None`.
#[tokio::test]
async fn dynamodb_delete_group_with_matching_etag_succeeds() {
    let (store, org_id) = fresh_store_with_draft_org("dg-delete-ok").await;

    let entry = make_entry("admin", &["cp:org:read"]);
    let created = store
        .put_group(&org_id, validated_single(entry), None)
        .await
        .unwrap();

    store
        .delete_group(&org_id, "admin", created.etag().as_str())
        .await
        .unwrap();

    let fetched = store.get_group(&org_id, "admin").await.unwrap();
    assert!(fetched.is_none(), "group must be absent after DELETE");
}

/// `list_inheritors` must return groups whose `inherits` list includes the
/// target group name.
#[tokio::test]
async fn dynamodb_list_inheritors_finds_dependents() {
    let (store, org_id) = fresh_store_with_draft_org("dg-inheritors").await;

    // Create base group "member"
    let member = make_entry("member", &["cp:org:read"]);
    store
        .put_group(&org_id, validated_single(member.clone()), None)
        .await
        .unwrap();

    // Create "admin" that inherits "member"
    let admin = make_entry_with_inherits("admin", &["cp:org:write"], &["member"]);
    let all_after = vec![member.clone(), admin.clone()];
    let validated_admin = validate_rbac_entry(admin, &all_after).unwrap();
    store
        .put_group(&org_id, validated_admin, None)
        .await
        .unwrap();

    // Create "owner" that also inherits "admin" (not "member" directly)
    let owner = make_entry_with_inherits("owner", &["cp:org:delete"], &["admin"]);
    let all_after2 = vec![
        member,
        make_entry_with_inherits("admin", &["cp:org:write"], &["member"]),
        owner.clone(),
    ];
    let validated_owner = validate_rbac_entry(owner, &all_after2).unwrap();
    store
        .put_group(&org_id, validated_owner, None)
        .await
        .unwrap();

    // list_inheritors("member") must return ["admin"] only (owner does not
    // directly inherit member)
    let mut inheritors = store.list_inheritors(&org_id, "member").await.unwrap();
    inheritors.sort();
    assert_eq!(
        inheritors,
        vec!["admin"],
        "only direct inheritors should be returned"
    );

    // list_inheritors("admin") must return ["owner"]
    let mut inheritors2 = store.list_inheritors(&org_id, "admin").await.unwrap();
    inheritors2.sort();
    assert_eq!(inheritors2, vec!["owner"]);

    // list_inheritors("owner") must return []
    let no_inheritors = store.list_inheritors(&org_id, "owner").await.unwrap();
    assert!(
        no_inheritors.is_empty(),
        "owner has no dependents, got: {no_inheritors:?}"
    );
}

/// `count_memberships_for_group` must count membership rows correctly.
///
/// Membership rows: `PK=USER#{sub}, SK=ORG#{org_id}, groups=List<String>`
/// The scan counts one entry per user whose `groups` list contains the target
/// group name. We write membership rows directly via the DynamoDB client since
/// there is no public helper for seeding them.
#[tokio::test]
async fn dynamodb_count_memberships_for_group_returns_per_user_counts() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;
    let store = DynamoOrgStore::new(client.clone(), table.clone());

    let now = chrono::Utc::now();
    let org_id = OrganizationId::new("dg-count-mem").unwrap();
    let org = forgeguard_core::Organization::new(
        org_id.clone(),
        "Count Membership Org".to_string(),
        forgeguard_core::OrgStatus::Draft,
        now,
    );
    store.create(org, None).await.unwrap();

    // Create the group "admin"
    let entry = make_entry("admin", &["cp:org:read"]);
    store
        .put_group(&org_id, validated_single(entry), None)
        .await
        .unwrap();

    // Seed two membership rows: user-a and user-b are both in "admin";
    // user-c is in "member" only (should not appear in "admin" count).
    //
    // Row layout (from count_memberships_for_group):
    //   PK = USER#{sub}
    //   SK = ORG#{org_id}
    //   groups = AttributeValue::L([AttributeValue::S(group_name), ...])
    let seed_member = |sub: &str, group: &str| {
        client
            .put_item()
            .table_name(&table)
            .item(super::pk(), AttributeValue::S(format!("USER#{sub}")))
            .item(super::sk(), AttributeValue::S(format!("ORG#{org_id}")))
            .item(
                "groups",
                AttributeValue::L(vec![AttributeValue::S(group.to_string())]),
            )
            .send()
    };

    seed_member("user-a", "admin").await.unwrap();
    seed_member("user-b", "admin").await.unwrap();
    // user-c is in "member" only
    seed_member("user-c", "member").await.unwrap();

    let counts = store
        .count_memberships_for_group(&org_id, "admin")
        .await
        .unwrap();

    // Expect exactly user-a and user-b with count 1 each (one ORG row per user)
    assert_eq!(
        counts.len(),
        2,
        "expected 2 users in admin, got: {counts:?}"
    );
    assert_eq!(counts.get("user-a"), Some(&1u32));
    assert_eq!(counts.get("user-b"), Some(&1u32));
    assert!(
        counts.get("user-c").is_none(),
        "user-c is not in admin and must not appear"
    );
}

/// `is_declared_group` returns `true` for an existing group and `false` for
/// an unknown name.
#[tokio::test]
async fn dynamodb_is_declared_group_round_trip() {
    let (store, org_id) = fresh_store_with_draft_org("dg-is-declared").await;

    // Not yet declared
    let before = store.is_declared_group(&org_id, "admin").await.unwrap();
    assert!(!before, "group must not exist before creation");

    // Create it
    let entry = make_entry("admin", &["cp:org:read"]);
    store
        .put_group(&org_id, validated_single(entry), None)
        .await
        .unwrap();

    // Now declared
    let after = store.is_declared_group(&org_id, "admin").await.unwrap();
    assert!(after, "group must exist after creation");

    // Unknown name still false
    let unknown = store
        .is_declared_group(&org_id, "nonexistent")
        .await
        .unwrap();
    assert!(!unknown, "nonexistent group must not be declared");
}

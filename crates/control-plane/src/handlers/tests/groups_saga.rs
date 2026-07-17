//! Integration tests for the V4 saga handoff stub
//! (`crates/control-plane/src/handlers/groups/saga.rs`).
//!
//! Tests use the in-memory `OrgStore` plus `StubVpClient` (test-support
//! cfg-gated). No DynamoDB, no AWS, no network.

use std::collections::BTreeMap;
use std::sync::Arc;

use forgeguard_authz_core::{validate_rbac_entry, Actor, RbacEntry, TenantConfig};
use forgeguard_core::{OrgStatus, Organization, OrganizationId};

use crate::handlers::groups::saga::{
    materialize_groups_to_vp, MaterializeError, MaterializeParams,
};
use crate::model_event_store::{InMemoryModelEventStore, ModelEventStore};
use crate::store::{InMemoryOrgStore, OrgStore};
use crate::vp_client::stub::{StubCall, StubVpClient};

const NAMESPACE: &str = "app";
const VP_STORE_ID: &str = "ps-test-store";

fn make_entry(name: &str, allow: &[&str], inherits: &[&str]) -> RbacEntry {
    RbacEntry {
        name: name.to_owned(),
        description: None,
        inherits: inherits.iter().map(|s| (*s).to_owned()).collect(),
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        tenant_scoped: false,
    }
}

async fn seed_org_with_groups(entries: Vec<RbacEntry>) -> (Arc<InMemoryOrgStore>, OrganizationId) {
    let store = Arc::new(InMemoryOrgStore::new(BTreeMap::new()));
    let org_id = OrganizationId::new("org-saga-test").unwrap();
    let now = chrono::Utc::now();
    let org = Organization::new(
        org_id.clone(),
        "Saga Test Org".to_owned(),
        OrgStatus::Draft,
        now,
    );
    store.write_through_org(org, None).await;

    let model_events =
        InMemoryModelEventStore::new_with_org_store(Arc::clone(&store) as Arc<dyn OrgStore>);

    // Seed entries in order; each must validate against the running set
    // (any inherits referenced must already exist).
    for entry in entries {
        let prior = store.list_groups(&org_id).await.unwrap();
        let mut all_after: Vec<RbacEntry> = prior.iter().map(|eg| eg.entry().clone()).collect();
        all_after.push(entry.clone());
        let validated = validate_rbac_entry(entry, &all_after).unwrap();
        model_events
            .put_group(org_id.as_str(), validated.into_inner(), Actor::System, None)
            .await
            .unwrap();
    }

    (store, org_id)
}

fn make_params<'a>(
    store: &'a InMemoryOrgStore,
    vp: &'a StubVpClient,
    org_id: &'a OrganizationId,
    raw_org_id: &'a str,
    tenant: &'a TenantConfig,
) -> MaterializeParams<'a, StubVpClient> {
    MaterializeParams {
        store,
        vp,
        org_id,
        raw_org_id,
        vp_store_id: VP_STORE_ID,
        namespace: NAMESPACE,
        tenant,
    }
}

// ---- Test 1: empty store → no VP calls, Ok(()) ----

#[tokio::test]
async fn empty_groups_no_vp_calls() {
    let (store, org_id) = seed_org_with_groups(vec![]).await;
    let vp = StubVpClient::new();
    let tenant = TenantConfig::default();

    let result =
        materialize_groups_to_vp(make_params(&store, &vp, &org_id, "org-saga-test", &tenant)).await;

    assert!(result.is_ok(), "expected Ok, got {result:?}");
    assert!(vp.calls().is_empty(), "expected no VP calls");
}

// ---- Test 2: three groups, alphabetical-by-name push order ----

#[tokio::test]
async fn three_groups_pushed_in_alphabetical_order() {
    let entries = vec![
        make_entry("zeta", &["cp:x:read"], &[]),
        make_entry("alpha", &["cp:x:read"], &[]),
        make_entry("member", &["cp:x:read"], &[]),
    ];
    let (store, org_id) = seed_org_with_groups(entries).await;
    let vp = StubVpClient::new();
    let tenant = TenantConfig::default();

    let result =
        materialize_groups_to_vp(make_params(&store, &vp, &org_id, "org-saga-test", &tenant)).await;

    assert!(result.is_ok(), "expected Ok, got {result:?}");

    // push_permit always emits delete-then-create per permit, so 3 entries
    // produce 6 calls (3 deletes interleaved with 3 creates).
    let calls = vp.calls();
    let expected = vec![
        StubCall::DeletePolicyByName {
            store_id: VP_STORE_ID.to_owned(),
            name: "cp-rbac-alpha".to_owned(),
        },
        StubCall::CreatePolicy {
            store_id: VP_STORE_ID.to_owned(),
            name: "cp-rbac-alpha".to_owned(),
        },
        StubCall::DeletePolicyByName {
            store_id: VP_STORE_ID.to_owned(),
            name: "cp-rbac-member".to_owned(),
        },
        StubCall::CreatePolicy {
            store_id: VP_STORE_ID.to_owned(),
            name: "cp-rbac-member".to_owned(),
        },
        StubCall::DeletePolicyByName {
            store_id: VP_STORE_ID.to_owned(),
            name: "cp-rbac-zeta".to_owned(),
        },
        StubCall::CreatePolicy {
            store_id: VP_STORE_ID.to_owned(),
            name: "cp-rbac-zeta".to_owned(),
        },
    ];
    assert_eq!(calls, expected);
}

// ---- Test 3: mid-walk push failure → first error returned, no recovery ----

#[tokio::test]
async fn push_failure_aborts_with_first_failed_name() {
    let entries = vec![
        make_entry("alpha", &["cp:x:read"], &[]),
        make_entry("member", &["cp:x:read"], &[]),
        make_entry("zeta", &["cp:x:read"], &[]),
    ];
    let (store, org_id) = seed_org_with_groups(entries).await;
    let vp = StubVpClient::new();
    // Inject a create failure on the second permit (alphabetical: member).
    vp.fail_on_create("cp-rbac-member");
    let tenant = TenantConfig::default();

    let result =
        materialize_groups_to_vp(make_params(&store, &vp, &org_id, "org-saga-test", &tenant)).await;

    match result {
        Err(MaterializeError::PushFailed { name, .. }) => {
            assert_eq!(name, "cp-rbac-member");
        }
        other => panic!("expected PushFailed for cp-rbac-member, got {other:?}"),
    }

    // Alpha was pushed (delete + create); member's delete then failed-create.
    // Zeta must NOT appear at all.
    let calls = vp.calls();
    let names: Vec<&str> = calls
        .iter()
        .map(|c| match c {
            StubCall::CreatePolicy { name, .. } => name.as_str(),
            StubCall::DeletePolicyByName { name, .. } => name.as_str(),
            StubCall::ListPolicyIds { .. } => unreachable!("saga does not list"),
        })
        .collect();
    assert!(
        !names.contains(&"cp-rbac-zeta"),
        "saga must stop before reaching zeta; calls were {names:?}"
    );
}

// ---- Test 4: idempotent re-run pushes the same set of permits ----

#[tokio::test]
async fn second_run_against_same_stub_repeats_delete_then_create() {
    let entries = vec![make_entry("alpha", &["cp:x:read"], &[])];
    let (store, org_id) = seed_org_with_groups(entries).await;
    let vp = StubVpClient::new();
    let tenant = TenantConfig::default();

    materialize_groups_to_vp(make_params(&store, &vp, &org_id, "org-saga-test", &tenant))
        .await
        .unwrap();
    materialize_groups_to_vp(make_params(&store, &vp, &org_id, "org-saga-test", &tenant))
        .await
        .unwrap();

    // Two runs × (1 delete + 1 create) = 4 calls. The second run's delete
    // succeeds (the first run's create populated the stub); both creates
    // succeed because the preceding delete cleared the slot.
    assert_eq!(vp.calls().len(), 4);
}

use std::collections::BTreeMap;

use forgeguard_authn_core::user_schema::{
    AttrType, CustomAttrName, CustomAttrSpec, StandardAttrName, StandardAttrSpec,
};
use forgeguard_authn_core::UserSchema;
use forgeguard_core::OrganizationId;

use super::*;
use crate::etag::Etag;
use crate::store::OrgStore;

fn schema_with_name_required() -> UserSchema {
    let mut standard = BTreeMap::new();
    standard.insert(StandardAttrName::Name, StandardAttrSpec { required: true });
    UserSchema::new(standard, BTreeMap::new())
}

fn schema_with_custom_dept() -> UserSchema {
    let mut custom = BTreeMap::new();
    custom.insert(
        CustomAttrName::try_new("dept").unwrap(),
        CustomAttrSpec {
            ty: AttrType::String {
                min_length: Some(1),
                max_length: Some(20),
                required: false,
            },
        },
    );
    UserSchema::new(BTreeMap::new(), custom)
}

async fn fresh_store_with_draft_org(org_id_str: &str) -> (DynamoOrgStore, OrganizationId) {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;
    let store = DynamoOrgStore::new(client.clone(), table.clone());
    let now = chrono::Utc::now();
    let org_id = OrganizationId::new(org_id_str).unwrap();
    let org = forgeguard_core::Organization::new(
        org_id.clone(),
        "User Schema Test Org".to_string(),
        forgeguard_core::OrgStatus::Draft,
        now,
    );
    put_test_org(&client, &table, &org, None).await;
    (store, org_id)
}

#[tokio::test]
async fn dynamodb_get_user_schema_absent_returns_none() {
    let (store, org_id) = fresh_store_with_draft_org("dus-absent").await;
    let result = store.get_user_schema(&org_id).await.unwrap();
    assert!(result.is_none(), "fresh org has no user_schema row");
}

#[tokio::test]
async fn dynamodb_put_user_schema_create_no_etag_succeeds() {
    let (store, org_id) = fresh_store_with_draft_org("dus-create").await;
    let written = store
        .put_user_schema(&org_id, schema_with_name_required(), None)
        .await
        .unwrap();
    assert!(!written.etag().as_str().is_empty());
    assert!(
        written.etag().as_str().starts_with('"') && written.etag().as_str().ends_with('"'),
        "etag must be a quoted string, got: {}",
        written.etag()
    );

    let fetched = store.get_user_schema(&org_id).await.unwrap().unwrap();
    assert_eq!(fetched.etag(), written.etag());
    assert_eq!(fetched.schema(), &schema_with_name_required());
}

#[tokio::test]
async fn dynamodb_put_user_schema_create_with_etag_conflicts() {
    let (store, org_id) = fresh_store_with_draft_org("dus-create-etag").await;
    let etag = Etag::try_new("\"anything\"").unwrap();
    let result = store
        .put_user_schema(&org_id, schema_with_name_required(), Some(&etag))
        .await;

    match result {
        Err(crate::error::Error::PreconditionFailed { current_etag }) => {
            assert!(
                current_etag.is_none(),
                "no row exists yet — current etag must be None"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
}

#[tokio::test]
async fn dynamodb_put_user_schema_update_matching_etag_succeeds() {
    let (store, org_id) = fresh_store_with_draft_org("dus-update").await;
    let created = store
        .put_user_schema(&org_id, schema_with_name_required(), None)
        .await
        .unwrap();
    let etag = created.etag().clone();

    let updated = store
        .put_user_schema(&org_id, schema_with_custom_dept(), Some(&etag))
        .await
        .unwrap();
    assert_ne!(updated.etag(), &etag, "content changed → etag must change");
    assert_eq!(updated.schema(), &schema_with_custom_dept());

    let fetched = store.get_user_schema(&org_id).await.unwrap().unwrap();
    assert_eq!(fetched.etag(), updated.etag());
}

#[tokio::test]
async fn dynamodb_put_user_schema_update_stale_etag_returns_412() {
    let (store, org_id) = fresh_store_with_draft_org("dus-stale").await;
    let created = store
        .put_user_schema(&org_id, schema_with_name_required(), None)
        .await
        .unwrap();
    let stored_etag = created.etag().clone();

    let stale = Etag::try_new("\"definitely-stale\"").unwrap();
    let result = store
        .put_user_schema(&org_id, schema_with_custom_dept(), Some(&stale))
        .await;

    match result {
        Err(crate::error::Error::PreconditionFailed { current_etag }) => {
            assert_eq!(current_etag, Some(stored_etag));
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
}

#[tokio::test]
async fn dynamodb_put_user_schema_idempotent_same_content() {
    let (store, org_id) = fresh_store_with_draft_org("dus-idemp").await;
    let created = store
        .put_user_schema(&org_id, schema_with_name_required(), None)
        .await
        .unwrap();
    let etag = created.etag().clone();

    let again = store
        .put_user_schema(&org_id, schema_with_name_required(), Some(&etag))
        .await
        .unwrap();
    assert_eq!(
        again.etag(),
        &etag,
        "etag is content-addressed — same content yields same etag"
    );
}

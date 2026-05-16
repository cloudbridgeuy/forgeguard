#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use forgeguard_authn_core::user_schema::{
    AttrType, CustomAttrName, CustomAttrSpec, StandardAttrName, StandardAttrSpec,
};
use forgeguard_authn_core::UserSchema;
use forgeguard_core::OrganizationId;

use crate::error::Error;
use crate::store::{InMemoryOrgStore, OrgStore};

fn store() -> InMemoryOrgStore {
    InMemoryOrgStore::new(BTreeMap::new())
}

fn org(id: &str) -> OrganizationId {
    OrganizationId::new(id).unwrap()
}

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

#[tokio::test]
async fn get_user_schema_absent_returns_none() {
    let s = store();
    let oid = org("org-us-absent");
    let result = s.get_user_schema(&oid).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn put_user_schema_create_no_etag_succeeds() {
    let s = store();
    let oid = org("org-us-create");
    let written = s
        .put_user_schema(&oid, schema_with_name_required(), None)
        .await
        .unwrap();
    assert!(!written.etag().as_str().is_empty());
    assert_eq!(written.schema(), &schema_with_name_required());
}

#[tokio::test]
async fn put_user_schema_create_with_etag_conflicts() {
    use crate::etag::Etag;

    let s = store();
    let oid = org("org-us-create-etag");
    let etag = Etag::try_new("\"anything\"").unwrap();
    let result = s
        .put_user_schema(&oid, schema_with_name_required(), Some(&etag))
        .await;

    match result {
        Err(Error::PreconditionFailed { current_etag }) => {
            assert!(
                current_etag.is_none(),
                "no row exists yet — current etag should be None"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
}

#[tokio::test]
async fn put_user_schema_update_matching_etag_succeeds() {
    let s = store();
    let oid = org("org-us-update");
    let created = s
        .put_user_schema(&oid, schema_with_name_required(), None)
        .await
        .unwrap();
    let etag = created.etag().clone();

    let updated = s
        .put_user_schema(&oid, schema_with_custom_dept(), Some(&etag))
        .await
        .unwrap();

    assert_ne!(updated.etag(), &etag, "content changed → etag must change");
    assert_eq!(updated.schema(), &schema_with_custom_dept());
}

#[tokio::test]
async fn put_user_schema_update_stale_etag_returns_412() {
    use crate::etag::Etag;

    let s = store();
    let oid = org("org-us-stale");
    let created = s
        .put_user_schema(&oid, schema_with_name_required(), None)
        .await
        .unwrap();
    let stored_etag = created.etag().clone();

    let stale = Etag::try_new("\"definitely-stale\"").unwrap();
    let result = s
        .put_user_schema(&oid, schema_with_custom_dept(), Some(&stale))
        .await;

    match result {
        Err(Error::PreconditionFailed { current_etag }) => {
            assert_eq!(current_etag, Some(stored_etag));
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
}

#[tokio::test]
async fn put_user_schema_idempotent_same_content() {
    let s = store();
    let oid = org("org-us-idemp");
    let created = s
        .put_user_schema(&oid, schema_with_name_required(), None)
        .await
        .unwrap();
    let etag = created.etag().clone();

    let again = s
        .put_user_schema(&oid, schema_with_name_required(), Some(&etag))
        .await
        .unwrap();
    assert_eq!(
        again.etag(),
        &etag,
        "etag is content-addressed — same content yields same etag"
    );
}

#[tokio::test]
async fn user_schemas_are_isolated_per_org() {
    let s = store();
    let a = org("org-us-a");
    let b = org("org-us-b");

    s.put_user_schema(&a, schema_with_name_required(), None)
        .await
        .unwrap();

    assert!(s.get_user_schema(&b).await.unwrap().is_none());
    assert!(s.get_user_schema(&a).await.unwrap().is_some());
}

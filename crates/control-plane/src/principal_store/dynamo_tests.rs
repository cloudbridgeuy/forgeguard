//! DynamoDB-Local integration tests for `principal_store.rs`, feature-gated
//! behind `dynamodb-tests` (see `.claude/context/seed-qa.md`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_dynamodb::types::{
    AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput, ScalarAttributeType,
};
use forgeguard_authz_core::Actor;
use forgeguard_core::Segment;
use tokio::sync::OnceCell;

use super::*;

async fn warm_engine_once(client: &aws_sdk_dynamodb::Client) {
    static WARMED: OnceCell<()> = OnceCell::const_new();
    WARMED
        .get_or_init(|| async {
            const MAX_ATTEMPTS: u32 = 25;
            for _ in 0..MAX_ATTEMPTS {
                if client.list_tables().send().await.is_ok() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            panic!("DynamoDB Local did not become ready");
        })
        .await;
}

async fn test_client() -> aws_sdk_dynamodb::Client {
    let endpoint =
        std::env::var("DYNAMODB_ENDPOINT").unwrap_or_else(|_| "http://localhost:8000".to_string());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .region(aws_config::Region::new("us-east-1"))
        .test_credentials()
        .load()
        .await;
    let client = aws_sdk_dynamodb::Client::new(&config);
    warm_engine_once(&client).await;
    client
}

fn unique_table_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test-principal-{ts}-{n}")
}

async fn create_test_table(client: &aws_sdk_dynamodb::Client, table_name: &str) {
    client
        .create_table()
        .table_name(table_name)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name(pk())
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name(sk())
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(pk())
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(sk())
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .provisioned_throughput(
            ProvisionedThroughput::builder()
                .read_capacity_units(5)
                .write_capacity_units(5)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn put_then_get_round_trips() {
    let client = test_client().await;
    let table_name = unique_table_name();
    create_test_table(&client, &table_name).await;

    let native_id = NativeId::try_new("usr_1").unwrap();
    let payload = serde_json::json!({ "role": "admin" });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let state =
        principal_state_put("acme", &native_id, &payload_bytes, "2026-07-14T00:00:00Z").unwrap();

    let mut item = state.attributes.clone();
    item.insert(pk().to_string(), AttributeValue::S(state.pk.clone()));
    item.insert(sk().to_string(), AttributeValue::S(state.sk.clone()));
    client
        .put_item()
        .table_name(&table_name)
        .set_item(Some(item))
        .send()
        .await
        .unwrap();

    let fetched = get_principal(&client, &table_name, "acme", &native_id)
        .await
        .unwrap();
    assert_eq!(fetched, Some(payload));
}

#[tokio::test]
async fn missing_principal_returns_none() {
    let client = test_client().await;
    let table_name = unique_table_name();
    create_test_table(&client, &table_name).await;

    let native_id = NativeId::try_new("usr_missing").unwrap();
    let fetched = get_principal(&client, &table_name, "acme", &native_id)
        .await
        .unwrap();
    assert_eq!(fetched, None);
}

#[tokio::test]
async fn promotion_put_get_list_tombstone_roundtrip() {
    let client = test_client().await;
    let table_name = unique_table_name();
    create_test_table(&client, &table_name).await;
    let store = DynamoPrincipalEventStore::new(client, table_name);

    let resource_type = Segment::try_new("document").unwrap();
    let native_id = NativeId::try_new("doc_1").unwrap();
    let actor = Actor::System;

    let revision = store
        .put_promotion("acme", &resource_type, &native_id, actor.clone())
        .await
        .unwrap();
    assert_eq!(revision, Revision::new(1));

    let fgrn = store
        .get_promotion("acme", &resource_type, &native_id)
        .await
        .unwrap();
    assert_eq!(fgrn, Some("fgrn:acme:resource:document/doc_1".to_string()));

    let entries = store
        .list_promotions("acme", &resource_type, None, 10)
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].native_id, "doc_1");

    let tombstoned = store
        .tombstone_promotion("acme", &resource_type, &native_id, actor.clone())
        .await
        .unwrap();
    assert_eq!(tombstoned, Some(Revision::new(2)));

    let gone = store
        .get_promotion("acme", &resource_type, &native_id)
        .await
        .unwrap();
    assert_eq!(gone, None);

    let repeat = store
        .tombstone_promotion("acme", &resource_type, &native_id, actor)
        .await
        .unwrap();
    assert_eq!(repeat, None);

    let log = DynamoEventLog::new(store.client.clone(), store.table_name.clone(), "acme");
    let counter = EventLog::latest_revision(&log).await.unwrap();
    assert_eq!(counter, Revision::new(2));
}

#[tokio::test]
async fn list_signing_keys_empty_before_any_append() {
    let client = test_client().await;
    let table_name = unique_table_name();
    create_test_table(&client, &table_name).await;
    let store = DynamoPrincipalEventStore::new(client, table_name);

    let keys = store.list_signing_keys("acme").await.unwrap();
    assert!(keys.is_empty());
}

#[tokio::test]
async fn list_signing_keys_verifies_appended_event() {
    use base64::Engine as _;
    use forgeguard_authn_core::signing::{verify_bytes, VerifyingKey};
    use forgeguard_authz_core::canonical_envelope_bytes;

    let client = test_client().await;
    let table_name = unique_table_name();
    create_test_table(&client, &table_name).await;
    let store = DynamoPrincipalEventStore::new(client, table_name);

    let native_id = NativeId::try_new("usr_1").unwrap();
    store
        .upsert_changed(
            "acme",
            &native_id,
            Actor::System,
            serde_json::json!({"role": "admin"}),
        )
        .await
        .unwrap();

    let keys = store.list_signing_keys("acme").await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id, "event-signing-key-1");

    let events = EventLog::events_after(
        &DynamoEventLog::new(store.client.clone(), store.table_name.clone(), "acme"),
        Revision::new(0),
        10,
    )
    .await
    .unwrap();
    let envelope = &events[0];

    let vk = VerifyingKey::from_public_key_pem(&keys[0].public_key_pem).unwrap();
    let sig_bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(envelope.signature())
        .unwrap()
        .try_into()
        .unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let bytes = canonical_envelope_bytes(envelope, "acme");
    assert!(verify_bytes(&vk, &bytes, &sig).is_ok());
}

/// V5 demo, DynamoDB half: `fold_at(N)` time-travels; `fold_at(None)`
/// matches the strongly-read state items; unknown revision errors.
#[tokio::test]
async fn fold_at_time_travels_and_matches_state_items() {
    let client = test_client().await;
    let table_name = unique_table_name();
    create_test_table(&client, &table_name).await;
    let store = DynamoPrincipalEventStore::new(client, table_name);

    let usr = NativeId::try_new("usr_1").unwrap();
    let doc_type = Segment::try_new("document").unwrap();
    let doc = NativeId::try_new("doc_1").unwrap();

    store
        .upsert_changed(
            "acme",
            &usr,
            Actor::System,
            serde_json::json!({"role": "admin"}),
        )
        .await
        .unwrap();
    store
        .upsert_changed(
            "acme",
            &usr,
            Actor::System,
            serde_json::json!({"role": "viewer"}),
        )
        .await
        .unwrap();
    store
        .put_promotion("acme", &doc_type, &doc, Actor::System)
        .await
        .unwrap();
    store
        .tombstone_promotion("acme", &doc_type, &doc, Actor::System)
        .await
        .unwrap();

    let at_1 = store.fold_at("acme", Some(Revision::new(1))).await.unwrap();
    assert_eq!(
        at_1.principal("usr_1"),
        Some(&serde_json::json!({"role": "admin"}))
    );
    assert!(at_1.promotions().is_empty());

    let at_3 = store.fold_at("acme", Some(Revision::new(3))).await.unwrap();
    assert_eq!(
        at_3.promotion("document", "doc_1"),
        Some("fgrn:acme:resource:document/doc_1")
    );

    // Latest fold matches the state items the hot path reads.
    let latest = store.fold_at("acme", None).await.unwrap();
    assert_eq!(latest.revision(), Revision::new(4));
    let principal_item = store.get_principal("acme", &usr).await.unwrap();
    assert_eq!(latest.principal("usr_1"), principal_item.as_ref());
    let promotion_item = store.get_promotion("acme", &doc_type, &doc).await.unwrap();
    assert_eq!(promotion_item, None);
    assert_eq!(latest.promotion("document", "doc_1"), None);

    let err = store
        .fold_at("acme", Some(Revision::new(9)))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown revision 9"));
}

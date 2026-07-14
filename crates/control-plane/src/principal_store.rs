//! Principal state item mapping (D6): the imperative shell around
//! [`forgeguard_authz_core::decide_upsert`].
//!
//! Not yet wired into a handler (that lands with the principal upsert
//! endpoint), so the production build sees these items as unused until then.
#![allow(dead_code)]

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_core::NativeId;

use crate::dynamo_store::{get_s, map_sdk_error, pk, sk, ORG_PREFIX};
use crate::error::{Error, Result};
use crate::event_log::StatePut;

const PRINCIPAL_PREFIX: &str = "PRINCIPAL#";

/// Build the `StatePut` for a principal's current payload.
///
/// `PK=ORG#{org_id}, SK=PRINCIPAL#{native_id}`, carrying `payload` (the exact
/// canonical bytes, as a UTF-8 string) and `updated_at` (RFC3339, minted by
/// the caller — this function stays a pure mapping).
pub(crate) fn principal_state_put(
    org_id: &str,
    native_id: &NativeId,
    payload_bytes: &[u8],
    updated_at: &str,
) -> Result<StatePut> {
    let payload = std::str::from_utf8(payload_bytes)
        .map_err(|e| Error::Store(format!("principal payload is not valid UTF-8: {e}")))?;

    let mut attributes = HashMap::new();
    attributes.insert(
        "payload".to_string(),
        AttributeValue::S(payload.to_string()),
    );
    attributes.insert(
        "updated_at".to_string(),
        AttributeValue::S(updated_at.to_string()),
    );

    Ok(StatePut {
        pk: format!("{ORG_PREFIX}{org_id}"),
        sk: format!("{PRINCIPAL_PREFIX}{native_id}"),
        attributes,
    })
}

/// Strongly-consistent read of a principal's current payload.
///
/// Must be consistent, not eventually-consistent: `decide_upsert` compares
/// against this value, and a stale replica-lagged read could produce a
/// spurious `NoOp` or a spurious `Changed` (D6).
pub(crate) async fn get_principal(
    client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    org_id: &str,
    native_id: &NativeId,
) -> Result<Option<serde_json::Value>> {
    let result = client
        .get_item()
        .table_name(table_name)
        .key(pk(), AttributeValue::S(format!("{ORG_PREFIX}{org_id}")))
        .key(
            sk(),
            AttributeValue::S(format!("{PRINCIPAL_PREFIX}{native_id}")),
        )
        .consistent_read(true)
        .send()
        .await
        .map_err(map_sdk_error)?;

    let Some(item) = result.item else {
        return Ok(None);
    };
    let payload = get_s(&item, "payload")?;
    serde_json::from_str(&payload)
        .map_err(|e| Error::Store(format!("deserialize principal payload: {e}")))
        .map(Some)
}

#[cfg(test)]
#[cfg(feature = "dynamodb-tests")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use aws_sdk_dynamodb::types::{
        AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput, ScalarAttributeType,
    };
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
        let endpoint = std::env::var("DYNAMODB_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());
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
        let state = principal_state_put("acme", &native_id, &payload_bytes, "2026-07-14T00:00:00Z")
            .unwrap();

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
}

//! DynamoDB-backed [`SigningKeyStore`] for Ed25519 public key lookup.
//!
//! Reads the org item from DynamoDB, deserializes the `signing_keys` attribute,
//! finds the requested key, validates its status, and parses the PEM into a
//! [`VerifyingKey`].

use std::future::Future;
use std::pin::Pin;

use chrono::Utc;
use forgeguard_authn_core::signing::VerifyingKey;
use forgeguard_authn_core::SigningKeyStore;

use aws_sdk_dynamodb::types::AttributeValue;

use crate::dynamo_store::{pk, signing_keys_from_item, sk, ORG_PREFIX, SK_META};

/// Shorthand: wrap a message in `forgeguard_authn_core::Error::InvalidCredential`.
fn invalid_credential(msg: impl Into<String>) -> forgeguard_authn_core::Error {
    forgeguard_authn_core::Error::InvalidCredential(msg.into())
}

/// DynamoDB-backed signing key store.
///
/// Implements [`SigningKeyStore`] by reading the org item from DynamoDB,
/// finding the key entry, and converting the stored PEM to a [`VerifyingKey`].
pub(crate) struct DynamoSigningKeyStore {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoSigningKeyStore {
    pub(crate) fn new(client: aws_sdk_dynamodb::Client, table_name: String) -> Self {
        Self { client, table_name }
    }
}

impl SigningKeyStore for DynamoSigningKeyStore {
    fn get_key(
        &self,
        org_id: &str,
        key_id: &str,
    ) -> Pin<Box<dyn Future<Output = forgeguard_authn_core::Result<VerifyingKey>> + Send + '_>>
    {
        let org_id = org_id.to_string();
        let key_id = key_id.to_string();

        Box::pin(async move {
            let pk_value = format!("{ORG_PREFIX}{org_id}");

            let result = self
                .client
                .get_item()
                .table_name(&self.table_name)
                .key(pk(), AttributeValue::S(pk_value))
                .key(sk(), AttributeValue::S(SK_META.to_string()))
                .send()
                .await
                .map_err(|e| invalid_credential(e.to_string()))?;

            let item = result
                .item
                .ok_or_else(|| invalid_credential(format!("organization '{org_id}' not found")))?;

            let keys =
                signing_keys_from_item(&item).map_err(|e| invalid_credential(e.to_string()))?;

            let entry = keys.iter().find(|k| k.key_id() == key_id).ok_or_else(|| {
                invalid_credential(format!(
                    "signing key '{key_id}' not found for org '{org_id}'"
                ))
            })?;

            let now = Utc::now();
            if !entry.is_active(now) {
                return Err(invalid_credential(format!(
                    "key '{key_id}' for org '{org_id}' is not active (status: {})",
                    entry.status()
                )));
            }

            VerifyingKey::from_public_key_pem(entry.public_key_pem())
        })
    }
}

// ---------------------------------------------------------------------------
// Integration tests — feature-gated behind `dynamodb-tests`
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "dynamodb-tests")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::dynamo_store::{pk, sk};
    use crate::store::OrgStore;

    use aws_sdk_dynamodb::types::{
        AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput, ScalarAttributeType,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    async fn test_client() -> aws_sdk_dynamodb::Client {
        let endpoint = std::env::var("DYNAMODB_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .endpoint_url(endpoint)
            .region(aws_config::Region::new("us-east-1"))
            .test_credentials()
            .load()
            .await;
        aws_sdk_dynamodb::Client::new(&config)
    }

    fn unique_table_name() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("test-sks-{ts}-{n}")
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

    fn sample_config() -> crate::config::OrgConfig {
        serde_json::from_value(serde_json::json!({
            "version": "2026-04-07",
            "project_id": "todo-app",
            "upstream_url": "https://api.acme.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }))
        .unwrap()
    }

    /// Helper: create an `OrgStore` + `DynamoSigningKeyStore` sharing the same
    /// table, with one org already inserted.
    async fn setup_with_org(
        org_id_str: &str,
    ) -> (
        crate::dynamo_store::DynamoOrgStore,
        DynamoSigningKeyStore,
        forgeguard_core::OrganizationId,
    ) {
        let client = test_client().await;
        let table = unique_table_name();
        create_test_table(&client, &table).await;

        let org_store = crate::dynamo_store::DynamoOrgStore::new(client.clone(), table.clone());
        let key_store = DynamoSigningKeyStore::new(client, table);

        let org_id = forgeguard_core::OrganizationId::new(org_id_str).unwrap();
        let org = forgeguard_core::Organization::new(
            org_id.clone(),
            "Test Org".to_string(),
            forgeguard_core::OrgStatus::Draft,
            chrono::Utc::now(),
        );
        org_store.create(org, sample_config()).await.unwrap();

        (org_store, key_store, org_id)
    }

    #[tokio::test]
    async fn get_key_returns_active_key() {
        let (org_store, key_store, org_id) = setup_with_org("org-sks-active").await;

        // Generate a key via the org store
        let generated = org_store.generate_key(&org_id).await.unwrap();

        // Look it up via the signing key store
        let vk = key_store
            .get_key(org_id.as_str(), generated.key_id())
            .await
            .unwrap();

        // Verify we got a valid key by parsing the original PEM and comparing
        let expected = VerifyingKey::from_public_key_pem(generated.public_key_pem()).unwrap();

        // Sign with a fresh signing key derived from the generated PEM and verify
        // with both keys — but since we only have the public PEM, we just confirm
        // the returned key is parseable and matches by signing a test payload.
        use forgeguard_authn_core::signing::{
            sign, verify, CanonicalPayload, KeyId, SigningKey, Timestamp,
        };

        let sk = SigningKey::from_pkcs8_pem(generated.private_key_pem()).unwrap();
        let key_id = KeyId::try_from(generated.key_id().to_string()).unwrap();
        let ts = Timestamp::from_millis(1);
        let payload = CanonicalPayload::new("t", ts, &[]);
        let signed = sign(&sk, &key_id, &payload, ts, "t".into());

        // Verify with the key returned from the store
        assert!(verify(&vk, &payload, signed.signature()).is_ok());
        // Also verify with the expected key for good measure
        assert!(verify(&expected, &payload, signed.signature()).is_ok());
    }

    #[tokio::test]
    async fn get_key_revoked_returns_error() {
        let (org_store, key_store, org_id) = setup_with_org("org-sks-revoked").await;

        let generated = org_store.generate_key(&org_id).await.unwrap();
        org_store
            .revoke_key(&org_id, generated.key_id())
            .await
            .unwrap();

        let result = key_store.get_key(org_id.as_str(), generated.key_id()).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not active"),
            "expected 'not active' in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn get_key_unknown_key_returns_error() {
        let (_org_store, key_store, org_id) = setup_with_org("org-sks-unknown-key").await;

        let result = key_store
            .get_key(org_id.as_str(), "key-does-not-exist")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "expected 'not found' in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn get_key_unknown_org_returns_error() {
        let client = test_client().await;
        let table = unique_table_name();
        create_test_table(&client, &table).await;

        let key_store = DynamoSigningKeyStore::new(client, table);

        let result = key_store.get_key("org-nonexistent", "key-abc").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "expected 'not found' in error, got: {msg}"
        );
    }
}

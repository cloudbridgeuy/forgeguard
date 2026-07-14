//! Principal state item mapping (D6): the imperative shell around
//! [`forgeguard_authz_core::decide_upsert`].
//!
//! Also carries the `PrincipalEventStore` seam (Task 7): the trait-object
//! boundary the `upsert_principal` handler uses so `InMemoryPrincipalEventStore`
//! can stand in for `DynamoPrincipalEventStore` in handler tests without a
//! DynamoDB Local dependency.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_authn_core::signing::{sign_bytes, SigningKey};
use forgeguard_authz_core::{
    canonical_event_bytes, Actor, EventDraft, EventDraftParams, EventEnvelope, EventId, EventKind,
    EventLog, InMemoryEventLog, Revision,
};
use forgeguard_core::NativeId;

use crate::dynamo_store::{get_s, map_sdk_error, pk, sk, ORG_PREFIX};
use crate::error::{Error, Result};
use crate::event_log::{DynamoEventLog, StatePut};

const PRINCIPAL_PREFIX: &str = "PRINCIPAL#";
const SK_EVENT_SIGNING_KEY: &str = "EVENT_SIGNING_KEY";
const EVENT_SIGNING_KEY_ID: &str = "event-signing-key-1";

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
    serde_json::from_str::<serde_json::Value>(payload)
        .map_err(|e| Error::Store(format!("principal payload is not valid JSON: {e}")))?;

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

// ---------------------------------------------------------------------------
// PrincipalEventStore — the seam `upsert_principal` (Task 7) is written against
// ---------------------------------------------------------------------------

/// Everything the `PUT /organizations/{org_id}/principals/{native_id}` handler
/// needs: a strongly-consistent principal read, the log's current revision,
/// and the full "mint + sign + append" shell for a `Changed` decision.
///
/// Bundling all three into one trait (rather than composing `EventLog` +
/// `get_principal` + a signing helper at the call site) keeps the handler
/// generic over `Arc<dyn PrincipalEventStore>` — the same object-safe seam
/// `OrgStore`/`SagaTicketStore` already establish — so `InMemoryPrincipalEventStore`
/// can stand in for the DynamoDB implementation in handler tests.
#[async_trait]
pub(crate) trait PrincipalEventStore: Send + Sync {
    /// Strongly-consistent read of a principal's current payload.
    async fn get_principal(
        &self,
        org_id: &str,
        native_id: &NativeId,
    ) -> Result<Option<serde_json::Value>>;

    /// The event log's current revision for `org_id`.
    async fn latest_revision(&self, org_id: &str) -> Result<Revision>;

    /// Mint an `EventId`/`occurred_at`, build+sign the envelope, and append it
    /// alongside the principal's new state item — all inside one transaction.
    async fn upsert_changed(
        &self,
        org_id: &str,
        native_id: &NativeId,
        actor: Actor,
        payload: serde_json::Value,
    ) -> Result<Revision>;

    /// Events with seq > `after`, ascending, at most `limit` — the read side
    /// the `GET /organizations/{org_id}/events` cursor handler (Task 8)
    /// replays through. Bundled onto this seam rather than a second parallel
    /// trait/`AppState` field: `PrincipalEventStore` already owns the per-org
    /// `EventLog` handle (`DynamoEventLog`/`InMemoryEventLog`) for the upsert
    /// path, so exposing `events_after` here reuses the exact same log
    /// instance instead of standing up a second seam to the same data.
    async fn events_after(
        &self,
        org_id: &str,
        after: Revision,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>>;
}

/// Parameters for [`build_principal_event`].
///
/// `native_id` isn't threaded into the signed bytes — the event envelope
/// carries no subject field of its own, since the principal's identity is
/// already implicit in the `StatePut` key it lands alongside — so this struct
/// carries no `native_id` field at all.
struct BuildPrincipalEventParams<'a> {
    org_id: &'a str,
    actor: Actor,
    payload: serde_json::Value,
    signing_key: &'a SigningKey,
    key_id: &'a str,
    occurred_at: &'a str,
    revision: Revision,
}

/// Build the signed `EventEnvelope` + canonical payload bytes for a principal
/// upsert at `revision`, given an already-loaded signing key.
fn build_principal_event(
    params: BuildPrincipalEventParams<'_>,
) -> (forgeguard_authz_core::EventEnvelope, Vec<u8>) {
    let BuildPrincipalEventParams {
        org_id,
        actor,
        payload,
        signing_key,
        key_id,
        occurred_at,
        revision,
    } = params;

    let event_id = EventId::try_new(ulid::Ulid::new().to_string())
        .unwrap_or_else(|_| unreachable!("ulid string is always non-empty"));
    let draft = EventDraft::new(EventDraftParams {
        event_id,
        seq: revision,
        kind: EventKind::PrincipalUpserted,
        occurred_at: occurred_at.to_string(),
        actor,
        payload: payload.clone(),
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let canonical_bytes = canonical_event_bytes(&draft, org_id);
    let signature = sign_bytes(signing_key, &canonical_bytes);
    let signature_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes(),
    );
    let envelope =
        forgeguard_authz_core::EventEnvelope::from_signed(draft, key_id.to_string(), signature_b64);
    (envelope, payload_bytes)
}

// ---------------------------------------------------------------------------
// DynamoDB implementation
// ---------------------------------------------------------------------------

/// DynamoDB-backed [`PrincipalEventStore`].
pub(crate) struct DynamoPrincipalEventStore {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoPrincipalEventStore {
    pub(crate) fn new(client: aws_sdk_dynamodb::Client, table_name: String) -> Self {
        Self { client, table_name }
    }

    /// Read the org's Ed25519 event-signing key, minting and persisting one
    /// lazily on first use. The private key material lives only in this
    /// dedicated item (`SK=EVENT_SIGNING_KEY`) — distinct from the public
    /// `signing_keys` list `crate::store::generate_key_material` populates for
    /// externally-verifiable request signing, since here the control plane is
    /// the signer, not the verifier.
    async fn ensure_signing_key(&self, org_id: &str) -> Result<(SigningKey, String)> {
        let pk_value = format!("{ORG_PREFIX}{org_id}");

        let existing = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(pk_value.clone()))
            .key(sk(), AttributeValue::S(SK_EVENT_SIGNING_KEY.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(map_sdk_error)?;

        if let Some(item) = existing.item {
            let private_pem = get_s(&item, "private_key_pem")?;
            let key_id = get_s(&item, "key_id")?;
            let signing_key = SigningKey::from_pkcs8_pem(&private_pem)
                .map_err(|e| Error::Store(format!("stored event signing key invalid: {e}")))?;
            return Ok((signing_key, key_id));
        }

        // Not present — mint one. Reuses `generate_key_material`, the same
        // Ed25519-keypair-generation routine `OrgStore::generate_key` uses,
        // so keygen logic lives in exactly one place.
        let generated = crate::store::generate_key_material()?;

        let mut item = HashMap::new();
        item.insert(pk().to_string(), AttributeValue::S(pk_value));
        item.insert(
            sk().to_string(),
            AttributeValue::S(SK_EVENT_SIGNING_KEY.to_string()),
        );
        item.insert(
            "key_id".to_string(),
            AttributeValue::S(EVENT_SIGNING_KEY_ID.to_string()),
        );
        item.insert(
            "private_key_pem".to_string(),
            AttributeValue::S(generated.private_key_pem().to_string()),
        );

        // Conditional put: if a concurrent request minted the key first, fall
        // back to re-reading its item rather than clobbering it.
        let put_result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression(format!("attribute_not_exists({})", sk()))
            .send()
            .await;

        match put_result {
            Ok(_) => {
                let signing_key =
                    SigningKey::from_pkcs8_pem(generated.private_key_pem()).map_err(|e| {
                        Error::Store(format!("generated event signing key invalid: {e}"))
                    })?;
                Ok((signing_key, EVENT_SIGNING_KEY_ID.to_string()))
            }
            Err(sdk_err) => {
                let is_conflict = matches!(
                    &sdk_err,
                    aws_sdk_dynamodb::error::SdkError::ServiceError(e)
                        if e.err().is_conditional_check_failed_exception()
                );
                if !is_conflict {
                    return Err(map_sdk_error(sdk_err));
                }
                // Lost the race — re-read the winner's key.
                Box::pin(self.ensure_signing_key(org_id)).await
            }
        }
    }
}

#[async_trait]
impl PrincipalEventStore for DynamoPrincipalEventStore {
    async fn get_principal(
        &self,
        org_id: &str,
        native_id: &NativeId,
    ) -> Result<Option<serde_json::Value>> {
        get_principal(&self.client, &self.table_name, org_id, native_id).await
    }

    async fn latest_revision(&self, org_id: &str) -> Result<Revision> {
        let log = DynamoEventLog::new(self.client.clone(), self.table_name.clone(), org_id);
        EventLog::latest_revision(&log)
            .await
            .map_err(|e| Error::Store(e.to_string()))
    }

    async fn upsert_changed(
        &self,
        org_id: &str,
        native_id: &NativeId,
        actor: Actor,
        payload: serde_json::Value,
    ) -> Result<Revision> {
        let (signing_key, key_id) = self.ensure_signing_key(org_id).await?;
        let occurred_at = chrono::Utc::now().to_rfc3339();
        let log = DynamoEventLog::new(self.client.clone(), self.table_name.clone(), org_id);

        let org_id_owned = org_id.to_string();
        let payload_for_state = payload.clone();
        let build = move |revision: Revision| {
            build_principal_event(BuildPrincipalEventParams {
                org_id: &org_id_owned,
                actor: actor.clone(),
                payload: payload_for_state.clone(),
                signing_key: &signing_key,
                key_id: &key_id,
                occurred_at: &occurred_at,
                revision,
            })
        };

        // Peek the payload bytes once up front for the `StatePut` — the
        // exact bytes stored are `serde_json::to_vec(&payload)`, matching
        // what `build_principal_event` embeds in the envelope.
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| Error::Store(format!("serialize principal payload: {e}")))?;
        let updated_at = chrono::Utc::now().to_rfc3339();
        let state = principal_state_put(org_id, native_id, &payload_bytes, &updated_at)?;

        log.append(build, state).await
    }

    async fn events_after(
        &self,
        org_id: &str,
        after: Revision,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>> {
        let log = DynamoEventLog::new(self.client.clone(), self.table_name.clone(), org_id);
        EventLog::events_after(&log, after, limit)
            .await
            .map_err(|e| Error::Store(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation — dev-mode `--store=memory` backing and handler
// tests
// ---------------------------------------------------------------------------

/// In-memory [`PrincipalEventStore`]. Backs `--store=memory` dev mode and lets
/// handler tests exercise the full upsert flow (including a real Ed25519
/// signature) without DynamoDB Local.
pub(crate) struct InMemoryPrincipalEventStore {
    principals: Mutex<HashMap<(String, NativeId), serde_json::Value>>,
    /// One log per org — a shared log would leak one org's events into
    /// another org's `events_after`/`latest_revision` read. `Arc`-wrapped so
    /// the map's lock can be dropped before `.await`-ing the log itself
    /// (`std::sync::MutexGuard` isn't `Send`, and this trait's futures must be).
    logs: Mutex<HashMap<String, std::sync::Arc<InMemoryEventLog>>>,
    signing_key: SigningKey,
}

impl InMemoryPrincipalEventStore {
    pub(crate) fn new() -> Self {
        Self {
            principals: Mutex::new(HashMap::new()),
            logs: Mutex::new(HashMap::new()),
            signing_key: SigningKey::from_bytes(&[7u8; 32]),
        }
    }

    fn log_for(&self, org_id: &str) -> Result<std::sync::Arc<InMemoryEventLog>> {
        let mut logs = self
            .logs
            .lock()
            .map_err(|e| Error::Store(format!("in-memory event log map lock poisoned: {e}")))?;
        Ok(std::sync::Arc::clone(
            logs.entry(org_id.to_string())
                .or_insert_with(|| std::sync::Arc::new(InMemoryEventLog::new())),
        ))
    }
}

impl Default for InMemoryPrincipalEventStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PrincipalEventStore for InMemoryPrincipalEventStore {
    async fn get_principal(
        &self,
        org_id: &str,
        native_id: &NativeId,
    ) -> Result<Option<serde_json::Value>> {
        let guard = self
            .principals
            .lock()
            .map_err(|e| Error::Store(format!("in-memory principal store lock poisoned: {e}")))?;
        Ok(guard.get(&(org_id.to_string(), native_id.clone())).cloned())
    }

    async fn latest_revision(&self, org_id: &str) -> Result<Revision> {
        let log = self.log_for(org_id)?;
        EventLog::latest_revision(log.as_ref())
            .await
            .map_err(|e| Error::Store(e.to_string()))
    }

    async fn upsert_changed(
        &self,
        org_id: &str,
        native_id: &NativeId,
        actor: Actor,
        payload: serde_json::Value,
    ) -> Result<Revision> {
        let log = self.log_for(org_id)?;
        let current = EventLog::latest_revision(log.as_ref())
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
        let revision = current.next();
        let occurred_at = chrono::Utc::now().to_rfc3339();
        let (envelope, _payload_bytes) = build_principal_event(BuildPrincipalEventParams {
            org_id,
            actor,
            payload: payload.clone(),
            signing_key: &self.signing_key,
            key_id: "in-memory-test-key",
            occurred_at: &occurred_at,
            revision,
        });
        log.push(envelope);

        let mut guard = self
            .principals
            .lock()
            .map_err(|e| Error::Store(format!("in-memory principal store lock poisoned: {e}")))?;
        guard.insert((org_id.to_string(), native_id.clone()), payload);
        Ok(revision)
    }

    async fn events_after(
        &self,
        org_id: &str,
        after: Revision,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>> {
        let log = self.log_for(org_id)?;
        EventLog::events_after(log.as_ref(), after, limit)
            .await
            .map_err(|e| Error::Store(e.to_string()))
    }
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

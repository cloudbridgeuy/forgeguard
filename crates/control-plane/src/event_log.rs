//! DynamoDB-backed [`EventLog`] and transactional event-append shell (D9/A1).
//!
//! One [`DynamoEventLog`] is scoped to a single organization (mirroring the
//! trait's per-org contract: `events_after`/`latest_revision` take no
//! `org_id`). The counter, event, and state items written here deliberately
//! omit `GSI1PK`/`GSI1SK` so they stay out of the sparse GSI1 index (D10).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, TransactWriteItem, Update};
use forgeguard_authz_core::{
    EventDraft, EventDraftParams, EventEnvelope, EventId, EventKind, EventLog, Revision,
};

use crate::dynamo_store::{get_s, map_sdk_error, pk, sk, ORG_PREFIX};
use crate::error::{Error, Result};

const SK_SEQ: &str = "SEQ";
const EVT_PREFIX: &str = "EVT#";
/// Upper bound for the `events_after` sort-key range: greater than any real
/// `EVT#{seq:020}` key, but still less than the `SEQ` counter's sort key
/// (`E` < `S`), so the counter item never leaks into the query results.
const EVT_SK_MAX: &str = "EVT#99999999999999999999";
/// Retry ceiling for the counter-increment CAS race in [`DynamoEventLog::append`].
///
/// Higher than a single-writer workload strictly needs — under N concurrent
/// appends to the same org, a losing writer may need up to N-1 retries before
/// winning the counter CAS, so the ceiling must clear the highest expected
/// concurrent-writer count rather than a fixed small constant.
const MAX_APPEND_ATTEMPTS: u32 = 50;

/// Whether a [`StatePut`]'s state item must not already exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum StateGuard {
    /// No condition on the state item (the common case: create-or-overwrite).
    #[default]
    None,
    /// The state item must not already exist — used by org creation so a
    /// duplicate `create_org` cannot silently overwrite an existing org.
    MustNotExist,
}

/// One state write that must land atomically with its event (D9/A1).
pub(crate) struct StatePut {
    pub(crate) pk: String,
    pub(crate) sk: String,
    pub(crate) attributes: HashMap<String, AttributeValue>,
    pub(crate) guard: StateGuard,
}

/// One state delete that must land atomically with its event (D7: tombstone
/// hard-deletes the promotion item in the same transaction as the
/// `resource.tombstoned` event).
///
/// Wired up by `handlers/promotions/mod.rs` in Task 4; until then transitively
/// dead (its only caller, `ModelEventStore::tombstone_promotion`, is
/// itself unreachable from any handler yet).
#[allow(dead_code)]
pub(crate) struct StateDelete {
    pub(crate) pk: String,
    pub(crate) sk: String,
}

/// DynamoDB-backed event log for a single organization.
pub(crate) struct DynamoEventLog {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
    org_pk: String,
}

fn event_sk(seq: u64) -> String {
    format!("{EVT_PREFIX}{seq:020}")
}

/// Build the event item's attribute map from a signed envelope + its exact
/// canonical payload bytes.
fn event_item(
    org_pk: &str,
    envelope: &EventEnvelope,
    payload_bytes: &[u8],
) -> Result<HashMap<String, AttributeValue>> {
    let actor_json = serde_json::to_string(envelope.actor())
        .map_err(|e| Error::Store(format!("serialize event actor: {e}")))?;
    let payload_str = String::from_utf8(payload_bytes.to_vec())
        .map_err(|e| Error::Store(format!("event payload is not valid UTF-8: {e}")))?;

    let mut item = HashMap::new();
    item.insert(pk().to_string(), AttributeValue::S(org_pk.to_string()));
    item.insert(
        sk().to_string(),
        AttributeValue::S(event_sk(envelope.seq().value())),
    );
    item.insert(
        "event_id".to_string(),
        AttributeValue::S(envelope.event_id().as_str().to_string()),
    );
    item.insert(
        "seq".to_string(),
        AttributeValue::N(envelope.seq().value().to_string()),
    );
    item.insert(
        "kind".to_string(),
        AttributeValue::S(envelope.kind().as_str().to_string()),
    );
    item.insert(
        "occurred_at".to_string(),
        AttributeValue::S(envelope.occurred_at().to_string()),
    );
    item.insert("actor".to_string(), AttributeValue::S(actor_json));
    item.insert(
        "narrowing".to_string(),
        AttributeValue::Bool(envelope.narrowing()),
    );
    item.insert(
        "schema_version".to_string(),
        AttributeValue::N(envelope.schema_version().to_string()),
    );
    item.insert("payload".to_string(), AttributeValue::S(payload_str));
    item.insert(
        "key_id".to_string(),
        AttributeValue::S(envelope.key_id().to_string()),
    );
    item.insert(
        "signature".to_string(),
        AttributeValue::S(envelope.signature().to_string()),
    );
    Ok(item)
}

/// Parse a stored event item back into an [`EventEnvelope`].
fn envelope_from_item(item: &HashMap<String, AttributeValue>) -> Result<EventEnvelope> {
    let payload_str = get_s(item, "payload")?;
    let payload: serde_json::Value = serde_json::from_str(&payload_str)
        .map_err(|e| Error::Store(format!("deserialize event payload: {e}")))?;
    let actor_json = get_s(item, "actor")?;
    let actor = serde_json::from_str(&actor_json)
        .map_err(|e| Error::Store(format!("deserialize event actor: {e}")))?;
    let event_id_str = get_s(item, "event_id")?;
    let event_id = EventId::try_new(event_id_str)
        .map_err(|e| Error::Store(format!("invalid stored event_id: {e}")))?;
    let seq = item
        .get("seq")
        .and_then(|v| v.as_n().ok())
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or_else(|| Error::Store("missing or invalid 'seq' attribute".to_string()))?;
    let kind_str = get_s(item, "kind")?;
    let kind: EventKind = kind_str
        .parse()
        .map_err(|e| Error::Store(format!("invalid stored event kind: {e}")))?;
    let occurred_at = get_s(item, "occurred_at")?;
    let key_id = get_s(item, "key_id")?;
    let signature = get_s(item, "signature")?;

    let draft = EventDraft::new(EventDraftParams {
        event_id,
        seq: Revision::new(seq),
        kind,
        occurred_at,
        actor,
        payload,
    });
    Ok(EventEnvelope::from_signed(draft, key_id, signature))
}

impl DynamoEventLog {
    pub(crate) fn new(client: aws_sdk_dynamodb::Client, table_name: String, org_id: &str) -> Self {
        Self {
            client,
            table_name,
            org_pk: format!("{ORG_PREFIX}{org_id}"),
        }
    }

    /// Read the counter item's current `seq`, or `0` if absent.
    async fn read_counter(&self) -> Result<u64> {
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(self.org_pk.clone()))
            .key(sk(), AttributeValue::S(SK_SEQ.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(map_sdk_error)?;

        match result.item {
            None => Ok(0),
            Some(item) => item
                .get("seq")
                .and_then(|v| v.as_n().ok())
                .and_then(|n| n.parse::<u64>().ok())
                .ok_or_else(|| {
                    Error::Store("missing or invalid counter 'seq' attribute".to_string())
                }),
        }
    }

    /// Build the counter's conditional `Update` item: CAS from `current` to
    /// `current + 1` (or "must not exist yet" when `current == 0`). Shared by
    /// [`Self::append`] and [`Self::append_with_delete`] — both transactions
    /// open with the identical counter-increment item.
    fn counter_update(&self, current: u64, candidate: u64) -> Result<Update> {
        let mut counter_update = Update::builder()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(self.org_pk.clone()))
            .key(sk(), AttributeValue::S(SK_SEQ.to_string()))
            .update_expression("SET seq = :new")
            .expression_attribute_values(":new", AttributeValue::N(candidate.to_string()));
        counter_update = if current == 0 {
            counter_update.condition_expression("attribute_not_exists(seq)")
        } else {
            counter_update
                .condition_expression("seq = :expected")
                .expression_attribute_values(":expected", AttributeValue::N(current.to_string()))
        };
        counter_update
            .build()
            .map_err(|e| Error::Store(format!("build counter update: {e}")))
    }

    /// Build the event's conditional `Put` item: fails if the sort key is
    /// already occupied (a duplicate seq must never land silently). Shared by
    /// [`Self::append`] and [`Self::append_with_delete`].
    fn event_put(&self, envelope: &EventEnvelope, payload_bytes: &[u8]) -> Result<Put> {
        let event_attrs = event_item(&self.org_pk, envelope, payload_bytes)?;
        Put::builder()
            .table_name(&self.table_name)
            .set_item(Some(event_attrs))
            .condition_expression(format!("attribute_not_exists({})", sk()))
            .build()
            .map_err(|e| Error::Store(format!("build event put: {e}")))
    }

    /// The A1 transaction: conditional counter increment + event put + state put.
    ///
    /// Retries up to [`MAX_APPEND_ATTEMPTS`] times on `TransactionCanceledException`,
    /// re-reading the counter and re-invoking `build` each attempt (seq is part
    /// of the canonical signing bytes, so the envelope must be rebuilt for the
    /// new candidate revision).
    pub(crate) async fn append(
        &self,
        expected_revision: Option<Revision>,
        build: impl Fn(Revision) -> (EventEnvelope, Vec<u8>),
        state: StatePut,
    ) -> Result<Revision> {
        for attempt in 0..MAX_APPEND_ATTEMPTS {
            let current = self.read_counter().await?;
            if let Some(expected) = expected_revision {
                if current != expected.value() {
                    return Err(Error::RevisionMismatch { current });
                }
            }
            let candidate = current + 1;
            let revision = Revision::new(candidate);
            let (envelope, payload_bytes) = build(revision);

            let counter_update = self.counter_update(current, candidate)?;
            let event_put = self.event_put(&envelope, &payload_bytes)?;

            let mut state_attrs = state.attributes.clone();
            state_attrs.insert(pk().to_string(), AttributeValue::S(state.pk.clone()));
            state_attrs.insert(sk().to_string(), AttributeValue::S(state.sk.clone()));
            let mut state_put_builder = Put::builder()
                .table_name(&self.table_name)
                .set_item(Some(state_attrs));
            if state.guard == StateGuard::MustNotExist {
                state_put_builder = state_put_builder
                    .condition_expression("attribute_not_exists(#pk)")
                    .expression_attribute_names("#pk", pk());
            }
            let state_put = state_put_builder
                .build()
                .map_err(|e| Error::Store(format!("build state put: {e}")))?;

            let result = self
                .client
                .transact_write_items()
                .transact_items(TransactWriteItem::builder().update(counter_update).build())
                .transact_items(TransactWriteItem::builder().put(event_put).build())
                .transact_items(TransactWriteItem::builder().put(state_put).build())
                .send()
                .await;

            match result {
                Ok(_) => return Ok(revision),
                Err(sdk_err) => {
                    let cancellation_reasons = match &sdk_err {
                        aws_sdk_dynamodb::error::SdkError::ServiceError(e) => match e.err() {
                            TransactWriteItemsError::TransactionCanceledException(cancelled) => {
                                Some(cancelled.cancellation_reasons())
                            }
                            _ => None,
                        },
                        _ => None,
                    };

                    if state.guard == StateGuard::MustNotExist {
                        // Transaction item order is [counter, event, state
                        // put] — index 2 is the state item. `MustNotExist`
                        // failing here is a permanent condition (the org
                        // already exists), not a counter race, so it must
                        // not be retried.
                        let state_failed = cancellation_reasons
                            .and_then(|reasons| reasons.get(2))
                            .and_then(|r| r.code())
                            .is_some_and(|c| c == "ConditionalCheckFailed");
                        if state_failed {
                            return Err(Error::Conflict(format!(
                                "state item already exists for '{}'",
                                self.org_pk
                            )));
                        }
                    }
                    let is_last_attempt = attempt + 1 == MAX_APPEND_ATTEMPTS;
                    let is_cancelled = cancellation_reasons.is_some();
                    if is_cancelled && !is_last_attempt {
                        // Small linear backoff to de-correlate retries under
                        // heavy concurrent contention on the same counter.
                        tokio::time::sleep(std::time::Duration::from_millis(
                            u64::from(attempt) * 5,
                        ))
                        .await;
                        continue;
                    }
                    return Err(map_sdk_error(sdk_err));
                }
            }
        }

        Err(Error::Store(format!(
            "append: exhausted {MAX_APPEND_ATTEMPTS} attempts for '{}'",
            self.org_pk
        )))
    }

    /// Like [`Self::append`], but the third transaction item is a
    /// conditional `Delete` instead of a `Put` (D7: the tombstone hard-deletes
    /// the promotion state item in the same transaction as its
    /// `resource.tombstoned` event).
    ///
    /// Returns `Ok(Some(revision))` when the event was appended and the state
    /// item deleted. Returns `Ok(None)` when the state item was already gone
    /// (its `attribute_exists` condition failed) — a concurrent delete won
    /// the race, so nothing is appended and the caller must not retry into a
    /// duplicate event.
    ///
    /// Wired up by `handlers/promotions/mod.rs` in Task 4; until then
    /// transitively dead via `ModelEventStore::tombstone_promotion`.
    #[allow(dead_code)]
    pub(crate) async fn append_with_delete(
        &self,
        build: impl Fn(Revision) -> (EventEnvelope, Vec<u8>),
        state: StateDelete,
    ) -> Result<Option<Revision>> {
        for attempt in 0..MAX_APPEND_ATTEMPTS {
            let current = self.read_counter().await?;
            let candidate = current + 1;
            let revision = Revision::new(candidate);
            let (envelope, payload_bytes) = build(revision);

            let counter_update = self.counter_update(current, candidate)?;
            let event_put = self.event_put(&envelope, &payload_bytes)?;

            let state_delete = Delete::builder()
                .table_name(&self.table_name)
                .key(pk(), AttributeValue::S(state.pk.clone()))
                .key(sk(), AttributeValue::S(state.sk.clone()))
                .condition_expression(format!("attribute_exists({})", pk()))
                .build()
                .map_err(|e| Error::Store(format!("build state delete: {e}")))?;

            let result = self
                .client
                .transact_write_items()
                .transact_items(TransactWriteItem::builder().update(counter_update).build())
                .transact_items(TransactWriteItem::builder().put(event_put).build())
                .transact_items(TransactWriteItem::builder().delete(state_delete).build())
                .send()
                .await;

            match result {
                Ok(_) => return Ok(Some(revision)),
                Err(sdk_err) => {
                    if let aws_sdk_dynamodb::error::SdkError::ServiceError(e) = &sdk_err {
                        if let TransactWriteItemsError::TransactionCanceledException(cancelled) =
                            e.err()
                        {
                            // Transaction item order is [counter, event, state
                            // delete] — index 2 is the delete. Its
                            // ConditionalCheckFailed means the item is already
                            // gone: a concurrent delete won, nothing was
                            // appended, and retrying would append a duplicate
                            // tombstone event.
                            let delete_failed = cancelled
                                .cancellation_reasons()
                                .get(2)
                                .and_then(|r| r.code())
                                .is_some_and(|c| c == "ConditionalCheckFailed");
                            if delete_failed {
                                return Ok(None);
                            }
                            let is_last_attempt = attempt + 1 == MAX_APPEND_ATTEMPTS;
                            if !is_last_attempt {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    u64::from(attempt) * 5,
                                ))
                                .await;
                                continue;
                            }
                        }
                    }
                    return Err(map_sdk_error(sdk_err));
                }
            }
        }

        Err(Error::Store(format!(
            "append_with_delete: exhausted {MAX_APPEND_ATTEMPTS} attempts for '{}'",
            self.org_pk
        )))
    }
}

impl EventLog for DynamoEventLog {
    fn events_after(
        &self,
        after: Revision,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = forgeguard_authz_core::Result<Vec<EventEnvelope>>> + Send + '_>>
    {
        Box::pin(async move {
            // Inclusive lower bound: the smallest key strictly greater than
            // `after` is the next integer's zero-padded key. `after` is a
            // client-controlled cursor, so `after.value() == u64::MAX` must
            // saturate rather than wrap to 0 (which would turn an
            // out-of-range cursor into "return the entire history").
            let after_sk = event_sk(after.value().saturating_add(1));
            let result = self
                .client
                .query()
                .table_name(&self.table_name)
                .key_condition_expression("#pk = :pk AND #sk BETWEEN :after AND :max")
                .expression_attribute_names("#pk", pk())
                .expression_attribute_names("#sk", sk())
                .expression_attribute_values(":pk", AttributeValue::S(self.org_pk.clone()))
                .expression_attribute_values(":after", AttributeValue::S(after_sk))
                .expression_attribute_values(":max", AttributeValue::S(EVT_SK_MAX.to_string()))
                .limit(i32::try_from(limit).unwrap_or(i32::MAX))
                .send()
                .await
                .map_err(|e| {
                    forgeguard_authz_core::Error::EvaluationFailed(format!("event log query: {e}"))
                })?;

            result
                .items
                .unwrap_or_default()
                .iter()
                .map(envelope_from_item)
                .collect::<Result<Vec<_>>>()
                .map_err(|e| forgeguard_authz_core::Error::EvaluationFailed(e.to_string()))
        })
    }

    fn latest_revision(
        &self,
    ) -> Pin<Box<dyn Future<Output = forgeguard_authz_core::Result<Revision>> + Send + '_>> {
        Box::pin(async move {
            self.read_counter()
                .await
                .map(Revision::new)
                .map_err(|e| forgeguard_authz_core::Error::EvaluationFailed(e.to_string()))
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
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput, ScalarAttributeType,
    };
    use forgeguard_authz_core::{Actor, EventDraft, EventDraftParams, EventId, EventKind};
    use forgeguard_core::{Fgrn, NativeId, Segment};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::OnceCell;

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
        format!("test-evt-{ts}-{n}")
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

    fn sample_envelope(seq: Revision) -> (EventEnvelope, Vec<u8>) {
        let payload = serde_json::json!({ "seq": seq.value() });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let draft = EventDraft::new(EventDraftParams {
            event_id: EventId::try_new(format!("01J{:022}", seq.value())).unwrap(),
            seq,
            kind: EventKind::PrincipalUpserted,
            occurred_at: "2026-07-14T00:00:00Z".to_string(),
            actor: Actor::Principal(Fgrn::principal(
                &Segment::try_new("acme").unwrap(),
                &NativeId::try_new("usr_1").unwrap(),
            )),
            payload,
        });
        let envelope = EventEnvelope::from_signed(draft, "key-1".to_string(), "sig".to_string());
        (envelope, payload_bytes)
    }

    fn state_put(seq: u64) -> StatePut {
        let mut attributes = HashMap::new();
        attributes.insert("marker".to_string(), AttributeValue::S(seq.to_string()));
        StatePut {
            pk: format!("{ORG_PREFIX}acme"),
            sk: format!("PRINCIPAL#usr_{seq}"),
            attributes,
            guard: StateGuard::None,
        }
    }

    async fn new_log() -> DynamoEventLog {
        let client = test_client().await;
        let table = unique_table_name();
        create_test_table(&client, &table).await;
        DynamoEventLog::new(client, table, "acme")
    }

    #[tokio::test]
    async fn first_append_returns_revision_1_and_persists_items() {
        let log = new_log().await;

        let revision = log
            .append(None, sample_envelope, state_put(1))
            .await
            .unwrap();
        assert_eq!(revision, Revision::new(1));

        let counter = log.read_counter().await.unwrap();
        assert_eq!(counter, 1);

        let item = log
            .client
            .get_item()
            .table_name(&log.table_name)
            .key(pk(), AttributeValue::S(log.org_pk.clone()))
            .key(sk(), AttributeValue::S(event_sk(1)))
            .send()
            .await
            .unwrap()
            .item
            .unwrap();
        assert_eq!(item.get("seq").unwrap().as_n().unwrap(), "1");
    }

    #[tokio::test]
    async fn two_sequential_appends_produce_no_gap() {
        let log = new_log().await;

        let r1 = log
            .append(None, sample_envelope, state_put(1))
            .await
            .unwrap();
        let r2 = log
            .append(None, sample_envelope, state_put(2))
            .await
            .unwrap();

        assert_eq!(r1, Revision::new(1));
        assert_eq!(r2, Revision::new(2));
    }

    #[tokio::test]
    async fn concurrent_appends_produce_exact_gapless_sequence() {
        let log = std::sync::Arc::new(new_log().await);

        let mut handles = Vec::new();
        for i in 0..20u64 {
            let log = log.clone();
            handles.push(tokio::spawn(async move {
                log.append(None, sample_envelope, state_put(i))
                    .await
                    .unwrap()
            }));
        }

        let mut revisions: Vec<u64> = Vec::new();
        for handle in handles {
            revisions.push(handle.await.unwrap().value());
        }
        revisions.sort_unstable();

        assert_eq!(revisions, (1..=20).collect::<Vec<u64>>());
    }

    #[tokio::test]
    async fn events_after_returns_ascending_deserializable_envelopes() {
        let log = new_log().await;
        log.append(None, sample_envelope, state_put(1))
            .await
            .unwrap();
        log.append(None, sample_envelope, state_put(2))
            .await
            .unwrap();
        log.append(None, sample_envelope, state_put(3))
            .await
            .unwrap();

        let page = log.events_after(Revision::new(0), 10).await.unwrap();
        let seqs: Vec<u64> = page.iter().map(|e| e.seq().value()).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn latest_revision_matches_last_append() {
        let log = new_log().await;
        log.append(None, sample_envelope, state_put(1))
            .await
            .unwrap();
        let r2 = log
            .append(None, sample_envelope, state_put(2))
            .await
            .unwrap();

        let latest = log.latest_revision().await.unwrap();
        assert_eq!(latest, r2);
    }

    #[tokio::test]
    async fn append_with_must_not_exist_conflicts_on_second_put() {
        let log = new_log().await;
        let mut state = state_put(1);
        state.guard = StateGuard::MustNotExist;
        log.append(None, sample_envelope, state).await.unwrap();

        let mut state = state_put(1);
        state.guard = StateGuard::MustNotExist;
        let err = log.append(None, sample_envelope, state).await.unwrap_err();
        assert!(matches!(err, Error::Conflict(_)));
        assert_eq!(log.read_counter().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn append_with_expected_revision_mismatch_returns_error_without_appending() {
        let log = new_log().await;
        log.append(None, sample_envelope, state_put(1))
            .await
            .unwrap();

        let err = log
            .append(Some(Revision::new(0)), sample_envelope, state_put(2))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RevisionMismatch { current: 1 }));
        assert_eq!(log.read_counter().await.unwrap(), 1);
    }

    fn tombstone_envelope(seq: Revision) -> (EventEnvelope, Vec<u8>) {
        let payload = serde_json::json!({ "fgrn": "fgrn:acme:resource:document/doc_1" });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let draft = EventDraft::new(EventDraftParams {
            event_id: EventId::try_new(format!("01K{:022}", seq.value())).unwrap(),
            seq,
            kind: EventKind::ResourceTombstoned,
            occurred_at: "2026-07-15T00:00:00Z".to_string(),
            actor: Actor::System,
            payload,
        });
        (
            EventEnvelope::from_signed(draft, "key-1".to_string(), "sig".to_string()),
            payload_bytes,
        )
    }

    #[tokio::test]
    async fn append_with_delete_removes_item_and_appends_event() {
        let log = new_log().await;
        log.append(
            None,
            sample_envelope,
            StatePut {
                pk: format!("{ORG_PREFIX}acme"),
                sk: "PROMO#document#doc_1".to_string(),
                attributes: HashMap::new(),
                guard: StateGuard::None,
            },
        )
        .await
        .unwrap();

        let revision = log
            .append_with_delete(
                tombstone_envelope,
                StateDelete {
                    pk: format!("{ORG_PREFIX}acme"),
                    sk: "PROMO#document#doc_1".to_string(),
                },
            )
            .await
            .unwrap();
        assert_eq!(revision, Some(Revision::new(2)));

        let gone = log
            .client
            .get_item()
            .table_name(&log.table_name)
            .key(pk(), AttributeValue::S(format!("{ORG_PREFIX}acme")))
            .key(sk(), AttributeValue::S("PROMO#document#doc_1".to_string()))
            .send()
            .await
            .unwrap()
            .item;
        assert!(gone.is_none());
        assert_eq!(log.read_counter().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn append_with_delete_on_absent_item_appends_nothing() {
        let log = new_log().await;
        let revision = log
            .append_with_delete(
                tombstone_envelope,
                StateDelete {
                    pk: format!("{ORG_PREFIX}acme"),
                    sk: "PROMO#document#doc_missing".to_string(),
                },
            )
            .await
            .unwrap();
        assert_eq!(revision, None);
        assert_eq!(log.read_counter().await.unwrap(), 0);
    }
}

//! Principal state item mapping (D6): the imperative shell around
//! [`forgeguard_authz_core::decide_upsert`].
//!
//! Also carries the `ModelEventStore` seam (Task 7): the trait-object
//! boundary the `upsert_principal` handler uses so `InMemoryModelEventStore`
//! can stand in for `DynamoModelEventStore` in handler tests without a
//! DynamoDB Local dependency.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_authn_core::signing::SigningKey;
use forgeguard_authz_core::{
    fold_events, key_event_payload, principal_event_payload, Actor, EventEnvelope, EventKind,
    EventLog, FoldedState, InMemoryEventLog, Revision,
};
use forgeguard_core::NativeId;

use forgeguard_core::Segment;

use crate::dynamo_store::{
    from_item, get_s, map_sdk_error, pk, signing_keys_from_item, sk, to_item, ORG_PREFIX, SK_META,
};
use crate::error::{Error, Result};
use crate::event_log::{DynamoEventLog, StateDelete, StateGuard, StatePut};
use crate::promotion_store::{
    promotion_event_payload, promotion_fgrn, promotion_sk, promotion_state_put, PromotionEntry,
    PromotionStatePutParams, PROMO_PREFIX,
};
use crate::signing_key::{GenerateKeyResult, SigningKeyEntry};
use crate::store::{generate_key_material, OrgRecord};

mod support;
use support::{
    build_model_event, encode_verifying_key_pem, generate_key_transition, get_raw_org_item,
    org_payload, public_pem_from_private, revoke_key_transition, rotate_key_transition,
    BuildModelEventParams,
};
pub(crate) use support::{get_principal, principal_state_put, EventSigningKey};

const SK_EVENT_SIGNING_KEY: &str = "EVENT_SIGNING_KEY";
const EVENT_SIGNING_KEY_ID: &str = "event-signing-key-1";
/// Fixed Ed25519 seed for `InMemoryModelEventStore`'s signing key — kept
/// as a single const so `Self::new` and `list_signing_keys` can't drift apart.
const IN_MEMORY_SEED: [u8; 32] = [7u8; 32];
/// `key_id` reported for the in-memory store's single fixed signing key.
const IN_MEMORY_KEY_ID: &str = "in-memory-test-key";
/// Page size for `fold_at`'s log replay.
const FOLD_PAGE_SIZE: usize = 100;
/// Retry budget for `append_org_keys`' internal revision-mismatch loop.
/// No HTTP route calls `append_org_keys` in Task 4 — wired in Task 5, hence
/// `dead_code`, same precedent as `put_promotion`.
#[allow(dead_code)]
const MAX_KEY_APPEND_ATTEMPTS: u8 = 3;

// ---------------------------------------------------------------------------
// ModelEventStore — the seam `upsert_principal` (Task 7) is written against
// ---------------------------------------------------------------------------

/// Everything the `PUT /organizations/{org_id}/principals/{native_id}` handler
/// needs: a strongly-consistent principal read, the log's current revision,
/// and the full "mint + sign + append" shell for a `Changed` decision.
///
/// Bundling all three into one trait (rather than composing `EventLog` +
/// `get_principal` + a signing helper at the call site) keeps the handler
/// generic over `Arc<dyn ModelEventStore>` — the same object-safe seam
/// `OrgStore`/`SagaTicketStore` already establish — so `InMemoryModelEventStore`
/// can stand in for the DynamoDB implementation in handler tests.
///
/// V3 (#110) additionally hangs the promotion lifecycle (`get_promotion`,
/// `put_promotion`, `tombstone_promotion`, `list_promotions`) off this same
/// seam — it already owns the per-org signing key + event log this side of
/// the boundary needs, and standing up a second trait just to avoid the name
/// mismatch isn't worth the duplication. This is the model-wide event store
/// seam (#113); principal, promotion, and org-domain writes all funnel
/// through the append transaction.
#[async_trait]
pub(crate) trait ModelEventStore: Send + Sync {
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
    /// The appended envelope's payload is the V5 identity wrapper
    /// (`principal_event_payload`); the state item keeps the raw doc.
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
    /// trait/`AppState` field: `ModelEventStore` already owns the per-org
    /// `EventLog` handle (`DynamoEventLog`/`InMemoryEventLog`) for the upsert
    /// path, so exposing `events_after` here reuses the exact same log
    /// instance instead of standing up a second seam to the same data.
    async fn events_after(
        &self,
        org_id: &str,
        after: Revision,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>>;

    /// Strongly-consistent read of a promotion's FGRN, or `None` if no
    /// promotion is recorded for `resource_type`/`native_id`.
    async fn get_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
    ) -> Result<Option<String>>;

    /// Store-level seed/apply: mint + sign a `resource.promoted` event and
    /// write the promotion state item transactionally. No HTTP route calls
    /// this in #110 — seeding is store-level only (tests + future flows).
    #[allow(dead_code)]
    async fn put_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
        actor: Actor,
    ) -> Result<Revision>;

    /// Tombstone a promotion: append `resource.tombstoned` + hard-delete the
    /// state item in one transaction. `Some(rev)` means the event was
    /// appended and the item deleted; `None` means the item was already gone
    /// at delete time (a concurrent delete won the race, or none ever
    /// existed) — nothing was appended (D7's idempotent no-op rule).
    async fn tombstone_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
        actor: Actor,
    ) -> Result<Option<Revision>>;

    /// Reconciliation page: promotions of `resource_type`, ascending by
    /// `native_id`, starting strictly after `after` (exclusive cursor), at
    /// most `limit` rows.
    async fn list_promotions(
        &self,
        org_id: &str,
        resource_type: &Segment,
        after: Option<&NativeId>,
        limit: usize,
    ) -> Result<Vec<PromotionEntry>>;

    /// The org's published event-signing public keys (public halves only,
    /// D8). Empty if no model event has ever been appended (no key minted).
    async fn list_signing_keys(&self, org_id: &str) -> Result<Vec<EventSigningKey>>;

    /// Generate a new request-signing key, append `org.key_generated`
    /// (public half only) + the org's new `signing_keys` list in one
    /// transaction, and return the material (including the private half,
    /// returned once and never persisted in the event payload). No HTTP
    /// route calls this in Task 4 — wired in Task 5, hence `dead_code`, same
    /// precedent as `put_promotion`.
    #[allow(dead_code)]
    async fn generate_org_key(&self, org_id: &str, actor: Actor) -> Result<GenerateKeyResult>;

    /// Revoke a request-signing key and append `org.key_revoked` (narrowing)
    /// + the org's new `signing_keys` list in one transaction. `None` is the
    /// D6 no-op: `key_id` absent or already revoked — nothing is appended.
    /// No HTTP route calls this in Task 4 — wired in Task 5, hence
    /// `dead_code`, same precedent as `put_promotion`.
    #[allow(dead_code)]
    async fn revoke_org_key(
        &self,
        org_id: &str,
        key_id: &str,
        actor: Actor,
    ) -> Result<Option<Revision>>;

    /// Rotate a request-signing key (target moves to `Rotating` with a grace
    /// window, a new `Active` entry is appended) and append `org.key_rotated`
    /// + the org's new `signing_keys` list in one transaction. Errors
    /// (`NotFound`/`Conflict`) propagate without appending. No HTTP route
    /// calls this in Task 4 — wired in Task 5, hence `dead_code`, same
    /// precedent as `put_promotion`.
    #[allow(dead_code)]
    async fn rotate_org_key(
        &self,
        org_id: &str,
        key_id: &str,
        actor: Actor,
    ) -> Result<GenerateKeyResult>;

    /// Append an `org.created` event + the org's initial state item in one
    /// transaction. `Err(Error::Conflict)` if the org already exists (#113 V1).
    async fn create_org(&self, record: OrgRecord, actor: Actor) -> Result<Revision>;

    /// Append an `org.updated` event + the org's new state item in one
    /// transaction. When `expected_revision` is `Some`, mismatches against the
    /// log's current revision fail with `Error::RevisionMismatch` instead of
    /// appending (#113 V1, D5).
    async fn update_org(
        &self,
        record: OrgRecord,
        actor: Actor,
        expected_revision: Option<Revision>,
    ) -> Result<Revision>;

    /// Append a lifecycle event (`org.activated`/`org.suspended`/
    /// `org.restored`) + the org's new state item in one transaction.
    /// `expected_revision` is the handler's observed revision and is
    /// MANDATORY: racing transitions serialize into one event and one
    /// `Error::RevisionMismatch` (#113 V2). `record` already carries the
    /// post-transition status.
    ///
    /// Called by the `activate`/`suspend`/`restore` handlers in
    /// `handlers::lifecycle`.
    async fn transition_org(
        &self,
        record: OrgRecord,
        kind: EventKind,
        actor: Actor,
        expected_revision: Revision,
    ) -> Result<Revision>;

    /// Revision-pinned historical read (V5 / N16, closing D9): fold the
    /// org's event log up to `at` (or the latest revision when `None`) into
    /// entity state. `None` on an empty log yields [`FoldedState::empty`];
    /// an explicit revision of 0 or past the latest errors.
    ///
    /// Default implementation pages `events_after` and delegates to the
    /// pure `fold_events` — both impls inherit it. No HTTP route consumes
    /// this in #110 (the V5 demo is conformance-test output), hence
    /// `dead_code`, same precedent as `put_promotion`.
    #[allow(dead_code)]
    async fn fold_at(&self, org_id: &str, at: Option<Revision>) -> Result<FoldedState> {
        let latest = self.latest_revision(org_id).await?;
        let target = match at {
            Some(revision) => revision,
            None if latest.value() == 0 => return Ok(FoldedState::empty()),
            None => latest,
        };

        let mut events = Vec::new();
        let mut after = Revision::new(0);
        loop {
            let page = self.events_after(org_id, after, FOLD_PAGE_SIZE).await?;
            let Some(last) = page.last() else { break };
            after = last.seq();
            let exhausted = page.len() < FOLD_PAGE_SIZE;
            events.extend(page);
            if exhausted || after.value() >= target.value() {
                break;
            }
        }

        fold_events(&events, target).map_err(|e| Error::Store(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// DynamoDB implementation
// ---------------------------------------------------------------------------

/// DynamoDB-backed [`ModelEventStore`].
pub(crate) struct DynamoModelEventStore {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoModelEventStore {
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

    /// Shared body for `create_org`/`update_org`/`transition_org`: append an
    /// org-domain event of `kind` + the org's new state item in one
    /// transaction. `create_org` passes `EventKind::OrgCreated` with a
    /// `MustNotExist` guard and no revision precondition; the other two pass
    /// `StateGuard::None` with their own `expected_revision`.
    async fn append_org_state(
        &self,
        record: OrgRecord,
        kind: EventKind,
        actor: Actor,
        expected_revision: Option<Revision>,
    ) -> Result<Revision> {
        let org_id = record.org().org_id().to_string();
        let (signing_key, key_id) = self.ensure_signing_key(&org_id).await?;
        let occurred_at = chrono::Utc::now().to_rfc3339();
        let log = DynamoEventLog::new(self.client.clone(), self.table_name.clone(), &org_id);

        let guard = if kind == EventKind::OrgCreated {
            StateGuard::MustNotExist
        } else {
            // Preserve `signing_keys` across the state item's replacement —
            // the META item is fully rewritten by `to_item`, and that
            // attribute lives outside `OrgRecord` (see `dynamo_store::update`).
            StateGuard::None
        };
        let existing_keys = match get_raw_org_item(&self.client, &self.table_name, &org_id).await? {
            Some(item) => signing_keys_from_item(&item)?,
            None => Vec::new(),
        };

        let payload = org_payload(&record)?;
        let mut attributes = to_item(record.org(), record.configured(), &existing_keys)?;
        attributes.remove(pk());
        attributes.remove(sk());
        let state = StatePut {
            pk: format!("{ORG_PREFIX}{org_id}"),
            sk: SK_META.to_string(),
            attributes,
            guard,
        };

        let org_id_owned = org_id.clone();
        let build = move |revision: Revision| {
            build_model_event(BuildModelEventParams {
                org_id: &org_id_owned,
                kind,
                actor: actor.clone(),
                payload: payload.clone(),
                signing_key: &signing_key,
                key_id: &key_id,
                occurred_at: &occurred_at,
                revision,
            })
        };

        log.append(expected_revision, build, state).await
    }

    /// Shared body for `generate_org_key`/`revoke_org_key`/`rotate_org_key`:
    /// read the org's current `signing_keys`, run the pure `transition`, and
    /// append `kind` + the new `signing_keys` list in one transaction.
    ///
    /// `transition` returns `Ok(None)` for a semantic no-op (nothing to
    /// append, D6), `Ok(Some((affected_key_id, new_keys)))` to append, or
    /// `Err(_)` to fail without appending.
    ///
    /// No HTTP route calls this in Task 4 — wired in Task 5, hence
    /// `dead_code`, same precedent as `put_promotion`.
    ///
    /// Unlike `append_org_state`, callers here never supply an
    /// `expected_revision` precondition of their own — the log's revision is
    /// an internal concurrency-control detail, not part of the key-mutation
    /// contract — so this loops on `Error::RevisionMismatch` internally
    /// (up to `MAX_KEY_APPEND_ATTEMPTS`) instead of surfacing the race to
    /// the caller.
    #[allow(dead_code)]
    async fn append_org_keys(
        &self,
        org_id: &str,
        kind: EventKind,
        actor: Actor,
        transition: impl Fn(Vec<SigningKeyEntry>) -> Result<Option<(String, Vec<SigningKeyEntry>)>>,
    ) -> Result<Option<Revision>> {
        for _ in 0..MAX_KEY_APPEND_ATTEMPTS {
            let item = get_raw_org_item(&self.client, &self.table_name, org_id)
                .await?
                .ok_or_else(|| Error::NotFound(format!("organization '{org_id}' not found")))?;
            let record = from_item(&item)?;
            let existing_keys = signing_keys_from_item(&item)?;

            let Some((affected_key_id, new_keys)) = transition(existing_keys)? else {
                return Ok(None);
            };

            let (signing_key, key_id) = self.ensure_signing_key(org_id).await?;
            let occurred_at = chrono::Utc::now().to_rfc3339();
            let log = DynamoEventLog::new(self.client.clone(), self.table_name.clone(), org_id);

            let payload = key_event_payload(
                &affected_key_id,
                &serde_json::to_value(&new_keys)
                    .map_err(|e| Error::Store(format!("serialize signing_keys: {e}")))?,
            );

            let mut attributes = to_item(record.org(), record.configured(), &new_keys)?;
            attributes.remove(pk());
            attributes.remove(sk());
            let state = StatePut {
                pk: format!("{ORG_PREFIX}{org_id}"),
                sk: SK_META.to_string(),
                attributes,
                guard: StateGuard::None,
            };

            let org_id_owned = org_id.to_string();
            let payload_for_event = payload.clone();
            let actor_for_event = actor.clone();
            let build = move |revision: Revision| {
                build_model_event(BuildModelEventParams {
                    org_id: &org_id_owned,
                    kind,
                    actor: actor_for_event.clone(),
                    payload: payload_for_event.clone(),
                    signing_key: &signing_key,
                    key_id: &key_id,
                    occurred_at: &occurred_at,
                    revision,
                })
            };

            let expected = EventLog::latest_revision(&log)
                .await
                .map_err(|e| Error::Store(e.to_string()))?;
            match log.append(Some(expected), build, state).await {
                Ok(revision) => return Ok(Some(revision)),
                Err(Error::RevisionMismatch { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Store(format!(
            "org '{org_id}' key mutation did not converge after {MAX_KEY_APPEND_ATTEMPTS} attempts"
        )))
    }
}

#[async_trait]
impl ModelEventStore for DynamoModelEventStore {
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
        let event_payload = principal_event_payload(native_id, &payload);
        let build = move |revision: Revision| {
            build_model_event(BuildModelEventParams {
                org_id: &org_id_owned,
                kind: EventKind::PrincipalUpserted,
                actor: actor.clone(),
                payload: event_payload.clone(),
                signing_key: &signing_key,
                key_id: &key_id,
                occurred_at: &occurred_at,
                revision,
            })
        };

        // The state item stores the raw doc (`serde_json::to_vec(&payload)`);
        // the envelope's payload is the V5 identity wrapper built above —
        // the two deliberately diverge so the fold can recover the subject
        // while `decide_upsert` keeps comparing raw docs.
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| Error::Store(format!("serialize principal payload: {e}")))?;
        let updated_at = chrono::Utc::now().to_rfc3339();
        let state = principal_state_put(org_id, native_id, &payload_bytes, &updated_at)?;

        log.append(None, build, state).await
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

    async fn get_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
    ) -> Result<Option<String>> {
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(format!("{ORG_PREFIX}{org_id}")))
            .key(
                sk(),
                AttributeValue::S(promotion_sk(resource_type, native_id)),
            )
            .consistent_read(true)
            .send()
            .await
            .map_err(map_sdk_error)?;

        let Some(item) = result.item else {
            return Ok(None);
        };
        get_s(&item, "fgrn").map(Some)
    }

    async fn put_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
        actor: Actor,
    ) -> Result<Revision> {
        let (signing_key, key_id) = self.ensure_signing_key(org_id).await?;
        let occurred_at = chrono::Utc::now().to_rfc3339();
        let log = DynamoEventLog::new(self.client.clone(), self.table_name.clone(), org_id);

        let fgrn = promotion_fgrn(org_id, resource_type, native_id)?;
        let payload = promotion_event_payload(&fgrn, resource_type, native_id);
        let state = promotion_state_put(PromotionStatePutParams {
            org_id,
            resource_type,
            native_id,
            fgrn: &fgrn,
            promoted_at: &occurred_at,
        });

        let org_id_owned = org_id.to_string();
        let payload_for_event = payload.clone();
        let build = move |revision: Revision| {
            build_model_event(BuildModelEventParams {
                org_id: &org_id_owned,
                kind: EventKind::ResourcePromoted,
                actor: actor.clone(),
                payload: payload_for_event.clone(),
                signing_key: &signing_key,
                key_id: &key_id,
                occurred_at: &occurred_at,
                revision,
            })
        };

        log.append(None, build, state).await
    }

    async fn tombstone_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
        actor: Actor,
    ) -> Result<Option<Revision>> {
        let (signing_key, key_id) = self.ensure_signing_key(org_id).await?;
        let occurred_at = chrono::Utc::now().to_rfc3339();
        let log = DynamoEventLog::new(self.client.clone(), self.table_name.clone(), org_id);

        let fgrn = promotion_fgrn(org_id, resource_type, native_id)?;
        let payload = promotion_event_payload(&fgrn, resource_type, native_id);
        let org_id_owned = org_id.to_string();
        let payload_for_event = payload.clone();
        let build = move |revision: Revision| {
            build_model_event(BuildModelEventParams {
                org_id: &org_id_owned,
                kind: EventKind::ResourceTombstoned,
                actor: actor.clone(),
                payload: payload_for_event.clone(),
                signing_key: &signing_key,
                key_id: &key_id,
                occurred_at: &occurred_at,
                revision,
            })
        };

        let state = StateDelete {
            pk: format!("{ORG_PREFIX}{org_id}"),
            sk: promotion_sk(resource_type, native_id),
        };

        log.append_with_delete(build, state).await
    }

    async fn list_promotions(
        &self,
        org_id: &str,
        resource_type: &Segment,
        after: Option<&NativeId>,
        limit: usize,
    ) -> Result<Vec<PromotionEntry>> {
        let type_prefix = format!("{PROMO_PREFIX}{resource_type}#");
        let mut query = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("#pk = :pk AND begins_with(#sk, :prefix)")
            .expression_attribute_names("#pk", pk())
            .expression_attribute_names("#sk", sk())
            .expression_attribute_values(":pk", AttributeValue::S(format!("{ORG_PREFIX}{org_id}")))
            .expression_attribute_values(":prefix", AttributeValue::S(type_prefix.clone()))
            .limit(i32::try_from(limit).unwrap_or(i32::MAX));
        if let Some(after) = after {
            let mut start = HashMap::new();
            start.insert(
                pk().to_string(),
                AttributeValue::S(format!("{ORG_PREFIX}{org_id}")),
            );
            start.insert(
                sk().to_string(),
                AttributeValue::S(format!("{type_prefix}{after}")),
            );
            query = query.set_exclusive_start_key(Some(start));
        }

        let result = query.send().await.map_err(map_sdk_error)?;
        result
            .items
            .unwrap_or_default()
            .iter()
            .map(|item| {
                Ok(PromotionEntry {
                    fgrn: get_s(item, "fgrn")?,
                    native_id: get_s(item, "native_id")?,
                })
            })
            .collect()
    }

    async fn list_signing_keys(&self, org_id: &str) -> Result<Vec<EventSigningKey>> {
        let pk_value = format!("{ORG_PREFIX}{org_id}");
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(pk_value))
            .key(sk(), AttributeValue::S(SK_EVENT_SIGNING_KEY.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(map_sdk_error)?;

        let Some(item) = result.item else {
            return Ok(Vec::new());
        };
        let private_pem = get_s(&item, "private_key_pem")?;
        let key_id = get_s(&item, "key_id")?;
        Ok(vec![EventSigningKey {
            key_id,
            public_key_pem: public_pem_from_private(&private_pem)?,
        }])
    }

    async fn create_org(&self, record: OrgRecord, actor: Actor) -> Result<Revision> {
        self.append_org_state(record, EventKind::OrgCreated, actor, None)
            .await
    }

    async fn update_org(
        &self,
        record: OrgRecord,
        actor: Actor,
        expected_revision: Option<Revision>,
    ) -> Result<Revision> {
        self.append_org_state(record, EventKind::OrgUpdated, actor, expected_revision)
            .await
    }

    async fn transition_org(
        &self,
        record: OrgRecord,
        kind: EventKind,
        actor: Actor,
        expected_revision: Revision,
    ) -> Result<Revision> {
        // `kind` must be a lifecycle event, never `OrgCreated` — that would
        // take the `MustNotExist` state-guard branch in `append_org_state`
        // for an org callers already believe exists, surfacing a confusing
        // `Error::Conflict` instead of the expected `RevisionMismatch`.
        debug_assert_ne!(
            kind,
            EventKind::OrgCreated,
            "transition_org must not be called with OrgCreated"
        );
        self.append_org_state(record, kind, actor, Some(expected_revision))
            .await
    }

    async fn generate_org_key(&self, org_id: &str, actor: Actor) -> Result<GenerateKeyResult> {
        // `ThreadRng` is not `Send` — generate before any `.await`.
        let result = generate_key_material()?;
        let new_entry = result.to_entry()?;
        let key_id = result.key_id().to_string();

        let outcome = self
            .append_org_keys(
                org_id,
                EventKind::OrgKeyGenerated,
                actor,
                generate_key_transition(new_entry, key_id),
            )
            .await?;
        debug_assert!(outcome.is_some(), "generate_org_key never no-ops");

        Ok(result)
    }

    async fn revoke_org_key(
        &self,
        org_id: &str,
        key_id: &str,
        actor: Actor,
    ) -> Result<Option<Revision>> {
        self.append_org_keys(
            org_id,
            EventKind::OrgKeyRevoked,
            actor,
            revoke_key_transition(key_id.to_string()),
        )
        .await
    }

    async fn rotate_org_key(
        &self,
        org_id: &str,
        key_id: &str,
        actor: Actor,
    ) -> Result<GenerateKeyResult> {
        // `ThreadRng` is not `Send` — generate before any `.await`.
        let result = generate_key_material()?;
        let new_entry = result.to_entry()?;
        let now = chrono::Utc::now();
        let grace = chrono::Duration::hours(crate::signing_key::ROTATION_GRACE_HOURS);

        self.append_org_keys(
            org_id,
            EventKind::OrgKeyRotated,
            actor,
            rotate_key_transition(key_id.to_string(), new_entry, now, grace),
        )
        .await?;

        Ok(result)
    }
}

mod in_memory;
pub(crate) use in_memory::InMemoryModelEventStore;

#[cfg(test)]
mod in_memory_tests;

#[cfg(test)]
#[cfg(feature = "dynamodb-tests")]
mod dynamo_tests;

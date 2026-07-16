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
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
use forgeguard_authn_core::signing::{sign_bytes, SigningKey};
use forgeguard_authz_core::{
    canonical_event_bytes, fold_events, principal_event_payload, Actor, EventDraft,
    EventDraftParams, EventEnvelope, EventId, EventKind, EventLog, FoldedState, InMemoryEventLog,
    Revision,
};
use forgeguard_core::NativeId;

use forgeguard_core::Segment;

use crate::dynamo_store::{get_s, map_sdk_error, pk, sk, ORG_PREFIX};
use crate::error::{Error, Result};
use crate::event_log::{DynamoEventLog, StateDelete, StatePut};
use crate::promotion_store::{
    promotion_event_payload, promotion_fgrn, promotion_sk, promotion_state_put, PromotionEntry,
    PromotionStatePutParams, PROMO_PREFIX,
};

const PRINCIPAL_PREFIX: &str = "PRINCIPAL#";
const SK_EVENT_SIGNING_KEY: &str = "EVENT_SIGNING_KEY";
const EVENT_SIGNING_KEY_ID: &str = "event-signing-key-1";
/// Fixed Ed25519 seed for `InMemoryPrincipalEventStore`'s signing key — kept
/// as a single const so `Self::new` and `list_signing_keys` can't drift apart.
const IN_MEMORY_SEED: [u8; 32] = [7u8; 32];
/// `key_id` reported for the in-memory store's single fixed signing key.
const IN_MEMORY_KEY_ID: &str = "in-memory-test-key";
/// Page size for `fold_at`'s log replay.
const FOLD_PAGE_SIZE: usize = 100;

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
///
/// V3 (#110) additionally hangs the promotion lifecycle (`get_promotion`,
/// `put_promotion`, `tombstone_promotion`, `list_promotions`) off this same
/// seam — it already owns the per-org signing key + event log this side of
/// the boundary needs, and standing up a second trait just to avoid the name
/// mismatch isn't worth the duplication. The rename to a model-wide name is
/// deferred to #113, when the handler surface churns anyway.
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

/// A published event-signing public key: `key_id` + SPKI public PEM.
/// The private half never leaves the store.
pub(crate) struct EventSigningKey {
    pub(crate) key_id: String,
    pub(crate) public_key_pem: String,
}

/// Derive the SPKI public PEM from a stored PKCS#8 private PEM. Pure.
///
/// The `EVENT_SIGNING_KEY` item persists only the private half; the public
/// half is derived at read time so no schema change or backfill is needed.
fn public_pem_from_private(private_pem: &str) -> Result<String> {
    let key = ed25519_dalek::SigningKey::from_pkcs8_pem(private_pem)
        .map_err(|e| Error::Store(format!("stored event signing key invalid: {e}")))?;
    encode_verifying_key_pem(&key.verifying_key())
}

/// Encode an Ed25519 verifying key as an SPKI public PEM. Pure.
fn encode_verifying_key_pem(key: &ed25519_dalek::VerifyingKey) -> Result<String> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| Error::Store(format!("failed to encode public key: {e}")))
}

/// Parameters for [`build_model_event`].
///
/// `native_id` isn't threaded into the signed bytes — the event envelope
/// carries no subject field of its own, since the subject's identity is
/// already implicit in the `StatePut`/`StateDelete` key it lands alongside —
/// so this struct carries no `native_id` field at all.
struct BuildModelEventParams<'a> {
    org_id: &'a str,
    kind: EventKind,
    actor: Actor,
    payload: serde_json::Value,
    signing_key: &'a SigningKey,
    key_id: &'a str,
    occurred_at: &'a str,
    revision: Revision,
}

/// Build the signed `EventEnvelope` + canonical payload bytes for a model
/// event (principal upsert, resource promotion, resource tombstone, ...) at
/// `revision`, given an already-loaded signing key.
fn build_model_event(
    params: BuildModelEventParams<'_>,
) -> (forgeguard_authz_core::EventEnvelope, Vec<u8>) {
    let BuildModelEventParams {
        org_id,
        kind,
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
        kind,
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

        log.append(build, state).await
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
    /// `(org_id, resource_type, native_id) -> fgrn`.
    promotions: Mutex<HashMap<(String, String, String), String>>,
}

impl InMemoryPrincipalEventStore {
    pub(crate) fn new() -> Self {
        Self {
            principals: Mutex::new(HashMap::new()),
            logs: Mutex::new(HashMap::new()),
            signing_key: SigningKey::from_bytes(&IN_MEMORY_SEED),
            promotions: Mutex::new(HashMap::new()),
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

    /// Shared by `upsert_changed`/`put_promotion`/`tombstone_promotion`: mint
    /// the next revision off `org_id`'s log, build+sign the envelope, and
    /// push it. Callers still own their own state-map bookkeeping (principal
    /// payload vs. promotion fgrn), so this only factors out the identical
    /// "next revision + sign + push" sequence.
    async fn mint_and_push(
        &self,
        org_id: &str,
        kind: EventKind,
        actor: Actor,
        payload: serde_json::Value,
    ) -> Result<Revision> {
        let log = self.log_for(org_id)?;
        let current = EventLog::latest_revision(log.as_ref())
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
        let revision = current.next();
        let occurred_at = chrono::Utc::now().to_rfc3339();
        let (envelope, _payload_bytes) = build_model_event(BuildModelEventParams {
            org_id,
            kind,
            actor,
            payload,
            signing_key: &self.signing_key,
            key_id: IN_MEMORY_KEY_ID,
            occurred_at: &occurred_at,
            revision,
        });
        log.push(envelope);
        Ok(revision)
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
        let event_payload = principal_event_payload(native_id, &payload);
        let revision = self
            .mint_and_push(org_id, EventKind::PrincipalUpserted, actor, event_payload)
            .await?;

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

    async fn get_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
    ) -> Result<Option<String>> {
        let guard = self
            .promotions
            .lock()
            .map_err(|e| Error::Store(format!("in-memory promotion store lock poisoned: {e}")))?;
        Ok(guard
            .get(&(
                org_id.to_string(),
                resource_type.to_string(),
                native_id.to_string(),
            ))
            .cloned())
    }

    async fn put_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
        actor: Actor,
    ) -> Result<Revision> {
        let fgrn = promotion_fgrn(org_id, resource_type, native_id)?;
        let payload = promotion_event_payload(&fgrn, resource_type, native_id);
        let revision = self
            .mint_and_push(org_id, EventKind::ResourcePromoted, actor, payload)
            .await?;

        let mut guard = self
            .promotions
            .lock()
            .map_err(|e| Error::Store(format!("in-memory promotion store lock poisoned: {e}")))?;
        guard.insert(
            (
                org_id.to_string(),
                resource_type.to_string(),
                native_id.to_string(),
            ),
            fgrn.to_string(),
        );
        Ok(revision)
    }

    async fn tombstone_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
        actor: Actor,
    ) -> Result<Option<Revision>> {
        let key = (
            org_id.to_string(),
            resource_type.to_string(),
            native_id.to_string(),
        );
        // Peek-then-append-then-remove (not atomic — acceptable for a test
        // double, but unlike the DynamoDB impl a concurrent tombstone could
        // both observe "present" and both append; real races are exercised
        // only against DynamoDB Local, Task 2/3 integration tests). The
        // removal happens last so a `mint_and_push` failure (e.g. a poisoned
        // log lock) never leaves the promotion deleted without its event.
        let stored = {
            let guard = self.promotions.lock().map_err(|e| {
                Error::Store(format!("in-memory promotion store lock poisoned: {e}"))
            })?;
            guard.get(&key).cloned()
        };
        let Some(fgrn) = stored else {
            return Ok(None);
        };

        let fgrn: forgeguard_core::Fgrn = fgrn
            .parse()
            .map_err(|e| Error::Store(format!("stored promotion fgrn invalid: {e}")))?;
        let payload = promotion_event_payload(&fgrn, resource_type, native_id);
        let revision = self
            .mint_and_push(org_id, EventKind::ResourceTombstoned, actor, payload)
            .await?;

        let mut guard = self
            .promotions
            .lock()
            .map_err(|e| Error::Store(format!("in-memory promotion store lock poisoned: {e}")))?;
        guard.remove(&key);
        Ok(Some(revision))
    }

    async fn list_promotions(
        &self,
        org_id: &str,
        resource_type: &Segment,
        after: Option<&NativeId>,
        limit: usize,
    ) -> Result<Vec<PromotionEntry>> {
        let guard = self
            .promotions
            .lock()
            .map_err(|e| Error::Store(format!("in-memory promotion store lock poisoned: {e}")))?;
        let mut entries: Vec<PromotionEntry> = guard
            .iter()
            .filter(|((o, t, _), _)| o == org_id && t == resource_type.as_str())
            .map(|((_, _, native_id), fgrn)| PromotionEntry {
                fgrn: fgrn.clone(),
                native_id: native_id.clone(),
            })
            .collect();
        entries.sort_by(|a, b| a.native_id.cmp(&b.native_id));
        if let Some(after) = after {
            entries.retain(|e| e.native_id.as_str() > after.as_str());
        }
        entries.truncate(limit);
        Ok(entries)
    }

    async fn list_signing_keys(&self, _org_id: &str) -> Result<Vec<EventSigningKey>> {
        // Same fixed seed as `Self::new` — the two must stay in sync.
        let key = ed25519_dalek::SigningKey::from_bytes(&IN_MEMORY_SEED);
        Ok(vec![EventSigningKey {
            key_id: IN_MEMORY_KEY_ID.to_string(),
            public_key_pem: encode_verifying_key_pem(&key.verifying_key())?,
        }])
    }
}

#[cfg(test)]
mod in_memory_tests;

#[cfg(test)]
#[cfg(feature = "dynamodb-tests")]
mod dynamo_tests;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{public_pem_from_private, LineEnding};
    use ed25519_dalek::pkcs8::spki::DecodePublicKey as _;
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    #[test]
    fn public_pem_from_private_rejects_garbage() {
        let result = public_pem_from_private("garbage");
        assert!(result.is_err());
    }

    #[test]
    fn public_pem_from_private_round_trips_known_good_key() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let private_pem = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();

        let public_pem = public_pem_from_private(&private_pem).unwrap();

        let derived = ed25519_dalek::VerifyingKey::from_public_key_pem(&public_pem).unwrap();
        assert_eq!(derived, signing_key.verifying_key());
    }
}

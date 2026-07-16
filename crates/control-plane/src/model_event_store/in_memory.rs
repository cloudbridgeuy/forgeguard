//! In-memory ModelEventStore implementation — dev-mode `--store=memory`
//! backing and handler tests (split out of `model_event_store.rs` to keep
//! that file under the 1000-line cap).

use super::{
    async_trait, build_model_event, encode_verifying_key_pem, org_payload, principal_event_payload,
    promotion_event_payload, promotion_fgrn, Actor, BuildModelEventParams, Error, EventEnvelope,
    EventKind, EventLog, EventSigningKey, HashMap, InMemoryEventLog, ModelEventStore, Mutex,
    NativeId, OrgRecord, PromotionEntry, Result, Revision, Segment, SigningKey, IN_MEMORY_KEY_ID,
    IN_MEMORY_SEED,
};

// ---------------------------------------------------------------------------
// In-memory implementation — dev-mode `--store=memory` backing and handler
// tests
// ---------------------------------------------------------------------------

/// In-memory [`ModelEventStore`]. Backs `--store=memory` dev mode and lets
/// handler tests exercise the full upsert flow (including a real Ed25519
/// signature) without DynamoDB Local.
pub(crate) struct InMemoryModelEventStore {
    principals: Mutex<HashMap<(String, NativeId), serde_json::Value>>,
    /// One log per org — a shared log would leak one org's events into
    /// another org's `events_after`/`latest_revision` read. `Arc`-wrapped so
    /// the map's lock can be dropped before `.await`-ing the log itself
    /// (`std::sync::MutexGuard` isn't `Send`, and this trait's futures must be).
    logs: Mutex<HashMap<String, std::sync::Arc<InMemoryEventLog>>>,
    signing_key: SigningKey,
    /// `(org_id, resource_type, native_id) -> fgrn`.
    promotions: Mutex<HashMap<(String, String, String), String>>,
    /// `org_id -> OrgRecord`, the org-domain analogue of `principals`.
    ///
    /// No HTTP route calls `create_org`/`update_org` yet (Task 7/8 wire them
    /// up) — same `dead_code` precedent as `put_promotion`.
    #[allow(dead_code)]
    orgs: Mutex<HashMap<String, OrgRecord>>,
}

/// Build the `Error::Store` for a poisoned in-memory lock, tagged with the
/// map's name (`"principal"`, `"promotion"`, `"org"`, `"event log"`) so the
/// message identifies which store's lock was poisoned.
fn lock_poisoned(map_name: &str, e: impl std::fmt::Display) -> Error {
    Error::Store(format!("in-memory {map_name} store lock poisoned: {e}"))
}

impl InMemoryModelEventStore {
    pub(crate) fn new() -> Self {
        Self {
            principals: Mutex::new(HashMap::new()),
            logs: Mutex::new(HashMap::new()),
            signing_key: SigningKey::from_bytes(&IN_MEMORY_SEED),
            promotions: Mutex::new(HashMap::new()),
            orgs: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn log_for(&self, org_id: &str) -> Result<std::sync::Arc<InMemoryEventLog>> {
        let mut logs = self
            .logs
            .lock()
            .map_err(|e| lock_poisoned("event log map", e))?;
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

impl Default for InMemoryModelEventStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ModelEventStore for InMemoryModelEventStore {
    async fn get_principal(
        &self,
        org_id: &str,
        native_id: &NativeId,
    ) -> Result<Option<serde_json::Value>> {
        let guard = self
            .principals
            .lock()
            .map_err(|e| lock_poisoned("principal", e))?;
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
            .map_err(|e| lock_poisoned("principal", e))?;
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
            .map_err(|e| lock_poisoned("promotion", e))?;
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
            .map_err(|e| lock_poisoned("promotion", e))?;
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
            let guard = self
                .promotions
                .lock()
                .map_err(|e| lock_poisoned("promotion", e))?;
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
            .map_err(|e| lock_poisoned("promotion", e))?;
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
            .map_err(|e| lock_poisoned("promotion", e))?;
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

    async fn create_org(&self, record: OrgRecord, actor: Actor) -> Result<Revision> {
        let org_id = record.org().org_id().to_string();
        // Check-then-act (not atomic — acceptable for a test double, but
        // unlike the DynamoDB impl's `StateGuard::MustNotExist` condition,
        // two concurrent `create_org` calls for the same org_id could both
        // observe "absent" here and both proceed to insert; real races are
        // exercised only against DynamoDB Local, Task 2/3 integration tests).
        {
            let guard = self.orgs.lock().map_err(|e| lock_poisoned("org", e))?;
            if guard.contains_key(&org_id) {
                return Err(Error::Conflict(format!(
                    "organization '{org_id}' already exists"
                )));
            }
        }

        let payload = org_payload(&record)?;
        let revision = self
            .mint_and_push(&org_id, EventKind::OrgCreated, actor, payload)
            .await?;

        let mut guard = self.orgs.lock().map_err(|e| lock_poisoned("org", e))?;
        guard.insert(org_id, record);
        Ok(revision)
    }

    async fn update_org(
        &self,
        record: OrgRecord,
        actor: Actor,
        expected_revision: Option<Revision>,
    ) -> Result<Revision> {
        let org_id = record.org().org_id().to_string();
        // Read-then-act (not atomic — acceptable for a test double, but
        // unlike the DynamoDB impl's CAS-based retry loop, this reads
        // `latest_revision` here and again inside `mint_and_push` with no
        // lock held across the steps, so a concurrent writer could slip in
        // between the two reads; real races are exercised only against
        // DynamoDB Local, Task 2/3 integration tests).
        let current = self.latest_revision(&org_id).await?;
        if let Some(expected) = expected_revision {
            if current != expected {
                return Err(Error::RevisionMismatch {
                    current: current.value(),
                });
            }
        }

        let payload = org_payload(&record)?;
        let revision = self
            .mint_and_push(&org_id, EventKind::OrgUpdated, actor, payload)
            .await?;

        let mut guard = self.orgs.lock().map_err(|e| lock_poisoned("org", e))?;
        guard.insert(org_id, record);
        Ok(revision)
    }
}

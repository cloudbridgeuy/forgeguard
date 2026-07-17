//! Pure/shared helpers factored out of `model_event_store::mod` to keep that
//! file under the 1000-line cap: principal/org state-item mapping, the
//! event-signing public-key derivation, and the shared signed-envelope
//! builder consumed by both `DynamoModelEventStore` and
//! `InMemoryModelEventStore`.

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
use forgeguard_authn_core::signing::{sign_bytes, SigningKey};
use forgeguard_authz_core::{
    canonical_event_bytes, org_event_payload, Actor, EventDraft, EventDraftParams, EventId,
    EventKind, Revision,
};
use forgeguard_core::NativeId;

use crate::dynamo_store::{get_s, map_sdk_error, pk, sk, ORG_PREFIX, SK_META};
use crate::error::{Error, Result};
use crate::event_log::{StateGuard, StatePut};
use crate::signing_key::SigningKeyEntry;
use crate::store::OrgRecord;

/// The `transition` closure shape `append_org_keys` (Dynamo and in-memory
/// alike) drives: given the org's current `signing_keys`, either report
/// `None` (D6 no-op, nothing to append) or `Some((affected_key_id,
/// new_keys))` to append.
type KeyTransition = Result<Option<(String, Vec<SigningKeyEntry>)>>;

pub(super) const PRINCIPAL_PREFIX: &str = "PRINCIPAL#";

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
        guard: StateGuard::None,
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

/// Strongly-consistent read of an org's raw state item, or `None` if absent.
///
/// Mirrors `DynamoOrgStore::get_raw_item`, duplicated here (rather than
/// shared) because that method lives on a different struct with no shared
/// base — both are thin wrappers around the same `GetItem` call.
pub(super) async fn get_raw_org_item(
    client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    org_id: &str,
) -> Result<Option<HashMap<String, AttributeValue>>> {
    let result = client
        .get_item()
        .table_name(table_name)
        .key(pk(), AttributeValue::S(format!("{ORG_PREFIX}{org_id}")))
        .key(sk(), AttributeValue::S(SK_META.to_string()))
        .consistent_read(true)
        .send()
        .await
        .map_err(map_sdk_error)?;
    Ok(result.item)
}

/// Build the D3/D4 event payload for an org mutation: `{"organization",
/// "config"}`, full post-mutation state.
pub(super) fn org_payload(record: &OrgRecord) -> Result<serde_json::Value> {
    let organization = serde_json::to_value(record.org())
        .map_err(|e| Error::Store(format!("serialize organization: {e}")))?;
    let config = record
        .config()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| Error::Store(format!("serialize org config: {e}")))?;
    Ok(org_event_payload(&organization, config.as_ref()))
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
pub(super) fn public_pem_from_private(private_pem: &str) -> Result<String> {
    let key = ed25519_dalek::SigningKey::from_pkcs8_pem(private_pem)
        .map_err(|e| Error::Store(format!("stored event signing key invalid: {e}")))?;
    encode_verifying_key_pem(&key.verifying_key())
}

/// Encode an Ed25519 verifying key as an SPKI public PEM. Pure.
pub(super) fn encode_verifying_key_pem(key: &ed25519_dalek::VerifyingKey) -> Result<String> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| Error::Store(format!("failed to encode public key: {e}")))
}

/// Parameters for [`build_model_event`].
///
/// `native_id` isn't threaded into the signed bytes — the event envelope
/// carries no subject field of its own, since the subject's identity is
/// already implicit in the `StatePut`/`StateDelete` key it lands alongside —
/// so this struct carries no `native_id` field at all.
pub(super) struct BuildModelEventParams<'a> {
    pub(super) org_id: &'a str,
    pub(super) kind: EventKind,
    pub(super) actor: Actor,
    pub(super) payload: serde_json::Value,
    pub(super) signing_key: &'a SigningKey,
    pub(super) key_id: &'a str,
    pub(super) occurred_at: &'a str,
    pub(super) revision: Revision,
}

/// Build the signed `EventEnvelope` + canonical payload bytes for a model
/// event (principal upsert, resource promotion, resource tombstone, ...) at
/// `revision`, given an already-loaded signing key.
pub(super) fn build_model_event(
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

/// Build the `generate_org_key` transition: push `new_entry` and report
/// `key_id` as the affected key. Shared by `DynamoModelEventStore` (which
/// calls the closure repeatedly across its CAS retry loop, hence `Fn`) and
/// `InMemoryModelEventStore` (which calls it once) — `Fn` satisfies both.
/// No HTTP route calls `generate_org_key` in Task 4 — wired in Task 5, hence
/// `dead_code`, same precedent as `put_promotion`.
#[allow(dead_code)]
pub(super) fn generate_key_transition(
    new_entry: SigningKeyEntry,
    key_id: String,
) -> impl Fn(Vec<SigningKeyEntry>) -> KeyTransition {
    move |mut keys| {
        keys.push(new_entry.clone());
        Ok(Some((key_id.clone(), keys)))
    }
}

/// Build the `revoke_org_key` transition: `None` if `target` is absent or
/// already revoked (D6 no-op), else the narrowed `signing_keys` list. No HTTP
/// route calls `revoke_org_key` in Task 4 — wired in Task 5, hence
/// `dead_code`, same precedent as `put_promotion`.
#[allow(dead_code)]
pub(super) fn revoke_key_transition(
    target: String,
) -> impl Fn(Vec<SigningKeyEntry>) -> KeyTransition {
    move |keys| {
        Ok(crate::signing_key::revoke_entries(keys, &target)
            .map(|new_keys| (target.clone(), new_keys)))
    }
}

/// Build the `rotate_org_key` transition: move `target` to `Rotating` with a
/// `grace` window as of `now`, and append `new_entry` as the new `Active` key.
/// No HTTP route calls `rotate_org_key` in Task 4 — wired in Task 5, hence
/// `dead_code`, same precedent as `put_promotion`.
#[allow(dead_code)]
pub(super) fn rotate_key_transition(
    target: String,
    new_entry: SigningKeyEntry,
    now: chrono::DateTime<chrono::Utc>,
    grace: chrono::Duration,
) -> impl Fn(Vec<SigningKeyEntry>) -> KeyTransition {
    move |keys| {
        let updated =
            crate::signing_key::rotate_entries(keys, &target, new_entry.clone(), now, grace)?;
        Ok(Some((target.clone(), updated)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use ed25519_dalek::pkcs8::spki::DecodePublicKey as _;
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    use super::{public_pem_from_private, LineEnding};

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

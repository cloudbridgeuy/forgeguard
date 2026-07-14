//! Unsigned drafts and signed envelopes for the per-org event log.

use forgeguard_core::Fgrn;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::event::kind::EventKind;
use crate::store::Revision;

/// Schema version of the persisted event envelope.
pub const SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// EventId
// ---------------------------------------------------------------------------

/// Identity of an appended event. A ULID string, minted by the shell.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(String);

impl EventId {
    /// Wrap a non-empty event id.
    pub fn try_new(value: String) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::InvalidEventId(value));
        }
        Ok(Self(value))
    }

    /// Borrow the raw id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// Who caused the mutation recorded by an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    /// A human or service principal identified by FGRN.
    Principal(Fgrn),
    /// A machine caller identified by its signing key id.
    Machine(String),
    /// The system itself (no external caller).
    System,
}

// ---------------------------------------------------------------------------
// EventDraft
// ---------------------------------------------------------------------------

/// Parameters for [`EventDraft::new`] — the params-struct carve-out (project
/// rule: never `#[allow(clippy::too_many_arguments)]`).
pub struct EventDraftParams {
    /// The shell-minted event id.
    pub event_id: EventId,
    /// The store revision this event will occupy.
    pub seq: Revision,
    /// The kind of mutation.
    pub kind: EventKind,
    /// RFC3339 timestamp, shell-provided.
    pub occurred_at: String,
    /// Who caused the mutation.
    pub actor: Actor,
    /// The full post-mutation entity state.
    pub payload: serde_json::Value,
}

/// An unsigned event, ready for canonicalization.
///
/// All inputs come from the shell (`event_id`, `occurred_at`) — the core
/// mints nothing itself (no clock, no randomness).
pub struct EventDraft {
    event_id: EventId,
    seq: Revision,
    kind: EventKind,
    occurred_at: String,
    actor: Actor,
    narrowing: bool,
    payload: serde_json::Value,
}

impl EventDraft {
    /// Build a draft. `narrowing` is derived from `kind.narrowing()` here —
    /// callers cannot set it inconsistently with the kind.
    pub fn new(params: EventDraftParams) -> Self {
        let narrowing = params.kind.narrowing();
        Self {
            event_id: params.event_id,
            seq: params.seq,
            kind: params.kind,
            occurred_at: params.occurred_at,
            actor: params.actor,
            narrowing,
            payload: params.payload,
        }
    }

    /// The event id.
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// The store revision this event occupies.
    pub fn seq(&self) -> Revision {
        self.seq
    }

    /// The event kind.
    pub fn kind(&self) -> EventKind {
        self.kind
    }

    /// RFC3339 occurrence timestamp.
    pub fn occurred_at(&self) -> &str {
        &self.occurred_at
    }

    /// Who caused the mutation.
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Whether this event narrows the effective access surface.
    pub fn narrowing(&self) -> bool {
        self.narrowing
    }

    /// The envelope schema version.
    pub fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }

    /// The full post-mutation entity state.
    pub fn payload(&self) -> &serde_json::Value {
        &self.payload
    }
}

// ---------------------------------------------------------------------------
// EventEnvelope
// ---------------------------------------------------------------------------

/// A signed envelope — what is stored and served.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    event_id: EventId,
    seq: Revision,
    kind: EventKindWire,
    occurred_at: String,
    actor: Actor,
    narrowing: bool,
    schema_version: u32,
    payload: serde_json::Value,
    key_id: String,
    signature: String,
}

/// Wire representation of [`EventKind`] — serializes via `as_str`/`FromStr`
/// rather than deriving serde directly on the enum, keeping the wire format
/// decoupled from Rust variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EventKindWire(EventKind);

impl Serialize for EventKindWire {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for EventKindWire {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<EventKind>()
            .map(EventKindWire)
            .map_err(serde::de::Error::custom)
    }
}

impl EventEnvelope {
    /// Seal a draft into a signed envelope.
    pub fn from_signed(draft: EventDraft, key_id: String, signature_b64: String) -> Self {
        Self {
            event_id: draft.event_id,
            seq: draft.seq,
            kind: EventKindWire(draft.kind),
            occurred_at: draft.occurred_at,
            actor: draft.actor,
            narrowing: draft.narrowing,
            schema_version: SCHEMA_VERSION,
            payload: draft.payload,
            key_id,
            signature: signature_b64,
        }
    }

    /// The event id.
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// The store revision this event occupies.
    pub fn seq(&self) -> Revision {
        self.seq
    }

    /// The event kind.
    pub fn kind(&self) -> EventKind {
        self.kind.0
    }

    /// RFC3339 occurrence timestamp.
    pub fn occurred_at(&self) -> &str {
        &self.occurred_at
    }

    /// Who caused the mutation.
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Whether this event narrows the effective access surface.
    pub fn narrowing(&self) -> bool {
        self.narrowing
    }

    /// The envelope schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The full post-mutation entity state.
    pub fn payload(&self) -> &serde_json::Value {
        &self.payload
    }

    /// The id of the key that produced [`Self::signature`].
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Base64-encoded Ed25519 signature over the canonical event bytes.
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::event::kind::EventKind;
    use forgeguard_core::{NativeId, Segment};

    fn draft(kind: EventKind) -> EventDraft {
        EventDraft::new(EventDraftParams {
            event_id: EventId::try_new("01J000000000000000000000".to_string()).unwrap(),
            seq: Revision::new(1),
            kind,
            occurred_at: "2026-07-14T00:00:00Z".to_string(),
            actor: Actor::Principal(Fgrn::principal(
                &Segment::try_new("acme").unwrap(),
                &NativeId::try_new("usr_1").unwrap(),
            )),
            payload: serde_json::json!({ "a": 1 }),
        })
    }

    #[test]
    fn empty_event_id_errors() {
        let err = EventId::try_new(String::new()).unwrap_err();
        assert!(matches!(err, Error::InvalidEventId(s) if s.is_empty()));
    }

    #[test]
    fn draft_derives_narrowing_from_kind() {
        let d = draft(EventKind::GrantRemoved);
        assert!(d.narrowing());

        let d = draft(EventKind::GrantAdded);
        assert!(!d.narrowing());
    }

    #[test]
    fn envelope_serde_round_trip_matches_expected_fields() {
        let envelope = EventEnvelope::from_signed(
            draft(EventKind::PrincipalUpserted),
            "key-1".to_string(),
            "c2ln".to_string(),
        );
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "event_id": "01J000000000000000000000",
                "seq": 1,
                "kind": "principal.upserted",
                "occurred_at": "2026-07-14T00:00:00Z",
                "actor": { "principal": "fgrn:acme:principal:usr_1" },
                "narrowing": false,
                "schema_version": 1,
                "payload": { "a": 1 },
                "key_id": "key-1",
                "signature": "c2ln",
            })
        );

        let back: EventEnvelope = serde_json::from_value(value).unwrap();
        assert_eq!(back.event_id().as_str(), envelope.event_id().as_str());
        assert_eq!(back.kind(), envelope.kind());
    }

    #[test]
    fn schema_version_serializes_as_one() {
        let envelope = EventEnvelope::from_signed(
            draft(EventKind::GrantAdded),
            "k".to_string(),
            "s".to_string(),
        );
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(value["schema_version"], serde_json::json!(1));
    }
}

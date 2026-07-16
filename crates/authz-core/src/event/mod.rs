//! The per-org append-only event log's pure model: kinds, envelopes, and
//! canonical byte encoding used for signing.

mod canonical;
mod envelope;
mod fold;
mod kind;
mod log;
mod upsert;

pub use canonical::{canonical_envelope_bytes, canonical_event_bytes};
pub use envelope::{Actor, EventDraft, EventDraftParams, EventEnvelope, EventId, SCHEMA_VERSION};
pub use fold::{
    fold_events, org_event_payload, org_semantic_view, principal_event_payload, FoldedState,
};
pub use kind::EventKind;
pub use log::EventLog;
pub use upsert::{decide_upsert, UpsertDecision};

#[cfg(any(test, feature = "test-support"))]
pub use log::InMemoryEventLog;

//! The per-org append-only event log's pure model: kinds, envelopes, and
//! canonical byte encoding used for signing.

mod canonical;
mod envelope;
mod kind;

pub use canonical::canonical_event_bytes;
pub use envelope::{Actor, EventDraft, EventDraftParams, EventEnvelope, EventId, SCHEMA_VERSION};
pub use kind::EventKind;

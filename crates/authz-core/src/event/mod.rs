//! The per-org append-only event log's pure model: kinds, envelopes, and
//! canonical byte encoding used for signing.

mod envelope;
mod kind;

pub use envelope::{Actor, EventDraft, EventDraftParams, EventEnvelope, EventId, SCHEMA_VERSION};
pub use kind::EventKind;

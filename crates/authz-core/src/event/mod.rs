//! The per-org append-only event log's pure model: kinds, envelopes, and
//! canonical byte encoding used for signing.

mod kind;

pub use kind::EventKind;

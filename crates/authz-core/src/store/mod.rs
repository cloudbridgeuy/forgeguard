//! Store trait and reference implementation: snapshot-at-revision reads,
//! revision-returning writes (Design A1's `fg-store`, scoped to phase 2 —
//! the change stream arrives with the event log in phase 3).

pub mod revision;

pub use revision::Revision;

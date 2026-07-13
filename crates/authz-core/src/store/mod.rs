//! Store trait and reference implementation: snapshot-at-revision reads,
//! revision-returning writes (Design A1's `fg-store`, scoped to phase 2 —
//! the change stream arrives with the event log in phase 3).

pub mod model;
pub mod revision;
pub mod slice;
pub mod traits;

pub use model::ModelState;
pub use revision::Revision;
pub use slice::{select_slice, EntitySlice};
pub use traits::{AuthzStore, SliceQuery, StoreWrite};

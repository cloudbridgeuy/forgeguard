//! Embedded Cedar engine (Design A1's `fg-engine`): one consistent store
//! read, in-process evaluation, decision records carrying versions.

pub mod record;

pub use record::{Decision, DecisionQuery, DecisionRecord};

//! Embedded Cedar engine (Design A1's `fg-engine`): one consistent store
//! read, in-process evaluation, decision records carrying versions.

pub mod engine;
pub mod record;
pub mod translate;

pub use engine::CedarEngine;
pub use record::{Decision, DecisionQuery, DecisionRecord};

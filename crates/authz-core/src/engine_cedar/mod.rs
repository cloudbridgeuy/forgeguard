//! Embedded Cedar engine (Design A1's `fg-engine`): one consistent store
//! read, in-process evaluation, decision records carrying versions.

pub mod adapter;
pub mod engine;
pub mod record;
mod scope_path;
pub mod translate;

pub use adapter::EmbeddedPolicyEngine;
pub use engine::CedarEngine;
pub use record::{Decision, DecisionQuery, DecisionRecord};
pub use scope_path::ScopePath;

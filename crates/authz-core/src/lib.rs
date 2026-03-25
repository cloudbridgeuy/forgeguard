#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod context;
pub mod decision;
pub mod engine;
pub mod error;
pub mod query;

#[cfg(feature = "test-support")]
pub mod static_engine;

pub use context::PolicyContext;
pub use decision::{DenyReason, PolicyDecision};
pub use engine::PolicyEngine;
pub use error::{Error, Result};
pub use query::PolicyQuery;

#[cfg(feature = "test-support")]
pub use static_engine::StaticPolicyEngine;

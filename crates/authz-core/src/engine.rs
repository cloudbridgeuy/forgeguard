//! Pluggable policy engine trait.

use std::future::Future;
use std::pin::Pin;

use crate::decision::PolicyDecision;
use crate::error::Result;
use crate::query::PolicyQuery;

/// Trait for evaluating authorization queries against a policy store.
///
/// Async because I/O implementations (e.g., AWS Verified Permissions)
/// need it. Pure implementations use `Box::pin(std::future::ready(...))`.
///
/// Defined in this pure crate, implemented in I/O crates.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate a policy query and return a decision.
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>>;
}

//! In-memory policy engine for testing consumers.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use forgeguard_core::QualifiedAction;

use crate::decision::PolicyDecision;
use crate::engine::PolicyEngine;
use crate::error::Result;
use crate::query::PolicyQuery;

/// A deterministic, in-memory policy engine for testing.
///
/// Returns a configurable default decision for any query,
/// with optional per-action overrides.
pub struct StaticPolicyEngine {
    default_decision: PolicyDecision,
    overrides: HashMap<String, PolicyDecision>,
}

impl StaticPolicyEngine {
    /// Create with a default decision applied to all queries.
    pub fn new(default_decision: PolicyDecision) -> Self {
        Self {
            default_decision,
            overrides: HashMap::new(),
        }
    }

    /// Add a per-action override. The action's `Display` representation
    /// (e.g., "todo:read:list") is used as the lookup key.
    pub fn with_override(mut self, action: &QualifiedAction, decision: PolicyDecision) -> Self {
        self.overrides.insert(action.to_string(), decision);
        self
    }
}

impl PolicyEngine for StaticPolicyEngine {
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
        let action_key = query.action().to_string();
        let decision = self
            .overrides
            .get(&action_key)
            .cloned()
            .unwrap_or_else(|| self.default_decision.clone());
        Box::pin(std::future::ready(Ok(decision)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::{PrincipalRef, QualifiedAction, UserId};

    use super::*;
    use crate::context::PolicyContext;
    use crate::decision::DenyReason;

    fn make_query(action_str: &str) -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new("test-user").unwrap());
        let action = QualifiedAction::parse(action_str).unwrap();
        let context = PolicyContext::new();
        PolicyQuery::new(principal, action, None, context)
    }

    #[tokio::test]
    async fn default_allow_returns_allow() {
        let engine = StaticPolicyEngine::new(PolicyDecision::Allow);
        let query = make_query("todo:read:list");

        let decision = engine.evaluate(&query).await.unwrap();
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn default_deny_returns_deny() {
        let engine = StaticPolicyEngine::new(PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        });
        let query = make_query("todo:read:list");

        let decision = engine.evaluate(&query).await.unwrap();
        assert!(decision.is_denied());
    }

    #[tokio::test]
    async fn override_takes_precedence_over_default() {
        let engine = StaticPolicyEngine::new(PolicyDecision::Allow).with_override(
            &QualifiedAction::parse("admin:delete:user").unwrap(),
            PolicyDecision::Deny {
                reason: DenyReason::ExplicitDeny {
                    policy_id: "no-delete-users".into(),
                },
            },
        );

        // Default action → allow
        let allowed_query = make_query("todo:read:list");
        let decision = engine.evaluate(&allowed_query).await.unwrap();
        assert!(decision.is_allowed());

        // Overridden action → deny
        let denied_query = make_query("admin:delete:user");
        let decision = engine.evaluate(&denied_query).await.unwrap();
        assert!(decision.is_denied());
    }

    #[tokio::test]
    async fn non_overridden_action_falls_through_to_default() {
        let engine = StaticPolicyEngine::new(PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        })
        .with_override(
            &QualifiedAction::parse("todo:read:list").unwrap(),
            PolicyDecision::Allow,
        );

        let query = make_query("admin:write:config");
        let decision = engine.evaluate(&query).await.unwrap();
        assert!(decision.is_denied());
    }
}

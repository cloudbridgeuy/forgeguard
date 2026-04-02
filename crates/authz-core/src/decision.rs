//! Authorization decision types.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Why a request was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    /// No policy matched the query.
    NoMatchingPolicy,
    /// A policy explicitly denied the request.
    ExplicitDeny { policy_id: String },
    /// An error occurred during policy evaluation.
    EvaluationError(String),
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMatchingPolicy => write!(f, "no matching policy"),
            Self::ExplicitDeny { policy_id } => {
                write!(f, "explicitly denied by policy '{policy_id}'")
            }
            Self::EvaluationError(msg) => write!(f, "evaluation error: {msg}"),
        }
    }
}

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// The request is allowed.
    Allow,
    /// The request is denied.
    Deny { reason: DenyReason },
}

impl PolicyDecision {
    /// Returns `true` if the decision is `Allow`.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if the decision is `Deny`.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allowed"),
            Self::Deny { reason } => write!(f, "denied: {reason}"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_allow() {
        let decision = PolicyDecision::Allow;
        assert_eq!(decision.to_string(), "allowed");
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
    }

    #[test]
    fn display_deny_no_matching_policy() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        };
        assert_eq!(decision.to_string(), "denied: no matching policy");
        assert!(!decision.is_allowed());
        assert!(decision.is_denied());
    }

    #[test]
    fn display_deny_explicit() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::ExplicitDeny {
                policy_id: "pol-admin-deny-delete".into(),
            },
        };
        assert_eq!(
            decision.to_string(),
            "denied: explicitly denied by policy 'pol-admin-deny-delete'"
        );
    }

    #[test]
    fn display_deny_evaluation_error() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::EvaluationError("connection timeout".into()),
        };
        assert_eq!(
            decision.to_string(),
            "denied: evaluation error: connection timeout"
        );
    }

    #[test]
    fn serde_round_trip_allow() {
        let decision = PolicyDecision::Allow;
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, decoded);
    }

    #[test]
    fn serde_round_trip_deny_explicit() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::ExplicitDeny {
                policy_id: "pol-1".into(),
            },
        };
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, decoded);
    }

    #[test]
    fn serde_round_trip_deny_no_matching() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        };
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, decoded);
    }
}

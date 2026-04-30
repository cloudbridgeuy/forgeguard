//! Pipeline outcome types — the result of running the auth pipeline.

use forgeguard_authn_core::Identity;
use forgeguard_core::ResolvedFlags;
use forgeguard_http::MatchedRoute;

// ---------------------------------------------------------------------------
// PipelineOutcome
// ---------------------------------------------------------------------------

/// The result of running the auth pipeline on a single request.
///
/// This is a closed enum — every possible pipeline result is a variant.
/// Protocol adapters pattern-match on this to produce framework-specific responses.
#[derive(Debug)]
pub enum PipelineOutcome {
    /// The request matched the health-check endpoint.
    Health(String),
    /// The request matched the debug endpoint.
    Debug(String),
    /// The pipeline rejected the request (auth failure, no route, etc.).
    Reject {
        /// HTTP status code to return (e.g. 401, 403, 404).
        status: http::StatusCode,
        /// Response body (error message or JSON).
        body: String,
    },
    /// The pipeline approved the request for forwarding to upstream.
    Forward {
        /// The resolved identity, if authentication succeeded.
        identity: Option<Identity>,
        /// Evaluated feature flags, if flag config is present.
        flags: Option<ResolvedFlags>,
        /// The matched route with action/resource, if a route matched.
        /// Boxed to reduce enum variant size disparity.
        matched_route: Option<Box<MatchedRoute>>,
    },
}

impl PipelineOutcome {
    /// Create a `Health` outcome.
    pub fn health(body: impl Into<String>) -> Self {
        Self::Health(body.into())
    }

    /// Create a `Debug` outcome.
    pub fn debug(body: impl Into<String>) -> Self {
        Self::Debug(body.into())
    }

    /// Create a `Reject` outcome.
    pub fn reject(status: http::StatusCode, body: impl Into<String>) -> Self {
        Self::Reject {
            status,
            body: body.into(),
        }
    }

    /// Create a `Forward` outcome with no identity, flags, or matched route.
    pub fn forward_anonymous() -> Self {
        Self::Forward {
            identity: None,
            flags: None,
            matched_route: None,
        }
    }

    /// Returns `true` if this outcome is a forward (request should proceed).
    pub fn is_forward(&self) -> bool {
        matches!(self, Self::Forward { .. })
    }

    /// Returns `true` if this outcome is a rejection.
    pub fn is_reject(&self) -> bool {
        matches!(self, Self::Reject { .. })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn health_outcome() {
        let outcome = PipelineOutcome::health("ok");
        match outcome {
            PipelineOutcome::Health(body) => assert_eq!(body, "ok"),
            _ => panic!("expected Health variant"),
        }
    }

    #[test]
    fn debug_outcome() {
        let outcome = PipelineOutcome::debug("{\"flags\":{}}");
        match outcome {
            PipelineOutcome::Debug(body) => assert_eq!(body, "{\"flags\":{}}"),
            _ => panic!("expected Debug variant"),
        }
    }

    #[test]
    fn reject_constructor_takes_typed_status() {
        let outcome = PipelineOutcome::reject(http::StatusCode::FORBIDDEN, "denied");
        match outcome {
            PipelineOutcome::Reject { status, body } => {
                assert_eq!(status, http::StatusCode::FORBIDDEN);
                assert_eq!(body, "denied");
            }
            _ => panic!("expected Reject"),
        }
    }

    #[test]
    fn forward_anonymous_outcome() {
        let outcome = PipelineOutcome::forward_anonymous();
        match outcome {
            PipelineOutcome::Forward {
                identity,
                flags,
                matched_route,
            } => {
                assert!(identity.is_none());
                assert!(flags.is_none());
                assert!(matched_route.is_none());
            }
            _ => panic!("expected Forward variant"),
        }
    }

    #[test]
    fn is_forward_returns_false_for_debug() {
        assert!(!PipelineOutcome::debug("info").is_forward());
    }

    #[test]
    fn is_forward_returns_false_for_health() {
        assert!(!PipelineOutcome::health("ok").is_forward());
    }

    #[test]
    fn is_reject_returns_false_for_debug() {
        assert!(!PipelineOutcome::debug("info").is_reject());
    }

    #[test]
    fn is_forward_returns_true_for_forward() {
        assert!(PipelineOutcome::forward_anonymous().is_forward());
    }

    #[test]
    fn is_forward_returns_false_for_reject() {
        assert!(
            !PipelineOutcome::reject(http::StatusCode::UNAUTHORIZED, "unauthorized").is_forward()
        );
    }

    #[test]
    fn is_reject_returns_true_for_reject() {
        assert!(PipelineOutcome::reject(http::StatusCode::FORBIDDEN, "forbidden").is_reject());
    }

    #[test]
    fn is_reject_returns_false_for_health() {
        assert!(!PipelineOutcome::health("ok").is_reject());
    }

    #[test]
    fn is_reject_returns_false_for_forward() {
        assert!(!PipelineOutcome::forward_anonymous().is_reject());
    }
}

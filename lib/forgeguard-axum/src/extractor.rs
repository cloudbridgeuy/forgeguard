//! Axum extractors for ForgeGuard auth context.
//!
//! These read from request extensions injected by [`crate::forgeguard_layer`].

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use forgeguard_authn_core::Identity;
use forgeguard_authz_core::DecisionRecord;
use forgeguard_core::ResolvedFlags;

/// Extractor for the resolved identity.
///
/// Returns `None` if the request was unauthenticated (e.g., public route
/// with `Anonymous` auth mode) or if the middleware has not run.
///
/// PDV exception: the inner field is intentionally `pub` so handlers can
/// destructure the extractor in parameter position. A private field would
/// prevent destructuring in handler parameter position, which is the idiomatic
/// Axum extractor usage.
///
/// # Example
///
/// ```rust,no_run
/// # use forgeguard_axum::ForgeGuardIdentity;
/// # use axum::response::IntoResponse;
/// async fn my_handler(
///     ForgeGuardIdentity(identity): ForgeGuardIdentity,
/// ) -> impl IntoResponse {
///     if let Some(id) = identity {
///         format!("Hello, {}", id.user_id())
///     } else {
///         "Hello, anonymous".to_string()
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ForgeGuardIdentity(pub Option<Identity>);

/// Extractor for evaluated feature flags.
///
/// Returns `None` if no flag configuration was present or if the
/// middleware has not run.
///
/// PDV exception: the inner field is intentionally `pub` so handlers can
/// destructure the extractor in parameter position. A private field would
/// prevent destructuring in handler parameter position, which is the idiomatic
/// Axum extractor usage.
///
/// # Example
///
/// ```rust,no_run
/// # use forgeguard_axum::ForgeGuardFlags;
/// # use axum::response::IntoResponse;
/// async fn my_handler(
///     ForgeGuardFlags(flags): ForgeGuardFlags,
/// ) -> impl IntoResponse {
///     let enabled = flags
///         .as_ref()
///         .map(|f| f.enabled("dark-mode"))
///         .unwrap_or(false);
///     format!("dark-mode: {enabled}")
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ForgeGuardFlags(pub Option<ResolvedFlags>);

/// The embedded-engine decision record for this request, when the policy
/// engine produced one (`None` under static/VP engines or public routes).
///
/// PDV exception: the inner field is intentionally `pub` so handlers can
/// destructure the extractor in parameter position. A private field would
/// prevent destructuring in handler parameter position, which is the idiomatic
/// Axum extractor usage.
///
/// # Example
///
/// ```rust,no_run
/// # use forgeguard_axum::ForgeGuardDecision;
/// # use axum::response::IntoResponse;
/// async fn my_handler(
///     ForgeGuardDecision(record): ForgeGuardDecision,
/// ) -> impl IntoResponse {
///     match record {
///         Some(r) => format!("scope: {}", r.scope_path()),
///         None => "no decision record".to_string(),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ForgeGuardDecision(pub Option<DecisionRecord>);

impl<S> FromRequestParts<S> for ForgeGuardIdentity
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<ForgeGuardIdentity>()
            .cloned()
            .unwrap_or(ForgeGuardIdentity(None)))
    }
}

impl<S> FromRequestParts<S> for ForgeGuardFlags
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<ForgeGuardFlags>()
            .cloned()
            .unwrap_or(ForgeGuardFlags(None)))
    }
}

impl<S> FromRequestParts<S> for ForgeGuardDecision
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<ForgeGuardDecision>()
            .cloned()
            .unwrap_or(ForgeGuardDecision(None)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn identity_extractor_returns_none_when_absent() {
        let app = Router::new().route(
            "/test",
            get(|ForgeGuardIdentity(id): ForgeGuardIdentity| async move {
                assert!(id.is_none());
                "ok"
            }),
        );

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn flags_extractor_returns_none_when_absent() {
        let app = Router::new().route(
            "/test",
            get(|ForgeGuardFlags(flags): ForgeGuardFlags| async move {
                assert!(flags.is_none());
                "ok"
            }),
        );

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn decision_extractor_returns_none_when_absent() {
        let app = Router::new().route(
            "/test",
            get(
                |ForgeGuardDecision(record): ForgeGuardDecision| async move {
                    assert!(record.is_none());
                    "ok"
                },
            ),
        );

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

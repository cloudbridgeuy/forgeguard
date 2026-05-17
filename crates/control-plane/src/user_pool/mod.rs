//! User-pool client abstraction for the V3 `POST /users` saga.
//!
//! ## Module structure
//!
//! - `mod` (this file) — `UserPoolClient` trait.
//! - `aws` — production impl `AwsCognitoUserPoolClient` (V3 sub-commit (b)).
//! - `memory` — in-process `InMemoryUserPoolClient` for tests
//!   (V3 sub-commit (b)).
//!
//! The trait returns the pure [`forgeguard_authn_core::UserPoolError`] so the
//! saga driver can pattern-match outcomes without ever depending on the AWS
//! SDK directly. Method names mirror the underlying Cognito API verbs
//! (`AdminCreateUser`, `AdminDeleteUser`, `AdminGetUser`, `UpdateUserPool`).

use async_trait::async_trait;
use forgeguard_authn_core::user_pool::{CreateUserParams, PoolId, UpdatePoolParams, UserPoolError};
use forgeguard_core::UserId;

/// Four Cognito operations the V3 saga driver depends on.
///
/// Implementations:
/// - `aws::AwsCognitoUserPoolClient` — production
/// - `memory::InMemoryUserPoolClient` — tests (with `arm_*` knobs)
#[async_trait]
#[allow(dead_code)] // consumers added in sub-commits (b)/(d)
pub(crate) trait UserPoolClient: Send + Sync {
    /// Stage S2 — AdminCreateUser with `MessageAction=SUPPRESS`.
    ///
    /// Returns the Cognito-issued sub. Pre-existing username/email surface as
    /// [`UserPoolError::UsernameExists`] / [`UserPoolError::AttributeAlreadyExists`]
    /// so the handler can map them to typed `409` responses.
    async fn admin_create_user(&self, params: CreateUserParams) -> Result<UserId, UserPoolError>;

    /// Compensation C2 — AdminDeleteUser by sub.
    ///
    /// MUST treat a not-found user as success (idempotent compensation).
    /// Transient errors propagate so the saga driver can record
    /// `CompensationFailed`.
    async fn admin_delete_user(&self, pool_id: &PoolId, sub: &UserId) -> Result<(), UserPoolError>;

    /// Look up an existing user's sub by email.
    ///
    /// Returns [`UserPoolError::UserNotFound`] when no user matches. Used by
    /// the saga driver to recover the sub of a partially-created user when a
    /// retry observes `UsernameExists`.
    async fn admin_get_user(&self, pool_id: &PoolId, email: &str) -> Result<UserId, UserPoolError>;

    /// Schema sync — UpdateUserPool with the rebuilt attribute list.
    ///
    /// V3 surfaces [`UserPoolError::AttributeAlreadyExists`] as a typed error;
    /// V4 will tolerate it as success in the schema-apply path.
    async fn update_user_pool(&self, params: UpdatePoolParams) -> Result<(), UserPoolError>;
}

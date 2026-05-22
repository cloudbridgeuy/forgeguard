//! User-pool client abstraction over Cognito admin operations.
//!
//! ## Module structure
//!
//! - `mod` (this file) — `UserPoolClient` trait.
//! - `aws` — production impl `AwsCognitoUserPoolClient`.
//! - `in_memory` — in-process `InMemoryUserPoolClient` for tests with
//!   `arm_*_once` failure injection knobs (gated behind the `testing` feature
//!   so cross-crate consumers can drive failure paths).
//!
//! The trait returns the pure [`forgeguard_authn_core::user_pool::UserPoolError`]
//! so callers can pattern-match outcomes without ever depending on the AWS SDK
//! directly. Method names mirror the underlying Cognito API verbs
//! (`AdminCreateUser`, `AdminDeleteUser`, `AdminGetUser`, `UpdateUserPool`).

pub mod aws;
pub mod in_memory;

pub use aws::AwsCognitoUserPoolClient;
pub use in_memory::InMemoryUserPoolClient;

use async_trait::async_trait;
use forgeguard_authn_core::user_pool::{CreateUserParams, PoolId, UpdatePoolParams, UserPoolError};
use forgeguard_core::UserId;

/// Four Cognito operations the `POST /users` saga driver and the xtask seed
/// depend on.
///
/// Implementations:
/// - `aws::AwsCognitoUserPoolClient` — production
/// - `in_memory::InMemoryUserPoolClient` — tests (with `arm_*` knobs)
#[async_trait]
pub trait UserPoolClient: Send + Sync {
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
    /// the saga driver and the xtask seed to recover the sub of a
    /// partially-created user when a retry observes `UsernameExists`.
    async fn admin_get_user(&self, pool_id: &PoolId, email: &str) -> Result<UserId, UserPoolError>;

    /// Schema sync — UpdateUserPool with the rebuilt attribute list.
    ///
    /// Surfaces [`UserPoolError::AttributeAlreadyExists`] as a typed error;
    /// the V4 Active schema-apply handler tolerates it as success.
    async fn update_user_pool(&self, params: UpdatePoolParams) -> Result<(), UserPoolError>;
}

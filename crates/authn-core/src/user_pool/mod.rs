//! Cognito user-pool parameter types and outcome enum.
//!
//! Pure types only — the async `UserPoolClient` trait lives in the
//! control-plane crate (V3). Re-exports below keep the public surface flat
//! for downstream consumers: `forgeguard_authn_core::user_pool::{PoolId, ...}`.

pub mod error;
pub mod params;

pub use error::UserPoolError;
pub use params::{CreateUserParams, PoolId, UpdatePoolParams};

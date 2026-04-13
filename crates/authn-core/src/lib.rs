#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod chain;
pub mod credential;
pub mod error;
pub mod identity;
pub mod jwt_claims;
pub mod resolver;
pub mod signing;
pub mod static_api_key;

#[cfg(feature = "test-support")]
pub mod builder;

pub use chain::IdentityChain;
pub use credential::Credential;
pub use error::{Error, Result};
pub use identity::{Identity, IdentityParams};
pub use jwt_claims::JwtClaims;
pub use resolver::IdentityResolver;
pub use static_api_key::StaticApiKeyResolver;

#[cfg(feature = "test-support")]
pub use builder::IdentityBuilder;

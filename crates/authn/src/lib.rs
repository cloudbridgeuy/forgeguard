#![deny(clippy::unwrap_used, clippy::expect_used)]

mod claims;
mod config;
mod ed25519_resolver;
pub mod error;
mod jwks;
mod resolver;
pub mod user_pool;

pub use config::JwtResolverConfig;
pub use ed25519_resolver::Ed25519SignatureResolver;
pub use error::{Error, Result};
pub use resolver::CognitoJwtResolver;

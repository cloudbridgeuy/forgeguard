#![doc = include_str!("../README.md")]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod extractor;
mod guard;
mod headers;
mod middleware;
mod outcome;
mod signing;

pub use extractor::{ForgeGuardDecision, ForgeGuardFlags, ForgeGuardIdentity};
pub use guard::ForgeGuard;
pub use middleware::forgeguard_layer;
pub use outcome::{Effect, EnforcementOutcome};
pub use signing::SigningConfig;

#![doc = include_str!("../README.md")]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod extractor;
mod guard;
mod middleware;

pub use extractor::{ForgeGuardFlags, ForgeGuardIdentity};
pub use guard::ForgeGuard;
pub use middleware::forgeguard_layer;

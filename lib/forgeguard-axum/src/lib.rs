#![doc = include_str!("../README.md")]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod extractor;
mod guard;
mod headers;
mod middleware;
mod mode;
mod outcome;
mod rls;
mod signing;
mod sink;

pub use extractor::{ForgeGuardDecision, ForgeGuardFlags, ForgeGuardIdentity};
pub use forgeguard_proxy_core::EnforcementMode;
pub use guard::ForgeGuard;
pub use middleware::forgeguard_layer;
pub use mode::{observe, ModeOverride};
pub use outcome::{Effect, EnforcementOutcome};
pub use rls::{Dialect, RlsContext, Statement};
pub use signing::SigningConfig;
pub use sink::{DecisionSink, TracingDecisionSink};

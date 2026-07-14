#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod app;

mod config;
mod dynamo_store;
mod error;
pub(crate) mod etag;
mod event_log;
mod handlers;
mod membership_store;
pub(crate) mod metrics;
mod signing_key;
mod signing_key_store;
mod store;
pub(crate) mod vp_client;

// `UserPoolClient` + impls moved to `forgeguard_authn` (V6 / issue #100): xtask
// needs them and cannot depend on this I/O crate. Re-exported so existing
// `crate::user_pool::*` paths in handlers keep resolving.
pub(crate) use forgeguard_authn::user_pool;

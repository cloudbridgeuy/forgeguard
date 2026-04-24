//! Test-support re-exports. xtask ships as a binary; this lib exists so
//! integration tests can reach the pure signing surface for drift checks.

#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod signing;

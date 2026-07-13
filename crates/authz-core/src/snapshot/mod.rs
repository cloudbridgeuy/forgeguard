//! Versioned, immutable policy snapshot (Design A1's `fg-compiler` output,
//! phase-2 scope: RBAC bridge only; multi-source merge + provenance are
//! phase 5, #112).

pub mod version;

pub use version::SnapshotVersion;

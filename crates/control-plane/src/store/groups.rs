//! `EtagedGroup` — coupling a stored `RbacEntry` with its precomputed etag.
//!
//! Analogous to `ConfiguredConfig` for org configs: holding an `EtagedGroup`
//! is proof that the `entry` and `etag` fields are consistent — the etag was
//! computed from the entry at write time and must not drift.

use forgeguard_authz_core::RbacEntry;

use crate::error::Result;
use crate::etag::Etag;

/// A stored RBAC group entry together with its content-addressed etag.
///
/// Construct via [`EtagedGroup::compute`] (computes the etag from the entry)
/// or [`EtagedGroup::from_stored`] (reuses an etag that was persisted
/// alongside the entry — e.g. read from DynamoDB).
#[derive(Debug, Clone)]
pub(crate) struct EtagedGroup {
    entry: RbacEntry,
    etag: Etag,
}

impl EtagedGroup {
    /// Build from an `RbacEntry`, computing the etag from its contents.
    pub(crate) fn compute(entry: RbacEntry) -> Result<Self> {
        let etag = crate::handlers::groups::pure::compute_group_etag(&entry)?;
        Ok(Self {
            entry,
            etag: Etag::from_validated(etag),
        })
    }

    /// Build from an already-paired (entry, etag) — e.g. when reconstituting
    /// an `EtagedGroup` from a DynamoDB item.
    pub(crate) fn from_stored(entry: RbacEntry, etag: Etag) -> Self {
        Self { entry, etag }
    }

    pub(crate) fn entry(&self) -> &RbacEntry {
        &self.entry
    }

    pub(crate) fn etag(&self) -> &Etag {
        &self.etag
    }
}

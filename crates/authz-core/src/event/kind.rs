//! The catalog of event kinds appendable to the per-org event log.

use std::str::FromStr;

use crate::error::{Error, Result};

/// The kind of mutation an appended event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// An organization was created.
    OrgCreated,
    /// An organization was updated.
    OrgUpdated,
    /// An org unit was created or updated.
    OrgUnitPut,
    /// A principal was created or updated.
    PrincipalUpserted,
    /// A principal set was created or updated.
    PrincipalSetPut,
    /// A grant was added.
    GrantAdded,
    /// A grant was removed.
    GrantRemoved,
    /// A resource was promoted.
    ResourcePromoted,
    /// A resource was tombstoned.
    ResourceTombstoned,
    /// A deny was created.
    DenyCreated,
    /// A deny was removed.
    DenyRemoved,
    /// An organization was activated.
    OrgActivated,
    /// An organization was suspended.
    OrgSuspended,
    /// An organization was restored from suspension.
    OrgRestored,
    /// A request-signing key was generated.
    OrgKeyGenerated,
    /// A request-signing key was revoked.
    OrgKeyRevoked,
    /// A request-signing key was rotated.
    OrgKeyRotated,
    /// A group was created or updated.
    GroupPut,
    /// A group was deleted.
    GroupDeleted,
}

impl EventKind {
    /// The wire-format name persisted in the event log and served to clients.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OrgCreated => "org.created",
            Self::OrgUpdated => "org.updated",
            Self::OrgUnitPut => "org_unit.put",
            Self::PrincipalUpserted => "principal.upserted",
            Self::PrincipalSetPut => "principal_set.put",
            Self::GrantAdded => "grant.added",
            Self::GrantRemoved => "grant.removed",
            Self::ResourcePromoted => "resource.promoted",
            Self::ResourceTombstoned => "resource.tombstoned",
            Self::DenyCreated => "deny.created",
            Self::DenyRemoved => "deny.removed",
            Self::OrgActivated => "org.activated",
            Self::OrgSuspended => "org.suspended",
            Self::OrgRestored => "org.restored",
            Self::OrgKeyGenerated => "org.key_generated",
            Self::OrgKeyRevoked => "org.key_revoked",
            Self::OrgKeyRotated => "org.key_rotated",
            Self::GroupPut => "group.put",
            Self::GroupDeleted => "group.deleted",
        }
    }

    /// Whether this kind narrows the effective access surface.
    ///
    /// `OrgUnitPut` returns `false`: re-parent narrowing detection (whether
    /// moving an org unit could narrow inherited grants) is out of V1 scope.
    ///
    /// `GroupPut` is conservatively narrowing: a put may remove entries from
    /// `allow`, and kind-level `narrowing()` cannot inspect payloads, so any
    /// group change is treated as potentially narrowing for cache invalidation.
    pub fn narrowing(&self) -> bool {
        matches!(
            self,
            Self::GrantRemoved
                | Self::ResourceTombstoned
                | Self::DenyCreated
                | Self::OrgSuspended
                | Self::OrgKeyRevoked
                | Self::GroupPut
                | Self::GroupDeleted
        )
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for EventKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "org.created" => Ok(Self::OrgCreated),
            "org.updated" => Ok(Self::OrgUpdated),
            "org_unit.put" => Ok(Self::OrgUnitPut),
            "principal.upserted" => Ok(Self::PrincipalUpserted),
            "principal_set.put" => Ok(Self::PrincipalSetPut),
            "grant.added" => Ok(Self::GrantAdded),
            "grant.removed" => Ok(Self::GrantRemoved),
            "resource.promoted" => Ok(Self::ResourcePromoted),
            "resource.tombstoned" => Ok(Self::ResourceTombstoned),
            "deny.created" => Ok(Self::DenyCreated),
            "deny.removed" => Ok(Self::DenyRemoved),
            "org.activated" => Ok(Self::OrgActivated),
            "org.suspended" => Ok(Self::OrgSuspended),
            "org.restored" => Ok(Self::OrgRestored),
            "org.key_generated" => Ok(Self::OrgKeyGenerated),
            "org.key_revoked" => Ok(Self::OrgKeyRevoked),
            "org.key_rotated" => Ok(Self::OrgKeyRotated),
            "group.put" => Ok(Self::GroupPut),
            "group.deleted" => Ok(Self::GroupDeleted),
            other => Err(Error::UnknownEventKind {
                kind: other.to_string(),
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const ALL_KINDS: [EventKind; 19] = [
        EventKind::OrgCreated,
        EventKind::OrgUpdated,
        EventKind::OrgUnitPut,
        EventKind::PrincipalUpserted,
        EventKind::PrincipalSetPut,
        EventKind::GrantAdded,
        EventKind::GrantRemoved,
        EventKind::ResourcePromoted,
        EventKind::ResourceTombstoned,
        EventKind::DenyCreated,
        EventKind::DenyRemoved,
        EventKind::OrgActivated,
        EventKind::OrgSuspended,
        EventKind::OrgRestored,
        EventKind::OrgKeyGenerated,
        EventKind::OrgKeyRevoked,
        EventKind::OrgKeyRotated,
        EventKind::GroupPut,
        EventKind::GroupDeleted,
    ];

    #[test]
    fn round_trips_all_kinds() {
        for kind in ALL_KINDS {
            let s = kind.as_str();
            let parsed = EventKind::from_str(s).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn narrowing_truth_table() {
        assert!(!EventKind::OrgCreated.narrowing());
        assert!(!EventKind::OrgUpdated.narrowing());
        assert!(!EventKind::OrgUnitPut.narrowing());
        assert!(!EventKind::PrincipalUpserted.narrowing());
        assert!(!EventKind::PrincipalSetPut.narrowing());
        assert!(!EventKind::GrantAdded.narrowing());
        assert!(EventKind::GrantRemoved.narrowing());
        assert!(!EventKind::ResourcePromoted.narrowing());
        assert!(EventKind::ResourceTombstoned.narrowing());
        assert!(EventKind::DenyCreated.narrowing());
        assert!(!EventKind::DenyRemoved.narrowing());
        assert!(!EventKind::OrgActivated.narrowing());
        assert!(EventKind::OrgSuspended.narrowing());
        assert!(!EventKind::OrgRestored.narrowing());
        assert!(!EventKind::OrgKeyGenerated.narrowing());
        assert!(EventKind::OrgKeyRevoked.narrowing());
        assert!(!EventKind::OrgKeyRotated.narrowing());
        assert!(EventKind::GroupPut.narrowing());
        assert!(EventKind::GroupDeleted.narrowing());
    }

    #[test]
    fn unknown_kind_errors() {
        let err = EventKind::from_str("bogus.kind").unwrap_err();
        assert!(matches!(err, Error::UnknownEventKind { kind } if kind == "bogus.kind"));
    }
}

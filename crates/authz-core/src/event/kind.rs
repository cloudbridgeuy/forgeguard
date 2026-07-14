//! The catalog of event kinds appendable to the per-org event log.

use std::str::FromStr;

use crate::error::{Error, Result};

/// The kind of mutation an appended event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
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
}

impl EventKind {
    /// The wire-format name persisted in the event log and served to clients.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OrgUnitPut => "org_unit.put",
            Self::PrincipalUpserted => "principal.upserted",
            Self::PrincipalSetPut => "principal_set.put",
            Self::GrantAdded => "grant.added",
            Self::GrantRemoved => "grant.removed",
            Self::ResourcePromoted => "resource.promoted",
            Self::ResourceTombstoned => "resource.tombstoned",
            Self::DenyCreated => "deny.created",
            Self::DenyRemoved => "deny.removed",
        }
    }

    /// Whether this kind narrows the effective access surface.
    ///
    /// `OrgUnitPut` returns `false`: re-parent narrowing detection (whether
    /// moving an org unit could narrow inherited grants) is out of V1 scope.
    pub fn narrowing(&self) -> bool {
        matches!(
            self,
            Self::GrantRemoved | Self::ResourceTombstoned | Self::DenyCreated
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
            "org_unit.put" => Ok(Self::OrgUnitPut),
            "principal.upserted" => Ok(Self::PrincipalUpserted),
            "principal_set.put" => Ok(Self::PrincipalSetPut),
            "grant.added" => Ok(Self::GrantAdded),
            "grant.removed" => Ok(Self::GrantRemoved),
            "resource.promoted" => Ok(Self::ResourcePromoted),
            "resource.tombstoned" => Ok(Self::ResourceTombstoned),
            "deny.created" => Ok(Self::DenyCreated),
            "deny.removed" => Ok(Self::DenyRemoved),
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

    const ALL_KINDS: [EventKind; 9] = [
        EventKind::OrgUnitPut,
        EventKind::PrincipalUpserted,
        EventKind::PrincipalSetPut,
        EventKind::GrantAdded,
        EventKind::GrantRemoved,
        EventKind::ResourcePromoted,
        EventKind::ResourceTombstoned,
        EventKind::DenyCreated,
        EventKind::DenyRemoved,
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
        assert!(!EventKind::OrgUnitPut.narrowing());
        assert!(!EventKind::PrincipalUpserted.narrowing());
        assert!(!EventKind::PrincipalSetPut.narrowing());
        assert!(!EventKind::GrantAdded.narrowing());
        assert!(EventKind::GrantRemoved.narrowing());
        assert!(!EventKind::ResourcePromoted.narrowing());
        assert!(EventKind::ResourceTombstoned.narrowing());
        assert!(EventKind::DenyCreated.narrowing());
        assert!(!EventKind::DenyRemoved.narrowing());
    }

    #[test]
    fn unknown_kind_errors() {
        let err = EventKind::from_str("bogus.kind").unwrap_err();
        assert!(matches!(err, Error::UnknownEventKind { kind } if kind == "bogus.kind"));
    }
}

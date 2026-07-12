//! Brief v1.4 FGRN — `fgrn:{organization}:{type}:{id}`.
//!
//! FGRNs are stable identity: they NEVER encode position (brief §
//! "Naming: FGRNs and selectors"). Re-parenting an org unit must not
//! rename its FGRN. Patterns that DO encode position are selectors — a
//! separate type, not covered here.
//!
//! A promoted resource's id is `{resource_type}/{native_id}`, the
//! native-id derivation rule that makes promotion a single ForgeGuard-side
//! write requiring no app-side column, mapping, or migration.

use std::fmt;
use std::str::FromStr;

use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::{Error, NativeId, Result, Segment};

// ---------------------------------------------------------------------------
// FgrnKind
// ---------------------------------------------------------------------------

/// The closed set of FGRN kinds. Not a string — an unrecognized kind is a
/// parse error, not a valid value to hold.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FgrnKind {
    OrgUnit,
    Principal,
    PrincipalSet,
    Resource,
}

impl FgrnKind {
    /// Borrow the canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OrgUnit => "orgunit",
            Self::Principal => "principal",
            Self::PrincipalSet => "principal-set",
            Self::Resource => "resource",
        }
    }
}

impl fmt::Display for FgrnKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FgrnKind {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "orgunit" => Ok(Self::OrgUnit),
            "principal" => Ok(Self::Principal),
            "principal-set" => Ok(Self::PrincipalSet),
            "resource" => Ok(Self::Resource),
            _ => Err(Error::Parse {
                field: "fgrn",
                value: s.to_string(),
                reason: "unknown kind — expected orgunit, principal, principal-set, or resource",
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Fgrn
// ---------------------------------------------------------------------------

/// Brief v1.4 FGRN — a stable identity name, never encoding position.
///
/// Format: `fgrn:{organization}:{type}:{id}` — exactly four `:`-separated
/// positions. The id itself cannot contain `:` (`NativeId`'s rules), so
/// `splitn(4, ':')` is unambiguous.
///
/// Resource kind: the id is `{resource_type}/{native_id}` split at the
/// FIRST `/`; `resource_type` is a [`Segment`] (ForgeGuard-declared,
/// styled), `native_id` a [`NativeId`] (the app's own id, which may
/// itself contain `/`). Non-resource kinds: id is a bare `NativeId`; a
/// `/` in it is legal and uninterpreted.
///
/// Parse Don't Validate: if you hold an `Fgrn`, every position is
/// guaranteed valid.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Fgrn {
    organization: Segment,
    kind: FgrnKind,
    id: NativeId,
    resource_type: Option<Segment>,
    native_id: Option<NativeId>,
    raw: String,
}

impl Fgrn {
    /// Parse from canonical string form.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(4, ':').collect();
        let ["fgrn", organization, kind, id] = parts.as_slice() else {
            return Err(Error::Parse {
                field: "fgrn",
                value: s.to_string(),
                reason: "expected fgrn:{organization}:{type}:{id}",
            });
        };

        let organization = Segment::try_new(*organization)?;
        let kind = FgrnKind::from_str(kind)?;

        let (id, resource_type, native_id) = if kind == FgrnKind::Resource {
            let Some((rtype, nid)) = id.split_once('/') else {
                return Err(Error::Parse {
                    field: "fgrn",
                    value: s.to_string(),
                    reason: "resource id must be {resource_type}/{native_id}",
                });
            };
            let resource_type = Segment::try_new(rtype)?;
            let native_id = NativeId::try_new(nid)?;
            let id = NativeId::try_new(*id)?;
            (id, Some(resource_type), Some(native_id))
        } else {
            (NativeId::try_new(*id)?, None, None)
        };

        Ok(Self {
            organization,
            kind,
            id,
            resource_type,
            native_id,
            raw: s.to_string(),
        })
    }

    /// Build an FGRN for an org unit.
    pub fn org_unit(organization: &Segment, id: &NativeId) -> Self {
        Self::new(
            organization.clone(),
            FgrnKind::OrgUnit,
            id.clone(),
            None,
            None,
        )
    }

    /// Build an FGRN for a principal.
    pub fn principal(organization: &Segment, id: &NativeId) -> Self {
        Self::new(
            organization.clone(),
            FgrnKind::Principal,
            id.clone(),
            None,
            None,
        )
    }

    /// Build an FGRN for a principal set.
    pub fn principal_set(organization: &Segment, id: &NativeId) -> Self {
        Self::new(
            organization.clone(),
            FgrnKind::PrincipalSet,
            id.clone(),
            None,
            None,
        )
    }

    /// Build an FGRN for a resource. The canonical id is
    /// `{resource_type}/{native_id}` — the native-id derivation rule.
    pub fn resource(organization: &Segment, resource_type: &Segment, native_id: &NativeId) -> Self {
        // Safe: Segment's alphabet (lowercase ASCII/digits/hyphens) and
        // NativeId's own charset (visible ASCII, no ':' or '*') can never
        // produce a '/'-joined compound that NativeId itself rejects. See
        // `resource_builder_never_panics_at_alphabet_edges` below, which
        // guards this invariant if either type's ruleset changes.
        let compound = NativeId::try_new(format!("{resource_type}/{native_id}"))
            .unwrap_or_else(|_| unreachable!("Segment and NativeId are both '/'-safe"));
        Self::new(
            organization.clone(),
            FgrnKind::Resource,
            compound,
            Some(resource_type.clone()),
            Some(native_id.clone()),
        )
    }

    fn new(
        organization: Segment,
        kind: FgrnKind,
        id: NativeId,
        resource_type: Option<Segment>,
        native_id: Option<NativeId>,
    ) -> Self {
        let raw = format!("fgrn:{organization}:{kind}:{id}");
        Self {
            organization,
            kind,
            id,
            resource_type,
            native_id,
            raw,
        }
    }

    /// Borrow the organization segment.
    pub fn organization(&self) -> &Segment {
        &self.organization
    }

    /// The FGRN kind.
    pub fn kind(&self) -> FgrnKind {
        self.kind
    }

    /// Borrow the id. For `Resource` kind, this is the compound
    /// `{resource_type}/{native_id}` — see [`Self::resource_parts`] for
    /// the split form.
    pub fn id(&self) -> &NativeId {
        &self.id
    }

    /// `Some((resource_type, native_id))` iff `kind() == FgrnKind::Resource`.
    pub fn resource_parts(&self) -> Option<(&Segment, &NativeId)> {
        self.resource_type.as_ref().zip(self.native_id.as_ref())
    }
}

impl fmt::Display for Fgrn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for Fgrn {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for Fgrn {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for Fgrn {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn seg(s: &str) -> Segment {
        Segment::try_new(s).unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    // -- Parse round-trip tests ----------------------------------------------

    #[test]
    fn parse_round_trip_principal() {
        let s = "fgrn:acme:principal:usr_8f3k2";
        let fgrn = Fgrn::parse(s).unwrap();
        assert_eq!(fgrn.to_string(), s);
        assert_eq!(fgrn.organization().as_str(), "acme");
        assert_eq!(fgrn.kind(), FgrnKind::Principal);
        assert_eq!(fgrn.id().as_str(), "usr_8f3k2");
    }

    #[test]
    fn parse_round_trip_orgunit() {
        let s = "fgrn:acme:orgunit:ou_finance";
        let fgrn = Fgrn::parse(s).unwrap();
        assert_eq!(fgrn.to_string(), s);
        assert_eq!(fgrn.kind(), FgrnKind::OrgUnit);
        assert_eq!(fgrn.id().as_str(), "ou_finance");
    }

    #[test]
    fn parse_round_trip_principal_set() {
        let s = "fgrn:acme:principal-set:proj_alpha_readers";
        let fgrn = Fgrn::parse(s).unwrap();
        assert_eq!(fgrn.to_string(), s);
        assert_eq!(fgrn.kind(), FgrnKind::PrincipalSet);
        assert_eq!(fgrn.id().as_str(), "proj_alpha_readers");
    }

    #[test]
    fn parse_round_trip_resource() {
        let s = "fgrn:acme:resource:document/doc_123";
        let fgrn = Fgrn::parse(s).unwrap();
        assert_eq!(fgrn.to_string(), s);
        assert_eq!(fgrn.kind(), FgrnKind::Resource);
        assert_eq!(fgrn.id().as_str(), "document/doc_123");
    }

    // -- Builder tests --------------------------------------------------------

    #[test]
    fn builder_org_unit() {
        let fgrn = Fgrn::org_unit(&seg("acme"), &nid("ou_finance"));
        assert_eq!(fgrn.to_string(), "fgrn:acme:orgunit:ou_finance");
    }

    #[test]
    fn builder_principal() {
        let fgrn = Fgrn::principal(&seg("acme"), &nid("usr_8f3k2"));
        assert_eq!(fgrn.to_string(), "fgrn:acme:principal:usr_8f3k2");
    }

    #[test]
    fn builder_principal_set() {
        let fgrn = Fgrn::principal_set(&seg("acme"), &nid("proj_alpha_readers"));
        assert_eq!(
            fgrn.to_string(),
            "fgrn:acme:principal-set:proj_alpha_readers"
        );
    }

    #[test]
    fn builder_resource() {
        let fgrn = Fgrn::resource(&seg("acme"), &seg("document"), &nid("doc_123"));
        assert_eq!(fgrn.to_string(), "fgrn:acme:resource:document/doc_123");
    }

    // -- resource_parts tests --------------------------------------------------

    #[test]
    fn resource_parts_some_for_resource() {
        let fgrn = Fgrn::resource(&seg("acme"), &seg("document"), &nid("doc_123"));
        let (resource_type, native_id) = fgrn.resource_parts().unwrap();
        assert_eq!(resource_type.as_str(), "document");
        assert_eq!(native_id.as_str(), "doc_123");
    }

    #[test]
    fn resource_parts_none_for_principal() {
        let fgrn = Fgrn::principal(&seg("acme"), &nid("usr_8f3k2"));
        assert!(fgrn.resource_parts().is_none());
    }

    /// Guards the `unreachable!` in `Fgrn::resource`: a `Segment`/`NativeId`
    /// pair joined by `/` must never fail `NativeId`'s own validation.
    /// Exercises alphabet edges of both types (visible-ASCII boundaries,
    /// digits, hyphens, underscores) so a future loosening of either
    /// type's charset trips this test before it trips the `unreachable!`.
    #[test]
    fn resource_builder_never_panics_at_alphabet_edges() {
        let rtype = seg("a0-z9");
        let nid = nid("!~_UP-lo_9");
        let fgrn = Fgrn::resource(&seg("acme"), &rtype, &nid);
        let (resource_type, native_id) = fgrn.resource_parts().unwrap();
        assert_eq!(resource_type.as_str(), "a0-z9");
        assert_eq!(native_id.as_str(), "!~_UP-lo_9");
    }

    // -- Native id containing '/' -----------------------------------------------

    #[test]
    fn resource_native_id_containing_slash() {
        let s = "fgrn:acme:resource:invoice/2024/Q3-001";
        let fgrn = Fgrn::parse(s).unwrap();
        assert_eq!(fgrn.to_string(), s);
        let (resource_type, native_id) = fgrn.resource_parts().unwrap();
        assert_eq!(resource_type.as_str(), "invoice");
        assert_eq!(native_id.as_str(), "2024/Q3-001");
    }

    // -- Error tests --------------------------------------------------------

    #[test]
    fn error_missing_positions() {
        assert!(Fgrn::parse("fgrn:acme:principal").is_err());
    }

    #[test]
    fn error_unknown_kind() {
        assert!(Fgrn::parse("fgrn:acme:widget:x").is_err());
    }

    #[test]
    fn error_bad_org_segment() {
        assert!(Fgrn::parse("fgrn:Acme:principal:x").is_err());
    }

    #[test]
    fn error_resource_without_slash() {
        assert!(Fgrn::parse("fgrn:acme:resource:doc_123").is_err());
    }

    #[test]
    fn error_wildcard_anywhere() {
        assert!(Fgrn::parse("fgrn:acme:principal:*").is_err());
    }

    #[test]
    fn error_empty_string() {
        assert!(Fgrn::parse("").is_err());
    }

    #[test]
    fn error_old_six_positional_string() {
        assert!(Fgrn::parse("fgrn:acme-app:acme-corp:iam:user:alice").is_err());
    }

    // -- Serde round-trip ----------------------------------------------------

    #[test]
    fn serde_round_trip() {
        let fgrn = Fgrn::parse("fgrn:acme:principal:usr_8f3k2").unwrap();
        let json = serde_json::to_string(&fgrn).unwrap();
        assert_eq!(json, "\"fgrn:acme:principal:usr_8f3k2\"");
        let deser: Fgrn = serde_json::from_str(&json).unwrap();
        assert_eq!(fgrn, deser);
    }

    // -- FromStr --------------------------------------------------------------

    #[test]
    fn from_str_works() {
        let fgrn: Fgrn = "fgrn:acme:principal:usr_8f3k2".parse().unwrap();
        assert_eq!(fgrn.to_string(), "fgrn:acme:principal:usr_8f3k2");
    }
}

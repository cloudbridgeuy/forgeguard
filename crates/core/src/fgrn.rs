//! ForgeGuard Resource Name — a structured, validated identifier for any
//! entity in the ForgeGuard system.
//!
//! Format: `fgrn:<project>:<tenant>:<namespace>:<resource-type>:<resource-id>`
//!
//! Six positions, always. Use `*` for wildcards, `-` for not-applicable.
//! All concrete segments are validated [`Segment`] values (lowercase, hyphens).
//! The `-` is a serialization convention for absent fields (`Option::None`),
//! NOT a valid `Segment` value.

use std::fmt;
use std::str::FromStr;

use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::action::{Entity, Namespace, ResourceId};
use crate::{Error, GroupName, PolicyName, ProjectId, Result, Segment, TenantId, UserId};

// ---------------------------------------------------------------------------
// Known segments
// ---------------------------------------------------------------------------

/// Pre-validated constant segments for known-good FGRN components.
/// Avoids `expect()` (denied by workspace clippy) in builder methods.
/// Validated once at first access via `std::sync::LazyLock` (stable since Rust 1.80).
pub(crate) mod known_segments {
    use super::Segment;
    use std::sync::LazyLock;

    pub(crate) static IAM: LazyLock<Segment> =
        LazyLock::new(|| Segment::try_new("iam").unwrap_or_else(|_| unreachable!()));
    pub(crate) static FORGEGUARD: LazyLock<Segment> =
        LazyLock::new(|| Segment::try_new("forgeguard").unwrap_or_else(|_| unreachable!()));
    pub(crate) static USER: LazyLock<Segment> =
        LazyLock::new(|| Segment::try_new("user").unwrap_or_else(|_| unreachable!()));
    pub(crate) static GROUP: LazyLock<Segment> =
        LazyLock::new(|| Segment::try_new("group").unwrap_or_else(|_| unreachable!()));
    pub(crate) static POLICY: LazyLock<Segment> =
        LazyLock::new(|| Segment::try_new("policy").unwrap_or_else(|_| unreachable!()));
}

// ---------------------------------------------------------------------------
// FgrnSegment
// ---------------------------------------------------------------------------

/// A single concrete-or-wildcard segment in an FGRN.
/// Either a validated Segment or a wildcard (`*`).
///
/// "Not applicable" is NOT a variant here — it's represented as
/// `Option<FgrnSegment>::None` at the `Fgrn` field level. The `-` character
/// only appears during serialization/deserialization of the FGRN string.
/// This keeps `Segment`'s validation rules strict and uncompromised.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum FgrnSegment {
    Value(Segment),
    Wildcard,
}

impl FgrnSegment {
    /// Parse a required FGRN segment (must be a value or wildcard, not `-`).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "*" => Ok(Self::Wildcard),
            _ => Ok(Self::Value(Segment::try_new(s)?)),
        }
    }

    /// Wrap a pre-validated `Segment` as a concrete `FgrnSegment`.
    pub fn from_segment(seg: &Segment) -> Self {
        Self::Value(seg.clone())
    }

    /// Does this segment match the given pattern?
    /// A `Wildcard` pattern matches anything.
    pub fn matches(&self, pattern: &FgrnSegment) -> bool {
        match pattern {
            FgrnSegment::Wildcard => true,
            FgrnSegment::Value(v) => matches!(self, FgrnSegment::Value(sv) if sv == v),
        }
    }

    /// Borrow the string representation of this segment.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Value(v) => v.as_str(),
            Self::Wildcard => "*",
        }
    }
}

// ---------------------------------------------------------------------------
// Fgrn
// ---------------------------------------------------------------------------

/// ForgeGuard Resource Name — a structured, validated identifier for any
/// entity in the ForgeGuard system.
///
/// Format: `fgrn:<project>:<tenant>:<namespace>:<resource-type>:<resource-id>`
///
/// Parse Don't Validate: if you hold an `Fgrn`, every segment is guaranteed valid.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Fgrn {
    project: Option<FgrnSegment>,
    tenant: Option<FgrnSegment>,
    namespace: FgrnSegment,
    resource_type: FgrnSegment,
    resource_id: FgrnSegment,
    raw: String,
}

impl Fgrn {
    /// Parse from canonical string form.
    /// `-` is deserialized as `None` (absent), not as a `Segment` value.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();
        match parts.as_slice() {
            ["fgrn", project, tenant, namespace, rtype, rid] => Ok(Self {
                project: parse_optional_segment(project)?,
                tenant: parse_optional_segment(tenant)?,
                namespace: FgrnSegment::parse(namespace)?,
                resource_type: FgrnSegment::parse(rtype)?,
                resource_id: FgrnSegment::parse(rid)?,
                raw: s.to_string(),
            }),
            _ => Err(Error::Parse {
                field: "fgrn",
                value: s.to_string(),
                reason:
                    "expected fgrn:<project>:<tenant>:<namespace>:<resource-type>:<resource-id>",
            }),
        }
    }

    /// Construct from validated parts. Builds canonical string once.
    pub fn new(
        project: Option<FgrnSegment>,
        tenant: Option<FgrnSegment>,
        namespace: FgrnSegment,
        resource_type: FgrnSegment,
        resource_id: FgrnSegment,
    ) -> Self {
        let raw = format!(
            "fgrn:{}:{}:{}:{}:{}",
            optional_segment_str(&project),
            optional_segment_str(&tenant),
            namespace.as_str(),
            resource_type.as_str(),
            resource_id.as_str(),
        );
        Self {
            project,
            tenant,
            namespace,
            resource_type,
            resource_id,
            raw,
        }
    }

    /// Build an FGRN for a user identity resource.
    pub fn user(project: &ProjectId, tenant: &TenantId, user_id: &UserId) -> Self {
        Self::new(
            Some(FgrnSegment::from_segment(project.as_segment())),
            Some(FgrnSegment::from_segment(tenant.as_segment())),
            FgrnSegment::from_segment(&known_segments::IAM),
            FgrnSegment::from_segment(&known_segments::USER),
            FgrnSegment::from_segment(user_id.as_segment()),
        )
    }

    /// Build an FGRN for a group identity resource.
    pub fn group(project: &ProjectId, tenant: &TenantId, group_name: &GroupName) -> Self {
        Self::new(
            Some(FgrnSegment::from_segment(project.as_segment())),
            Some(FgrnSegment::from_segment(tenant.as_segment())),
            FgrnSegment::from_segment(&known_segments::IAM),
            FgrnSegment::from_segment(&known_segments::GROUP),
            FgrnSegment::from_segment(group_name.as_segment()),
        )
    }

    /// Build an FGRN for a policy (not tenant-scoped).
    pub fn policy(project: &ProjectId, policy_name: &PolicyName) -> Self {
        Self::new(
            Some(FgrnSegment::from_segment(project.as_segment())),
            None, // policies are not tenant-scoped
            FgrnSegment::from_segment(&known_segments::FORGEGUARD),
            FgrnSegment::from_segment(&known_segments::POLICY),
            FgrnSegment::from_segment(policy_name.as_segment()),
        )
    }

    /// Build an FGRN for a customer-defined resource.
    pub fn resource(
        project: &ProjectId,
        tenant: &TenantId,
        namespace: &Namespace,
        entity: &Entity,
        id: &ResourceId,
    ) -> Self {
        Self::new(
            Some(FgrnSegment::from_segment(project.as_segment())),
            Some(FgrnSegment::from_segment(tenant.as_segment())),
            FgrnSegment::from_segment(namespace.as_segment()),
            FgrnSegment::from_segment(entity.as_segment()),
            FgrnSegment::from_segment(id.as_segment()),
        )
    }

    /// This string is used directly as the Verified Permissions entity ID.
    /// Single identifier everywhere — no mapping at any boundary.
    pub fn as_vp_entity_id(&self) -> &str {
        &self.raw
    }

    /// Cedar entity type: `"{namespace}::{resource_type}"` e.g., `"todo::list"`.
    /// Returns `None` if either segment is a wildcard.
    pub fn cedar_entity_type(&self) -> Option<String> {
        match (&self.namespace, &self.resource_type) {
            (FgrnSegment::Value(ns), FgrnSegment::Value(rt)) => Some(format!("{ns}::{rt}")),
            _ => None,
        }
    }

    /// Does this FGRN match another (potentially wildcarded) FGRN pattern?
    pub fn matches(&self, pattern: &Fgrn) -> bool {
        optional_matches(&self.project, &pattern.project)
            && optional_matches(&self.tenant, &pattern.tenant)
            && self.namespace.matches(&pattern.namespace)
            && self.resource_type.matches(&pattern.resource_type)
            && self.resource_id.matches(&pattern.resource_id)
    }

    /// Borrow the project segment, if present.
    pub fn project(&self) -> Option<&FgrnSegment> {
        self.project.as_ref()
    }

    /// Borrow the tenant segment, if present.
    pub fn tenant(&self) -> Option<&FgrnSegment> {
        self.tenant.as_ref()
    }

    /// Borrow the namespace segment.
    pub fn namespace(&self) -> &FgrnSegment {
        &self.namespace
    }

    /// Borrow the resource type segment.
    pub fn resource_type(&self) -> &FgrnSegment {
        &self.resource_type
    }

    /// Borrow the resource ID segment.
    pub fn resource_id(&self) -> &FgrnSegment {
        &self.resource_id
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
// Helper functions
// ---------------------------------------------------------------------------

/// Parse an optional FGRN segment: `-` becomes `None`, everything else is parsed.
fn parse_optional_segment(s: &str) -> Result<Option<FgrnSegment>> {
    match s {
        "-" => Ok(None),
        _ => Ok(Some(FgrnSegment::parse(s)?)),
    }
}

/// Serialize an optional segment: `None` becomes `"-"`.
fn optional_segment_str(seg: &Option<FgrnSegment>) -> &str {
    match seg {
        Some(s) => s.as_str(),
        None => "-",
    }
}

/// Match logic for optional segments:
/// - `None` pattern matches only `None` values (both are "not applicable")
/// - `Some(Wildcard)` matches anything including `None`
/// - `Some(Value)` matches only the same value
fn optional_matches(value: &Option<FgrnSegment>, pattern: &Option<FgrnSegment>) -> bool {
    match (pattern, value) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(FgrnSegment::Wildcard), _) => true,
        (Some(_), None) => false,
        (Some(p), Some(v)) => v.matches(p),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- Parse tests ---------------------------------------------------------

    #[test]
    fn parse_user_fgrn() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:iam:user:alice").unwrap();
        assert_eq!(
            fgrn.project(),
            Some(&FgrnSegment::Value(Segment::try_new("acme-app").unwrap()))
        );
        assert_eq!(
            fgrn.tenant(),
            Some(&FgrnSegment::Value(Segment::try_new("acme-corp").unwrap()))
        );
        assert_eq!(
            fgrn.namespace(),
            &FgrnSegment::Value(Segment::try_new("iam").unwrap())
        );
        assert_eq!(
            fgrn.resource_type(),
            &FgrnSegment::Value(Segment::try_new("user").unwrap())
        );
        assert_eq!(
            fgrn.resource_id(),
            &FgrnSegment::Value(Segment::try_new("alice").unwrap())
        );
    }

    #[test]
    fn parse_resource_fgrn() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-001").unwrap();
        assert_eq!(
            fgrn.namespace(),
            &FgrnSegment::Value(Segment::try_new("todo").unwrap())
        );
        assert_eq!(
            fgrn.resource_type(),
            &FgrnSegment::Value(Segment::try_new("list").unwrap())
        );
        assert_eq!(
            fgrn.resource_id(),
            &FgrnSegment::Value(Segment::try_new("list-001").unwrap())
        );
    }

    #[test]
    fn parse_wildcard_fgrn() {
        let fgrn = Fgrn::parse("fgrn:acme-app:*:todo:list:*").unwrap();
        assert_eq!(fgrn.tenant(), Some(&FgrnSegment::Wildcard));
        assert_eq!(fgrn.resource_id(), &FgrnSegment::Wildcard);
    }

    #[test]
    fn parse_not_applicable_becomes_none() {
        let fgrn = Fgrn::parse("fgrn:acme-app:-:forgeguard:policy:pol-001").unwrap();
        assert!(fgrn.tenant().is_none());
        assert!(fgrn.project().is_some());
    }

    #[test]
    fn parse_both_optional_none() {
        let fgrn = Fgrn::parse("fgrn:-:-:forgeguard:project:acme-app").unwrap();
        assert!(fgrn.project().is_none());
        assert!(fgrn.tenant().is_none());
    }

    // -- Matching tests ------------------------------------------------------

    #[test]
    fn wildcard_matches_specific() {
        let specific = Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-001").unwrap();
        let pattern = Fgrn::parse("fgrn:acme-app:*:todo:list:*").unwrap();
        assert!(specific.matches(&pattern));
    }

    #[test]
    fn wrong_namespace_does_not_match() {
        let specific = Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-001").unwrap();
        let pattern = Fgrn::parse("fgrn:acme-app:acme-corp:billing:list:list-001").unwrap();
        assert!(!specific.matches(&pattern));
    }

    #[test]
    fn none_matches_none() {
        let a = Fgrn::parse("fgrn:acme-app:-:forgeguard:policy:pol-001").unwrap();
        let b = Fgrn::parse("fgrn:acme-app:-:forgeguard:policy:pol-001").unwrap();
        assert!(a.matches(&b));
    }

    #[test]
    fn none_pattern_does_not_match_some_value() {
        let value = Fgrn::parse("fgrn:acme-app:acme-corp:iam:user:alice").unwrap();
        let pattern = Fgrn::parse("fgrn:acme-app:-:iam:user:alice").unwrap();
        assert!(!value.matches(&pattern));
    }

    #[test]
    fn wildcard_optional_matches_none() {
        let value = Fgrn::parse("fgrn:acme-app:-:forgeguard:policy:pol-001").unwrap();
        let pattern = Fgrn::parse("fgrn:acme-app:*:forgeguard:policy:pol-001").unwrap();
        assert!(value.matches(&pattern));
    }

    // -- Parse error tests ---------------------------------------------------

    #[test]
    fn parse_error_bad_format() {
        assert!(Fgrn::parse("not-a-fgrn").is_err());
    }

    #[test]
    fn parse_error_too_few_segments() {
        assert!(Fgrn::parse("fgrn:acme-app:acme-corp:iam:user").is_err());
    }

    #[test]
    fn parse_error_empty() {
        assert!(Fgrn::parse("").is_err());
    }

    #[test]
    fn parse_error_uppercase_segment() {
        assert!(Fgrn::parse("fgrn:AcmeApp:acme-corp:iam:user:alice").is_err());
    }

    // -- Builder tests -------------------------------------------------------

    #[test]
    fn builder_user() {
        let project = ProjectId::new("acme-app").unwrap();
        let tenant = TenantId::new("acme-corp").unwrap();
        let user_id = UserId::new("alice").unwrap();
        let fgrn = Fgrn::user(&project, &tenant, &user_id);
        assert_eq!(fgrn.to_string(), "fgrn:acme-app:acme-corp:iam:user:alice");
    }

    #[test]
    fn builder_group() {
        let project = ProjectId::new("acme-app").unwrap();
        let tenant = TenantId::new("acme-corp").unwrap();
        let group = GroupName::new("admin").unwrap();
        let fgrn = Fgrn::group(&project, &tenant, &group);
        assert_eq!(fgrn.to_string(), "fgrn:acme-app:acme-corp:iam:group:admin");
    }

    #[test]
    fn builder_policy() {
        let project = ProjectId::new("acme-app").unwrap();
        let policy = PolicyName::new("todo-viewer").unwrap();
        let fgrn = Fgrn::policy(&project, &policy);
        assert_eq!(
            fgrn.to_string(),
            "fgrn:acme-app:-:forgeguard:policy:todo-viewer"
        );
    }

    // -- Display / vp_entity_id ----------------------------------------------

    #[test]
    fn display_equals_vp_entity_id() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:iam:user:alice").unwrap();
        assert_eq!(fgrn.to_string(), fgrn.as_vp_entity_id());
    }

    // -- Cedar entity type ---------------------------------------------------

    #[test]
    fn cedar_entity_type_concrete() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-001").unwrap();
        assert_eq!(fgrn.cedar_entity_type(), Some("todo::list".to_string()));
    }

    #[test]
    fn cedar_entity_type_wildcard_returns_none() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:todo:*:list-001").unwrap();
        assert_eq!(fgrn.cedar_entity_type(), None);
    }

    // -- Serde round-trip ----------------------------------------------------

    #[test]
    fn serde_round_trip() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:iam:user:alice").unwrap();
        let json = serde_json::to_string(&fgrn).unwrap();
        assert_eq!(json, "\"fgrn:acme-app:acme-corp:iam:user:alice\"");
        let deser: Fgrn = serde_json::from_str(&json).unwrap();
        assert_eq!(fgrn, deser);
    }

    // -- new() + Display round-trip ------------------------------------------

    #[test]
    fn new_display_round_trip() {
        let fgrn = Fgrn::new(
            Some(FgrnSegment::Value(Segment::try_new("acme-app").unwrap())),
            Some(FgrnSegment::Value(Segment::try_new("acme-corp").unwrap())),
            FgrnSegment::Value(Segment::try_new("todo").unwrap()),
            FgrnSegment::Value(Segment::try_new("list").unwrap()),
            FgrnSegment::Value(Segment::try_new("list-001").unwrap()),
        );
        let s = fgrn.to_string();
        let parsed: Fgrn = s.parse().unwrap();
        assert_eq!(fgrn, parsed);
    }

    // -- FromStr -------------------------------------------------------------

    #[test]
    fn from_str_works() {
        let fgrn: Fgrn = "fgrn:acme-app:acme-corp:iam:user:alice".parse().unwrap();
        assert_eq!(fgrn.to_string(), "fgrn:acme-app:acme-corp:iam:user:alice");
    }
}

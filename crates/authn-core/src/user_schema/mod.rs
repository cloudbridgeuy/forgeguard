//! Per-org user attribute schema — pure domain types and `diff_schema`.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use forgeguard_core::{GroupName, OrgStatus};
use serde::{Deserialize, Serialize};

use crate::error::Error;

pub mod cognito_mapping;
pub mod types;
pub mod validation;

pub use cognito_mapping::{schema_to_cognito_attrs, CognitoAttrDef, CognitoStringConstraints};
pub use types::{RawAttrMap, UserAttributes};
pub use validation::{validate_attributes, FieldError, FieldErrorKind, ValidationErrors};

/// One of the 15 Cognito standard user attributes ForgeGuard recognises.
///
/// Unknown names are rejected at deserialization / `FromStr` time, so any value
/// of this type names a real Cognito attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardAttrName {
    Address,
    Birthdate,
    FamilyName,
    Gender,
    GivenName,
    Locale,
    MiddleName,
    Name,
    Nickname,
    PhoneNumber,
    Picture,
    PreferredUsername,
    Profile,
    Website,
    Zoneinfo,
}

impl StandardAttrName {
    /// All variants in declaration order — useful for exhaustive iteration.
    pub const ALL: [Self; 15] = [
        Self::Address,
        Self::Birthdate,
        Self::FamilyName,
        Self::Gender,
        Self::GivenName,
        Self::Locale,
        Self::MiddleName,
        Self::Name,
        Self::Nickname,
        Self::PhoneNumber,
        Self::Picture,
        Self::PreferredUsername,
        Self::Profile,
        Self::Website,
        Self::Zoneinfo,
    ];

    /// Wire-format name (snake_case) for this attribute.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Birthdate => "birthdate",
            Self::FamilyName => "family_name",
            Self::Gender => "gender",
            Self::GivenName => "given_name",
            Self::Locale => "locale",
            Self::MiddleName => "middle_name",
            Self::Name => "name",
            Self::Nickname => "nickname",
            Self::PhoneNumber => "phone_number",
            Self::Picture => "picture",
            Self::PreferredUsername => "preferred_username",
            Self::Profile => "profile",
            Self::Website => "website",
            Self::Zoneinfo => "zoneinfo",
        }
    }
}

impl fmt::Display for StandardAttrName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StandardAttrName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "address" => Ok(Self::Address),
            "birthdate" => Ok(Self::Birthdate),
            "family_name" => Ok(Self::FamilyName),
            "gender" => Ok(Self::Gender),
            "given_name" => Ok(Self::GivenName),
            "locale" => Ok(Self::Locale),
            "middle_name" => Ok(Self::MiddleName),
            "name" => Ok(Self::Name),
            "nickname" => Ok(Self::Nickname),
            "phone_number" => Ok(Self::PhoneNumber),
            "picture" => Ok(Self::Picture),
            "preferred_username" => Ok(Self::PreferredUsername),
            "profile" => Ok(Self::Profile),
            "website" => Ok(Self::Website),
            "zoneinfo" => Ok(Self::Zoneinfo),
            other => Err(Error::InvalidStandardAttrName(other.to_owned())),
        }
    }
}

impl<'de> Deserialize<'de> for StandardAttrName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Schema entry for a standard attribute — just the `required` flag.
///
/// Cognito fixes everything else (length bounds, mutability) at pool creation
/// for standard attributes, so this carries no further knobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardAttrSpec {
    pub required: bool,
}

/// Custom-attribute name — lowercase ASCII alphanumerics and dashes, 1..=20 chars.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CustomAttrName(String);

impl CustomAttrName {
    /// Maximum length per Cognito constraints on custom attribute names.
    pub const MAX_LENGTH: usize = 20;

    /// Validate and wrap a raw string into a `CustomAttrName`.
    pub fn try_new(raw: impl Into<String>) -> Result<Self, Error> {
        let s = raw.into();
        if s.is_empty() {
            return Err(Error::InvalidCustomAttrName {
                raw: s,
                reason: "must not be empty",
            });
        }
        if s.len() > Self::MAX_LENGTH {
            return Err(Error::InvalidCustomAttrName {
                raw: s,
                reason: "must not exceed 20 characters",
            });
        }
        let all_valid = s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !all_valid {
            return Err(Error::InvalidCustomAttrName {
                raw: s,
                reason: "must contain only lowercase letters, digits, and dashes",
            });
        }
        Ok(Self(s))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CustomAttrName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CustomAttrName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl<'de> Deserialize<'de> for CustomAttrName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

/// Value-type and constraints for a custom attribute.
///
/// V1 ships only the `String` variant; additional variants land in later slices.
/// `#[non_exhaustive]` keeps adding new variants from being a breaking change
/// for downstream `match` consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AttrType {
    String {
        min_length: Option<u32>,
        max_length: Option<u32>,
        required: bool,
    },
}

/// Schema entry for a custom attribute — wraps the `AttrType`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomAttrSpec {
    #[serde(flatten)]
    pub ty: AttrType,
}

/// A full per-org user attribute schema.
///
/// Fields are private; construct via `UserSchema::new` or serde and read via
/// `standard()` / `custom()`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSchema {
    #[serde(default)]
    standard: BTreeMap<StandardAttrName, StandardAttrSpec>,
    #[serde(default)]
    custom: BTreeMap<CustomAttrName, CustomAttrSpec>,
}

impl UserSchema {
    /// Build a `UserSchema` from already-validated maps.
    pub fn new(
        standard: BTreeMap<StandardAttrName, StandardAttrSpec>,
        custom: BTreeMap<CustomAttrName, CustomAttrSpec>,
    ) -> Self {
        Self { standard, custom }
    }

    pub fn standard(&self) -> &BTreeMap<StandardAttrName, StandardAttrSpec> {
        &self.standard
    }

    pub fn custom(&self) -> &BTreeMap<CustomAttrName, CustomAttrSpec> {
        &self.custom
    }
}

/// Diff result returned on a successful schema transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaDelta {
    pub added_custom: Vec<CustomAttrName>,
}

/// Append-only invariant failure: returned from `diff_schema` for Active orgs
/// when the requested transition would alter or remove existing entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendOnlyViolation {
    pub violations: Vec<FieldViolation>,
}

/// One field-level append-only violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldViolation {
    pub field: String,
    pub reason: ViolationKind,
}

/// Categorical reason a field violates the append-only invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    Removed,
    TypeChanged,
    RequiredToggled,
    LengthBoundsChanged,
    StandardMapEdited,
}

/// In-domain command produced by the wire-to-domain conversion in V2 handlers.
///
/// Holds the raw attribute payload; downstream code is expected to run
/// `validate_attributes(&schema, &cmd.attributes)` before persisting.
#[derive(Debug, Clone)]
pub struct CreateUserCommand {
    pub email: String,
    pub attributes: RawAttrMap,
    pub groups: Vec<GroupName>,
}

/// Diff two `UserSchema`s under the org's lifecycle status.
///
/// `Draft` orgs accept any diff — the schema is still being shaped. `Active`
/// orgs enforce append-only: only adding new custom attrs is allowed; every
/// other shape change accumulates a `FieldViolation`.
///
/// Other lifecycle statuses (`Suspended`, `Deleting`, `Deleted`) inherit the
/// Active rules — there is no legitimate reason to relax append-only after a
/// schema has left Draft.
pub fn diff_schema(
    old: &UserSchema,
    new: &UserSchema,
    org_status: &OrgStatus,
) -> Result<SchemaDelta, AppendOnlyViolation> {
    let added_custom: Vec<CustomAttrName> = new
        .custom
        .keys()
        .filter(|k| !old.custom.contains_key(*k))
        .cloned()
        .collect();

    if matches!(org_status, OrgStatus::Draft) {
        return Ok(SchemaDelta { added_custom });
    }

    let mut violations = Vec::new();

    if old.standard != new.standard {
        violations.push(FieldViolation {
            field: "standard".to_owned(),
            reason: ViolationKind::StandardMapEdited,
        });
    }

    for (name, old_spec) in &old.custom {
        match new.custom.get(name) {
            None => violations.push(FieldViolation {
                field: format!("custom.{name}"),
                reason: ViolationKind::Removed,
            }),
            Some(new_spec) => {
                check_custom_attr_compat(name, old_spec, new_spec, &mut violations);
            }
        }
    }

    if violations.is_empty() {
        Ok(SchemaDelta { added_custom })
    } else {
        Err(AppendOnlyViolation { violations })
    }
}

fn check_custom_attr_compat(
    name: &CustomAttrName,
    old_spec: &CustomAttrSpec,
    new_spec: &CustomAttrSpec,
    violations: &mut Vec<FieldViolation>,
) {
    // The struct match is irrefutable today because `AttrType` has a single
    // variant. When more variants land, replace this with a `match` and emit
    // `ViolationKind::TypeChanged` on the cross-variant arm.
    let AttrType::String {
        min_length: old_min,
        max_length: old_max,
        required: old_required,
    } = &old_spec.ty;
    let AttrType::String {
        min_length: new_min,
        max_length: new_max,
        required: new_required,
    } = &new_spec.ty;

    if old_required != new_required {
        violations.push(FieldViolation {
            field: format!("custom.{name}"),
            reason: ViolationKind::RequiredToggled,
        });
    }
    if old_min != new_min || old_max != new_max {
        violations.push(FieldViolation {
            field: format!("custom.{name}"),
            reason: ViolationKind::LengthBoundsChanged,
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn cust(name: &str) -> CustomAttrName {
        CustomAttrName::try_new(name).unwrap()
    }

    fn bounded_string(min: Option<u32>, max: Option<u32>, required: bool) -> CustomAttrSpec {
        CustomAttrSpec {
            ty: AttrType::String {
                min_length: min,
                max_length: max,
                required,
            },
        }
    }

    fn schema_with_custom(entries: &[(&str, CustomAttrSpec)]) -> UserSchema {
        let mut custom = BTreeMap::new();
        for (name, spec) in entries {
            custom.insert(cust(name), spec.clone());
        }
        UserSchema::new(BTreeMap::new(), custom)
    }

    fn schema_with_standard(entries: &[(StandardAttrName, bool)]) -> UserSchema {
        let mut standard = BTreeMap::new();
        for (name, required) in entries {
            standard.insert(
                *name,
                StandardAttrSpec {
                    required: *required,
                },
            );
        }
        UserSchema::new(standard, BTreeMap::new())
    }

    // -- StandardAttrName ----------------------------------------------------

    #[test]
    fn standard_attr_name_roundtrip_serde() {
        for variant in StandardAttrName::ALL {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: StandardAttrName = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant, "round-trip failed for {variant:?}");
        }
    }

    #[test]
    fn standard_attr_name_display_matches_serde() {
        for variant in StandardAttrName::ALL {
            let json = serde_json::to_string(&variant).unwrap();
            let display = variant.to_string();
            assert_eq!(json, format!("\"{display}\""));
        }
    }

    #[test]
    fn standard_attr_name_outside_allowlist() {
        let result: Result<StandardAttrName, _> = serde_json::from_str(r#""unknown_attr""#);
        assert!(result.is_err());
    }

    // -- CustomAttrName ------------------------------------------------------

    #[test]
    fn custom_attr_name_valid() {
        assert!(CustomAttrName::try_new("my-attr").is_ok());
        assert!(CustomAttrName::try_new("dept").is_ok());
        assert!(CustomAttrName::try_new("dept-1").is_ok());
    }

    #[test]
    fn custom_attr_name_too_long() {
        let twenty_one = "a".repeat(21);
        assert!(matches!(
            CustomAttrName::try_new(&twenty_one),
            Err(Error::InvalidCustomAttrName { .. })
        ));
    }

    #[test]
    fn custom_attr_name_max_length_accepted() {
        let twenty = "a".repeat(20);
        assert!(CustomAttrName::try_new(twenty).is_ok());
    }

    #[test]
    fn custom_attr_name_rejects_uppercase() {
        assert!(CustomAttrName::try_new("MyAttr").is_err());
    }

    #[test]
    fn custom_attr_name_rejects_spaces() {
        assert!(CustomAttrName::try_new("my attr").is_err());
    }

    #[test]
    fn custom_attr_name_rejects_underscore() {
        assert!(CustomAttrName::try_new("my_attr").is_err());
    }

    #[test]
    fn custom_attr_name_empty() {
        assert!(CustomAttrName::try_new("").is_err());
    }

    #[test]
    fn custom_attr_name_roundtrip_serde() {
        let name = CustomAttrName::try_new("dept-1").unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"dept-1\"");
        let parsed: CustomAttrName = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, name);
    }

    #[test]
    fn custom_attr_name_deserialize_rejects_invalid() {
        let result: Result<CustomAttrName, _> = serde_json::from_str(r#""Bad Name""#);
        assert!(result.is_err());
    }

    // -- UserSchema serde roundtrip -----------------------------------------

    #[test]
    fn user_schema_roundtrip_serde() {
        let mut standard = BTreeMap::new();
        standard.insert(StandardAttrName::Name, StandardAttrSpec { required: true });
        let mut custom = BTreeMap::new();
        custom.insert(cust("dept"), bounded_string(Some(1), Some(20), true));
        let schema = UserSchema::new(standard, custom);

        let json = serde_json::to_string(&schema).unwrap();
        let parsed: UserSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, schema);
    }

    // -- diff_schema: Draft is permissive ------------------------------------

    #[test]
    fn diff_schema_draft_allows_removal() {
        let old = schema_with_custom(&[("foo", bounded_string(None, None, false))]);
        let new = schema_with_custom(&[]);
        let delta = diff_schema(&old, &new, &OrgStatus::Draft).unwrap();
        assert!(delta.added_custom.is_empty());
    }

    #[test]
    fn diff_schema_draft_allows_retype() {
        let old = schema_with_custom(&[("foo", bounded_string(None, Some(10), true))]);
        let new = schema_with_custom(&[("foo", bounded_string(None, Some(20), false))]);
        assert!(diff_schema(&old, &new, &OrgStatus::Draft).is_ok());
    }

    #[test]
    fn diff_schema_draft_allows_standard_map_edit() {
        let old = schema_with_standard(&[]);
        let new = schema_with_standard(&[(StandardAttrName::Name, true)]);
        assert!(diff_schema(&old, &new, &OrgStatus::Draft).is_ok());
    }

    #[test]
    fn diff_schema_draft_empty_delta_on_no_change() {
        let schema = schema_with_custom(&[("foo", bounded_string(None, None, false))]);
        let delta = diff_schema(&schema, &schema, &OrgStatus::Draft).unwrap();
        assert!(delta.added_custom.is_empty());
    }

    #[test]
    fn diff_schema_draft_added_custom_listed() {
        let old = schema_with_custom(&[]);
        let new = schema_with_custom(&[("foo", bounded_string(None, None, false))]);
        let delta = diff_schema(&old, &new, &OrgStatus::Draft).unwrap();
        assert_eq!(delta.added_custom, vec![cust("foo")]);
    }

    // -- diff_schema: Active is append-only ----------------------------------

    #[test]
    fn diff_schema_active_allows_new_custom_attr() {
        let old = schema_with_custom(&[]);
        let new = schema_with_custom(&[("bar", bounded_string(None, None, false))]);
        let delta = diff_schema(&old, &new, &OrgStatus::Active).unwrap();
        assert_eq!(delta.added_custom, vec![cust("bar")]);
    }

    #[test]
    fn diff_schema_active_allows_no_op() {
        let schema = schema_with_custom(&[("foo", bounded_string(None, None, false))]);
        let delta = diff_schema(&schema, &schema, &OrgStatus::Active).unwrap();
        assert!(delta.added_custom.is_empty());
    }

    #[test]
    fn diff_schema_active_rejects_removal() {
        let old = schema_with_custom(&[("foo", bounded_string(None, None, false))]);
        let new = schema_with_custom(&[]);
        let err = diff_schema(&old, &new, &OrgStatus::Active).unwrap_err();
        assert!(err
            .violations
            .iter()
            .any(|v| matches!(v.reason, ViolationKind::Removed) && v.field == "custom.foo"));
    }

    #[test]
    fn diff_schema_active_rejects_required_toggle() {
        let old = schema_with_custom(&[("foo", bounded_string(None, None, false))]);
        let new = schema_with_custom(&[("foo", bounded_string(None, None, true))]);
        let err = diff_schema(&old, &new, &OrgStatus::Active).unwrap_err();
        assert!(err
            .violations
            .iter()
            .any(|v| matches!(v.reason, ViolationKind::RequiredToggled)));
    }

    #[test]
    fn diff_schema_active_rejects_length_bounds_change() {
        let old = schema_with_custom(&[("foo", bounded_string(None, Some(10), false))]);
        let new = schema_with_custom(&[("foo", bounded_string(None, Some(20), false))]);
        let err = diff_schema(&old, &new, &OrgStatus::Active).unwrap_err();
        assert!(err
            .violations
            .iter()
            .any(|v| matches!(v.reason, ViolationKind::LengthBoundsChanged)));
    }

    #[test]
    fn diff_schema_active_rejects_standard_map_edit() {
        let old = schema_with_standard(&[]);
        let new = schema_with_standard(&[(StandardAttrName::Name, true)]);
        let err = diff_schema(&old, &new, &OrgStatus::Active).unwrap_err();
        assert!(err
            .violations
            .iter()
            .any(|v| matches!(v.reason, ViolationKind::StandardMapEdited)));
    }

    #[test]
    fn diff_schema_non_draft_inherits_active_rules() {
        // Smoke test: any non-Draft status uses append-only semantics.
        let old = schema_with_custom(&[("foo", bounded_string(None, None, false))]);
        let new = schema_with_custom(&[]);
        for status in [
            OrgStatus::Suspended,
            OrgStatus::Deleting,
            OrgStatus::Deleted,
        ] {
            let err = diff_schema(&old, &new, &status).unwrap_err();
            assert!(
                err.violations
                    .iter()
                    .any(|v| matches!(v.reason, ViolationKind::Removed)),
                "status {status:?} should reject removal"
            );
        }
    }

    #[test]
    fn diff_schema_active_collects_multiple_violations() {
        let old = schema_with_custom(&[
            ("foo", bounded_string(None, None, false)),
            ("bar", bounded_string(None, Some(10), false)),
        ]);
        let new = schema_with_custom(&[("bar", bounded_string(None, Some(20), false))]);
        let err = diff_schema(&old, &new, &OrgStatus::Active).unwrap_err();
        assert_eq!(err.violations.len(), 2);
        let kinds: Vec<_> = err.violations.iter().map(|v| v.reason).collect();
        assert!(kinds.contains(&ViolationKind::Removed));
        assert!(kinds.contains(&ViolationKind::LengthBoundsChanged));
    }
}

//! Schema-driven validation for raw attribute maps.

use serde::{Deserialize, Serialize};

use super::types::{RawAttrMap, UserAttributes};
use super::{AttrType, CustomAttrName, StandardAttrName, UserSchema};

/// Aggregated validation errors returned from [`validate_attributes`].
///
/// Carries every field-level error so callers can render the full list to the
/// user in one round-trip (e.g. a 422 response body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationErrors {
    pub errors: Vec<FieldError>,
}

/// One field-level validation error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldError {
    pub field: String,
    pub reason: FieldErrorKind,
}

/// Why a single field failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldErrorKind {
    /// The attribute name is not in the schema and is not an always-accepted
    /// invariant (`email`, `email_verified`).
    Unknown,
    /// The schema marks this attribute as required, but the input omitted it.
    MissingRequired,
    /// Value length is below the schema's `min_length`.
    TooShort { min: u32 },
    /// Value length is above the schema's `max_length`.
    TooLong { max: u32 },
}

/// Attribute keys ForgeGuard always accepts on top of the org's `UserSchema`.
const ALWAYS_ACCEPTED: &[&str] = &["email", "email_verified"];

/// Strict-allowlist validation of a raw attribute map against a schema.
///
/// On success, returns a `UserAttributes` containing every key from `attrs`
/// (including the always-accepted `email` / `email_verified` invariants).
/// On failure, returns every field-level error in a single `ValidationErrors`.
pub fn validate_attributes(
    schema: &UserSchema,
    attrs: &RawAttrMap,
) -> Result<UserAttributes, ValidationErrors> {
    let mut errors = Vec::new();

    collect_missing_required(schema, attrs, &mut errors);
    for (key, value) in attrs {
        classify_provided_key(schema, key, value, &mut errors);
    }

    if errors.is_empty() {
        Ok(UserAttributes::from_validated(attrs.clone()))
    } else {
        Err(ValidationErrors { errors })
    }
}

fn collect_missing_required(schema: &UserSchema, attrs: &RawAttrMap, errors: &mut Vec<FieldError>) {
    let standard_fields = schema
        .standard()
        .iter()
        .map(|(name, spec)| (name.to_string(), spec.required));

    let custom_fields = schema.custom().iter().map(|(name, spec)| {
        // Irrefutable today (single AttrType variant). When more variants land,
        // replace with `match` and handle each arm explicitly.
        let AttrType::String { required, .. } = &spec.ty;
        (name.to_string(), *required)
    });

    for (field, required) in standard_fields.chain(custom_fields) {
        if required && !attrs.contains_key(&field) {
            errors.push(FieldError {
                field,
                reason: FieldErrorKind::MissingRequired,
            });
        }
    }
}

fn classify_provided_key(
    schema: &UserSchema,
    key: &str,
    value: &str,
    errors: &mut Vec<FieldError>,
) {
    if ALWAYS_ACCEPTED.contains(&key) {
        return;
    }

    if let Ok(std_name) = key.parse::<StandardAttrName>() {
        if schema.standard().contains_key(&std_name) {
            return;
        }
    }

    if let Ok(custom_name) = CustomAttrName::try_new(key) {
        if let Some(spec) = schema.custom().get(&custom_name) {
            check_string_bounds(key, value, &spec.ty, errors);
            return;
        }
    }

    errors.push(FieldError {
        field: key.to_owned(),
        reason: FieldErrorKind::Unknown,
    });
}

fn check_string_bounds(key: &str, value: &str, ty: &AttrType, errors: &mut Vec<FieldError>) {
    // Irrefutable today (single AttrType variant). When more variants land,
    // replace with `match` and route non-string types to a TypeMismatch error.
    let AttrType::String {
        min_length,
        max_length,
        ..
    } = ty;
    let len = u32::try_from(value.chars().count()).unwrap_or(u32::MAX);
    if let Some(min) = min_length {
        if len < *min {
            errors.push(FieldError {
                field: key.to_owned(),
                reason: FieldErrorKind::TooShort { min: *min },
            });
            return;
        }
    }
    if let Some(max) = max_length {
        if len > *max {
            errors.push(FieldError {
                field: key.to_owned(),
                reason: FieldErrorKind::TooLong { max: *max },
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::user_schema::{CustomAttrSpec, StandardAttrSpec};

    fn cust(name: &str) -> CustomAttrName {
        CustomAttrName::try_new(name).unwrap()
    }

    fn string_spec(required: bool, min: Option<u32>, max: Option<u32>) -> CustomAttrSpec {
        CustomAttrSpec {
            ty: AttrType::String {
                min_length: min,
                max_length: max,
                required,
            },
        }
    }

    fn schema_with(
        standard: &[(StandardAttrName, bool)],
        custom: &[(&str, CustomAttrSpec)],
    ) -> UserSchema {
        let mut std_map = BTreeMap::new();
        for (name, required) in standard {
            std_map.insert(
                *name,
                StandardAttrSpec {
                    required: *required,
                },
            );
        }
        let mut custom_map = BTreeMap::new();
        for (name, spec) in custom {
            custom_map.insert(cust(name), spec.clone());
        }
        UserSchema::new(std_map, custom_map)
    }

    fn attrs(entries: &[(&str, &str)]) -> RawAttrMap {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn validate_attributes_happy_path() {
        let schema = schema_with(
            &[(StandardAttrName::Name, true)],
            &[("dept", string_spec(true, Some(1), Some(10)))],
        );
        let input = attrs(&[
            ("email", "alice@example.com"),
            ("name", "Alice"),
            ("dept", "ENG"),
        ]);
        let validated = validate_attributes(&schema, &input).unwrap();
        assert_eq!(validated.as_map(), &input);
    }

    #[test]
    fn validate_attributes_unknown_attr_yields_error() {
        let schema = schema_with(&[], &[]);
        let input = attrs(&[("favorite-color", "blue")]);
        let err = validate_attributes(&schema, &input).unwrap_err();
        assert!(err.errors.iter().any(|e| {
            matches!(e.reason, FieldErrorKind::Unknown) && e.field == "favorite-color"
        }));
    }

    #[test]
    fn validate_attributes_missing_required_custom() {
        let schema = schema_with(&[], &[("dept", string_spec(true, None, None))]);
        let err = validate_attributes(&schema, &attrs(&[])).unwrap_err();
        assert!(err
            .errors
            .iter()
            .any(|e| { matches!(e.reason, FieldErrorKind::MissingRequired) && e.field == "dept" }));
    }

    #[test]
    fn validate_attributes_missing_required_standard() {
        let schema = schema_with(&[(StandardAttrName::Name, true)], &[]);
        let err = validate_attributes(&schema, &attrs(&[])).unwrap_err();
        assert!(err
            .errors
            .iter()
            .any(|e| { matches!(e.reason, FieldErrorKind::MissingRequired) && e.field == "name" }));
    }

    #[test]
    fn validate_attributes_email_always_accepted() {
        let schema = schema_with(&[], &[]);
        let input = attrs(&[("email", "alice@example.com")]);
        assert!(validate_attributes(&schema, &input).is_ok());
    }

    #[test]
    fn validate_attributes_email_verified_always_accepted() {
        let schema = schema_with(&[], &[]);
        let input = attrs(&[("email_verified", "true")]);
        assert!(validate_attributes(&schema, &input).is_ok());
    }

    #[test]
    fn validate_attributes_optional_attr_absent_is_ok() {
        let schema = schema_with(&[], &[("dept", string_spec(false, None, None))]);
        assert!(validate_attributes(&schema, &attrs(&[])).is_ok());
    }

    #[test]
    fn validate_attributes_value_too_short() {
        let schema = schema_with(&[], &[("dept", string_spec(false, Some(3), None))]);
        let input = attrs(&[("dept", "AB")]);
        let err = validate_attributes(&schema, &input).unwrap_err();
        assert!(err
            .errors
            .iter()
            .any(|e| matches!(e.reason, FieldErrorKind::TooShort { min: 3 })));
    }

    #[test]
    fn validate_attributes_value_too_long() {
        let schema = schema_with(&[], &[("dept", string_spec(false, None, Some(2)))]);
        let input = attrs(&[("dept", "ENG")]);
        let err = validate_attributes(&schema, &input).unwrap_err();
        assert!(err
            .errors
            .iter()
            .any(|e| matches!(e.reason, FieldErrorKind::TooLong { max: 2 })));
    }

    #[test]
    fn validate_attributes_collects_multiple_errors() {
        let schema = schema_with(
            &[(StandardAttrName::Name, true)],
            &[("dept", string_spec(true, None, None))],
        );
        let input = attrs(&[("bogus", "x")]);
        let err = validate_attributes(&schema, &input).unwrap_err();
        let kinds: Vec<_> = err.errors.iter().map(|e| e.reason).collect();
        assert!(
            kinds
                .iter()
                .filter(|k| matches!(k, FieldErrorKind::MissingRequired))
                .count()
                >= 2
        );
        assert!(kinds.iter().any(|k| matches!(k, FieldErrorKind::Unknown)));
    }

    #[test]
    fn validate_attributes_standard_attr_not_in_schema_is_unknown() {
        // "name" is a valid Cognito standard attr but the schema doesn't accept it.
        let schema = schema_with(&[], &[]);
        let input = attrs(&[("name", "Alice")]);
        let err = validate_attributes(&schema, &input).unwrap_err();
        assert!(err
            .errors
            .iter()
            .any(|e| matches!(e.reason, FieldErrorKind::Unknown) && e.field == "name"));
    }

    #[test]
    fn validate_attributes_standard_attr_no_length_check() {
        // Standard attrs ignore length bounds (Cognito fixes them at pool creation).
        let schema = schema_with(&[(StandardAttrName::Name, false)], &[]);
        let input = attrs(&[("name", "A".repeat(1000).as_str())]);
        assert!(validate_attributes(&schema, &input).is_ok());
    }
}

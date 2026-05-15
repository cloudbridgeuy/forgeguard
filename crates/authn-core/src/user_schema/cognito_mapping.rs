//! Pure mapping from a `UserSchema` to Cognito's wire schema-attribute shape.
//!
//! This module owns the `custom:` prefix — no other crate should hard-code it.
//! Standard attributes are deliberately omitted: Cognito fixes them at pool
//! creation and they cannot be modified via `UpdateUserPool` (shaping doc R4.3).

use serde::{Deserialize, Serialize};

use super::{AttrType, CustomAttrSpec, UserSchema};

/// Pure mirror of AWS `SchemaAttributeType` — no SDK dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CognitoAttrDef {
    pub name: String,
    pub attribute_data_type: String,
    pub mutable: bool,
    pub required: bool,
    pub string_attribute_constraints: Option<CognitoStringConstraints>,
}

/// Pure mirror of AWS `StringAttributeConstraintsType`. Cognito's API expresses
/// bounds as strings, so we serialize as strings on the way out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CognitoStringConstraints {
    pub min_length: Option<String>,
    pub max_length: Option<String>,
}

/// Map each custom attribute in `schema` to a `CognitoAttrDef`.
///
/// - Standard attributes are excluded — they are immutable post-pool creation.
/// - Names are prefixed with `custom:` (the only place that prefix lives).
/// - Results are in name order; `BTreeMap` iteration guarantees this.
/// - `mutable` is always `true`; the domain `AttrType` carries no `mutable`
///   knob (shaping doc A2.1).
/// - For `AttrType::String` attrs, `string_attribute_constraints` is always
///   `Some` so the Cognito API call carries an explicit "no bounds" signal
///   rather than letting AWS infer defaults; `min_length` and `max_length`
///   inside it may individually be `None`.
pub fn schema_to_cognito_attrs(schema: &UserSchema) -> Vec<CognitoAttrDef> {
    schema
        .custom()
        .iter()
        .map(|(name, spec)| custom_attr_to_cognito(name.as_str(), spec))
        .collect()
}

fn custom_attr_to_cognito(name: &str, spec: &CustomAttrSpec) -> CognitoAttrDef {
    // Irrefutable today (single AttrType variant). When more variants land,
    // replace with `match` and emit the matching Cognito `attribute_data_type`.
    let AttrType::String {
        min_length,
        max_length,
        required,
    } = &spec.ty;
    CognitoAttrDef {
        name: format!("custom:{name}"),
        attribute_data_type: "String".to_owned(),
        mutable: true,
        required: *required,
        string_attribute_constraints: Some(CognitoStringConstraints {
            min_length: min_length.map(|n| n.to_string()),
            max_length: max_length.map(|n| n.to_string()),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::user_schema::{
        CustomAttrName, CustomAttrSpec, StandardAttrName, StandardAttrSpec, UserSchema,
    };

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

    fn schema_with_custom(entries: &[(&str, CustomAttrSpec)]) -> UserSchema {
        let mut custom = BTreeMap::new();
        for (name, spec) in entries {
            custom.insert(cust(name), spec.clone());
        }
        UserSchema::new(BTreeMap::new(), custom)
    }

    #[test]
    fn schema_to_cognito_attrs_empty_schema() {
        let schema = UserSchema::new(BTreeMap::new(), BTreeMap::new());
        assert!(schema_to_cognito_attrs(&schema).is_empty());
    }

    #[test]
    fn schema_to_cognito_attrs_custom_attr_has_custom_prefix() {
        let schema = schema_with_custom(&[("dept", string_spec(false, None, None))]);
        let defs = schema_to_cognito_attrs(&schema);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "custom:dept");
    }

    #[test]
    fn schema_to_cognito_attrs_standard_attrs_excluded() {
        let mut standard = BTreeMap::new();
        standard.insert(StandardAttrName::Name, StandardAttrSpec { required: true });
        let schema = UserSchema::new(standard, BTreeMap::new());
        assert!(schema_to_cognito_attrs(&schema).is_empty());
    }

    #[test]
    fn schema_to_cognito_attrs_mutable_always_true() {
        let schema = schema_with_custom(&[
            ("a", string_spec(true, None, None)),
            ("b", string_spec(false, Some(1), Some(5))),
        ]);
        for def in schema_to_cognito_attrs(&schema) {
            assert!(def.mutable, "{} should be mutable", def.name);
        }
    }

    #[test]
    fn schema_to_cognito_attrs_constraints_propagated() {
        let schema = schema_with_custom(&[("dept", string_spec(false, Some(2), Some(10)))]);
        let defs = schema_to_cognito_attrs(&schema);
        let constraints = defs[0]
            .string_attribute_constraints
            .as_ref()
            .expect("constraints present");
        assert_eq!(constraints.min_length.as_deref(), Some("2"));
        assert_eq!(constraints.max_length.as_deref(), Some("10"));
    }

    #[test]
    fn schema_to_cognito_attrs_sorted_by_name() {
        let schema = schema_with_custom(&[
            ("z-attr", string_spec(false, None, None)),
            ("a-attr", string_spec(false, None, None)),
        ]);
        let defs = schema_to_cognito_attrs(&schema);
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["custom:a-attr", "custom:z-attr"]);
    }

    #[test]
    fn schema_to_cognito_attrs_required_propagated() {
        let schema = schema_with_custom(&[
            ("opt", string_spec(false, None, None)),
            ("req", string_spec(true, None, None)),
        ]);
        let defs = schema_to_cognito_attrs(&schema);
        let opt = defs.iter().find(|d| d.name == "custom:opt").unwrap();
        let req = defs.iter().find(|d| d.name == "custom:req").unwrap();
        assert!(!opt.required);
        assert!(req.required);
    }

    #[test]
    fn schema_to_cognito_attrs_attribute_data_type_is_string() {
        let schema = schema_with_custom(&[("dept", string_spec(false, None, None))]);
        let defs = schema_to_cognito_attrs(&schema);
        assert_eq!(defs[0].attribute_data_type, "String");
    }

    #[test]
    fn schema_to_cognito_attrs_constraints_present_with_no_bounds() {
        // Even with no min/max, the constraints object is present (so the
        // Cognito API call carries the explicit "no bounds" signal rather
        // than letting AWS infer defaults).
        let schema = schema_with_custom(&[("dept", string_spec(false, None, None))]);
        let defs = schema_to_cognito_attrs(&schema);
        let constraints = defs[0].string_attribute_constraints.as_ref().unwrap();
        assert!(constraints.min_length.is_none());
        assert!(constraints.max_length.is_none());
    }
}

//! Functional core for the user-schema handlers — deterministic, I/O-free,
//! unit-testable without an async runtime or AWS SDK.

use std::collections::BTreeMap;
use std::str::FromStr;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authn_core::user_schema::{
    CustomAttrName, CustomAttrSpec, StandardAttrName, StandardAttrSpec,
};
use forgeguard_authn_core::UserSchema;
use serde::{Deserialize, Serialize};

use crate::etag::Etag;

/// Wire DTO for `PUT /api/v1/organizations/{org_id}/user-schema`.
///
/// Both maps use raw `String` keys so that [`parse_user_schema_payload`] can
/// surface parse failures as typed [`UserSchemaPayloadError`] values rather
/// than opaque serde errors, enabling precise 422 response bodies.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct UpdateUserSchemaPayload {
    #[serde(default)]
    pub(crate) standard: BTreeMap<String, StandardAttrSpec>,
    #[serde(default)]
    pub(crate) custom: BTreeMap<String, CustomAttrSpec>,
}

/// Typed failure from [`parse_user_schema_payload`]: either an unrecognised
/// Cognito standard attribute name, or a custom attribute name that violates
/// the `CustomAttrName` invariant (lowercase ASCII alphanumeric + dashes,
/// 1–20 chars).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UserSchemaPayloadError {
    UnknownStandardAttr { raw: String },
    InvalidCustomAttrName { raw: String, reason: String },
}

impl UserSchemaPayloadError {
    /// Stable machine-readable label — safe to use in metrics and wire bodies.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::UnknownStandardAttr { .. } => "unknown_standard_attr",
            Self::InvalidCustomAttrName { .. } => "invalid_custom_attr_name",
        }
    }

    /// Dotted field path of the violation, for client-side field highlighting.
    pub(crate) fn field(&self) -> String {
        match self {
            Self::UnknownStandardAttr { raw } => format!("standard.{raw}"),
            Self::InvalidCustomAttrName { raw, .. } => format!("custom.{raw}"),
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::UnknownStandardAttr { raw } => {
                format!("'{raw}' is not a recognised Cognito standard attribute")
            }
            Self::InvalidCustomAttrName { raw, reason } => {
                format!("custom attribute name '{raw}' is invalid: {reason}")
            }
        }
    }
}

/// Convert the wire DTO into a validated [`UserSchema`].
///
/// Fails fast on the first invalid key — partial successes are not modelled.
pub(crate) fn parse_user_schema_payload(
    payload: UpdateUserSchemaPayload,
) -> Result<UserSchema, UserSchemaPayloadError> {
    let mut standard = BTreeMap::new();
    for (raw, spec) in payload.standard {
        let name = StandardAttrName::from_str(&raw)
            .map_err(|_| UserSchemaPayloadError::UnknownStandardAttr { raw })?;
        standard.insert(name, spec);
    }

    let mut custom = BTreeMap::new();
    for (raw, spec) in payload.custom {
        let name = CustomAttrName::try_new(raw.clone()).map_err(|e| {
            UserSchemaPayloadError::InvalidCustomAttrName {
                raw,
                reason: e.to_string(),
            }
        })?;
        custom.insert(name, spec);
    }

    Ok(UserSchema::new(standard, custom))
}

/// Response DTO for `GET /user-schema` and successful `PUT /user-schema`.
///
/// Transparent so the wire shape matches the input payload exactly.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub(crate) struct UserSchemaResource {
    schema: UserSchema,
}

impl UserSchemaResource {
    pub(crate) fn new(schema: UserSchema) -> Self {
        Self { schema }
    }
}

#[derive(Debug, Serialize)]
struct InvalidPayloadBody {
    error: &'static str,
    reason: &'static str,
    field: String,
    message: String,
}

/// Build an `ETag` response header from a stored etag value.
///
/// Returns an empty `HeaderMap` if the etag string cannot be parsed as a
/// valid HTTP header value (should not occur for well-formed etags).
pub(crate) fn etag_header(etag: &Etag) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(val) = etag.as_str().parse() {
        headers.insert(axum::http::header::ETAG, val);
    }
    headers
}

/// Map a parse error to a `422 Unprocessable Entity` response with a stable
/// JSON body (`error`, `reason`, `field`, `message`).
pub(crate) fn shape_422_response(err: &UserSchemaPayloadError) -> Response {
    let body = InvalidPayloadBody {
        error: "invalid_payload",
        reason: err.reason(),
        field: err.field(),
        message: err.message(),
    };
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_authn_core::user_schema::AttrType;

    use super::*;

    fn payload_from_json(json: serde_json::Value) -> UpdateUserSchemaPayload {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn parse_payload_minimal_draft() {
        let payload = payload_from_json(serde_json::json!({
            "standard": {},
            "custom": {}
        }));
        let schema = parse_user_schema_payload(payload).unwrap();
        assert!(schema.standard().is_empty());
        assert!(schema.custom().is_empty());
        assert_eq!(schema, UserSchema::default());
    }

    #[test]
    fn parse_payload_standard_attrs() {
        let payload = payload_from_json(serde_json::json!({
            "standard": { "name": { "required": true } },
            "custom": {}
        }));
        let schema = parse_user_schema_payload(payload).unwrap();
        let spec = schema.standard().get(&StandardAttrName::Name).unwrap();
        assert!(spec.required);
    }

    #[test]
    fn parse_payload_custom_attrs() {
        let payload = payload_from_json(serde_json::json!({
            "standard": {},
            "custom": {
                "badge-number": {
                    "type": "string",
                    "min_length": 1,
                    "max_length": 20,
                    "required": false
                }
            }
        }));
        let schema = parse_user_schema_payload(payload).unwrap();
        let name = CustomAttrName::try_new("badge-number").unwrap();
        let spec = schema.custom().get(&name).unwrap();
        match &spec.ty {
            AttrType::String {
                min_length,
                max_length,
                required,
            } => {
                assert_eq!(*min_length, Some(1));
                assert_eq!(*max_length, Some(20));
                assert!(!required);
            }
            other => panic!("expected AttrType::String, got {other:?}"),
        }
    }

    #[test]
    fn parse_payload_unknown_standard_attr() {
        let payload = payload_from_json(serde_json::json!({
            "standard": { "not-a-real-attr": { "required": true } },
            "custom": {}
        }));
        let err = parse_user_schema_payload(payload).unwrap_err();
        match &err {
            UserSchemaPayloadError::UnknownStandardAttr { raw } => {
                assert_eq!(raw, "not-a-real-attr");
            }
            other => panic!("expected UnknownStandardAttr, got {other:?}"),
        }
        let response = shape_422_response(&err);
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn parse_payload_invalid_custom_attr_name() {
        let payload = payload_from_json(serde_json::json!({
            "standard": {},
            "custom": {
                "UPPERCASE": {
                    "type": "string",
                    "required": false
                }
            }
        }));
        let err = parse_user_schema_payload(payload).unwrap_err();
        match &err {
            UserSchemaPayloadError::InvalidCustomAttrName { raw, .. } => {
                assert_eq!(raw, "UPPERCASE");
            }
            other => panic!("expected InvalidCustomAttrName, got {other:?}"),
        }
        let response = shape_422_response(&err);
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn payload_error_reason_labels_are_stable() {
        let unknown = UserSchemaPayloadError::UnknownStandardAttr {
            raw: "x".to_string(),
        };
        assert_eq!(unknown.reason(), "unknown_standard_attr");
        assert_eq!(unknown.field(), "standard.x");

        let invalid = UserSchemaPayloadError::InvalidCustomAttrName {
            raw: "X".to_string(),
            reason: "bad".to_string(),
        };
        assert_eq!(invalid.reason(), "invalid_custom_attr_name");
        assert_eq!(invalid.field(), "custom.X");
    }
}

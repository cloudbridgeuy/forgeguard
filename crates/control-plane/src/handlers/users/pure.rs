//! Functional core for the `POST /users` handler — deterministic, I/O-free.
//!
//! Owns:
//! - `CreateUserPayload` — wire DTO.
//! - Response DTOs for the seven saga outcome paths (plan §9).
//! - Helpers that shape the bodies into ready `axum::response::Response` values.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authn_core::saga::TicketId;
use forgeguard_authn_core::user_schema::{CreateUserCommand, RawAttrMap, ValidationErrors};
use forgeguard_core::{GroupName, UserId};
use serde::{Deserialize, Serialize};

/// Wire DTO for `POST /api/v1/organizations/{org_id}/users`.
///
/// `groups` defaults to an empty list — callers that omit the field create a
/// member with no groups. `attributes` is a free-form `String → String` map
/// validated against the org's `UserSchema` in stage S1.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CreateUserPayload {
    pub(crate) email: String,
    #[serde(default)]
    pub(crate) attributes: RawAttrMap,
    #[serde(default)]
    pub(crate) groups: Vec<String>,
}

/// Path 1 — 201 Created. Returned after S3 succeeds and the ticket is `Done`.
#[derive(Debug, Serialize)]
pub(crate) struct CreatedUserBody {
    pub(crate) sub: UserId,
    pub(crate) attributes: RawAttrMap,
    pub(crate) groups: Vec<String>,
    pub(crate) ticket_id: TicketId,
}

/// Path 2 — 202 Accepted. S3 failed transiently and C2 rolled the user back.
#[derive(Debug, Serialize)]
pub(crate) struct ParkedSagaBody {
    pub(crate) ticket_id: TicketId,
    pub(crate) status: &'static str,
    pub(crate) sub: Option<UserId>,
    pub(crate) message: &'static str,
}

/// Path 3 — 500 Internal. C2 also failed; manual reconciliation required.
#[derive(Debug, Serialize)]
pub(crate) struct CompensationFailedBody {
    pub(crate) ticket_id: TicketId,
    pub(crate) status: &'static str,
    pub(crate) reason: &'static str,
}

/// Path 4 — 409 Conflict. S2 returned `UsernameExists`.
#[derive(Debug, Serialize)]
pub(crate) struct UsernameExistsBody {
    pub(crate) error: &'static str,
    pub(crate) message: &'static str,
}

/// Path 4b — 409 Conflict. S2 returned `AttributeAlreadyExists`. Same wire
/// shape as `UsernameExistsBody` but distinct type so the `error` discriminator
/// can't drift from the struct's documented purpose.
#[derive(Debug, Serialize)]
pub(crate) struct AttributeAlreadyExistsBody {
    pub(crate) error: &'static str,
    pub(crate) message: &'static str,
}

/// Path 5 — 409 Conflict. A different in-flight saga already targets this email.
#[derive(Debug, Serialize)]
pub(crate) struct InFlightSagaBody {
    pub(crate) error: &'static str,
    pub(crate) existing_ticket_id: TicketId,
    pub(crate) message: &'static str,
}

/// Path 6 — 422 Unprocessable Entity body for S1 attribute-validation errors.
#[derive(Debug, Serialize)]
pub(crate) struct ValidationErrorBody {
    pub(crate) errors: Vec<ValidationFieldErrorWire>,
}

/// One field-level entry inside `ValidationErrorBody.errors`.
///
/// Re-projected to a flat wire shape: the schema's `ValidationErrors` uses a
/// tagged `FieldErrorKind` enum, which is friendly for `serde` but produces a
/// nested `reason: { kind, ... }` JSON shape. The flatter shape here gives
/// clients a stable `(field, reason)` pair plus optional `min`/`max` bounds.
#[derive(Debug, Serialize)]
pub(crate) struct ValidationFieldErrorWire {
    pub(crate) field: String,
    pub(crate) reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) min: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max: Option<u32>,
}

/// Path 7 — 502 Bad Gateway body for S2 non-recoverable Cognito errors.
#[derive(Debug, Serialize)]
pub(crate) struct UpstreamErrorBody {
    pub(crate) ticket_id: TicketId,
    pub(crate) error: &'static str,
    pub(crate) message: &'static str,
}

/// Decode a wire `CreateUserPayload` into the domain `CreateUserCommand`.
///
/// Pure wire-to-domain conversion (plan §9 step 2 / §16 sub-commit (d) step 18):
/// parses each raw group name with `GroupName::new`. Returns a 422 response
/// with `reason: "invalid_group_name"` on the first malformed group.
///
/// Membership declaration (`is_declared_group`) and attribute validation
/// (`validate_attributes`) are intentionally NOT done here — both require
/// inputs (store, schema) that live in the imperative shell or are passed
/// separately to keep this function free of borrowed schema references.
#[allow(clippy::result_large_err)] // `Response` *is* the error payload here
pub(crate) fn payload_to_command(
    payload: CreateUserPayload,
) -> Result<CreateUserCommand, Response> {
    let CreateUserPayload {
        email,
        attributes,
        groups,
    } = payload;
    let mut parsed_groups: Vec<GroupName> = Vec::with_capacity(groups.len());
    for raw in groups {
        match GroupName::new(&raw) {
            Ok(name) => parsed_groups.push(name),
            Err(_) => return Err(shape_422_invalid_group_name(&raw)),
        }
    }
    Ok(CreateUserCommand {
        email,
        attributes,
        groups: parsed_groups,
    })
}

/// Project `ValidationErrors` from `authn-core` into the flat wire shape and
/// emit a 422 response.
pub(crate) fn shape_422_validation(errors: &ValidationErrors) -> Response {
    use forgeguard_authn_core::FieldErrorKind;
    let wire: Vec<_> = errors
        .errors
        .iter()
        .map(|e| match e.reason {
            FieldErrorKind::Unknown => ValidationFieldErrorWire {
                field: e.field.clone(),
                reason: "unknown_attribute",
                min: None,
                max: None,
            },
            FieldErrorKind::MissingRequired => ValidationFieldErrorWire {
                field: e.field.clone(),
                reason: "missing_required",
                min: None,
                max: None,
            },
            FieldErrorKind::TooShort { min } => ValidationFieldErrorWire {
                field: e.field.clone(),
                reason: "too_short",
                min: Some(min),
                max: None,
            },
            FieldErrorKind::TooLong { max } => ValidationFieldErrorWire {
                field: e.field.clone(),
                reason: "too_long",
                min: None,
                max: Some(max),
            },
        })
        .collect();
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(ValidationErrorBody { errors: wire }),
    )
        .into_response()
}

/// 422 response for an undeclared group reference (S1 stage 5).
pub(crate) fn shape_422_undeclared_group(group: &str) -> Response {
    shape_422_group_error(format!("groups.{group}"), "undeclared_group")
}

/// 422 response for a malformed group name (`GroupName::new` rejected it).
pub(crate) fn shape_422_invalid_group_name(raw: &str) -> Response {
    shape_422_group_error(format!("groups.{raw}"), "invalid_group_name")
}

fn shape_422_group_error(field: String, reason: &'static str) -> Response {
    let body = ValidationErrorBody {
        errors: vec![ValidationFieldErrorWire {
            field,
            reason,
            min: None,
            max: None,
        }],
    };
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_authn_core::{FieldError, FieldErrorKind};

    use super::*;

    #[test]
    fn parse_payload_groups_default_empty() {
        let payload: CreateUserPayload = serde_json::from_value(serde_json::json!({
            "email": "alice@example.com",
            "attributes": {}
        }))
        .unwrap();
        assert_eq!(payload.email, "alice@example.com");
        assert!(payload.attributes.is_empty());
        assert!(payload.groups.is_empty());
    }

    #[test]
    fn parse_payload_full() {
        let payload: CreateUserPayload = serde_json::from_value(serde_json::json!({
            "email": "alice@example.com",
            "attributes": {"name": "Alice"},
            "groups": ["admin", "eng"]
        }))
        .unwrap();
        assert_eq!(payload.attributes.get("name"), Some(&"Alice".to_string()));
        assert_eq!(payload.groups, vec!["admin", "eng"]);
    }

    #[test]
    fn shape_422_renders_unknown_and_missing() {
        let errors = ValidationErrors {
            errors: vec![
                FieldError {
                    field: "bogus".to_owned(),
                    reason: FieldErrorKind::Unknown,
                },
                FieldError {
                    field: "name".to_owned(),
                    reason: FieldErrorKind::MissingRequired,
                },
            ],
        };
        let response = shape_422_validation(&errors);
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn shape_422_too_short_carries_min() {
        let errors = ValidationErrors {
            errors: vec![FieldError {
                field: "dept".to_owned(),
                reason: FieldErrorKind::TooShort { min: 3 },
            }],
        };
        let response = shape_422_validation(&errors);
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn shape_422_undeclared_group_response_status() {
        let response = shape_422_undeclared_group("admin");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn payload_to_command_parses_valid_groups() {
        let payload = CreateUserPayload {
            email: "alice@example.com".to_owned(),
            attributes: RawAttrMap::new(),
            groups: vec!["admin".to_owned(), "eng".to_owned()],
        };
        let cmd = payload_to_command(payload).expect("valid groups should parse");
        assert_eq!(cmd.email, "alice@example.com");
        assert_eq!(cmd.groups.len(), 2);
    }

    #[test]
    fn payload_to_command_rejects_invalid_group_name() {
        let payload = CreateUserPayload {
            email: "alice@example.com".to_owned(),
            attributes: RawAttrMap::new(),
            groups: vec!["".to_owned()],
        };
        let err = payload_to_command(payload).expect_err("empty group name must reject");
        assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

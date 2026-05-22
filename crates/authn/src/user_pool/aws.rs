//! AWS Cognito-backed `UserPoolClient`.
//!
//! Single seam between the saga driver / xtask seed and the AWS SDK.
//! `map_*_error` helpers classify SDK errors into the four [`UserPoolError`]
//! variants so callers can pattern-match outcomes without inspecting SDK types
//! directly.
//!
//! The "update_user_pool" trait method name predates the realisation that
//! Cognito only supports schema mutations via `AddCustomAttributes`
//! (`UpdateUserPool` cannot touch the `Schema` field). The trait keeps the
//! conceptual name; the implementation uses the correct verb.

use async_trait::async_trait;
use aws_sdk_cognitoidentityprovider::operation::add_custom_attributes::AddCustomAttributesError;
use aws_sdk_cognitoidentityprovider::operation::admin_create_user::AdminCreateUserError;
use aws_sdk_cognitoidentityprovider::operation::admin_delete_user::AdminDeleteUserError;
use aws_sdk_cognitoidentityprovider::operation::admin_get_user::AdminGetUserError;
use aws_sdk_cognitoidentityprovider::types::{
    AttributeType, MessageActionType, SchemaAttributeType,
};
use forgeguard_authn_core::user_pool::{CreateUserParams, PoolId, UpdatePoolParams, UserPoolError};
use forgeguard_authn_core::user_schema::CognitoAttrDef;
use forgeguard_core::UserId;

use crate::user_pool::UserPoolClient;

/// Production `UserPoolClient` backed by AWS Cognito.
#[derive(Debug, Clone)]
pub struct AwsCognitoUserPoolClient {
    client: aws_sdk_cognitoidentityprovider::Client,
}

impl AwsCognitoUserPoolClient {
    pub fn new(client: aws_sdk_cognitoidentityprovider::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl UserPoolClient for AwsCognitoUserPoolClient {
    async fn admin_create_user(&self, params: CreateUserParams) -> Result<UserId, UserPoolError> {
        let mut attrs: Vec<AttributeType> = Vec::with_capacity(params.attributes.len() + 1);
        attrs.push(
            AttributeType::builder()
                .name("email")
                .value(&params.email)
                .build()
                .map_err(|e| UserPoolError::Permanent {
                    source: Box::new(e),
                })?,
        );
        for (name, value) in &params.attributes {
            attrs.push(
                AttributeType::builder()
                    .name(name)
                    .value(value)
                    .build()
                    .map_err(|e| UserPoolError::Permanent {
                        source: Box::new(e),
                    })?,
            );
        }
        let output = self
            .client
            .admin_create_user()
            .user_pool_id(params.pool_id.as_str())
            .username(&params.email)
            .message_action(MessageActionType::Suppress)
            .set_user_attributes(Some(attrs))
            .send()
            .await
            .map_err(map_admin_create_error)?;

        let sub = output
            .user
            .and_then(|u| u.attributes)
            .and_then(|list| {
                list.into_iter()
                    .find(|a| a.name() == "sub")
                    .and_then(|a| a.value)
            })
            .ok_or_else(|| UserPoolError::Permanent {
                source: Box::new(MissingSubAttribute),
            })?;

        UserId::new(&sub).map_err(|e| UserPoolError::Permanent {
            source: Box::new(e),
        })
    }

    async fn admin_delete_user(&self, pool_id: &PoolId, sub: &UserId) -> Result<(), UserPoolError> {
        match self
            .client
            .admin_delete_user()
            .user_pool_id(pool_id.as_str())
            .username(sub.as_str())
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(sdk_err) => match map_admin_delete_error(sdk_err) {
                UserPoolError::UserNotFound => Ok(()),
                other => Err(other),
            },
        }
    }

    async fn admin_get_user(&self, pool_id: &PoolId, email: &str) -> Result<UserId, UserPoolError> {
        let output = self
            .client
            .admin_get_user()
            .user_pool_id(pool_id.as_str())
            .username(email)
            .send()
            .await
            .map_err(map_admin_get_error)?;

        let sub = output
            .user_attributes
            .and_then(|list| {
                list.into_iter()
                    .find(|a| a.name() == "sub")
                    .and_then(|a| a.value)
            })
            .ok_or_else(|| UserPoolError::Permanent {
                source: Box::new(MissingSubAttribute),
            })?;

        UserId::new(&sub).map_err(|e| UserPoolError::Permanent {
            source: Box::new(e),
        })
    }

    async fn update_user_pool(&self, params: UpdatePoolParams) -> Result<(), UserPoolError> {
        let schema_attrs: Vec<SchemaAttributeType> = params
            .schema_attrs
            .iter()
            .map(build_schema_attribute)
            .collect();

        self.client
            .add_custom_attributes()
            .user_pool_id(params.pool_id.as_str())
            .set_custom_attributes(Some(schema_attrs))
            .send()
            .await
            .map_err(map_add_custom_attributes_error)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("cognito response missing required `sub` attribute")]
struct MissingSubAttribute;

fn build_schema_attribute(def: &CognitoAttrDef) -> SchemaAttributeType {
    SchemaAttributeType::builder()
        .name(&def.name)
        .attribute_data_type(def.attribute_data_type.as_str().into())
        .mutable(def.mutable)
        .required(def.required)
        .build()
}

fn map_admin_create_error(
    sdk_err: aws_sdk_cognitoidentityprovider::error::SdkError<AdminCreateUserError>,
) -> UserPoolError {
    use aws_sdk_cognitoidentityprovider::error::SdkError;
    match sdk_err {
        SdkError::ServiceError(svc) => match svc.into_err() {
            AdminCreateUserError::UsernameExistsException(_) => UserPoolError::UsernameExists,
            AdminCreateUserError::TooManyRequestsException(e) => UserPoolError::Transient {
                source: Box::new(e),
            },
            other => UserPoolError::Permanent {
                source: Box::new(other),
            },
        },
        other => transient_or_permanent(other),
    }
}

fn map_admin_delete_error(
    sdk_err: aws_sdk_cognitoidentityprovider::error::SdkError<AdminDeleteUserError>,
) -> UserPoolError {
    use aws_sdk_cognitoidentityprovider::error::SdkError;
    match sdk_err {
        SdkError::ServiceError(svc) => match svc.into_err() {
            AdminDeleteUserError::UserNotFoundException(_) => UserPoolError::UserNotFound,
            AdminDeleteUserError::TooManyRequestsException(e) => UserPoolError::Transient {
                source: Box::new(e),
            },
            other => UserPoolError::Permanent {
                source: Box::new(other),
            },
        },
        other => transient_or_permanent(other),
    }
}

fn map_admin_get_error(
    sdk_err: aws_sdk_cognitoidentityprovider::error::SdkError<AdminGetUserError>,
) -> UserPoolError {
    use aws_sdk_cognitoidentityprovider::error::SdkError;
    match sdk_err {
        SdkError::ServiceError(svc) => match svc.into_err() {
            AdminGetUserError::UserNotFoundException(_) => UserPoolError::UserNotFound,
            AdminGetUserError::TooManyRequestsException(e) => UserPoolError::Transient {
                source: Box::new(e),
            },
            other => UserPoolError::Permanent {
                source: Box::new(other),
            },
        },
        other => transient_or_permanent(other),
    }
}

fn map_add_custom_attributes_error(
    sdk_err: aws_sdk_cognitoidentityprovider::error::SdkError<AddCustomAttributesError>,
) -> UserPoolError {
    use aws_sdk_cognitoidentityprovider::error::SdkError;
    match sdk_err {
        SdkError::ServiceError(svc) => {
            let svc_err = svc.into_err();
            // V3 classifies the "attribute already exists" case; the V4
            // schema-apply path tolerates it as success.
            if let AddCustomAttributesError::InvalidParameterException(ref e) = svc_err {
                let message = e.message.as_deref().unwrap_or_default();
                if message.contains("already exists") {
                    if let Some(name) = parse_existing_attr_name(message) {
                        return UserPoolError::AttributeAlreadyExists { name };
                    }
                }
            }
            match svc_err {
                AddCustomAttributesError::TooManyRequestsException(e) => UserPoolError::Transient {
                    source: Box::new(e),
                },
                other => UserPoolError::Permanent {
                    source: Box::new(other),
                },
            }
        }
        other => transient_or_permanent(other),
    }
}

/// Cognito phrases the duplicate-attribute message inconsistently; this picks
/// up the attribute name when wrapped in single quotes, otherwise returns None
/// so the caller falls through to `Permanent`.
fn parse_existing_attr_name(message: &str) -> Option<String> {
    let start = message.find('\'')?;
    let rest = &message[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_owned())
}

fn transient_or_permanent<E>(
    err: aws_sdk_cognitoidentityprovider::error::SdkError<E>,
) -> UserPoolError
where
    E: std::error::Error + Send + Sync + 'static,
{
    use aws_sdk_cognitoidentityprovider::error::SdkError;
    match err {
        SdkError::TimeoutError(e) => UserPoolError::Transient {
            source: Box::new(TimeoutWrapper(format!("{e:?}"))),
        },
        SdkError::DispatchFailure(e) => UserPoolError::Transient {
            source: Box::new(DispatchFailureWrapper(format!("{e:?}"))),
        },
        SdkError::ResponseError(e) => UserPoolError::Transient {
            source: Box::new(ResponseErrorWrapper(format!("{e:?}"))),
        },
        SdkError::ConstructionFailure(e) => UserPoolError::Permanent {
            source: Box::new(ConstructionErrorWrapper(format!("{e:?}"))),
        },
        SdkError::ServiceError(_) => UserPoolError::Permanent {
            source: Box::new(GenericServiceErrorWrapper),
        },
        _ => UserPoolError::Permanent {
            source: Box::new(UnclassifiedSdkErrorWrapper),
        },
    }
}

// Newtype wrappers preserve diagnostic context across the `Send + Sync + 'static`
// boundary required by `UserPoolError::{Transient,Permanent}.source`. The SDK
// error variants themselves aren't always `'static` (e.g. `TimeoutError`
// doesn't implement `std::error::Error`).
#[derive(Debug, thiserror::Error)]
#[error("cognito SDK timeout: {0}")]
struct TimeoutWrapper(String);

#[derive(Debug, thiserror::Error)]
#[error("cognito SDK dispatch failure: {0}")]
struct DispatchFailureWrapper(String);

#[derive(Debug, thiserror::Error)]
#[error("cognito SDK response error: {0}")]
struct ResponseErrorWrapper(String);

#[derive(Debug, thiserror::Error)]
#[error("cognito SDK construction failure: {0}")]
struct ConstructionErrorWrapper(String);

#[derive(Debug, thiserror::Error)]
#[error("cognito SDK service error (unmapped variant)")]
struct GenericServiceErrorWrapper;

#[derive(Debug, thiserror::Error)]
#[error("cognito SDK error (unclassified variant)")]
struct UnclassifiedSdkErrorWrapper;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_existing_attr_name_quotes() {
        let msg = "Attribute 'custom:role' already exists in pool.";
        assert_eq!(
            parse_existing_attr_name(msg).as_deref(),
            Some("custom:role")
        );
    }

    #[test]
    fn parse_existing_attr_name_no_quotes_returns_none() {
        assert!(parse_existing_attr_name("custom:role already exists").is_none());
    }
}

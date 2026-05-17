#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod chain;
pub mod credential;
pub mod error;
pub mod identity;
pub mod jwt_claims;
pub mod membership;
pub mod resolver;
pub mod saga;
pub mod signing;
pub mod signing_key_store;
pub mod static_api_key;
pub mod user_pool;
pub mod user_schema;

#[cfg(feature = "test-support")]
pub mod builder;

pub use chain::IdentityChain;
pub use credential::Credential;
pub use error::{Error, Result};
pub use identity::{Identity, IdentityParams};
pub use jwt_claims::JwtClaims;
pub use membership::{MembershipRow, MembershipRowParams};
pub use resolver::IdentityResolver;
pub use saga::{
    SagaStage, SagaStatus, SagaTicket, SagaTicketFromStorage, SagaTicketParams, TicketId,
};
pub use signing_key_store::{InMemorySigningKeyStore, SigningKeyStore};
pub use static_api_key::StaticApiKeyResolver;
pub use user_pool::{CreateUserParams, PoolId, UpdatePoolParams, UserPoolError};
pub use user_schema::{
    diff_schema, schema_to_cognito_attrs, validate_attributes, AppendOnlyViolation, AttrType,
    CognitoAttrDef, CognitoStringConstraints, CreateUserCommand, CustomAttrName, CustomAttrSpec,
    FieldError, FieldErrorKind, FieldViolation, RawAttrMap, SchemaDelta, StandardAttrName,
    StandardAttrSpec, UserAttributes, UserSchema, ValidationErrors, ViolationKind,
};

#[cfg(feature = "test-support")]
pub use builder::IdentityBuilder;

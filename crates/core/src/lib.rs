#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod action;
pub mod cedar;
pub mod cedar_ident;
pub mod config_version;
pub mod default_policy;
pub mod error;
pub mod features;
pub mod fgrn;
pub mod org;
pub mod percentage;
pub mod permission;
pub mod saga_id;
pub mod segment;

pub use action::{
    Action, Entity, Namespace, PrincipalKind, PrincipalRef, QualifiedAction, ResourceId,
    ResourceRef,
};
pub use cedar::{
    compile_all_to_cedar, compile_policy_to_cedar, generate_cedar_schema, CedarAttributeType,
    EntitySchemaConfig,
};
pub use cedar_ident::{CedarEntityType, CedarIdent, CedarNamespace};
pub use config_version::ConfigVersion;
pub use default_policy::DefaultPolicy;
pub use error::{Error, Result};
pub use features::{
    evaluate_flags, evaluate_flags_detailed, DetailedResolvedFlags, FlagConfig, FlagDefinition,
    FlagDefinitionParams, FlagName, FlagOverride, FlagType, FlagValue, ResolutionReason,
    ResolvedFlag, ResolvedFlags,
};
pub use fgrn::{Fgrn, FgrnSegment};
pub use org::{OrgStatus, Organization};
pub use percentage::Percentage;
pub use permission::{
    ActionPattern, CedarEntityRef, Effect, GroupDefinition, PatternSegment, Policy,
    PolicyStatement, ResourceConstraint,
};
pub use saga_id::SagaId;
pub use segment::{
    FlowId, GroupName, OrganizationId, PolicyName, ProjectId, Segment, TenantId, UserId,
};

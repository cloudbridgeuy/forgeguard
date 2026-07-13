#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod action;
pub mod anchored_resource;
pub mod cedar;
pub mod cedar_ident;
pub mod config_version;
pub mod default_policy;
pub mod delegation;
pub mod error;
pub mod features;
pub mod fgrn;
pub mod grant;
pub mod native_id;
pub mod org;
pub mod percentage;
pub mod permission;
pub mod principal;
pub mod principal_set;
pub mod promotion;
pub mod resource_type;
pub mod saga_id;
pub mod segment;
pub mod selector;
pub mod spine;
pub mod verb;
pub mod visibility;
pub mod vp_fgrn;

pub use action::{
    Action, Entity, Namespace, PrincipalKind, PrincipalRef, QualifiedAction, ResourceId,
    ResourceOrgSource, ResourceRef,
};
pub use anchored_resource::AnchoredResource;
pub use cedar::{
    compile_all_to_cedar, compile_policy_to_cedar, generate_cedar_schema, CedarAttributeType,
    EntitySchemaConfig,
};
pub use cedar_ident::{CedarEntityType, CedarIdent, CedarNamespace};
pub use config_version::ConfigVersion;
pub use default_policy::DefaultPolicy;
pub use delegation::{effective_verbs, DelegationChain, EffectiveScopeQuery};
pub use error::{Error, Result};
pub use features::{
    evaluate_flags, evaluate_flags_detailed, DetailedResolvedFlags, FlagConfig, FlagDefinition,
    FlagDefinitionParams, FlagName, FlagOverride, FlagType, FlagValue, ResolutionReason,
    ResolvedFlag, ResolvedFlags,
};
pub use fgrn::{Fgrn, FgrnKind};
pub use grant::Grant;
pub use native_id::NativeId;
pub use org::{OrgStatus, Organization};
pub use percentage::Percentage;
pub use permission::{
    ActionPattern, CedarEntityRef, Effect, GroupDefinition, PatternSegment, Policy,
    PolicyStatement, ResourceConstraint,
};
pub use principal::Principal;
pub use principal_set::PrincipalSet;
pub use promotion::{share, PromotedResource, ShareRequest};
pub use resource_type::{Anchoring, ResourceTypeDecl, UserBoundary};
pub use saga_id::SagaId;
pub use segment::{
    FlowId, GroupName, OrganizationId, PolicyName, ProjectId, Segment, TenantId, UserId,
};
pub use selector::{Selector, SelectorScope};
pub use spine::{OrgUnit, Spine};
pub use verb::Verb;
pub use visibility::{subtree_visible, ResolvedAnchor, VisibilityQuery};
pub use vp_fgrn::{FgrnSegment, VpFgrn};

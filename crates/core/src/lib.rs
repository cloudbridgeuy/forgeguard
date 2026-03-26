#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod action;
pub mod cedar;
pub mod error;
pub mod features;
pub mod fgrn;
pub mod permission;
pub mod segment;

pub use action::{
    Action, Entity, Namespace, PrincipalRef, QualifiedAction, ResourceId, ResourceRef,
};
pub use cedar::{compile_all_to_cedar, compile_policy_to_cedar};
pub use error::{Error, Result};
pub use features::{
    evaluate_flags, evaluate_flags_detailed, DetailedResolvedFlags, FlagConfig, FlagDefinition,
    FlagName, FlagOverride, FlagType, FlagValue, ResolutionReason, ResolvedFlag, ResolvedFlags,
};
pub use fgrn::{Fgrn, FgrnSegment};
pub use permission::{
    ActionPattern, CedarEntityRef, Effect, GroupDefinition, PatternSegment, Policy,
    PolicyStatement, ResourceConstraint,
};
pub use segment::{FlowId, GroupName, PolicyName, ProjectId, Segment, TenantId, UserId};

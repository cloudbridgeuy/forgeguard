//! Permission model types for the ForgeGuard authorization system.
//!
//! These types represent policies, groups, effects, action patterns, and
//! Cedar entity references used in the permission evaluation pipeline.

use std::fmt;

use serde::de::Deserializer;
use serde::Deserialize;

use crate::{Error, GroupName, PolicyName, QualifiedAction, Result, Segment};

// ---------------------------------------------------------------------------
// Effect
// ---------------------------------------------------------------------------

/// Whether a policy statement allows or denies the matched actions.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

// ---------------------------------------------------------------------------
// PatternSegment
// ---------------------------------------------------------------------------

/// A single segment in an action pattern: either an exact match or a wildcard.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum PatternSegment {
    Exact(Segment),
    Wildcard,
}

impl PatternSegment {
    /// Does this pattern segment match the given concrete segment?
    pub fn matches(&self, segment: &Segment) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Exact(s) => s == segment,
        }
    }
}

// ---------------------------------------------------------------------------
// ActionPattern
// ---------------------------------------------------------------------------

/// A pattern that matches qualified actions. Each of the three positions
/// (namespace, entity, action) can be an exact segment or a wildcard (`*`).
///
/// Format: `"namespace:entity:action"` where any part can be `*`.
///
/// Examples: `"todo:list:read"`, `"todo:*:*"`, `"*:*:*"`
#[derive(Debug, Clone)]
pub struct ActionPattern {
    namespace: PatternSegment,
    action: PatternSegment,
    entity: PatternSegment,
}

/// Parse a single segment of an action pattern: `*` becomes `Wildcard`,
/// anything else is validated as a `Segment`.
fn parse_pattern_segment(s: &str) -> Result<PatternSegment> {
    if s == "*" {
        Ok(PatternSegment::Wildcard)
    } else {
        Ok(PatternSegment::Exact(Segment::try_new(s)?))
    }
}

impl ActionPattern {
    /// Parse an action pattern from the canonical format: `"namespace:entity:action"`.
    /// Each segment may be `*` (wildcard) or a valid [`Segment`].
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(4, ':').collect();
        match parts.as_slice() {
            [ns, entity, action] => Ok(Self {
                namespace: parse_pattern_segment(ns)?,
                action: parse_pattern_segment(action)?,
                entity: parse_pattern_segment(entity)?,
            }),
            _ => Err(Error::Parse {
                field: "action_pattern",
                value: s.to_string(),
                reason: "expected namespace:entity:action (e.g., 'todo:list:read' or 'todo:*:*')",
            }),
        }
    }

    /// Borrow the namespace segment of this pattern.
    pub fn namespace(&self) -> &PatternSegment {
        &self.namespace
    }

    /// Borrow the action segment of this pattern.
    pub fn action(&self) -> &PatternSegment {
        &self.action
    }

    /// Borrow the entity segment of this pattern.
    pub fn entity(&self) -> &PatternSegment {
        &self.entity
    }

    /// Does this pattern match the given qualified action?
    pub fn matches(&self, action: &QualifiedAction) -> bool {
        self.namespace.matches(action.namespace().as_segment())
            && self.action.matches(action.action().as_segment())
            && self.entity.matches(action.entity().as_segment())
    }
}

impl<'de> Deserialize<'de> for ActionPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// CedarEntityRef
// ---------------------------------------------------------------------------

/// A reference to a Cedar entity in the format `"namespace::entity::id"`.
///
/// All three components are validated [`Segment`] values.
/// Parse Don't Validate: if you hold a `CedarEntityRef`, every component is
/// guaranteed valid.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CedarEntityRef {
    namespace: Segment,
    entity: Segment,
    id: Segment,
}

impl CedarEntityRef {
    /// Parse from the canonical format: `"namespace::entity::id"`.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split("::").collect();
        match parts.as_slice() {
            [ns, entity, id] => Ok(Self {
                namespace: Segment::try_new(*ns)?,
                entity: Segment::try_new(*entity)?,
                id: Segment::try_new(*id)?,
            }),
            _ => Err(Error::Parse {
                field: "cedar_entity_ref",
                value: s.to_string(),
                reason: "expected namespace::entity::id (e.g., 'todo::list::top-secret')",
            }),
        }
    }

    /// Borrow the namespace segment.
    pub fn namespace(&self) -> &Segment {
        &self.namespace
    }

    /// Borrow the entity segment.
    pub fn entity(&self) -> &Segment {
        &self.entity
    }

    /// Borrow the id segment.
    pub fn id(&self) -> &Segment {
        &self.id
    }

    /// The Cedar string representation: `"namespace::entity::id"`.
    pub fn as_cedar_str(&self) -> String {
        format!("{}::{}::{}", self.namespace, self.entity, self.id)
    }
}

impl fmt::Display for CedarEntityRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", self.namespace, self.entity, self.id)
    }
}

impl<'de> Deserialize<'de> for CedarEntityRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// ResourceConstraint
// ---------------------------------------------------------------------------

/// Constraint on which resources a policy statement applies to.
/// `All` means no restriction (the default when the field is absent).
/// `Specific` lists concrete Cedar entity references.
#[derive(Debug, Clone, Default)]
pub enum ResourceConstraint {
    #[default]
    All,
    Specific(Vec<CedarEntityRef>),
}

impl<'de> Deserialize<'de> for ResourceConstraint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let refs = Vec::<CedarEntityRef>::deserialize(deserializer)?;
        if refs.is_empty() {
            Ok(Self::All)
        } else {
            Ok(Self::Specific(refs))
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyStatement
// ---------------------------------------------------------------------------

/// A single statement within a policy: effect + actions + optional resource
/// constraint + optional group exceptions.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyStatement {
    effect: Effect,
    actions: Vec<ActionPattern>,
    #[serde(default)]
    resources: ResourceConstraint,
    #[serde(default)]
    except: Vec<GroupName>,
}

impl PolicyStatement {
    /// The effect of this statement (allow or deny).
    pub fn effect(&self) -> Effect {
        self.effect
    }

    /// The action patterns this statement applies to.
    pub fn actions(&self) -> &[ActionPattern] {
        &self.actions
    }

    /// The resource constraint for this statement.
    pub fn resources(&self) -> &ResourceConstraint {
        &self.resources
    }

    /// Groups excepted from this statement.
    pub fn except(&self) -> &[GroupName] {
        &self.except
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// A named collection of policy statements that optionally belongs to one or
/// more groups.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    name: PolicyName,
    #[serde(default)]
    description: Option<String>,
    statements: Vec<PolicyStatement>,
    #[serde(default)]
    groups: Vec<GroupName>,
}

impl Policy {
    /// The policy name.
    pub fn name(&self) -> &PolicyName {
        &self.name
    }

    /// Optional description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The statements in this policy.
    pub fn statements(&self) -> &[PolicyStatement] {
        &self.statements
    }

    /// The groups this policy belongs to.
    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }
}

// ---------------------------------------------------------------------------
// GroupDefinition
// ---------------------------------------------------------------------------

/// A named group with optional description and member groups. Policies declare
/// which groups they belong to via [`Policy::groups`]; this struct carries only
/// group metadata and nesting.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupDefinition {
    name: GroupName,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    member_groups: Vec<GroupName>,
}

impl GroupDefinition {
    /// The group name.
    pub fn name(&self) -> &GroupName {
        &self.name
    }

    /// Optional description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Other groups that are members of this group.
    pub fn member_groups(&self) -> &[GroupName] {
        &self.member_groups
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- ActionPattern::parse ------------------------------------------------

    #[test]
    fn action_pattern_parse_all_exact() {
        let ap = ActionPattern::parse("todo:list:read").unwrap();
        assert!(matches!(ap.namespace, PatternSegment::Exact(_)));
        assert!(matches!(ap.action, PatternSegment::Exact(_)));
        assert!(matches!(ap.entity, PatternSegment::Exact(_)));
    }

    #[test]
    fn action_pattern_parse_namespace_exact_rest_wildcard() {
        let ap = ActionPattern::parse("todo:*:*").unwrap();
        assert!(matches!(ap.namespace, PatternSegment::Exact(_)));
        assert!(matches!(ap.action, PatternSegment::Wildcard));
        assert!(matches!(ap.entity, PatternSegment::Wildcard));
    }

    #[test]
    fn action_pattern_parse_all_wildcard() {
        let ap = ActionPattern::parse("*:*:*").unwrap();
        assert!(matches!(ap.namespace, PatternSegment::Wildcard));
        assert!(matches!(ap.action, PatternSegment::Wildcard));
        assert!(matches!(ap.entity, PatternSegment::Wildcard));
    }

    #[test]
    fn action_pattern_parse_two_segments_error() {
        assert!(ActionPattern::parse("todo:read").is_err());
    }

    // -- ActionPattern::matches ----------------------------------------------

    #[test]
    fn action_pattern_matches_namespace_wildcard() {
        let ap = ActionPattern::parse("todo:*:*").unwrap();
        let qa_todo = QualifiedAction::parse("todo:list:read").unwrap();
        let qa_billing = QualifiedAction::parse("billing:invoice:read").unwrap();
        assert!(ap.matches(&qa_todo));
        assert!(!ap.matches(&qa_billing));
    }

    #[test]
    fn action_pattern_matches_action_wildcard() {
        let ap = ActionPattern::parse("*:*:read").unwrap();
        let qa_read = QualifiedAction::parse("todo:list:read").unwrap();
        let qa_delete = QualifiedAction::parse("todo:item:delete").unwrap();
        assert!(ap.matches(&qa_read));
        assert!(!ap.matches(&qa_delete));
    }

    // -- Effect serde --------------------------------------------------------

    #[test]
    fn effect_serde_allow() {
        let e: Effect = serde_json::from_str("\"allow\"").unwrap();
        assert_eq!(e, Effect::Allow);
    }

    #[test]
    fn effect_serde_deny() {
        let e: Effect = serde_json::from_str("\"deny\"").unwrap();
        assert_eq!(e, Effect::Deny);
    }

    #[test]
    fn effect_serde_uppercase_fails() {
        assert!(serde_json::from_str::<Effect>("\"ALLOW\"").is_err());
    }

    #[test]
    fn effect_serde_permit_fails() {
        assert!(serde_json::from_str::<Effect>("\"permit\"").is_err());
    }

    // -- CedarEntityRef ------------------------------------------------------

    #[test]
    fn cedar_entity_ref_parse_valid() {
        let cer = CedarEntityRef::parse("todo::list::top-secret").unwrap();
        assert_eq!(cer.namespace().as_str(), "todo");
        assert_eq!(cer.entity().as_str(), "list");
        assert_eq!(cer.id().as_str(), "top-secret");
    }

    #[test]
    fn cedar_entity_ref_parse_missing_id() {
        assert!(CedarEntityRef::parse("todo::list").is_err());
    }

    #[test]
    fn cedar_entity_ref_parse_uppercase() {
        assert!(CedarEntityRef::parse("Todo::List::TopSecret").is_err());
    }

    #[test]
    fn cedar_entity_ref_display_round_trip() {
        let cer = CedarEntityRef::parse("todo::list::top-secret").unwrap();
        let display = cer.to_string();
        let parsed = CedarEntityRef::parse(&display).unwrap();
        assert_eq!(cer, parsed);
    }

    #[test]
    fn cedar_entity_ref_serde_round_trip() {
        let cer = CedarEntityRef::parse("todo::list::top-secret").unwrap();
        let json = serde_json::to_string(&cer.to_string()).unwrap();
        let deser: CedarEntityRef = serde_json::from_str(&json).unwrap();
        assert_eq!(cer, deser);
    }

    #[test]
    fn cedar_entity_ref_as_cedar_str() {
        let cer = CedarEntityRef::parse("todo::list::top-secret").unwrap();
        assert_eq!(cer.as_cedar_str(), "todo::list::top-secret");
    }

    // -- ResourceConstraint --------------------------------------------------

    #[test]
    fn resource_constraint_default_is_all() {
        let rc = ResourceConstraint::default();
        assert!(matches!(rc, ResourceConstraint::All));
    }

    // -- PolicyStatement serde -----------------------------------------------

    #[test]
    fn policy_statement_deny_with_except_deserializes() {
        let json = r#"{
            "effect": "deny",
            "actions": ["todo:*:delete"],
            "except": ["admin"]
        }"#;
        let stmt: PolicyStatement = serde_json::from_str(json).unwrap();
        assert_eq!(stmt.effect(), Effect::Deny);
        assert_eq!(stmt.actions().len(), 1);
        assert!(matches!(stmt.resources(), ResourceConstraint::All));
        assert_eq!(stmt.except().len(), 1);
        assert_eq!(stmt.except()[0].as_str(), "admin");
    }

    // -- Policy serde --------------------------------------------------------

    #[test]
    fn policy_with_groups_deserializes() {
        let json = r#"{
            "name": "todo-read",
            "description": "Read-only access to todos",
            "statements": [
                { "effect": "allow", "actions": ["todo:*:read"] }
            ],
            "groups": ["viewer", "editor"]
        }"#;
        let p: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(p.name().as_str(), "todo-read");
        assert_eq!(p.description(), Some("Read-only access to todos"));
        assert_eq!(p.statements().len(), 1);
        assert_eq!(p.groups().len(), 2);
        assert_eq!(p.groups()[0].as_str(), "viewer");
        assert_eq!(p.groups()[1].as_str(), "editor");
    }

    #[test]
    fn policy_without_groups_defaults_to_empty() {
        let json = r#"{
            "name": "todo-read",
            "statements": [
                { "effect": "allow", "actions": ["todo:*:read"] }
            ]
        }"#;
        let p: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(p.name().as_str(), "todo-read");
        assert!(p.description().is_none());
        assert!(p.groups().is_empty());
    }

    // -- GroupDefinition serde -----------------------------------------------

    #[test]
    fn group_definition_with_member_groups_deserializes() {
        let json = r#"{
            "name": "super-admin",
            "description": "Full access group",
            "member_groups": ["admin", "ops"]
        }"#;
        let gd: GroupDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(gd.name().as_str(), "super-admin");
        assert_eq!(gd.description(), Some("Full access group"));
        assert_eq!(gd.member_groups().len(), 2);
        assert_eq!(gd.member_groups()[0].as_str(), "admin");
        assert_eq!(gd.member_groups()[1].as_str(), "ops");
    }
}

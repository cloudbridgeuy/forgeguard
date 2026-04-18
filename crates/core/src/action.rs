//! Action vocabulary types for the ForgeGuard authorization model.
//!
//! These types represent the three-part action format: `namespace:entity:action`.
//! All components are validated [`Segment`] values (lowercase, kebab-case).

use std::fmt;
use std::hash::{Hash, Hasher};

use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::fgrn::known_segments;
use crate::{
    CedarEntityType, CedarNamespace, Error, Fgrn, ProjectId, Result, Segment, TenantId, UserId,
};

// ---------------------------------------------------------------------------
// Namespace
// ---------------------------------------------------------------------------

const RESERVED_NAMESPACES: &[&str] = &["iam", "forgeguard"];

/// A namespace within a project. Groups related resources and actions.
/// The customer's domain organizing principle.
///
/// Reserved namespaces:
///   "iam"        — user, group, role entities (identity primitives)
///   "forgeguard" — policy, feature-flag, webhook entities (system internals)
///
/// Customer namespaces must be valid Segment values and cannot use reserved names.
#[derive(Debug, Clone)]
pub struct Namespace(NamespaceInner);

#[derive(Debug, Clone)]
enum NamespaceInner {
    User(Segment),
    Reserved(Segment),
}

impl Namespace {
    /// Parse a user-provided namespace. Rejects reserved names.
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if RESERVED_NAMESPACES.contains(&s.as_str()) {
            return Err(Error::Parse {
                field: "namespace",
                value: s,
                reason: "reserved namespace — 'iam' and 'forgeguard' cannot be used by customers",
            });
        }
        Ok(Self(NamespaceInner::User(Segment::try_new(s)?)))
    }

    /// The iam namespace where user and group entities live.
    pub fn iam() -> Self {
        Self(NamespaceInner::Reserved(known_segments::IAM.clone()))
    }

    /// The forgeguard namespace where policy, feature-flag, webhook entities live.
    pub fn forgeguard() -> Self {
        Self(NamespaceInner::Reserved(known_segments::FORGEGUARD.clone()))
    }

    /// Borrow the inner segment.
    pub fn as_segment(&self) -> &Segment {
        match &self.0 {
            NamespaceInner::User(seg) | NamespaceInner::Reserved(seg) => seg,
        }
    }

    /// Whether this is a reserved (system) namespace.
    pub fn is_reserved(&self) -> bool {
        matches!(self.0, NamespaceInner::Reserved(_))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        self.as_segment().as_str()
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_segment(), f)
    }
}

impl PartialEq for Namespace {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Namespace {}

impl Hash for Namespace {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl Serialize for Namespace {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Namespace {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// An action verb. Kebab-case — any verb the developer wants.
/// e.g., "read", "create", "force-delete", "bulk-export", "countersign"
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Action(Segment);

impl Action {
    /// Parse and validate an action verb.
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        Ok(Self(Segment::try_new(s)?))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Borrow the inner segment.
    pub fn as_segment(&self) -> &Segment {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Entity
// ---------------------------------------------------------------------------

/// A resource/entity type. Kebab-case.
/// e.g., "invoice", "payment-tracker", "shipping-label"
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Entity(Segment);

impl Entity {
    /// Parse and validate an entity type.
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        Ok(Self(Segment::try_new(s)?))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Borrow the inner segment.
    pub fn as_segment(&self) -> &Segment {
        &self.0
    }

    /// Cedar entity type: "billing::invoice"
    pub fn cedar_entity_type(&self, ns: &Namespace) -> String {
        format!("{}::{}", ns.as_str(), self.as_str())
    }
}

// ---------------------------------------------------------------------------
// QualifiedAction
// ---------------------------------------------------------------------------

/// A fully qualified action: namespace:entity:action
///
/// ForgeGuard:  "todo:list:read"
/// Cedar maps:  namespace=todo, action="read-list", entity=todo::list
///
/// Three explicit segments — no parsing heuristics to split verb from entity.
/// If you hold a `QualifiedAction`, every component is guaranteed valid.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct QualifiedAction {
    namespace: Namespace,
    action: Action,
    entity: Entity,
}

impl QualifiedAction {
    /// Construct from already-parsed parts. No validation — types carry the proof.
    pub fn new(namespace: Namespace, action: Action, entity: Entity) -> Self {
        Self {
            namespace,
            action,
            entity,
        }
    }

    /// Parse from the canonical format: "todo:list:read" (namespace:entity:action)
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(4, ':').collect();
        match parts.as_slice() {
            [ns, entity, action] => Ok(Self {
                namespace: Namespace::parse(*ns)?,
                action: Action::parse(*action)?,
                entity: Entity::parse(*entity)?,
            }),
            _ => Err(Error::Parse {
                field: "qualified_action",
                value: s.to_string(),
                reason: "expected namespace:entity:action (e.g., 'todo:list:read')",
            }),
        }
    }

    /// Borrow the namespace.
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// Borrow the action.
    pub fn action(&self) -> &Action {
        &self.action
    }

    /// Borrow the entity.
    pub fn entity(&self) -> &Entity {
        &self.entity
    }

    /// Verified Permissions `IsAuthorized`: actionType — e.g. "todo_app::Action"
    ///
    /// Uses the VP namespace derived from the project ID, not the ForgeGuard namespace.
    pub fn vp_action_type(&self, project: &ProjectId) -> String {
        let ns = CedarNamespace::from_project(project);
        format!("{}::Action", ns.as_str())
    }

    /// Verified Permissions `IsAuthorized`: actionId — "todo-list-read" (namespace-entity-action)
    ///
    /// Includes the ForgeGuard namespace to disambiguate actions with the same
    /// entity-verb pair across different namespaces (e.g., `todo:list:read` vs
    /// `shopping:list:read`).
    pub fn vp_action_id(&self) -> String {
        format!(
            "{}-{}-{}",
            self.namespace.as_str(),
            self.entity.as_str(),
            self.action.as_str()
        )
    }

    /// Cedar action reference: `todo_app::Action::"todo-list-read"`
    ///
    /// Uses the VP namespace derived from the project ID.
    pub fn cedar_action_ref(&self, project: &ProjectId) -> String {
        let ns = CedarNamespace::from_project(project);
        format!("{}::Action::\"{}\"", ns.as_str(), self.vp_action_id())
    }

    /// VP entity type for the resource: e.g. "todo_app::todo__list"
    ///
    /// Uses the VP namespace and CedarEntityType format.
    pub fn vp_entity_type(&self, project: &ProjectId) -> String {
        let ns = CedarNamespace::from_project(project);
        let entity_type = CedarEntityType::new(&self.namespace, &self.entity);
        format!("{}::{}", ns.as_str(), entity_type)
    }
}

impl fmt::Display for QualifiedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.namespace.as_str(),
            self.entity.as_str(),
            self.action.as_str()
        )
    }
}

impl Serialize for QualifiedAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for QualifiedAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// ResourceId
// ---------------------------------------------------------------------------

/// A validated, non-empty resource ID. Built on Segment (kebab-case).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ResourceId(Segment);

impl ResourceId {
    /// Parse and validate a resource ID.
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        Ok(Self(Segment::try_new(s)?))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Borrow the inner segment.
    pub fn as_segment(&self) -> &Segment {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// ResourceRef
// ---------------------------------------------------------------------------

/// A concrete resource instance for authorization checks.
/// Constructed from a `QualifiedAction` (namespace + entity) + extracted path param.
#[derive(Debug, Clone)]
pub struct ResourceRef {
    namespace: Namespace,
    entity: Entity,
    id: ResourceId,
    /// Optional Cedar entity type override. When set, `vp_entity_type` uses
    /// this directly instead of deriving from `namespace`/`entity`.
    cedar_entity_type: Option<String>,
}

impl ResourceRef {
    /// Construct from a matched route's action + extracted resource ID.
    /// No validation needed — `QualifiedAction` and `ResourceId` carry the proof.
    pub fn from_route(action: &QualifiedAction, id: ResourceId) -> Self {
        Self {
            namespace: action.namespace().clone(),
            entity: action.entity().clone(),
            id,
            cedar_entity_type: None,
        }
    }

    /// Construct with an explicit Cedar entity type override.
    pub fn from_route_with_entity_type(
        action: &QualifiedAction,
        id: ResourceId,
        cedar_entity_type: String,
    ) -> Self {
        Self {
            namespace: action.namespace().clone(),
            entity: action.entity().clone(),
            id,
            cedar_entity_type: Some(cedar_entity_type),
        }
    }

    /// Verified Permissions entity type: e.g. "todo_app::Organization"
    ///
    /// When a Cedar entity type override is set, uses it directly prefixed
    /// with the VP namespace. Otherwise derives from namespace/entity segments.
    pub fn vp_entity_type(&self, project: &ProjectId) -> String {
        let ns = CedarNamespace::from_project(project);
        match &self.cedar_entity_type {
            Some(override_type) => format!("{}::{}", ns.as_str(), override_type),
            None => {
                let entity_type = CedarEntityType::new(&self.namespace, &self.entity);
                format!("{}::{}", ns.as_str(), entity_type)
            }
        }
    }

    /// Build the FGRN for this resource. Used as the Verified Permissions entity ID.
    /// Requires tenant because FGRNs include the tenant segment.
    pub fn to_fgrn(&self, project: &ProjectId, tenant: &TenantId) -> Fgrn {
        Fgrn::resource(project, tenant, &self.namespace, &self.entity, &self.id)
    }

    /// Borrow the namespace.
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// Borrow the entity.
    pub fn entity(&self) -> &Entity {
        &self.entity
    }

    /// Borrow the resource ID.
    pub fn id(&self) -> &ResourceId {
        &self.id
    }
}

impl fmt::Display for ResourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.namespace.as_str(),
            self.entity.as_str(),
            self.id.as_str()
        )
    }
}

// ---------------------------------------------------------------------------
// PrincipalKind
// ---------------------------------------------------------------------------

/// Distinguishes human users from machine principals (service accounts / API keys).
///
/// Drives Cedar entity type selection:
/// - `User`    → `{ns}::User`
/// - `Machine` → `{ns}::Machine`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    /// A human user identity (default).
    #[default]
    User,
    /// A machine identity — service account or Ed25519-signed API key.
    Machine,
}

// ---------------------------------------------------------------------------
// PrincipalRef
// ---------------------------------------------------------------------------

/// Principal reference — carries either a human user or a machine identity.
#[derive(Debug)]
pub struct PrincipalRef {
    user_id: UserId,
    kind: PrincipalKind,
}

impl PrincipalRef {
    /// Wrap a user ID as a human principal reference (default kind: `User`).
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            kind: PrincipalKind::User,
        }
    }

    /// Wrap a user ID as a machine principal reference (kind: `Machine`).
    pub fn machine(user_id: UserId) -> Self {
        Self {
            user_id,
            kind: PrincipalKind::Machine,
        }
    }

    /// Borrow the user ID.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The kind of this principal.
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// Verified Permissions entity type for this principal.
    ///
    /// - `User`    → `"{ns}::User"`    e.g. `"todo_app::User"`
    /// - `Machine` → `"{ns}::Machine"` e.g. `"todo_app::Machine"`
    ///
    /// Uses the VP namespace derived from the project ID.
    pub fn vp_entity_type(&self, project: &ProjectId) -> String {
        let ns = CedarNamespace::from_project(project);
        match self.kind {
            PrincipalKind::User => format!("{}::User", ns.as_str()),
            PrincipalKind::Machine => format!("{}::Machine", ns.as_str()),
        }
    }

    /// VP group entity type: e.g. "todo_app::Group"
    ///
    /// Uses the VP namespace derived from the project ID.
    pub fn vp_group_entity_type(project: &ProjectId) -> String {
        let ns = CedarNamespace::from_project(project);
        format!("{}::Group", ns.as_str())
    }

    /// Build the FGRN for this principal. Used as the Verified Permissions entity ID.
    /// Requires tenant because FGRNs include the tenant segment.
    ///
    /// - `User`    → `fgrn:<project>:<tenant>:iam:user:<user_id>`
    /// - `Machine` → `fgrn:<project>:<tenant>:iam:machine:<user_id>`
    pub fn to_fgrn(&self, project: &ProjectId, tenant: &TenantId) -> Fgrn {
        match self.kind {
            PrincipalKind::User => Fgrn::user(project, tenant, &self.user_id),
            PrincipalKind::Machine => Fgrn::machine(project, tenant, &self.user_id),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- Namespace -----------------------------------------------------------

    #[test]
    fn namespace_parse_valid() {
        assert!(Namespace::parse("todo").is_ok());
    }

    #[test]
    fn namespace_rejects_iam() {
        assert!(Namespace::parse("iam").is_err());
    }

    #[test]
    fn namespace_rejects_forgeguard() {
        assert!(Namespace::parse("forgeguard").is_err());
    }

    #[test]
    fn namespace_rejects_empty() {
        assert!(Namespace::parse("").is_err());
    }

    #[test]
    fn namespace_rejects_uppercase() {
        assert!(Namespace::parse("Todo").is_err());
    }

    #[test]
    fn namespace_iam_is_reserved() {
        assert!(Namespace::iam().is_reserved());
    }

    #[test]
    fn namespace_forgeguard_is_reserved() {
        assert!(Namespace::forgeguard().is_reserved());
    }

    #[test]
    fn namespace_user_is_not_reserved() {
        assert!(!Namespace::parse("todo").unwrap().is_reserved());
    }

    // -- Action --------------------------------------------------------------

    #[test]
    fn action_parse_valid() {
        assert!(Action::parse("read").is_ok());
        assert!(Action::parse("force-delete").is_ok());
        assert!(Action::parse("bulk-export").is_ok());
    }

    #[test]
    fn action_rejects_uppercase() {
        assert!(Action::parse("Read").is_err());
    }

    #[test]
    fn action_rejects_empty() {
        assert!(Action::parse("").is_err());
    }

    #[test]
    fn action_rejects_underscore() {
        assert!(Action::parse("force_delete").is_err());
    }

    // -- Entity --------------------------------------------------------------

    #[test]
    fn entity_parse_valid() {
        assert!(Entity::parse("invoice").is_ok());
        assert!(Entity::parse("payment-tracker").is_ok());
    }

    #[test]
    fn entity_rejects_uppercase() {
        assert!(Entity::parse("Invoice").is_err());
    }

    // -- QualifiedAction -----------------------------------------------------

    #[test]
    fn qualified_action_parse_valid() {
        let qa = QualifiedAction::parse("todo:list:read").unwrap();
        assert_eq!(qa.namespace().as_str(), "todo");
        assert_eq!(qa.entity().as_str(), "list");
        assert_eq!(qa.action().as_str(), "read");
    }

    #[test]
    fn qualified_action_parse_complex() {
        let qa = QualifiedAction::parse("billing:payment-tracker:force-delete").unwrap();
        assert_eq!(qa.namespace().as_str(), "billing");
        assert_eq!(qa.entity().as_str(), "payment-tracker");
        assert_eq!(qa.action().as_str(), "force-delete");
    }

    #[test]
    fn qualified_action_parse_two_segments_error() {
        assert!(QualifiedAction::parse("s3:get-object").is_err());
    }

    #[test]
    fn qualified_action_parse_uppercase_error() {
        assert!(QualifiedAction::parse("Todo:Read:List").is_err());
    }

    #[test]
    fn qualified_action_parse_empty_error() {
        assert!(QualifiedAction::parse("").is_err());
    }

    fn test_project() -> ProjectId {
        ProjectId::new("todo-app").unwrap()
    }

    #[test]
    fn vp_action_type() {
        let qa = QualifiedAction::parse("todo:list:read").unwrap();
        assert_eq!(qa.vp_action_type(&test_project()), "todo_app::Action");
    }

    #[test]
    fn vp_action_id() {
        let qa = QualifiedAction::parse("todo:list:read").unwrap();
        assert_eq!(qa.vp_action_id(), "todo-list-read");
    }

    #[test]
    fn cedar_action_ref() {
        let qa = QualifiedAction::parse("todo:list:read").unwrap();
        assert_eq!(
            qa.cedar_action_ref(&test_project()),
            "todo_app::Action::\"todo-list-read\""
        );
    }

    #[test]
    fn vp_entity_type_on_action() {
        let qa = QualifiedAction::parse("todo:list:read").unwrap();
        assert_eq!(qa.vp_entity_type(&test_project()), "todo_app::todo__list");
    }

    #[test]
    fn qualified_action_display() {
        let qa = QualifiedAction::parse("todo:list:read").unwrap();
        assert_eq!(qa.to_string(), "todo:list:read");
    }

    #[test]
    fn qualified_action_serde_round_trip() {
        let qa = QualifiedAction::parse("todo:list:read").unwrap();
        let json = serde_json::to_string(&qa).unwrap();
        assert_eq!(json, "\"todo:list:read\"");
        let deser: QualifiedAction = serde_json::from_str(&json).unwrap();
        assert_eq!(qa, deser);
    }

    // -- ResourceId ----------------------------------------------------------

    #[test]
    fn resource_id_parse_empty_error() {
        assert!(ResourceId::parse("").is_err());
    }

    #[test]
    fn resource_id_parse_valid() {
        assert!(ResourceId::parse("list-123").is_ok());
    }

    #[test]
    fn resource_id_rejects_underscore() {
        assert!(ResourceId::parse("list_123").is_err());
    }

    // -- PrincipalRef --------------------------------------------------------

    #[test]
    fn vp_entity_type_user() {
        let project = ProjectId::new("todo-app").unwrap();
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        assert_eq!(principal.vp_entity_type(&project), "todo_app::User");
    }

    #[test]
    fn vp_entity_type_machine() {
        let project = ProjectId::new("todo-app").unwrap();
        let principal = PrincipalRef::machine(UserId::new("svc-worker").unwrap());
        assert_eq!(principal.vp_entity_type(&project), "todo_app::Machine");
    }

    #[test]
    fn principal_ref_default_is_user() {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        assert_eq!(principal.kind(), PrincipalKind::User);
    }

    #[test]
    fn principal_ref_machine_constructor() {
        let principal = PrincipalRef::machine(UserId::new("svc-worker").unwrap());
        assert_eq!(principal.kind(), PrincipalKind::Machine);
    }

    #[test]
    fn principal_kind_default_is_user() {
        assert_eq!(PrincipalKind::default(), PrincipalKind::User);
    }

    #[test]
    fn principal_ref_vp_group_entity_type() {
        let project = ProjectId::new("todo-app").unwrap();
        assert_eq!(
            PrincipalRef::vp_group_entity_type(&project),
            "todo_app::Group"
        );
    }

    #[test]
    fn principal_ref_to_fgrn() {
        let project = ProjectId::new("acme-app").unwrap();
        let tenant = TenantId::new("acme-corp").unwrap();
        let user_id = UserId::new("alice").unwrap();
        let principal = PrincipalRef::new(user_id);
        let fgrn = principal.to_fgrn(&project, &tenant);
        assert_eq!(fgrn.to_string(), "fgrn:acme-app:acme-corp:iam:user:alice");
    }

    #[test]
    fn principal_ref_machine_to_fgrn() {
        let project = ProjectId::new("acme-app").unwrap();
        let tenant = TenantId::new("acme-corp").unwrap();
        let user_id = UserId::new("svc-worker").unwrap();
        let principal = PrincipalRef::machine(user_id);
        let fgrn = principal.to_fgrn(&project, &tenant);
        assert_eq!(
            fgrn.to_string(),
            "fgrn:acme-app:acme-corp:iam:machine:svc-worker"
        );
    }

    // -- ResourceRef ---------------------------------------------------------

    #[test]
    fn resource_ref_to_fgrn() {
        let project = ProjectId::new("acme-app").unwrap();
        let tenant = TenantId::new("acme-corp").unwrap();
        let qa = QualifiedAction::parse("todo:list:read").unwrap();
        let rid = ResourceId::parse("list-123").unwrap();
        let resource = ResourceRef::from_route(&qa, rid);
        let fgrn = resource.to_fgrn(&project, &tenant);
        assert_eq!(
            fgrn.to_string(),
            "fgrn:acme-app:acme-corp:todo:list:list-123"
        );
    }
}

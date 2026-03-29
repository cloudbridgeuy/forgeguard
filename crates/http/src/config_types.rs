//! Supplementary validated config types for schema, AWS, and policy tests.

use std::collections::HashMap;

use forgeguard_core::{CedarEntityRef, GroupName, QualifiedAction};

// ---------------------------------------------------------------------------
// AwsConfig
// ---------------------------------------------------------------------------

/// AWS-level defaults: region and profile. Both optional.
///
/// Precedence: CLI flag > env var > `[aws]` config > SDK default chain.
#[derive(Debug, Clone, Default)]
pub struct AwsConfig {
    region: Option<String>,
    profile: Option<String>,
}

impl AwsConfig {
    /// Create a new `AwsConfig`.
    pub(crate) fn new(region: Option<String>, profile: Option<String>) -> Self {
        Self { region, profile }
    }

    /// The AWS region, if configured.
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// The AWS profile, if configured.
    pub fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }
}

// ---------------------------------------------------------------------------
// SchemaConfig
// ---------------------------------------------------------------------------

/// Validated entity schema configuration.
///
/// Maps namespace to entity-name to validated `EntitySchema`.
#[derive(Debug, Clone, Default)]
pub struct SchemaConfig {
    entities: HashMap<String, HashMap<String, EntitySchema>>,
}

impl SchemaConfig {
    /// Create a new `SchemaConfig`.
    pub(crate) fn new(entities: HashMap<String, HashMap<String, EntitySchema>>) -> Self {
        Self { entities }
    }

    /// The entity definitions, keyed by namespace then entity name.
    pub fn entities(&self) -> &HashMap<String, HashMap<String, EntitySchema>> {
        &self.entities
    }
}

/// A validated entity schema: membership and attributes.
#[derive(Debug, Clone)]
pub struct EntitySchema {
    member_of: Vec<String>,
    attributes: HashMap<String, String>,
}

impl EntitySchema {
    /// Create a new `EntitySchema`.
    pub(crate) fn new(member_of: Vec<String>, attributes: HashMap<String, String>) -> Self {
        Self {
            member_of,
            attributes,
        }
    }

    /// Entity types this entity can be a member of.
    pub fn member_of(&self) -> &[String] {
        &self.member_of
    }

    /// Attribute definitions for this entity type.
    pub fn attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }
}

// ---------------------------------------------------------------------------
// PolicyTest
// ---------------------------------------------------------------------------

/// The expected outcome of a policy test.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PolicyTestExpect {
    /// The request should be allowed.
    Allow,
    /// The request should be denied.
    Deny,
}

/// A validated inline policy test scenario.
#[derive(Debug, Clone)]
pub struct PolicyTest {
    name: String,
    principal: String,
    groups: Vec<GroupName>,
    tenant: String,
    action: QualifiedAction,
    resource: Option<CedarEntityRef>,
    expect: PolicyTestExpect,
}

/// Parameters for constructing a `PolicyTest`.
pub(crate) struct PolicyTestParams {
    pub(crate) name: String,
    pub(crate) principal: String,
    pub(crate) groups: Vec<GroupName>,
    pub(crate) tenant: String,
    pub(crate) action: QualifiedAction,
    pub(crate) resource: Option<CedarEntityRef>,
    pub(crate) expect: PolicyTestExpect,
}

impl PolicyTest {
    /// Create a new `PolicyTest` from params.
    pub(crate) fn new(params: PolicyTestParams) -> Self {
        Self {
            name: params.name,
            principal: params.principal,
            groups: params.groups,
            tenant: params.tenant,
            action: params.action,
            resource: params.resource,
            expect: params.expect,
        }
    }

    /// Test scenario name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The principal identity for this test.
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Groups the principal belongs to.
    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }

    /// The tenant context for this test.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The action being tested.
    pub fn action(&self) -> &QualifiedAction {
        &self.action
    }

    /// Optional resource reference.
    pub fn resource(&self) -> Option<&CedarEntityRef> {
        self.resource.as_ref()
    }

    /// Expected outcome.
    pub fn expect(&self) -> PolicyTestExpect {
        self.expect
    }
}

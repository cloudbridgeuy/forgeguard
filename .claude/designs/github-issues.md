# ForgeGate — GitHub Issues: Target B Milestone

> **Goal:** A developer runs the ForgeGate proxy in front of their app. The proxy resolves identity, checks authorization, injects identity headers, and proxies the request upstream. The policy domain (identity resolution + authorization decisions) is protocol-agnostic — the HTTP proxy is one adapter consuming it. No Smithy, no dashboard, no SDK generation — just auth enforcement on a real app.

---

## Milestone: `target-b-proxy-enforces-auth`

## Architecture: Policy Domain + Protocol Adapter

The design enforces a clean separation between the **policy domain** (protocol-agnostic rules about identity and authorization) and the **HTTP adapter** (one protocol binding that translates HTTP into policy queries and policy decisions into HTTP responses).

```
POLICY DOMAIN (pure, no HTTP, no I/O)          POLICY I/O
────────────────────────────────────            ──────────

forgegate_core                                  forgegate_authn
  UserId, TenantId, config types                  CognitoJwtResolver
                                                  (Credential → Identity)
forgegate_authn_core
  Credential, Identity,                         forgegate_authz
  IdentityResolver trait, chain                   VpPolicyEngine
                                                  (PolicyQuery → PolicyDecision)
forgegate_authz_core
  PolicyQuery, PolicyDecision,
  PolicyEngine trait


HTTP ADAPTER (one protocol binding — lives entirely in the proxy crate)
───────────────────────────────────────────────────────────────────────

forgegate_proxy
  HTTP header → Credential extraction
  (method, path) → (action, resource) route matching
  Identity → X-ForgeGate-* header injection
  PolicyDecision → 401/403/200 response translation
  Reverse proxying, health check, config
```

Tomorrow a gRPC interceptor, a WebSocket middleware, an MCP tool gate, or a queue consumer would be different adapters consuming the same policy domain. None of them would need to change `authn_core` or `authz_core`.

## Dependency Graph

```
                    ┌─────────────────────┐
                    │  #1 forgegate_core   │
                    │  shared primitives   │
                    └──────┬──────────────┘
                           │
              ┌────────────┼────────────────┐
              ▼            │                ▼
┌──────────────────┐       │    ┌──────────────────────────┐
│ #2 authn_core    │       │    │ #3 authz_core            │
│ Credential,      │       │    │ PolicyQuery,              │
│ Identity,        │       │    │ PolicyDecision,           │
│ IdentityResolver │       │    │ PolicyEngine trait         │
└────────┬─────────┘       │    └────────────┬─────────────┘
         │                 │                 │
         ▼                 │                 ▼
┌──────────────────┐       │    ┌──────────────────────────┐
│ #4 authn (I/O)   │       │    │ #5 authz (I/O)           │
│ CognitoJwt       │       │    │ Verified Permissions      │
│ Resolver         │       │    │ client + cache            │
└────────┬─────────┘       │    └────────────┬─────────────┘
         │                 │                 │
         └─────────┬───────┘─────────────────┘
                   ▼
         ┌──────────────────┐
         │ #6 proxy config  │
         │ route mappings   │
         │ (HTTP-specific)  │
         └────────┬─────────┘
                  ▼
         ┌──────────────────┐
         │ #7 proxy binary  │
         │ HTTP adapter:    │
         │ extraction,      │
         │ routing,         │
         │ translation      │
         └────────┬─────────┘
                  ▼
         ┌──────────────────┐       ┌──────────────────────────┐
         │ #8a Cognito      │──────►│ #8b Verified Permissions │
         │ (identity infra) │       │ + Cedar (authz infra)    │
         └──────┬───────────┘       └────────────┬─────────────┘
                │ also unblocks                  │
                │ #4 integration tests           │
                └────────────┬───────────────────┘
                             ▼
                  ┌──────────────────┐
                  │ #9 e2e demo      │
                  │ TODO app + proxy │
                  └──────────────────┘
```

Note: The `http` crate is a dependency of the proxy binary only.

---

## Crate Ownership Map

| Crate | Owns | Classification |
|-------|------|----------------|
| `forgegate_core` | `UserId`, `TenantId`, `Fgrn`, `Segment`, `QualifiedAction`, `FlagName`, `FlagValue`, `FlagConfig`, `ResolvedFlags` | Pure (no I/O) |
| `forgegate_authn_core` | `Credential`, `Identity`, `IdentityResolver` trait, `IdentityResolverChain` | Pure (no I/O) |
| `forgegate_authz_core` | `PolicyQuery`, `PolicyDecision`, `PolicyEngine` trait | Pure (no I/O) |
| `forgegate_authn` | `CognitoJwtResolver`, `ApiKeyResolver`, JWKS fetching | I/O (`reqwest`) |
| `forgegate_authz` | `VpPolicyEngine`, Verified Permissions API calls, decision cache | I/O (`aws-sdk`) |
| `forgegate_proxy` | `ProxyConfig`, `AuthConfig`, `AuthzConfig`, `RouteMapping`, `RouteMatcher`, `PathPattern`, `HttpMethod`, `RequestCtx`, `IdentityProjection`, credential extraction from headers, header injection, HTTP status code translation, `forgegate.toml` loading | Binary (`http`, `pingora`) |

**CI gate:** `cargo tree -p forgegate_authn_core | grep -E "^.* http "` must return nothing. Same for `core`, `authz_core`, `authn`, `authz`.

---

## Issue #1: `forgegate_core` — Shared primitives and config types

**Crate:** `crates/core/` (pure, no I/O)
**Labels:** `core`, `pure`, `layer-1`
**Blocked by:** nothing
**Unblocks:** #2, #3, #4, #5, #6, #7

### Description

Define the foundational types that every other crate depends on. These are the typed IDs, error infrastructure, feature flag types and evaluation, and `ResolvedFlags`.

This crate has zero dependencies on `http`, `tokio`, AWS SDKs, or any I/O library. It compiles to `wasm32-unknown-unknown`.

### Acceptance Criteria

**ForgeGate Resource Name (FGRN)** — the universal addressing scheme for every entity, modeled after AWS ARNs but organized by **namespace** (the customer's domain) rather than service (ForgeGate's internals).

All concrete segments use `Segment` — a validated kebab-case identifier that survives every environment ForgeGate touches without translation: URIs, Cedar entity IDs, S3 keys, HTTP headers, CloudWatch dimensions, structured logs. No case-sensitivity issues, no encoding needed.

```rust
/// A validated identifier segment.
///
/// Rules:
/// - Lowercase ASCII letters, digits, and hyphens only
/// - Must start with a letter
/// - Must not end with a hyphen
/// - No consecutive hyphens (reserved, Punycode-style)
/// - Non-empty, no upper length limit
///
/// This format survives every environment without translation:
/// URIs, Cedar entity IDs, S3 keys, HTTP headers, CloudWatch dimensions,
/// DNS labels, structured logs, TOML values, JSON keys.
///
/// Examples: "acme-corp", "todo-app", "list", "item-abc123", "quarterly-report"
/// Invalid: "AcmeCorp", "my_project", "-leading", "trailing-", "no--double", ""
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Segment(String);

impl Segment {
    pub fn try_new(raw: impl Into<String>) -> Result<Self> {
        let s = raw.into();

        if s.is_empty() {
            return Err(Error::Parse {
                field: "segment", value: s, reason: "cannot be empty",
            });
        }
        if !s.as_bytes()[0].is_ascii_lowercase() {
            return Err(Error::Parse {
                field: "segment", value: s, reason: "must start with a lowercase letter",
            });
        }
        if s.ends_with('-') {
            return Err(Error::Parse {
                field: "segment", value: s, reason: "must not end with a hyphen",
            });
        }
        if s.contains("--") {
            return Err(Error::Parse {
                field: "segment", value: s, reason: "consecutive hyphens are not allowed",
            });
        }
        if !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(Error::Parse {
                field: "segment", value: s,
                reason: "must contain only lowercase letters, digits, and hyphens",
            });
        }

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// ForgeGate Resource Name — a structured, validated identifier for any
/// entity in the ForgeGate system.
///
/// Format: fgrn:<project>:<tenant>:<namespace>:<resource-type>:<resource-id>
///
/// Six positions, always. Use `*` for wildcards, `-` for not-applicable.
/// All concrete segments are validated `Segment` values (lowercase, hyphens).
/// The `-` is a serialization convention for absent fields (Option::None),
/// NOT a valid Segment value.
///
/// Customer domain resources:
///   fgrn:acme-app:acme-corp:todo:list:list-001
///   fgrn:acme-app:acme-corp:todo:item:item-042
///   fgrn:acme-app:acme-corp:billing:invoice:inv-789
///   fgrn:acme-app:*:todo:list:*                    ← all lists, all tenants
///   fgrn:acme-app:acme-corp:todo:*:*               ← all todo resources in tenant
///
/// Identity resources (reserved "iam" namespace):
///   fgrn:acme-app:acme-corp:iam:user:user-abc123
///   fgrn:acme-app:acme-corp:iam:group:admin
///   fgrn:acme-app:acme-corp:iam:user:*             ← all users in tenant
///
/// System resources (reserved "forgegate" namespace):
///   fgrn:acme-app:-:forgegate:policy:pol-001       ← tenant is None (not tenant-scoped)
///   fgrn:acme-app:-:forgegate:feature-flag:ai-suggestions
///   fgrn:acme-app:-:forgegate:webhook:wh-001
///   fgrn:-:-:forgegate:project:acme-app             ← project and tenant both None (back office)
///
/// Used as:
///   - Cedar/Verified Permissions entity IDs (single identifier everywhere — no mapping)
///   - Audit log entity references
///   - API resource identifiers
///   - Webhook event payloads
///   - Event log references
///
/// Parse Don't Validate: if you hold a Fgrn, every segment is guaranteed valid.
///
/// Design note: `-` in the string form is a serialization convention for absent
/// fields (None at the type level). It is NOT a valid Segment — Segment stays
/// strict (must start with a letter, no lone hyphens). The "not applicable"
/// semantics live in the Fgrn type's parse/display logic, not in Segment.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Fgrn {
    project: Option<FgrnSegment>,   // None for platform-level resources (back office)
    tenant: Option<FgrnSegment>,    // None for non-tenant-scoped resources
    namespace: FgrnSegment,         // always present
    resource_type: FgrnSegment,     // always present
    resource_id: FgrnSegment,       // always present
    raw: String,                    // cached canonical form for Display + Verified Permissions entity ID
}

/// A single concrete-or-wildcard segment in an FGRN.
/// Either a validated Segment or a wildcard (*).
///
/// "Not applicable" is NOT a variant here — it's represented as
/// Option<FgrnSegment>::None at the Fgrn field level. The `-` character
/// only appears during serialization/deserialization of the FGRN string.
/// This keeps Segment's validation rules strict and uncompromised.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum FgrnSegment {
    Value(Segment),
    Wildcard,
}

/// Reserved namespaces — customers cannot use these.
const RESERVED_NS_IAM: &str = "iam";
const RESERVED_NS_FORGEGATE: &str = "forgegate";

impl Fgrn {
    /// Parse from canonical string form.
    /// `-` is deserialized as None (absent), not as a Segment value.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();
        match parts.as_slice() {
            ["fgrn", project, tenant, namespace, rtype, rid] => {
                Ok(Self {
                    project: parse_optional_segment(project)?,
                    tenant: parse_optional_segment(tenant)?,
                    namespace: FgrnSegment::parse(namespace)?,
                    resource_type: FgrnSegment::parse(rtype)?,
                    resource_id: FgrnSegment::parse(rid)?,
                    raw: s.to_string(),
                })
            }
            _ => Err(Error::Parse {
                field: "fgrn",
                value: s.to_string(),
                reason: "expected fgrn:<project>:<tenant>:<namespace>:<resource-type>:<resource-id>",
            }),
        }
    }

    /// Construct from validated parts. Builds canonical string once.
    pub fn new(
        project: Option<FgrnSegment>,
        tenant: Option<FgrnSegment>,
        namespace: FgrnSegment,
        resource_type: FgrnSegment,
        resource_id: FgrnSegment,
    ) -> Self {
        let raw = format!(
            "fgrn:{}:{}:{}:{}:{}",
            optional_segment_str(&project),
            optional_segment_str(&tenant),
            namespace.as_str(),
            resource_type.as_str(),
            resource_id.as_str(),
        );
        Self { project, tenant, namespace, resource_type, resource_id, raw }
    }

    /// Builder helpers for common FGRN patterns
    pub fn user(project: &ProjectId, tenant: &TenantId, user_id: &UserId) -> Self {
        Self::new(
            Some(FgrnSegment::value(project.as_str())),
            Some(FgrnSegment::value(tenant.as_str())),
            FgrnSegment::value(RESERVED_NS_IAM),
            FgrnSegment::value("user"),
            FgrnSegment::value(user_id.as_str()),
        )
    }

    pub fn group(project: &ProjectId, tenant: &TenantId, group_name: &str) -> Self {
        Self::new(
            Some(FgrnSegment::value(project.as_str())),
            Some(FgrnSegment::value(tenant.as_str())),
            FgrnSegment::value(RESERVED_NS_IAM),
            FgrnSegment::value("group"),
            FgrnSegment::value(group_name),
        )
    }

    pub fn resource(
        project: &ProjectId, tenant: &TenantId,
        namespace: &Namespace, entity: &Entity, id: &str,
    ) -> Self {
        Self::new(
            Some(FgrnSegment::value(project.as_str())),
            Some(FgrnSegment::value(tenant.as_str())),
            FgrnSegment::value(namespace.as_str()),
            FgrnSegment::value(entity.as_str()),
            FgrnSegment::value(id),
        )
    }

    /// Cedar entity type: "{namespace}::{resource_type}" e.g., "todo::list"
    pub fn cedar_entity_type(&self) -> Option<String> {
        match (&self.namespace, &self.resource_type) {
            (FgrnSegment::Value(ns), FgrnSegment::Value(rt)) => {
                Some(format!("{ns}::{rt}"))
            }
            _ => None,
        }
    }

    /// This string is used directly as the Verified Permissions entity ID.
    /// Single identifier everywhere — no mapping at any boundary.
    pub fn as_vp_entity_id(&self) -> &str {
        &self.raw
    }

    /// Does this FGRN match another (potentially wildcarded) FGRN?
    pub fn matches(&self, pattern: &Fgrn) -> bool {
        optional_matches(&self.project, &pattern.project)
            && optional_matches(&self.tenant, &pattern.tenant)
            && self.namespace.matches(&pattern.namespace)
            && self.resource_type.matches(&pattern.resource_type)
            && self.resource_id.matches(&pattern.resource_id)
    }

    pub fn project(&self) -> Option<&FgrnSegment> { self.project.as_ref() }
    pub fn tenant(&self) -> Option<&FgrnSegment> { self.tenant.as_ref() }
    pub fn namespace(&self) -> &FgrnSegment { &self.namespace }
    pub fn resource_type(&self) -> &FgrnSegment { &self.resource_type }
    pub fn resource_id(&self) -> &FgrnSegment { &self.resource_id }
}

impl FgrnSegment {
    /// Parse a required FGRN segment (must be a value or wildcard, not `-`).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "*" => Ok(Self::Wildcard),
            _ => Ok(Self::Value(Segment::try_new(s)?)),
        }
    }

    /// Convenience constructor for Value variant.
    fn value(s: &str) -> Self {
        Self::Value(Segment::try_new(s).expect("invalid segment in builder"))
    }

    pub fn matches(&self, pattern: &FgrnSegment) -> bool {
        match pattern {
            FgrnSegment::Wildcard => true,
            FgrnSegment::Value(v) => matches!(self, FgrnSegment::Value(sv) if sv == v),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Value(v) => v.as_str(),
            Self::Wildcard => "*",
        }
    }
}

/// Parse an optional FGRN segment: `-` becomes None, everything else is parsed.
fn parse_optional_segment(s: &str) -> Result<Option<FgrnSegment>> {
    match s {
        "-" => Ok(None),
        _ => Ok(Some(FgrnSegment::parse(s)?)),
    }
}

/// Serialize an optional segment: None becomes `-`.
fn optional_segment_str(seg: &Option<FgrnSegment>) -> &str {
    match seg {
        Some(s) => s.as_str(),
        None => "-",
    }
}

/// Match logic for optional segments:
/// - None pattern matches only None values (both are "not applicable")
/// - Some(Wildcard) matches anything including None
/// - Some(Value) matches only the same value
fn optional_matches(value: &Option<FgrnSegment>, pattern: &Option<FgrnSegment>) -> bool {
    match (pattern, value) {
        (None, None) => true,                // both not-applicable
        (None, Some(_)) => false,            // pattern says absent, value is present
        (Some(FgrnSegment::Wildcard), _) => true, // wildcard matches anything
        (Some(_), None) => false,            // pattern expects value, but absent
        (Some(p), Some(v)) => v.matches(p),  // both present, delegate to FgrnSegment
    }
}

impl fmt::Display for Fgrn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for Fgrn {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> { Self::parse(s) }
}

/// Serialize as canonical string, deserialize via parse.
impl Serialize for Fgrn { /* serialize_str(&self.raw) */ }
impl<'de> Deserialize<'de> for Fgrn { /* parse from string */ }
```

See [FGRN Design Spike](spike-fgrn-design.md) for the full design rationale, Cedar mapping, and how FGRNs flow through the proxy, Verified Permissions, audit log, webhooks, and dashboard.

**Typed IDs** — newtype wrappers built on `Segment`, with `Display`, `FromStr`, `Serialize`, `Deserialize`, `Clone`, `Eq`, `Hash`:

```rust
// Internal define_id! macro generates newtype over Segment + Display, FromStr,
// Serialize, Deserialize, Clone, Eq, Hash, and a validating constructor.
// Defined once in this crate, used for all ID types. No external crate dependency.
define_id!(UserId, "user-");      // validates prefix + kebab-case
define_id!(TenantId, "tenant-");
define_id!(ProjectId, "proj-");

pub struct FlowId(Uuid);          // FlowId uses Uuid, not Segment
```

- Constructor delegates to `Segment::try_new` then checks prefix
- `UserId::new("user-abc123")` succeeds, `UserId::new("user_abc")` returns `Err` (underscore), `UserId::new("")` returns `Err`
- All IDs are `pub(crate)` inner field, exposed via `.as_str()` / `.as_segment()`

**Action vocabulary types** — the core modeling for `namespace:action:entity`:

ForgeGate actions follow the pattern `namespace:action:entity` (e.g., `todo:read:list`, `billing:refund:invoice`). This mirrors AWS IAM's `service:VerbNoun` (e.g., `s3:GetObject`), but with three explicit segments instead of two. The third segment eliminates parsing ambiguity — no guessing where the verb ends and the resource begins.

All three segments are validated `Segment` values (kebab-case). If you hold a `QualifiedAction`, every component is guaranteed valid. No downstream code ever re-validates.

```rust
/// A namespace within a project. Groups related resources and actions.
/// The customer's domain organizing principle.
///
/// Reserved namespaces:
///   "iam"       — user, group, role entities (identity primitives)
///   "forgegate" — policy, feature-flag, webhook entities (system internals)
///
/// Customer namespaces must be valid Segment values and cannot use reserved names.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Namespace(NamespaceInner);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
enum NamespaceInner {
    User(Segment),
    Reserved(Segment),
}

const RESERVED_NAMESPACES: &[&str] = &["iam", "forgegate"];

impl Namespace {
    /// Parse a user-provided namespace. Rejects reserved names.
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if RESERVED_NAMESPACES.contains(&s.as_str()) {
            return Err(Error::Parse {
                field: "namespace",
                value: s,
                reason: "reserved namespace — 'iam' and 'forgegate' cannot be used by customers",
            });
        }
        Ok(Self(NamespaceInner::User(Segment::try_new(s)?)))
    }

    /// The iam namespace where user and group entities live.
    pub fn iam() -> Self {
        Self(NamespaceInner::Reserved(
            Segment::try_new("iam").expect("iam is a valid segment")
        ))
    }

    /// The forgegate namespace where policy, feature-flag, webhook entities live.
    pub fn forgegate() -> Self {
        Self(NamespaceInner::Reserved(
            Segment::try_new("forgegate").expect("forgegate is a valid segment")
        ))
    }

    pub fn is_reserved(&self) -> bool {
        matches!(self.0, NamespaceInner::Reserved(_))
    }

    pub fn as_str(&self) -> &str {
        match &self.0 {
            NamespaceInner::User(seg) => seg.as_str(),
            NamespaceInner::Reserved(seg) => seg.as_str(),
        }
    }
}

/// An action verb. Kebab-case — any verb the developer wants.
/// e.g., "read", "create", "force-delete", "bulk-export", "countersign"
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Action(Segment);

impl Action {
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        Ok(Self(Segment::try_new(s)?))
    }
    pub fn as_str(&self) -> &str { self.0.as_str() }
}

/// A resource/entity type. Kebab-case.
/// e.g., "invoice", "payment-tracker", "shipping-label"
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Entity(Segment);

impl Entity {
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        Ok(Self(Segment::try_new(s)?))
    }
    pub fn as_str(&self) -> &str { self.0.as_str() }

    /// Cedar entity type: "billing::invoice"
    pub fn cedar_entity_type(&self, ns: &Namespace) -> String {
        format!("{}::{}", ns.as_str(), self.as_str())
    }
}

/// A fully qualified action: namespace:action:entity
///
/// ForgeGate:     "todo:read:list"
/// AWS analog:    "s3:GetObject"
/// Cedar maps:    namespace=todo, action="read-list", entity=todo::list
///
/// Three explicit segments — no parsing heuristics to split verb from entity.
/// If you hold a QualifiedAction, every component is guaranteed valid.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct QualifiedAction {
    namespace: Namespace,
    action: Action,
    entity: Entity,
}

impl QualifiedAction {
    /// Construct from already-parsed parts. No validation — types carry the proof.
    pub fn new(namespace: Namespace, action: Action, entity: Entity) -> Self {
        Self { namespace, action, entity }
    }

    /// Parse from the canonical format: "todo:read:list"
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        match parts.as_slice() {
            [ns, action, entity] => Ok(Self {
                namespace: Namespace::parse(*ns)?,
                action: Action::parse(*action)?,
                entity: Entity::parse(*entity)?,
            }),
            _ => Err(Error::Parse {
                field: "qualified_action",
                value: s.to_string(),
                reason: "expected namespace:action:entity (e.g., 'todo:read:list')",
            }),
        }
    }

    pub fn namespace(&self) -> &Namespace { &self.namespace }
    pub fn action(&self) -> &Action { &self.action }
    pub fn entity(&self) -> &Entity { &self.entity }

    /// Verified Permissions `IsAuthorized`: actionType — "todo::action"
    pub fn vp_action_type(&self) -> String {
        format!("{}::action", self.namespace.as_str())
    }

    /// Verified Permissions `IsAuthorized`: actionId — "read-list" (action + entity, hyphen-joined)
    pub fn vp_action_id(&self) -> String {
        format!("{}-{}", self.action.as_str(), self.entity.as_str())
    }

    /// Cedar action reference: todo::action::"read-list"
    pub fn cedar_action_ref(&self) -> String {
        format!("{}::action::\"{}\"", self.namespace.as_str(), self.vp_action_id())
    }

    /// Cedar entity type for the resource: todo::list
    pub fn cedar_entity_type(&self) -> String {
        self.entity.cedar_entity_type(&self.namespace)
    }
}

/// Serde: serializes as "todo:read:list", deserializes via parse.
impl Serialize for QualifiedAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for QualifiedAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A validated, non-empty resource ID. Built on Segment (kebab-case).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ResourceId(Segment);

impl ResourceId {
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        Ok(Self(Segment::try_new(s)?))
    }
    pub fn as_str(&self) -> &str { self.0.as_str() }
}

/// A concrete resource instance for authorization checks.
/// Constructed from a QualifiedAction (namespace + entity) + extracted path param.
pub struct ResourceRef {
    namespace: Namespace,
    entity: Entity,
    id: ResourceId,
}

impl ResourceRef {
    /// Construct from a matched route's action + extracted resource ID.
    /// No validation needed — QualifiedAction and ResourceId carry the proof.
    pub fn from_route(action: &QualifiedAction, id: ResourceId) -> Self {
        Self {
            namespace: action.namespace().clone(),
            entity: action.entity().clone(),
            id,
        }
    }

    /// Verified Permissions entity type: "todo::list"
    pub fn vp_entity_type(&self) -> String {
        self.entity.cedar_entity_type(&self.namespace)
    }

    /// Build the FGRN for this resource. Used as the Verified Permissions entity ID.
    /// Requires tenant because FGRNs include the tenant segment.
    pub fn to_fgrn(&self, project: &ProjectId, tenant: &TenantId) -> Fgrn {
        Fgrn::resource(project, tenant, &self.namespace, &self.entity, self.id.as_str())
    }
}

/// Principal reference — always in the iam::user entity type.
pub struct PrincipalRef {
    user_id: UserId,
}

impl PrincipalRef {
    pub fn new(user_id: UserId) -> Self { Self { user_id } }

    /// Verified Permissions entity type for principals.
    pub fn vp_entity_type() -> &'static str {
        "iam::user"
    }

    /// Build the FGRN for this principal. Used as the Verified Permissions entity ID.
    /// Requires tenant because FGRNs include the tenant segment.
    pub fn to_fgrn(&self, project: &ProjectId, tenant: &TenantId) -> Fgrn {
        Fgrn::user(project, tenant, &self.user_id)
    }
}
```

**Error infrastructure:**

```rust
// Pattern: each crate has Error + Result<T>
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid {field}: '{value}' — {reason}")]
    Parse {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    #[error("configuration error: {0}")]
    Config(String),
    #[error("unknown feature flag type: {0}")]
    InvalidFlagType(String),
}
```

**Feature flag types and evaluation** (pure — no I/O, WASM-compatible):

```rust
/// A feature flag name. Either project-wide or namespace-scoped.
/// Kebab-case enforced — same Segment validation as everything else.
///
/// "maintenance-mode"         → global, project-wide
/// "todo:ai-suggestions"      → scoped to todo namespace
///
/// Parsed at the TOML boundary. If you hold a FlagName, it's valid.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum FlagName {
    /// Project-wide flag. Kebab-case, no namespace.
    Global(Segment),
    /// Namespace-scoped flag. namespace:name.
    Scoped { namespace: Namespace, name: Segment },
}

impl FlagName {
    pub fn parse(s: &str) -> Result<Self> {
        if let Some((ns, name)) = s.split_once(':') {
            Ok(Self::Scoped {
                namespace: Namespace::parse(ns)?,
                name: Segment::try_new(name)?,
            })
        } else {
            Ok(Self::Global(Segment::try_new(s)?))
        }
    }

    /// Check if this flag is in a specific namespace.
    pub fn is_in_namespace(&self, ns: &Namespace) -> bool {
        match self {
            Self::Global(_) => false,
            Self::Scoped { namespace, .. } => namespace == ns,
        }
    }
}

impl fmt::Display for FlagName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global(name) => write!(f, "{}", name),
            Self::Scoped { namespace, name } => write!(f, "{}:{}", namespace, name),
        }
    }
}

impl Serialize for FlagName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for FlagName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A resolved feature flag value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum FlagValue {
    Bool(bool),
    String(String),
    Number(f64),
}

/// All flags resolved for a specific request context.
/// Keys are the canonical FlagName display form: "MaintenanceMode" or "Todo:AiSuggestions".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolvedFlags {
    flags: HashMap<String, FlagValue>,
}

impl ResolvedFlags {
    pub fn enabled(&self, flag: &str) -> bool {
        matches!(self.flags.get(flag), Some(FlagValue::Bool(true)))
    }

    pub fn get(&self, flag: &str) -> Option<&FlagValue> {
        self.flags.get(flag)
    }

    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }
}

/// Definition of a single feature flag (from config).
#[derive(Debug, Clone, Deserialize)]
pub struct FlagDefinition {
    #[serde(rename = "type")]
    pub flag_type: FlagType,
    pub default: FlagValue,
    #[serde(default)]
    pub overrides: Vec<FlagOverride>,
    pub rollout_percentage: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagType {
    Boolean,
    String,
    Number,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlagOverride {
    pub tenant: Option<String>,
    pub user: Option<String>,
    pub value: FlagValue,
}

/// All flag definitions loaded from config.
/// Keys are FlagName — parsed and validated at config load time.
#[derive(Debug, Clone, Default)]
pub struct FlagConfig {
    pub flags: HashMap<FlagName, FlagDefinition>,
}
```

**Flag evaluation — pure function, deterministic, no I/O:**

```rust
/// Evaluate all flags for a given identity context.
/// Pure function — same inputs always produce same outputs.
/// Must produce identical results across all SDK languages (conformance-tested).
pub fn evaluate_flags(
    config: &FlagConfig,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
) -> ResolvedFlags {
    let mut flags = HashMap::new();
    for (name, def) in &config.flags {
        let display_name = name.to_string(); // "MaintenanceMode" or "Todo:AiSuggestions"
        flags.insert(display_name.clone(), resolve_single_flag(&display_name, def, tenant_id, user_id));
    }
    ResolvedFlags { flags }
}

fn resolve_single_flag(
    name: &str,
    flag: &FlagDefinition,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
) -> FlagValue {
    // 1. Check user-specific override (most specific wins)
    if let Some(ov) = flag.overrides.iter()
        .find(|o| o.user.as_deref() == Some(user_id.as_str()))
    {
        return ov.value.clone();
    }

    // 2. Check tenant-specific override
    if let Some(tenant) = tenant_id {
        if let Some(ov) = flag.overrides.iter()
            .find(|o| o.tenant.as_deref() == Some(tenant.as_str()) && o.user.is_none())
        {
            return ov.value.clone();
        }
    }

    // 3. Check percentage rollout (boolean flags only)
    if let Some(pct) = flag.rollout_percentage {
        let bucket = deterministic_bucket(name, tenant_id, user_id);
        return FlagValue::Bool(bucket < pct);
    }

    // 4. Default
    flag.default.clone()
}

/// Deterministic hash → 0..99 bucket.
/// Uses a stable, portable hash (NOT std HashMap hasher).
/// This function is part of the conformance test suite —
/// every SDK language must produce the same bucket for the same inputs.
fn deterministic_bucket(
    flag: &str,
    tenant: Option<&TenantId>,
    user: &UserId,
) -> u8 {
    use std::hash::Hasher;
    let mut hasher = XxHash64::with_seed(0);
    hasher.write(flag.as_bytes());
    hasher.write_u8(0xFF); // separator
    if let Some(t) = tenant {
        hasher.write(t.as_str().as_bytes());
    }
    hasher.write_u8(0xFF); // separator
    hasher.write(user.as_str().as_bytes());
    (hasher.finish() % 100) as u8
}
```

**Tests:**

- ID validation: valid formats accepted, empty/malformed rejected
- `Segment::try_new`: lowercase accepted, uppercase rejected, underscores rejected, empty rejected, leading/trailing hyphen rejected, consecutive hyphens rejected, starts-with-digit rejected
- `Namespace::parse`: kebab-case accepted, `"iam"` rejected (reserved), `"forgegate"` rejected (reserved), empty rejected, uppercase rejected
- `Namespace::iam()`: returns `iam`, `is_reserved()` is true
- `Action::parse`: `"read"`, `"force-delete"`, `"bulk-export"` all valid; `"Read"`, `""`, `"force_delete"` rejected
- `Entity::parse`: `"invoice"`, `"payment-tracker"`, `"shipping-label"` all valid; `"Invoice"` rejected
- `QualifiedAction::parse("todo:read:list")` → namespace=todo, action=read, entity=list
- `QualifiedAction::parse("billing:force-delete:payment-tracker")` → all three correct
- `QualifiedAction::parse("s3:get-object")` → error (only two segments)
- `QualifiedAction::parse("Todo:Read:List")` → error (uppercase)
- `QualifiedAction::parse("")` → error
- `QualifiedAction::vp_action_type()` → `"todo::action"`
- `QualifiedAction::vp_action_id()` → `"read-list"` (action-entity hyphen-joined)
- `QualifiedAction::cedar_action_ref()` → `"todo::action::\"read-list\""`
- `QualifiedAction::cedar_entity_type()` → `"todo::list"`
- `ResourceRef::from_route` constructs from parsed types — no validation at this point
- `ResourceId::parse("")` → error, `ResourceId::parse("list-123")` → ok, `ResourceId::parse("list_123")` → error (underscore)
- `PrincipalRef::vp_entity_type()` → `"iam::user"`
- `PrincipalRef::to_fgrn()` → `"fgrn:acme-app:acme-corp:iam:user:user-abc123"`
- `ResourceRef::to_fgrn()` → `"fgrn:acme-app:acme-corp:todo:list:list-123"`
- **FGRN parsing:** `Fgrn::parse("fgrn:acme-app:acme-corp:iam:user:user-abc123")` → project=`acme-app`, tenant=`acme-corp`, namespace=`iam`, resource_type=`user`, resource_id=`user-abc123`
- **FGRN parsing resources:** `Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-123")` → namespace=`todo`, resource_type=`list`, resource_id=`list-123`
- **FGRN wildcards:** `Fgrn::parse("fgrn:acme-app:*:todo:list:*")` → tenant=Wildcard, resource_id=Wildcard
- **FGRN not-applicable:** `Fgrn::parse("fgrn:acme-app:-:forgegate:policy:pol-001")` → tenant=None (the `-` deserializes as `Option::None`, not as a `Segment`)
- **FGRN matching:** specific FGRN matches wildcard pattern, doesn't match wrong namespace
- **FGRN parse errors:** `Fgrn::parse("bad:format")` → error, `Fgrn::parse("fgrn:acme-app")` → error (too few segments), `Fgrn::parse("")` → error
- **FGRN segment validation:** `Fgrn::parse("fgrn:AcmeApp:acme:todo:list:list-1")` → error (uppercase in project segment)
- **FGRN construction:** `Fgrn::new()` → `Display` round-trips to identical string
- **FGRN helpers:** `Fgrn::user()` produces `"fgrn:{project}:{tenant}:iam:user:{user_id}"`, `Fgrn::group()` produces `"fgrn:{project}:{tenant}:iam:group:{name}"`, `Fgrn::resource()` produces `"fgrn:{project}:{tenant}:{ns}:{entity}:{id}"`
- **FGRN as Verified Permissions entity ID:** `Fgrn::as_vp_entity_id()` returns the same string as `Display` — single identifier everywhere
- **FGRN namespace validation:** reserved namespaces `"iam"` and `"forgegate"` rejected for customer use via `Namespace::parse`, valid kebab-case accepted, empty rejected
- **FGRN serde:** serialize as canonical string, deserialize via parse, round-trip preserves equality
- Serde round-trip: `QualifiedAction` serializes as `"todo:read:list"` and deserializes back
- TOML deserialization of `QualifiedAction` in a route config works via the Deserialize impl
- `FlagName::parse("maintenance-mode")` → `FlagName::Global`
- `FlagName::parse("todo:ai-suggestions")` → `FlagName::Scoped { namespace: todo, name: ai-suggestions }`
- `FlagName::parse("MaintenanceMode")` → error (not kebab-case)
- `FlagName::parse("todo:aiSuggestions")` → error (not kebab-case)
- `FlagName::parse("")` → error
- `FlagName` display round-trip: parse → to_string → parse produces same value
- `FlagName` serde round-trip: serialize → deserialize produces same value
- `FlagName::is_in_namespace`: scoped flag matches its namespace, global flag matches nothing
- `FlagConfig` with `FlagName` keys: TOML like `[flags."todo:ai-suggestions"]` deserializes correctly
- `FlagConfig` with invalid key like `[flags.snake_case]` → rejected at parse time
- Config deserialization: round-trip TOML → struct → verify all fields including features
- Flag evaluation: boolean default, tenant override, user override, rollout percentage
- Deterministic hashing: same inputs → same bucket, different inputs → different buckets
- Rollout at 0% → all false, at 100% → all true
- Override precedence: user > tenant > rollout > default
- `ResolvedFlags` serialization: JSON round-trip
- Error display: messages include field name, value, and reason

---

## Issue #2: `forgegate_authn_core` — Identity resolution trait, chain, and credential types

**Crate:** `crates/authn-core/` (pure, no I/O, **no `http` dependency**)
**Labels:** `authn`, `pure`, `layer-1`
**Blocked by:** #1
**Unblocks:** #4, #7

### Description

Define the pluggable identity resolution abstraction — modeled after the AWS SDK's credential provider chain. This crate answers one question: "given a credential, who is this?"

This crate has zero dependencies on `http`, `tokio`, AWS SDKs, or any I/O library. It compiles to `wasm32-unknown-unknown`. The `IdentityResolver` trait takes a `Credential` and returns an `Identity`.

### Design: Following the AWS SDK Pattern

The AWS SDK uses a `DefaultCredentialsChain` that tries providers in order (env vars → shared credentials file → SSO → ECS metadata → EC2 IMDS). Each implements `ProvideCredentials`, and the chain returns the first success. The rest of the SDK never knows which provider resolved the credential.

ForgeGate mirrors this exactly:

```
Credential (extracted by the protocol adapter — not our concern)
    │
    ▼
IdentityChain tries resolvers in order:
    │
    ├─ CognitoJwtResolver: can_resolve(Bearer)? yes → validate → Identity ✅
    │
    ├─ StaticApiKeyResolver: can_resolve(ApiKey)? yes → lookup → Identity ✅
    │
    └─ OpaqueTokenResolver: can_resolve(Bearer)? yes → introspect → Identity
    │                                                                (future)
    │
Result: Identity (same type regardless of resolver)
```

`StaticApiKeyResolver` is a pure in-memory HashMap lookup — no I/O. It lives in this crate (`authn_core`). A future `DynamoApiKeyResolver` would live in `authn` (I/O).

### Acceptance Criteria

**Credential — the protocol-agnostic input:**

```rust
/// A raw, unvalidated credential. Protocol adapters produce these.
/// Identity resolvers consume them. Neither knows about the other's world.
///
/// This enum will grow as new auth mechanisms are added (mTLS, session tokens, etc.)
pub enum Credential {
    /// A bearer token (JWT or opaque)
    Bearer(String),
    /// An API key
    ApiKey(String),
    /// A session token (future)
    SessionToken(String),
}
```

No mention of `Authorization: Bearer` or `X-API-Key` headers — those are HTTP concepts. This enum describes what the credential *is*, not where it came from.

**Identity — the validated output:**

```rust
/// A resolved, trusted identity. Produced only by IdentityResolver implementations.
/// Protocol adapters and the authz layer consume this without knowing how it was produced.
///
/// This is ForgeGate's equivalent of aws_credential_types::Credentials.
pub struct Identity {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    roles: Vec<String>,
    scopes: Vec<String>,
    expiry: Option<SystemTime>,
    /// Which resolver produced this — for logging/metrics, never for branching.
    resolver: &'static str,
    /// Resolver-specific claims preserved for custom policy evaluation.
    /// JWT: decoded claims. API key: key metadata. None if not applicable.
    extra: Option<serde_json::Value>,
}
```

- Fields are `pub(crate)` with getter methods
- Constructor is `pub(crate)` — only resolver implementations can create one
- `resolver` field is purely diagnostic

**Identity resolver trait — the pluggable socket:**

```rust
/// Each resolver knows whether it can handle a credential type
/// and how to resolve it into a trusted Identity.
///
/// Modeled after aws_credential_types::provider::ProvideCredentials.
///
/// NOTE: No `http` dependency. No `extract` method. This trait operates
/// on Credentials, not on protocol-specific request types. The protocol
/// adapter (HTTP proxy, gRPC interceptor, etc.) is responsible for
/// extracting credentials from its own transport.
pub trait IdentityResolver: Send + Sync {
    /// Name for logging and diagnostics: "cognito_jwt", "static_api_key", etc.
    fn name(&self) -> &'static str;

    /// Can this resolver handle this credential type?
    /// Fast, synchronous check — typically just a match on the variant.
    fn can_resolve(&self, credential: &Credential) -> bool;

    /// Validate the credential and produce a trusted Identity.
    /// Async because it may involve I/O (JWKS fetch, token introspection).
    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>>;
}
```

**Identity chain — the orchestrator:**

```rust
/// Tries identity resolvers in order. First one that can resolve the
/// credential owns the outcome — success or failure, the chain stops.
///
/// Mirrors the AWS SDK's DefaultCredentialsChain pattern.
///
/// The chain order (configured in forgegate.toml) is the tiebreaker for
/// ambiguous credentials, e.g., a Bearer token that could be a JWT or
/// an opaque token. Whichever resolver is first in the chain gets first crack.
pub struct IdentityChain {
    resolvers: Vec<Arc<dyn IdentityResolver>>,
}

impl IdentityChain {
    pub fn new(resolvers: Vec<Arc<dyn IdentityResolver>>) -> Self {
        Self { resolvers }
    }

    /// Resolve a credential into an Identity.
    /// First resolver that can_resolve() owns the outcome.
    pub async fn resolve(&self, credential: &Credential) -> Result<Identity> {
        for resolver in &self.resolvers {
            if !resolver.can_resolve(credential) {
                continue;
            }

            // This resolver claims the credential. Its result is authoritative.
            return resolver.resolve(credential).await;
        }

        Err(Error::NoResolver {
            credential_type: credential.type_name().to_string(),
        })
    }
}
```

**Static API key resolver** (pure, in-memory HashMap lookup):

```rust
/// In-memory API key resolver. Keys are loaded from config at startup.
/// No I/O — the key map is passed in at construction time.
pub struct StaticApiKeyResolver {
    /// key string → (user_id, tenant_id, roles)
    keys: HashMap<String, ApiKeyEntry>,
}

struct ApiKeyEntry {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    roles: Vec<String>,
    description: String,
}

impl IdentityResolver for StaticApiKeyResolver {
    fn name(&self) -> &'static str { "static_api_key" }

    fn can_resolve(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::ApiKey(_))
    }

    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
        let result = match credential {
            Credential::ApiKey(key) => {
                match self.keys.get(key.as_str()) {
                    Some(entry) => Ok(Identity::new(/* ... */)),
                    None => Err(Error::InvalidCredential("unknown API key".into())),
                }
            }
            _ => Err(Error::InvalidCredential("expected ApiKey credential".into())),
        };
        Box::pin(std::future::ready(result))
    }
}
```

**JWT claims structure** (used by the CognitoJwtResolver in #4, defined here because it's a data type):

```rust
/// Raw JWT claims as deserialized from the token payload.
/// This is untrusted input — it becomes an Identity after validation.
pub struct JwtClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Option<String>,
    pub exp: u64,
    pub iat: u64,
    pub token_use: String,
    pub scope: Option<String>,
    pub cognito_groups: Option<Vec<String>>,
    pub custom_claims: HashMap<String, serde_json::Value>,
}
```

**Provide a test builder** (behind feature flag):

```rust
#[cfg(feature = "test-support")]
pub struct IdentityBuilder { /* ... */ }

#[cfg(feature = "test-support")]
impl IdentityBuilder {
    pub fn new(user_id: UserId) -> Self { /* ... */ }
    pub fn tenant(mut self, id: TenantId) -> Self { /* ... */ }
    pub fn roles(mut self, roles: Vec<String>) -> Self { /* ... */ }
    pub fn resolver(mut self, name: &'static str) -> Self { /* ... */ }
    pub fn build(self) -> Identity { /* ... */ }
}
```

**Errors:**

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no resolver available for credential type: {credential_type}")]
    NoResolver { credential_type: String },
    #[error("token expired")]
    TokenExpired,
    #[error("invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },
    #[error("invalid audience")]
    InvalidAudience,
    #[error("missing required claim: {0}")]
    MissingClaim(String),
    #[error("malformed token: {0}")]
    MalformedToken(String),
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
}
```

**Tests:**
- `IdentityChain` with JWT resolver + API key resolver: Bearer credential → JWT resolver handles it, ApiKey credential → API key resolver handles it
- `IdentityChain`: resolver returns `can_resolve() == false` → skipped, next resolver tried
- `IdentityChain`: resolver claims credential but fails to resolve → error returned (no fallthrough)
- `IdentityChain`: no resolver matches → `Error::NoResolver`
- `StaticApiKeyResolver`: known key → correct `Identity`
- `StaticApiKeyResolver`: unknown key → `Error::InvalidCredential`
- `Identity` cannot be constructed outside the crate (compile-time verification)
- `test-support` feature enables the builder
- **No `http` import anywhere in this crate** — verified by CI (`cargo tree -p forgegate_authn_core | grep -c "http"` == 0)

---

## Issue #3: `forgegate_authz_core` — Policy engine trait and authorization types

**Crate:** `crates/authz-core/` (pure, no I/O, **no `http` dependency**)
**Labels:** `authz`, `pure`, `layer-1`
**Blocked by:** #1
**Unblocks:** #5, #7

### Description

Define the authorization domain: "can principal P perform action A on resource R given context C?" This crate provides a pure trait for answering that question.

The `PolicyEngine` trait takes a `PolicyQuery` (principal + action + resource + context) and returns a `PolicyDecision` (allow or deny).

This crate has zero dependencies on `http`, `tokio`, AWS SDKs, or any I/O library. It compiles to `wasm32-unknown-unknown`.

### Acceptance Criteria

**Policy query — the protocol-agnostic input:**

```rust
use forgegate_core::{QualifiedAction, ResourceRef, PrincipalRef, TenantId};

/// The question: "can this principal do this action on this resource?"
/// No HTTP methods, no URL paths, no protocol-specific anything.
pub struct PolicyQuery {
    pub principal: PrincipalRef,
    pub action: QualifiedAction,
    pub resource: Option<ResourceRef>,
    pub context: PolicyContext,
}

/// Additional context for policy evaluation
pub struct PolicyContext {
    pub tenant_id: Option<TenantId>,
    pub roles: Vec<String>,
    pub ip_address: Option<IpAddr>,
    pub attributes: HashMap<String, serde_json::Value>,
}
```

**Policy decision — the answer:**

```rust
pub enum PolicyDecision {
    Allow,
    Deny { reason: DenyReason },
}

pub enum DenyReason {
    /// No matching ALLOW policy found
    NoMatchingPolicy,
    /// An explicit DENY policy matched
    ExplicitDeny { policy_id: String },
    /// Authorization service returned an error
    EvaluationError(String),
}
```

**Policy engine trait — the pluggable socket:**

```rust
/// Pure: takes a query, returns a decision.
/// No Verified Permissions, no HTTP, no I/O. The Verified Permissions client implements this trait
/// in the I/O crate.
pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>>;
}
```

**Helper to build a PolicyQuery from an Identity:**

```rust
use forgegate_authn_core::Identity;

/// Build a policy query from an identity and an action.
/// This is a pure data transformation — no I/O, no HTTP.
pub fn build_query(
    identity: &Identity,
    action: QualifiedAction,
    resource: Option<ResourceRef>,
    extra_context: HashMap<String, serde_json::Value>,
) -> PolicyQuery {
    PolicyQuery {
        principal: PrincipalRef::new(identity.user_id().clone()),
        action,
        resource,
        context: PolicyContext {
            tenant_id: identity.tenant_id().cloned(),
            roles: identity.roles().to_vec(),
            ip_address: None,
            attributes: extra_context,
        },
    }
}
```

**Tests:**
- `PolicyQuery` construction from Identity + action + resource
- `PolicyDecision` display: useful messages for each deny reason
- `build_query` maps identity fields correctly
- **No `http` import anywhere in this crate**
- **No route matching, path patterns, or HTTP methods in this crate**

---

## Issue #4: `forgegate_authn` — Cognito JWT identity resolver

**Crate:** `crates/authn/` (I/O crate, **no `http` dependency**)
**Labels:** `authn`, `io`, `layer-2`
**Blocked by:** #1, #2
**Unblocks:** #7
**Integration tests require:** #8a (Cognito User Pool — for testing against real JWKS and real tokens)

### Description

Implement `IdentityResolver` for Cognito JWTs. This resolver takes a `Credential::Bearer(token)`, fetches the JWKS from Cognito, verifies the signature, validates claims, and produces an `Identity`.

The `CognitoJwtResolver` implements `IdentityResolver` from `authn_core`. It receives a `Credential::Bearer(token)` and returns an `Identity` by validating the JWT against Cognito's JWKS endpoint.

Dependencies: `reqwest` (JWKS fetch), `jsonwebtoken` (JWT decode/verify), `forgegate_core`, `forgegate_authn_core`.

### Acceptance Criteria

**`CognitoJwtResolver` implements `IdentityResolver`:**

```rust
pub struct CognitoJwtResolver {
    jwks_cache: JwksCache,
    config: JwtResolverConfig,
}

pub struct JwtResolverConfig {
    pub jwks_url: Url,
    pub issuer: String,
    pub audience: Option<String>,
    pub tenant_claim: String,   // e.g., "custom:org_id"
    pub roles_claim: String,    // e.g., "cognito:groups"
}

impl IdentityResolver for CognitoJwtResolver {
    fn name(&self) -> &'static str { "cognito_jwt" }

    fn can_resolve(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::Bearer(_))
    }

    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
        Box::pin(async move {
            let token = match credential {
                Credential::Bearer(t) => t,
                _ => return Err(Error::Core(
                    forgegate_authn_core::Error::InvalidCredential(
                        "expected Bearer credential".into()
                    )
                )),
            };

            // 1. Decode header (no verification) to get kid
            // 2. Look up kid in JWKS cache (fetch if miss)
            // 3. Verify signature (RS256)
            // 4. Deserialize claims into JwtClaims
            // 5. Validate: exp, iss, aud, token_use
            // 6. Extract user_id from sub, tenant_id from configured claim,
            //    roles from configured claim
            // 7. Construct Identity with resolver = "cognito_jwt"
        })
    }
}
```

**JWKS fetcher and cache:**

- Fetch JWKS from the configured URL (Cognito's `/.well-known/jwks.json`)
- Cache in memory with a configurable TTL (default: 1 hour)
- Refresh on cache miss (key ID not found — Cognito may have rotated keys)
- Use `reqwest` for HTTP (the only network dependency in this crate)
- `RwLock<HashMap<String, DecodingKey>>` — read-heavy, rare writes

**JWT processing:**

- Use `jsonwebtoken` crate for decoding and signature verification
- Support RS256 (Cognito default)
- Extract `tenant_id` from the claim name configured in `tenant_claim` (default: `custom:org_id`)
- Extract roles from the claim name configured in `roles_claim` (default: `cognito:groups`)
- Map `sub` claim to `UserId`

**Errors:**

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] forgegate_authn_core::Error),
    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),
    #[error("key not found: kid={0}")]
    KeyNotFound(String),
    #[error("signature verification failed")]
    SignatureInvalid,
}
```

**Tests:**

Unit tests (no network):
- Generate an RSA key pair, sign a JWT, create a `CognitoJwtResolver` with a pre-loaded JWKS cache, call `resolve(Credential::Bearer(token))` → correct `Identity`
- `can_resolve(Credential::Bearer(_))` → true
- `can_resolve(Credential::ApiKey(_))` → false
- Expired token → `TokenExpired`
- Wrong issuer → `InvalidIssuer`
- Unknown kid triggers JWKS refresh logic
- Missing `sub` → `MissingClaim("sub")`
- Custom claim extraction: `tenant_claim = "custom:org_id"` reads the right field
- `resolver` field on the resulting `Identity` is `"cognito_jwt"`
- **No `http` import in this crate** — verified by CI

Integration test (gated by `#[cfg(feature = "integration")]` or `#[ignore]`):
- Fetch real Cognito JWKS from a test user pool and validate structure

---

## Issue #5: `forgegate_authz` — Verified Permissions client with caching

**Crate:** `crates/authz/` (I/O crate)
**Labels:** `authz`, `io`, `layer-2`
**Blocked by:** #1, #3
**Unblocks:** #7
**Integration tests require:** #8b (Verified Permissions Policy Store — for testing against real Cedar policies)

### Description

Implement `PolicyEngine` for AWS Verified Permissions. Takes a `PolicyQuery` (from `authz_core`), calls Verified Permissions `IsAuthorized`, caches the result, and returns a `PolicyDecision`. This is the I/O boundary for authorization — the pure `PolicyEngine` trait is defined in `authz_core`, this crate provides the Verified Permissions-backed implementation.

The `VpPolicyEngine` implements `PolicyEngine` from `authz_core`. It receives a `PolicyQuery` and returns a `PolicyDecision` by calling Verified Permissions `IsAuthorized` API, with an LRU cache in front.

Dependencies: `aws-sdk-verifiedpermissions`, `tokio`, `forgegate_core`, `forgegate_authz_core`.

### Acceptance Criteria

**`VpPolicyEngine` implements `PolicyEngine`:**

```rust
pub struct VpPolicyEngine {
    vp_client: aws_sdk_verifiedpermissions::Client,
    policy_store_id: String,
    cache: AuthzCache,
}

impl PolicyEngine for VpPolicyEngine {
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
        Box::pin(async move {
            // 1. Check cache
            // 2. If miss, call Verified Permissions `IsAuthorized`
            // 3. Map Verified Permissions response to PolicyDecision
            // 4. Cache the result
            // 5. Return
        })
    }
}
```

- Use `aws-sdk-verifiedpermissions` crate
- The `PolicyQuery` already contains `QualifiedAction` and `ResourceRef` with Verified Permissions-ready methods.
  FGRN strings are used directly as Verified Permissions entity IDs — single identifier everywhere, no mapping:
  - Principal → entity type `"iam::user"`, entity ID = `to_fgrn()` = `"fgrn:acme-app:acme-corp:iam:user:user-abc123"`
  - Action → `QualifiedAction::vp_action_type()` = `"todo::action"`, `.vp_action_id()` = `"read-list"`
  - Resource → entity type `"todo::list"`, entity ID = `to_fgrn()` = `"fgrn:acme-app:acme-corp:todo:list:list-123"`
  - Context → Verified Permissions context map (roles, tenant_id, etc.)

**Decision cache:**

```rust
pub struct AuthzCache {
    inner: Mutex<LruCache<CacheKey, CachedDecision>>,
    ttl: Duration,
    max_entries: usize,
}

struct CacheKey {
    principal: UserId,
    action: QualifiedAction,    // full three-part action
    resource: Option<ResourceId>,
    tenant_id: Option<TenantId>,
}

struct CachedDecision {
    decision: Decision,
    cached_at: Instant,
}
```

- LRU eviction when max entries exceeded
- TTL-based expiry (configurable, default 60s)
- Cache key is `(user, action, resource, tenant)` tuple
- Expose cache hit/miss counters for metrics (just `AtomicU64` counters for now — no full metrics pipeline yet)

**Errors:**

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] forgegate_authz_core::Error),
    #[error("Verified Permissions error: {0}")]
    VerifiedPermissions(String),
    #[error("policy store not found: {0}")]
    PolicyStoreNotFound(String),
}
```

**Tests:**
- Unit tests with a trait-based mock: define `MockPolicyEngine` implementing `PolicyEngine` in `#[cfg(test)]` that returns preconfigured decisions
- Cache hit: second `evaluate` call with same `PolicyQuery` doesn't call Verified Permissions
- Cache miss: expired entry triggers new Verified Permissions call
- Cache eviction: LRU behavior when max entries exceeded
- Verified Permissions error → `PolicyDecision::Deny { reason: EvaluationError }`
- Verified Permissions ALLOW response → `PolicyDecision::Allow`
- Verified Permissions DENY response → `PolicyDecision::Deny { reason: NoMatchingPolicy }`
- **No `http` import in this crate** — verified by CI

Integration test (gated, requires real AWS credentials + test policy store):
- Create a simple policy in Verified Permissions, call `check`, verify ALLOW
- Call `check` for unpermitted action, verify DENY

---

## Issue #6: Proxy configuration — Route mapping and config file

**Crate:** `crates/proxy/` (HTTP adapter — this is where all HTTP-specific types live)
**Labels:** `proxy`, `config`, `layer-2`
**Blocked by:** #1, #3
**Unblocks:** #7

### Description

The proxy needs two things:

1. **Route matching** — translating `(method, path)` into `(action, resource)` for the policy engine. `RouteMapping`, `PathPattern`, `RouteMatcher`, `HttpMethod` live here.
2. **Config file** — `forgegate.toml` defines the proxy configuration: listen address, upstream URL, route mappings, provider chain order, and feature flags.

Since we don't have Smithy parsing yet, routes are defined manually in the TOML. This is also the permanent format for prototyping and small projects that don't need the full model pipeline.

### Route Matching Types (in `crates/proxy/`)

```rust
use forgegate_core::{QualifiedAction, ResourceRef, ResourceId};
use forgegate_core::features::FlagName;

/// A single HTTP route → policy action mapping.
/// This is HTTP-specific: method + path pattern → authorization query inputs.
pub struct RouteMapping {
    pub method: HttpMethod,
    pub path_pattern: PathPattern,     // e.g., "/lists/{listId}"
    pub action: QualifiedAction,       // e.g., "Todo:Read:List"
    pub resource_param: Option<String>,// path param name for resource ID
    pub feature_gate: Option<FlagName>,
}

pub enum HttpMethod {
    Get, Post, Put, Patch, Delete, Any,
}

pub struct PathPattern { /* literal segments + {param} captures */ }

pub struct RouteMatcher {
    routes: Vec<RouteMapping>,
}

impl RouteMatcher {
    pub fn from_mappings(routes: Vec<RouteMapping>) -> Self { /* ... */ }
    pub fn match_request(&self, method: &http::Method, path: &str) -> Option<MatchedRoute> { /* ... */ }
}

pub struct MatchedRoute {
    pub action: QualifiedAction,
    pub resource: Option<ResourceRef>,
    pub path_params: HashMap<String, String>,
    pub feature_gate: Option<FlagName>,
}
```

- `PathPattern` supports literal segments and `{param}` captures
- `PathPattern::matches("/lists/abc123")` returns `Some(params)` where `params["listId"] = "abc123"`
- Path matching is case-sensitive, trailing-slash tolerant

### Configuration Struct Definitions (in `crates/proxy/`)

These types are the Rust-side representation of `forgegate.toml`.

```rust
pub struct ProxyConfig {
    pub project_id: ProjectId,
    pub listen_addr: SocketAddr,
    pub upstream_url: Url,
    pub default_policy: DefaultPolicy,
    pub auth: AuthConfig,
    pub authz: AuthzConfig,
    pub features: FeaturesConfig,
    pub routes: Vec<RouteMapping>,
}

pub enum DefaultPolicy {
    Passthrough,
    Deny,
}

pub struct AuthConfig {
    pub chain_order: Option<Vec<String>>,
    pub jwt: Option<JwtProviderConfig>,
    pub api_key: Option<ApiKeyProviderConfig>,
}

pub struct JwtProviderConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub jwks_url: Url,
    pub issuer: String,
    pub audience: Option<String>,
    pub tenant_claim: String,      // default: "custom:org_id"
    pub roles_claim: String,       // default: "cognito:groups"
}

pub struct ApiKeyProviderConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub header: String,            // default: "X-API-Key"
    pub prefix: Option<String>,
    pub keys: Vec<StaticApiKey>,
}

pub struct StaticApiKey {
    pub key: String,
    pub user_id: String,
    pub tenant_id: Option<String>,
    pub roles: Vec<String>,
    pub description: Option<String>,
}

pub struct AuthzConfig {
    pub policy_store_id: String,
    pub aws_region: String,
    pub cache_ttl_seconds: u64,
    pub cache_max_entries: usize,
}

pub struct FeaturesConfig {
    pub sync_interval_seconds: Option<u64>,
    #[serde(default)]
    pub flags: HashMap<FlagName, FlagDefinition>,
}
```

All derive `Deserialize` + `Debug`. `FeaturesConfig.flags` uses `FlagName` as key — TOML keys like `"todo:ai-suggestions"` are parsed through `FlagName::Deserialize` at load time. Invalid flag names are rejected at the TOML boundary.

### Header Injection (in `crates/proxy/`)

The proxy builds an `IdentityProjection` from the resolved `Identity` and translates it into HTTP headers:

```rust
/// Per-request identity data projected into key-value pairs for upstream injection.
pub struct IdentityProjection {
    pub user_id: String,
    pub tenant_id: Option<String>,
    pub roles: Vec<String>,
    pub auth_provider: String,
    pub principal_fgrn: String,
    pub features: HashMap<String, serde_json::Value>,
}

fn inject_headers(projection: &IdentityProjection, headers: &mut http::HeaderMap) {
    headers.insert("X-ForgeGate-User-Id", projection.user_id.parse().unwrap());
    if let Some(tenant) = &projection.tenant_id {
        headers.insert("X-ForgeGate-Tenant-Id", tenant.parse().unwrap());
    }
    headers.insert("X-ForgeGate-Roles", projection.roles.join(",").parse().unwrap());
    headers.insert("X-ForgeGate-Auth-Provider", projection.auth_provider.parse().unwrap());
    headers.insert("X-ForgeGate-Principal", projection.principal_fgrn.parse().unwrap());
    // features as JSON header
}
```

| Header | Source | Example |
|--------|--------|---------|
| `X-ForgeGate-User-Id` | `identity.user_id` | `user-abc123` |
| `X-ForgeGate-Tenant-Id` | `identity.tenant_id` | `acme-corp` |
| `X-ForgeGate-Roles` | `identity.roles` | `admin,member` |
| `X-ForgeGate-Auth-Provider` | `identity.provider` | `cognito_jwt` |
| `X-ForgeGate-Principal` | `identity.to_fgrn()` | `fgrn:acme-app:acme-corp:iam:user:user-abc123` |
| `X-ForgeGate-Features` | `features` (JSON) | `{"Todo:AiSuggestions":true,"Todo:MaxUploadMb":100}` |

### Acceptance Criteria

**Config file format** (`forgegate.toml`):

```toml
project_id = "acme-app"   # Used in FGRNs — every entity ID includes this

[proxy]
listen = "0.0.0.0:8000"
upstream = "http://127.0.0.1:3000"
default_policy = "passthrough"   # "passthrough" or "deny" for unmatched routes

[auth]
# No providers list needed. Sections present + enabled = providers active.
# Default chain order: api_key → jwt (cheapest first).
# Uncomment to override:
# chain_order = ["CognitoJwt", "ApiKey"]

# ── Static API Key Provider (testing only) ──
# ⚠ For local development. NEVER use static keys in production.
[auth.api_key]
# enabled = true           # default — set to false to disable without removing config
header = "X-API-Key"
prefix = "sk-test-"

[[auth.api_key.keys]]
key = "sk-test-alice-admin"
user_id = "alice"
tenant_id = "acme-org"
roles = ["admin"]
description = "Alice — admin role, full access"

[[auth.api_key.keys]]
key = "sk-test-bob-member"
user_id = "bob"
tenant_id = "acme-org"
roles = ["member"]
description = "Bob — member role, read + write items"

[[auth.api_key.keys]]
key = "sk-test-charlie-viewer"
user_id = "charlie"
tenant_id = "acme-org"
roles = ["viewer"]
description = "Charlie — viewer role, read only"

[[auth.api_key.keys]]
key = "sk-test-eve-other-tenant"
user_id = "eve"
tenant_id = "globex-inc"
roles = ["admin"]
description = "Eve — admin of a DIFFERENT tenant (for isolation tests)"

# ── JWT Provider (Cognito) ──
[auth.jwt]
jwks_url = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123/.well-known/jwks.json"
issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123"
audience = "your-app-client-id"
tenant_claim = "custom:org_id"
roles_claim = "cognito:groups"

[authz]
policy_store_id = "ps-abc123"
aws_region = "us-east-1"
cache_ttl_seconds = 60
cache_max_entries = 10000

# ── Feature Flags ──
# Inline flag definitions. This is a permanent feature, not a stopgap.
# Even with a control plane, inline flags are always evaluated.
# Inline flags take precedence over remote flags (local override).

[features.flags."Todo:AiSuggestions"]
type = "boolean"
default = false
overrides = [
    { tenant = "acme-corp", value = true },
]

[features.flags."Todo:CheckoutFlow"]
type = "string"
default = "multi_step"
overrides = [
    { tenant = "acme-corp", value = "single_page" },
]

[features.flags."Todo:MaxUploadMb"]
type = "number"
default = 50
overrides = [
    { tenant = "acme-corp", value = 100 },
]

[features.flags."Todo:PremiumAi"]
type = "boolean"
default = false
rollout_percentage = 25   # deterministic hash of (flag, tenant, user)

# ── Routes ──
# Actions use three-part format: namespace:action:entity
# Entity IS the resource type — no separate resource_type field.
# resource_param names the path segment that holds the instance ID.

[[routes]]
method = "GET"
path = "/lists"
action = "todo:list:list"

[[routes]]
method = "POST"
path = "/lists"
action = "todo:create:list"

[[routes]]
method = "GET"
path = "/lists/{listId}"
action = "todo:read:list"
resource_param = "listId"

[[routes]]
method = "DELETE"
path = "/lists/{listId}"
action = "todo:delete:list"
resource_param = "listId"

[[routes]]
method = "POST"
path = "/lists/{listId}/archive"
action = "todo:archive:list"
resource_param = "listId"

[[routes]]
method = "POST"
path = "/items/{itemId}/complete"
action = "todo:complete:item"
resource_param = "itemId"

# Feature-gated route: proxy returns 404 when flag is disabled for this tenant.
# The app never sees the request.
[[routes]]
method = "GET"
path = "/lists/{listId}/suggestions"
action = "todo:read:list"
resource_param = "listId"
feature_gate = "todo:ai-suggestions"
```

**Config loader** (in the proxy binary):

```rust
pub fn load_config(path: &Path) -> Result<ProxyConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: ProxyConfig = toml::from_str(&content)?;
    config.validate()?;
    Ok(config)
}
```

- Validation: no duplicate routes, all actions are three-part `Namespace:Action:Entity` (enforced by `QualifiedAction::Deserialize`), paths start with `/`
- Validation: `feature_gate` references must match a defined flag name in `[features.flags.*]`
- Validation: `rollout_percentage` must be 0..=100
- Missing `resource_param` is allowed (for collection endpoints like `GET /lists`)
- Environment variable overrides: `FORGEGATE_LISTEN`, `FORGEGATE_UPSTREAM`, `FORGEGATE_POLICY_STORE_ID`, etc.
- Env vars override file values (12-factor style)

**Tests:**
- Valid config parses correctly, including feature flags and feature-gated routes
- Missing required fields → clear error message
- Duplicate routes detected
- `feature_gate` referencing undefined flag → validation error
- `rollout_percentage` > 100 → validation error
- Env var overrides work
- Empty `[features]` section is valid (no flags configured)
- Example `forgegate.toml` committed to `examples/todo-app/`

---

## Issue #7: `forgegate_proxy` — Reverse proxy with auth enforcement (Pingora)

**Crate:** `crates/proxy/` (binary, Linux-only)
**Labels:** `proxy`, `binary`, `layer-3`, `pingora`
**Blocked by:** #2, #3, #4, #5, #6, #10
**Unblocks:** #9

### Description

The HTTP adapter. This is where all protocol-specific translation happens:

- **Credential extraction:** `Authorization: Bearer <token>` → `Credential::Bearer(token)`. `X-API-Key: sk-...` → `Credential::ApiKey(key)`.
- **Route matching:** `(GET, /lists/{id})` → `(action: Todo:Read:List, resource: list_123)` using `RouteMatcher`, `PathPattern`, and `HttpMethod`.
- **Policy query construction:** combines the `Identity` from the resolver chain with the `(action, resource)` from route matching to build a `PolicyQuery` for the engine.
- **Response translation:** `PolicyDecision::Deny` → `403 Forbidden`. `NoCredential` → `401 Unauthorized`. Feature gate disabled → `404 Not Found`.
- **Header injection:** `IdentityProjection` → `X-ForgeGate-*` headers on the upstream request.

The pure domain crates (`authn_core`, `authz_core`) know nothing about HTTP. A gRPC interceptor or WebSocket middleware would be a different adapter using the same `IdentityChain` and `PolicyEngine`.

This crate handles all HTTP-to-domain translations: `http::HeaderMap` → `Credential` (authentication), `(Method, Path)` → `(QualifiedAction, ResourceRef)` (authorization), `Identity` → `X-ForgeGate-*` headers (upstream injection), and `PolicyDecision` → HTTP status codes (response).

Dependencies: `http`, `hyper`, `pingora`, `forgegate_core`, `forgegate_authn_core`, `forgegate_authz_core`, `forgegate_authn`, `forgegate_authz`.

Built on Cloudflare's Pingora framework (`pingora 0.8`, `pingora-proxy 0.8`). Pingora gives us connection pooling to upstream, HTTP/1.1 + HTTP/2 + gRPC + WebSocket proxying, zero-downtime graceful restarts, and a work-stealing async scheduler — all battle-tested at 40M+ requests/second at Cloudflare.

**Platform:** Linux-only (Pingora's tier 1 target). Local development on macOS uses Docker. The CLI (future, not this issue) will be cross-platform.

### Acceptance Criteria

**Request lifecycle mapped to Pingora phases:**

```
Client → Proxy(:8000)
  │
  ├─ request_filter (Pingora phase)
  │   │
  │   ├─ 1. Extract Credential from HTTP headers
  │   │     Authorization: Bearer <token> → Credential::Bearer(token)
  │   │     X-API-Key: sk-... → Credential::ApiKey(key)
  │   │     └─ No recognized header? → 401, return Ok(true)
  │   │
  │   ├─ 2. IdentityChain.resolve(credential)   [domain — no HTTP]
  │   │     First resolver that can_resolve() owns the outcome.
  │   │     └─ Resolver failed? → 401, return Ok(true)
  │   │     └─ Resolved? → Identity stored in CTX
  │   │
  │   ├─ 3. Evaluate feature flags (pure, no I/O)
  │   │     evaluate_flags(config, tenant_id, user_id) → ResolvedFlags
  │   │
  │   ├─ 4. Match route (RouteMatcher)
  │   │     (method, path) → (action, resource)
  │   │     └─ No match? → depends on default_policy (passthrough or deny)
  │   │
  │   ├─ 5. Check feature gate (if route has feature_gate)
  │   │     └─ Flag disabled? → 404, return Ok(true)
  │   │
  │   └─ 6. Build PolicyQuery + call PolicyEngine.evaluate()  [domain — no HTTP]
  │         └─ PolicyDecision::Deny → 403, return Ok(true)
  │         └─ PolicyDecision::Allow → return Ok(false) [continue to upstream]
  │
  ├─ upstream_peer (Pingora phase)
  │   └─ Return HttpPeer pointing to configured upstream
  │
  ├─ upstream_request_filter (Pingora phase)
  │   └─ Build IdentityProjection from Identity
  │   └─ Inject as HTTP headers:
  │      X-ForgeGate-User-Id: user-abc123
  │      X-ForgeGate-Tenant-Id: acme-corp
  │      X-ForgeGate-Roles: admin,member
  │      X-ForgeGate-Auth-Provider: static_api_key
  │      X-ForgeGate-Principal: fgrn:acme-app:acme-corp:iam:user:user-abc123
  │      X-ForgeGate-Features: {"Todo:AiSuggestions":true,"Todo:MaxUploadMb":100}
  │
  └─ logging (Pingora phase)
      └─ Structured tracing with status, user, action, latency
```

Note: `request_filter` returning `Ok(true)` means "I already sent a response, don't proxy." This is Pingora's mechanism for short-circuiting — perfect for 401/403/404 rejections.

**Implementation outline:**

```rust
use async_trait::async_trait;
use pingora::prelude::*;
use pingora_proxy::{ProxyHttp, Session};
use pingora_http::RequestHeader;

/// Per-request context, carried across all Pingora phases.
pub struct RequestCtx {
    pub identity: Option<Identity>,
    pub flags: Option<ResolvedFlags>,
    pub matched_route: Option<MatchedRoute>,
    pub request_start: Instant,
    pub method: String,
    pub path: String,
}

/// The ForgeGate proxy — implements Pingora's ProxyHttp trait.
/// This is the HTTP adapter: it translates between HTTP and the policy domain.
pub struct ForgeGateProxy {
    identity_chain: IdentityChain,        // domain: Credential → Identity
    policy_engine: Arc<dyn PolicyEngine>,  // domain: PolicyQuery → PolicyDecision
    route_matcher: RouteMatcher,           // adapter: (method, path) → (action, resource)
    flag_config: FlagConfig,
    upstream: HttpPeer,
    default_policy: DefaultPolicy,
}

#[async_trait]
impl ProxyHttp for ForgeGateProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            identity: None,
            flags: None,
            matched_route: None,
            request_start: Instant::now(),
            method: String::new(),
            path: String::new(),
        }
    }

    /// Phase 1: Auth, flags, route matching, authorization.
    /// Returns Ok(true) to short-circuit with an error response.
    /// Returns Ok(false) to continue proxying.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        let req = session.req_header();
        ctx.method = req.method.to_string();
        ctx.path = req.uri.path().to_string();

        // Handle health check before auth
        if ctx.path == "/.well-known/forgeguard/health" {
            let body = self.health_check_json();
            session.respond_json(200, &body).await?;
            return Ok(true);
        }

        // ── ADAPTER: Extract Credential from HTTP headers ──
        let credential = match extract_credential(&req.headers) {
            Some(c) => c,
            None => {
                let body = json!({ "error": "Unauthorized", "detail": "no credential" });
                session.respond_json(401, &body).await?;
                return Ok(true);
            }
        };

        // ── DOMAIN: Resolve identity ──
        let identity = match self.identity_chain.resolve(&credential).await {
            Ok(id) => id,
            Err(e) => {
                let body = json!({ "error": "Unauthorized", "detail": e.to_string() });
                session.respond_json(401, &body).await?;
                return Ok(true);
            }
        };

        // ── DOMAIN: Evaluate feature flags (pure, no I/O) ──
        let flags = evaluate_flags(
            &self.flag_config,
            identity.tenant_id(),
            identity.user_id(),
        );

        // ── ADAPTER: Match route (HTTP method + path → action + resource) ──
        let matched = self.route_matcher.match_request(
            &req.method,
            req.uri.path(),
        );

        if let Some(ref route) = matched {
            // ── ADAPTER: Check feature gate ──
            if let Some(ref gate) = route.feature_gate {
                if !flags.enabled(&gate.to_string()) {
                    let body = json!({ "error": "Not Found" });
                    session.respond_json(404, &body).await?;
                    return Ok(true);
                }
            }

            // ── DOMAIN: Build PolicyQuery and evaluate ──
            let query = build_query(
                &identity,
                route.action.clone(),
                route.resource.clone(),
                HashMap::new(),
            );
            match self.policy_engine.evaluate(&query).await? {
                PolicyDecision::Allow => {}
                PolicyDecision::Deny { reason } => {
                    // ── ADAPTER: Translate domain decision to HTTP response ──
                    let body = json!({
                        "error": "Forbidden",
                        "action": route.action.to_string(),
                    });
                    session.respond_json(403, &body).await?;
                    return Ok(true);
                }
            }
        } else if self.default_policy == DefaultPolicy::Deny {
            let body = json!({ "error": "Forbidden", "detail": "unmatched route" });
            session.respond_json(403, &body).await?;
            return Ok(true);
        }

        // Store in CTX for header injection in upstream_request_filter
        ctx.identity = Some(identity);
        ctx.flags = Some(flags);
        ctx.matched_route = matched;

        Ok(false) // Continue to upstream
    }

    /// Phase 2: Select upstream target.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(self.upstream.clone()))
    }

    /// Phase 3: Inject identity + feature flag headers before sending to upstream.
    /// IdentityProjection → HTTP headers.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(ref identity) = ctx.identity {
            // DOMAIN: Build projection (pure data transformation)
            let projection = IdentityProjection::from_identity(identity);

            // ADAPTER: Inject into HTTP headers
            inject_headers(&projection, &mut upstream_request.headers);
        }
        if let Some(ref flags) = ctx.flags {
            inject_feature_headers(flags, &mut upstream_request.headers);
        }
        Ok(())
    }

    /// Phase 4: Structured logging after request completes.
    async fn logging(
        &self,
        session: &mut Session,
        _error: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = session.response_written()
            .map_or(0, |r| r.status.as_u16());
        let latency_ms = ctx.request_start.elapsed().as_millis();

        tracing::info!(
            method = %ctx.method,
            path = %ctx.path,
            status,
            user = ctx.identity.as_ref().map(|a| a.user_id().as_str()).unwrap_or("-"),
            tenant = ctx.identity.as_ref().and_then(|a| a.tenant_id()).map(|t| t.as_str()).unwrap_or("-"),
            resolver = ctx.identity.as_ref().map(|a| a.resolver()).unwrap_or("-"),
            action = ctx.matched_route.as_ref().map(|r| r.action.as_str()).unwrap_or("-"),
            latency_ms,
        );
    }
}

fn main() {
    // Pingora server setup
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let config = load_config(&args.config_path).unwrap();
    let identity_chain = build_identity_chain(&config.auth).unwrap();
    let policy_engine: Arc<dyn PolicyEngine> = Arc::new(
        VpPolicyEngine::new(&config.authz).unwrap()
    );
    let route_matcher = RouteMatcher::from_mappings(config.routes.clone());
    let flag_config = FlagConfig { flags: config.features.flags.clone() };

    let upstream = HttpPeer::new(
        config.proxy.upstream.as_str(),
        false,  // no TLS to upstream (local dev)
        String::new(),
    );

    let proxy = ForgeGateProxy {
        identity_chain,
        policy_engine,
        route_matcher,
        flag_config,
        upstream,
        default_policy: config.proxy.default_policy,
    };

    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.proxy.listen);

    // Optional: Prometheus metrics on a separate port
    let mut prometheus = Service::prometheus_http_service();
    prometheus.add_tcp("127.0.0.1:9090");

    server.add_service(proxy_service);
    server.add_service(prometheus);

    tracing::info!(
        listen = %config.proxy.listen,
        upstream = %config.proxy.upstream,
        routes = config.routes.len(),
        flags = flag_config.flags.len(),
        "ForgeGate proxy started (Pingora)"
    );

    server.run_forever();
}
```

**What Pingora gives us for free:**
- Connection pooling to upstream (reuses connections)
- HTTP/1.1 + HTTP/2 end-to-end, gRPC, WebSocket proxying
- Zero-downtime graceful restarts (`SIGQUIT` → drain connections → replace binary)
- Work-stealing async scheduler
- Built-in Prometheus metrics endpoint (on separate port)
- Rate limiting via `pingora-limits` (future use)
- `request_filter` returning `true` short-circuits without touching upstream

**Health check:** `GET /.well-known/forgeguard/health` is handled in `request_filter` before auth, returning 200 with:

```json
{
  "status": "healthy",
  "upstream": "reachable",
  "identity_providers": ["StaticApiKey", "CognitoJwt"],
  "jwks_cached": true,
  "authz_cache_entries": 42,
  "authz_cache_hit_rate": 0.87,
  "feature_flags": 4
}
```

**Error responses:**

- `401 Unauthorized`: no provider recognized the credential, or provider failed validation
- `403 Forbidden`: authorization denied (include action in response body for debugging)
- `404 Not Found`: feature-gated route where the flag is disabled for this tenant/user
- `502 Bad Gateway`: upstream unreachable (Pingora handles this via `fail_to_proxy`)
- All error responses are JSON: `{ "error": "...", "detail": "..." }`

**Structured logging:**

```
INFO  forgegate_proxy: started listen=0.0.0.0:8000 upstream=http://127.0.0.1:3000 routes=12 flags=4 runtime=pingora
INFO  forgegate_proxy: request method=GET path=/lists status=200 user=user-abc123 tenant=acme-corp action=Todo:Read:List provider=CognitoJwt latency_ms=4
INFO  forgegate_proxy: request method=GET path=/lists/abc/suggestions status=200 user=user-abc123 tenant=acme-corp action=Todo:Read:List provider=CognitoJwt gate=Todo:AiSuggestions latency_ms=6
WARN  forgegate_proxy: request method=GET path=/lists/abc/suggestions status=404 user=user_xyz789 tenant=tenant_other gate=Todo:AiSuggestions latency_ms=1
WARN  forgegate_proxy: request method=POST path=/lists status=403 user=user_xyz789 tenant=acme-corp action=Todo:Create:List provider=CognitoJwt latency_ms=3
WARN  forgegate_proxy: request method=GET path=/lists status=401 user=- error="token expired" latency_ms=2
ERROR forgegate_proxy: request method=GET path=/lists status=502 error="connection refused" latency_ms=1
```

**Docker for local dev on macOS:**

```dockerfile
# Dockerfile.proxy (in crates/proxy/)
FROM rust:1.84-slim AS builder
RUN apt-get update && apt-get install -y cmake clang libssl-dev pkg-config
WORKDIR /app
COPY . .
RUN cargo build --release -p forgegate_proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/forgegate_proxy /usr/local/bin/
ENTRYPOINT ["forgegate_proxy"]
```

```yaml
# docker-compose.yml (in examples/todo-app/)
services:
  proxy:
    build:
      context: ../../
      dockerfile: crates/proxy/Dockerfile.proxy
    ports:
      - "8000:8000"
      - "9090:9090"   # Prometheus metrics
    volumes:
      - ./forgegate.toml:/etc/forgegate/forgegate.toml:ro
    command: ["--config", "/etc/forgegate/forgegate.toml"]
    environment:
      - AWS_REGION=us-east-1
      - AWS_ACCESS_KEY_ID
      - AWS_SECRET_ACCESS_KEY
      - RUST_LOG=info,forgegate=debug
```

**Dependencies for `crates/proxy/Cargo.toml`:**

```toml
[dependencies]
forgegate_core = { path = "../core" }
forgegate_authn_core = { path = "../authn-core" }
forgegate_authn = { path = "../authn" }
forgegate_authz_core = { path = "../authz-core" }
forgegate_authz = { path = "../authz" }

pingora = { version = "0.8", features = ["proxy"] }
pingora-core = "0.8"
pingora-proxy = "0.8"
pingora-http = "0.8"
async-trait = "0.1"

serde = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
color-eyre = { workspace = true }
```

Pingora owns the HTTP layer entirely — no separate HTTP client or tower middleware needed.

**Tests:**
- Unit tests for the `ForgeGateProxy` with mocked `IdentityChain` and mocked `PolicyEngine` — Pingora provides `Session` test utilities
- Valid credential + allowed action → upstream receives request with all 6 injected headers (`User-Id`, `Tenant-Id`, `Roles`, `Auth-Provider`, `Principal` FGRN, `Features` JSON)
- Valid credential + denied action → 403 JSON response
- No credential extracted by any provider → 401
- Provider extracts but fails to resolve (expired token) → 401 (chain stops)
- Unmatched route + `default_policy = "passthrough"` → proxied without auth check, flags still injected
- Unmatched route + `default_policy = "deny"` → 403
- Feature-gated route + flag enabled → 200 (proceeds to authz)
- Feature-gated route + flag disabled → 404 (never reaches authz)
- Non-gated route still has `X-ForgeGate-Features` header with all resolved flags
- Health check at `/.well-known/forgeguard/health` returns 200 before auth (no token needed)
- Prometheus metrics endpoint on separate port
- Docker build succeeds and proxy starts in container

---

## Issue #8a: AWS bootstrap — Cognito User Pool for development

**Labels:** `infra`, `devex`, `authn`
**Blocked by:** nothing (can run in parallel with all code issues)
**Unblocks:** #4 (integration tests), #8b, #9

### Description

Provision the minimal Cognito infrastructure needed to issue real JWTs for development and testing. This is intentionally scoped to identity only — no Verified Permissions, no Cedar, no authorization. It unblocks Issue #4's integration tests and lets developers get real tokens flowing through the proxy early.

**Why real Cognito, not LocalStack:**

- LocalStack's Cognito support requires a Pro license (paid)
- Verified Permissions isn't supported by LocalStack at all, so we'd need real AWS anyway for #5
- Two infrastructure paths (LocalStack + real AWS) doubles the maintenance surface
- Unit tests in #4 already work without any infrastructure (self-signed JWTs with in-process JWKS)
- The only thing that needs real Cognito is integration tests and the e2e demo

### Acceptance Criteria

**Cognito User Pool:**
- Email-based sign-up
- App client with SRP auth enabled
- Custom attribute: `org_id` (string)
- Groups: `admin`, `member`, `viewer` (these become JWT `cognito:groups` claims)

**Two test tenants with users:**

Tenant `acme-org`:
- `alice` — `admin` group, `custom:org_id = "acme-corp"`
- `bob` — `member` group, `custom:org_id = "acme-corp"`
- `charlie` — `viewer` group, `custom:org_id = "acme-corp"`

Tenant `initech`:
- `dave` — `admin` group, `custom:org_id = "tenant_initech"`
- `eve` — `member` group, `custom:org_id = "tenant_initech"`

Two tenants are required to test tenant isolation and feature flag scoping later.

**Delivery format:**
- CDK stack in `infra/dev/cognito/`
- A `README.md` with manual setup instructions as fallback
- Script to create test users: `xtask dev-setup --cognito`

**Output:**
- Populated values in `forgegate.dev.toml` (JWKS URL, issuer, app client ID)
- A helper command to get a test JWT: `xtask dev-token --user alice`
- A helper to list all test users and their tenants: `xtask dev-users`

**Verification:** After running `xtask dev-setup --cognito`:

```bash
# Get a token for alice
TOKEN=$(cargo xtask dev-token --user alice)

# Decode it (no verification, just inspect claims)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .
# Should show: sub, iss, cognito:groups=["admin"], custom:org_id="acme-corp"
```

This is everything Issue #4 needs for its integration tests. Verified Permissions comes separately in #8b.

---

## Issue #8b: AWS bootstrap — Verified Permissions policy store for development

**Labels:** `infra`, `devex`, `authz`
**Blocked by:** #8a (Cognito must exist first — Verified Permissions policies reference user/group entities)
**Unblocks:** #5 (integration tests), #9

### Description

Provision the Verified Permissions policy store with the Cedar schema and policies for the TODO app example. This is the authorization infrastructure — separated from Cognito (#8a) so that identity and authorization can be developed and tested independently.

Cedar actions use the three-part `Namespace:Action:Entity` format (e.g., `Todo:Read:List`, `Todo:Complete:Item`). Policies reference these actions directly.

### Acceptance Criteria

**Verified Permissions Policy Store:**
- Cedar schema using `Iam` for principals and `Todo` namespace for resources.
  Entity IDs are FGRNs — the same string that appears in headers, logs, and API responses:

```cedar
namespace Iam {
    entity user in [group] {};
    entity group {};
}

namespace Todo {
    entity list {};
    entity item {};

    action "read-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "list-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "create-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "delete-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "archive-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "share-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "read-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
    action "create-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
    action "update-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
    action "delete-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
    action "complete-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
}
```

Note: Cedar action IDs are `Action+Entity` concatenated (e.g., `"read-list"`, `"complete-item"`) — this is the output of `QualifiedAction::vp_action_id()`. The three-part `Namespace:Action:Entity` format is ForgeGate's canonical format; Cedar sees the concatenated form.

- Cedar policies matching the TODO app role matrix:
  - `viewer`: `read-list`, `list-list`, `read-item`
  - `member`: viewer permissions + `create-list`, `create-item`, `update-item`, `delete-item`, `complete-item`
  - `admin`: all actions

```cedar
// viewer — FGRN entity IDs: iam::group::"fgrn:acme-app:acme-corp:iam:group:viewer"
permit(
    principal in iam::group::"fgrn:acme-app:acme-corp:iam:group:viewer",
    action in [
        todo::action::"read-list",
        todo::action::"list-list",
        todo::action::"read-item"
    ],
    resource
);

// member
permit(
    principal in iam::group::"fgrn:acme-app:acme-corp:iam:group:member",
    action in [
        todo::action::"read-list",
        todo::action::"list-list",
        todo::action::"create-list",
        todo::action::"read-item",
        todo::action::"create-item",
        todo::action::"update-item",
        todo::action::"delete-item",
        todo::action::"complete-item"
    ],
    resource
);

// admin
permit(
    principal in iam::group::"fgrn:acme-app:acme-corp:iam:group:admin",
    action,
    resource
);
```

**Verified Permissions entity registration** — entities must be registered in the policy store with FGRN entity IDs:

```
# Roles (groups)
iam::group  "fgrn:acme-app:acme-corp:iam:group:admin"
iam::group  "fgrn:acme-app:acme-corp:iam:group:member"
iam::group  "fgrn:acme-app:acme-corp:iam:group:viewer"

# Users (members of roles)
iam::user  "fgrn:acme-app:acme-corp:iam:user:alice"    parents: [iam::group::"fgrn:acme-app:acme-corp:iam:group:admin"]
iam::user  "fgrn:acme-app:acme-corp:iam:user:bob"      parents: [iam::group::"fgrn:acme-app:acme-corp:iam:group:member"]
iam::user  "fgrn:acme-app:acme-corp:iam:user:charlie"   parents: [iam::group::"fgrn:acme-app:acme-corp:iam:group:viewer"]
iam::user  "fgrn:acme-app:acme-corp:iam:user:dave"      parents: [iam::group::"fgrn:acme-app:acme-corp:iam:group:admin"]
iam::user  "fgrn:acme-app:acme-corp:iam:user:eve"       parents: [iam::group::"fgrn:acme-app:acme-corp:iam:group:member"]
```

The proxy constructs these same FGRNs at runtime from `project_id` + JWT claims. The Verified Permissions entity IDs match exactly — no mapping, no translation.

**Delivery format:**
- CDK stack in `infra/dev/verified-permissions/`
- Script: `xtask dev-setup --vp` (assumes Cognito from #8a already exists)
- `xtask dev-setup --all` runs both #8a and #8b together

**Verification:** After running `xtask dev-setup --vp`:

```bash
# Check that Verified Permissions evaluates correctly via CLI (or a test script)
aws verifiedpermissions is-authorized \
  --policy-store-id $POLICY_STORE_ID \
  --principal '{"entityType":"iam::user","entityId":"fgrn:acme-app:acme-corp:iam:user:alice"}' \
  --action '{"actionType":"todo::action","actionId":"delete-list"}' \
  --resource '{"entityType":"todo::list","entityId":"any"}' \
  --entities '...'
# → ALLOW (alice is admin)

aws verifiedpermissions is-authorized \
  --policy-store-id $POLICY_STORE_ID \
  --principal '{"entityType":"iam::user","entityId":"fgrn:acme-app:acme-corp:iam:user:charlie"}' \
  --action '{"actionType":"todo::action","actionId":"delete-list"}' \
  --resource '{"entityType":"todo::list","entityId":"any"}' \
  --entities '...'
# → DENY (charlie is viewer)
```

---

## Issue #9: End-to-end demo — TODO app behind the proxy

**Labels:** `demo`, `e2e`, `layer-4`
**Blocked by:** #7, #8a, #8b, #10
**Unblocks:** nothing (this IS the milestone)

### Description

A working end-to-end demonstration: a simple TODO API in Python (FastAPI) running behind the ForgeGate proxy, with real Cognito JWTs for human users, static API keys for service-to-service callers, and real Verified Permissions authorization. Python is deliberate — it matches the tutorial in Doc 14 and proves the proxy is language-agnostic.

The demo app has zero ForgeGate imports — it reads `X-ForgeGate-*` headers injected by the proxy. It never sees a JWT, never calls Verified Permissions, never checks a policy.

### Acceptance Criteria

**Demo app** in `examples/todo-app/`:

- 6-8 endpoints matching the TODO tutorial (lists CRUD + items CRUD + complete + archive)
- One feature-gated endpoint: `GET /lists/{listId}/suggestions` (gated by `Todo:AiSuggestions`)
- One endpoint that reads a flag from `X-ForgeGate-Features` for branching behavior (e.g., `Todo:MaxUploadMb`)
- Reads `X-ForgeGate-User-Id`, `X-ForgeGate-Tenant-Id`, and `X-ForgeGate-Features` from headers
- In-memory data store (HashMap, no database dependency)
- Zero auth code in the app
- Zero feature flag code in the app (except reading the header)

**`forgegate.toml`** in `examples/todo-app/`:

- Route mappings for all endpoints
- Points to the Cognito + Verified Permissions resources from #8
- Inline feature flag definitions:
  - `Todo:AiSuggestions`: boolean, default false, enabled for `acme-corp`, disabled for `tenant_initech` (the default)
  - `Todo:MaxUploadMb`: number, default 50, overridden to 100 for `acme-corp`, default for `tenant_initech`
  - `Todo:PremiumAi`: boolean, default false, 25% rollout (tenant-independent — tests deterministic hashing)

**Demo script** (`examples/todo-app/demo.sh` or documented in README):

```bash
# Terminal 1: Start the app (Python, runs natively on macOS/Linux)
cd examples/todo-app && python -m uvicorn app:app --port 3000

# Terminal 2: Start the proxy (Pingora, via Docker on macOS or native on Linux)
# On macOS:
docker compose -f examples/todo-app/docker-compose.yml up proxy
# On Linux (native):
cargo run -p forgegate_proxy -- --config examples/todo-app/forgegate.toml

# Terminal 3: Test it
TOKEN_ALICE=$(cargo xtask dev-token --user alice)       # admin, acme-corp
TOKEN_BOB=$(cargo xtask dev-token --user bob)           # member, acme-corp
TOKEN_CHARLIE=$(cargo xtask dev-token --user charlie)   # viewer, acme-corp
TOKEN_DAVE=$(cargo xtask dev-token --user dave)         # admin, tenant_initech
TOKEN_EVE=$(cargo xtask dev-token --user eve)           # member, tenant_initech

# ── Auth enforcement ──

# alice (admin) creates a list — should succeed
curl -s -X POST http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{"name":"Sprint tasks"}' | jq .
# → 201

# charlie (viewer) tries to create a list — should be denied
curl -s -X POST http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_CHARLIE" \
  -H "Content-Type: application/json" \
  -d '{"name":"My list"}' | jq .
# → 403 {"error":"Forbidden","action":"Todo:Create:List"}

# charlie (viewer) reads lists — should succeed
curl -s http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_CHARLIE" | jq .
# → 200

# no token — should be rejected
curl -s http://localhost:8000/lists | jq .
# → 401 {"error":"Unauthorized"}

# ── API key authentication (service-to-service) ──

# API keys are defined in forgegate.toml with hashed values.
# The proxy tries api_key first (fast HashMap lookup), then jwt.

# CI pipeline key (member role) creates an item — should succeed
curl -s -X POST http://localhost:8000/lists/list_001/items \
  -H "X-API-Key: sk-test-bob-member" \
  -H "Content-Type: application/json" \
  -d '{"title":"Deployed by CI"}' | jq .
# → 201

# viewer key tries to create — should be denied
curl -s -X POST http://localhost:8000/lists \
  -H "X-API-Key: sk-test-charlie-viewer" \
  -H "Content-Type: application/json" \
  -d '{"name":"Nope"}' | jq .
# → 403 {"error":"Forbidden","action":"Todo:Create:List"}

# invalid key — should be rejected
curl -s http://localhost:8000/lists \
  -H "X-API-Key: sk-does-not-exist" | jq .
# → 401 {"error":"Unauthorized"}

# debug/context shows provider = "StaticApiKey" for API key auth
curl -s http://localhost:8000/debug/context \
  -H "X-API-Key: sk-test-alice-admin" | jq .provider
# → "StaticApiKey"

# debug/context shows provider = "CognitoJwt" for JWT auth
curl -s http://localhost:8000/debug/context \
  -H "Authorization: Bearer $TOKEN_ALICE" | jq .provider
# → "CognitoJwt"

# ── Feature flags: the enabled path ──

# alice (acme-corp) requests AI suggestions — should succeed
# (Todo:AiSuggestions is enabled for acme-corp in forgegate.toml)
curl -s http://localhost:8000/lists/list_001/suggestions \
  -H "Authorization: Bearer $TOKEN_ALICE" | jq .
# → 200 {"suggestions": ["Buy groceries", "Review PR #42"]}

# ── Feature flags: the disabled path ──

# dave (tenant_initech) requests the same endpoint — should get 404
# (Todo:AiSuggestions is NOT enabled for tenant_initech — default is false)
curl -s http://localhost:8000/lists/list_001/suggestions \
  -H "Authorization: Bearer $TOKEN_DAVE" | jq .
# → 404 {"error":"Not Found"}
# The proxy never forwarded the request. The endpoint doesn't exist for this tenant.

# dave CAN access non-gated endpoints — he's authenticated and authorized
curl -s http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_DAVE" | jq .
# → 200 (empty list — different tenant, different data)

# ── Feature flags: header injection ──

# All proxied requests get the resolved flags as a JSON header,
# regardless of whether the route is gated:
curl -s http://localhost:8000/debug/context \
  -H "Authorization: Bearer $TOKEN_ALICE" | jq .
# → {
#     "user_id": "user_alice",
#     "tenant_id": "acme-corp",
#     "roles": "admin",
#     "provider": "CognitoJwt",
#     "features": {"Todo:AiSuggestions": true, "Todo:MaxUploadMb": 100, "Todo:PremiumAi": false},
#     "max_upload_mb": 100
#   }

curl -s http://localhost:8000/debug/context \
  -H "Authorization: Bearer $TOKEN_DAVE" | jq .
# → {
#     "user_id": "user_dave",
#     "tenant_id": "tenant_initech",
#     "features": {"Todo:AiSuggestions": false, "Todo:MaxUploadMb": 50, "Todo:PremiumAi": false},
#     "max_upload_mb": 50
#   }
# Same app, same proxy, different tenant → different flag values.
```

**Demo app feature flag usage** (in `app.py`):

```python
import json

@app.get("/lists/{list_id}/suggestions")
async def get_suggestions(list_id: str, request: Request):
    # This endpoint only receives requests when Todo:AiSuggestions is enabled
    # for this tenant — the proxy returns 404 otherwise.
    # The app doesn't check the flag. It just handles the request.
    return {"suggestions": ["Buy groceries", "Review PR #42"]}


@app.get("/debug/context")
async def debug_context(request: Request):
    """Debug endpoint that echoes the full resolved context."""
    features = json.loads(request.headers.get("X-ForgeGate-Features", "{}"))
    return {
        "user_id": request.headers.get("X-ForgeGate-User-Id"),
        "tenant_id": request.headers.get("X-ForgeGate-Tenant-Id"),
        "roles": request.headers.get("X-ForgeGate-Roles"),
        "provider": request.headers.get("X-ForgeGate-Auth-Provider"),
        "principal": request.headers.get("X-ForgeGate-Principal"),
        "features": features,
        "max_upload_mb": features.get("Todo:MaxUploadMb", 50),
    }
```

**Acceptance:**

Auth enforcement:
- Admin creates a resource → 201
- Viewer tries to create → 403
- Viewer reads → 200
- No token → 401

API key authentication:
- API key with member role creates item → 201
- API key with viewer role tries to create → 403 (same authz rules as JWT — provider doesn't matter)
- Invalid API key → 401
- `X-ForgeGate-Auth-Provider` is `static_api_key` for API key requests
- `X-ForgeGate-Auth-Provider` is `cognito_jwt` for JWT requests
- Request with both `Authorization: Bearer` and `X-API-Key` → api_key provider wins (first in chain)
- API key resolves to correct tenant, correct roles, correct user_id as configured in TOML

Feature flags — the critical scenarios:
- `acme-corp` user hits gated endpoint (flag enabled) → 200 (request reaches the app)
- `tenant_initech` user hits the same gated endpoint (flag disabled, default) → 404 (proxy blocks, app never sees the request)
- Both tenants hit a non-gated endpoint → 200 (flags don't block, but the `X-ForgeGate-Features` header shows different values per tenant)
- `X-ForgeGate-Features` header is present on ALL proxied requests, contains valid JSON, and correctly reflects per-tenant flag resolution
- Debug endpoint for `acme-corp` shows `Todo:MaxUploadMb: 100` (overridden)
- Debug endpoint for `tenant_initech` shows `Todo:MaxUploadMb: 50` (default)
- Proxy logs show `gate=Todo:AiSuggestions` on feature-gated requests

General:
- Proxy startup log shows flag count and provider list
- Health check returns `healthy` with correct flag count
- README explains the full demo from scratch including both tenants and both auth methods (JWT + API key) (prerequisites: Rust, Python, AWS credentials, CDK-deployed infra from #8a + #8b)

---

## Issue #10: Feature flag evaluation — local, deterministic, TOML-configured

**Crate:** `crates/core/` (pure, no I/O) + proxy integration in `crates/proxy/`
**Labels:** `feature-flags`, `pure`, `proxy`
**Blocked by:** #1 (needs `UserId`, `TenantId`), #6 (TOML config structure)
**Unblocks:** #9 (demo gates the `/suggestions` endpoint)

### Description

Implement local feature flag evaluation in the proxy. Flags are defined in `forgegate.toml`, evaluated per-request with zero network calls, and resolved through a four-level override hierarchy: user+tenant override → user override → tenant override → percentage rollout → default.

This mirrors the pattern from the design docs: feature flags share the permission context (who's asking, from which tenant) and answer the same kind of question ("should this entity see this thing?"), but are evaluated locally instead of calling Verified Permissions.

The flag evaluation logic lives in `forgegate_core` (pure, no I/O). It takes a `FlagName`, `TenantId`, and `UserId` and returns a `FlagValue`.

### TOML Configuration

Flags live in the `[flags.*]` section of `forgegate.toml`:

```toml
# Global flag — PascalCase, no namespace prefix
[flags.DarkMode]
type = "boolean"
default = false

# Namespace-scoped flag with percentage rollout
[flags."Todo:AiSuggestions"]
type = "boolean"
default = false
rollout_percentage = 25

# Namespace-scoped flag enabled for specific tenants
[flags."Billing:AdvancedExport"]
type = "boolean"
default = false

[[flags."Billing:AdvancedExport".overrides]]
tenant = "acme-corp"
value = true

[[flags."Billing:AdvancedExport".overrides]]
tenant = "tenant_globex"
value = true

# Namespace-scoped string variant flag (A/B test)
[flags."Todo:CheckoutFlow"]
type = "string"
default = "classic"
rollout_percentage = 30
rollout_variant = "streamlined"

[[flags."Todo:CheckoutFlow".overrides]]
tenant = "acme-corp"
value = "streamlined"

# Namespace-scoped numeric flag with tenant override
[flags."Todo:MaxUploadMb"]
type = "number"
default = 50

[[flags."Todo:MaxUploadMb".overrides]]
tenant = "acme-corp"
value = 100

# Global flag with user-level override (QA tester always sees the feature)
[flags.NewDashboard]
type = "boolean"
default = false
rollout_percentage = 10

[[flags.NewDashboard.overrides]]
user = "user_qa_alice"
value = true

[[flags.NewDashboard.overrides]]
user = "user_qa_bob"
value = true

# Namespace-scoped: tenant enabled, one user in that tenant excluded
[flags."Billing:BetaBilling"]
type = "boolean"
default = false

[[flags."Billing:BetaBilling".overrides]]
tenant = "acme-corp"
value = true

[[flags."Billing:BetaBilling".overrides]]
tenant = "acme-corp"
user = "user_finance_charlie"
value = false

# Global kill switch — evaluation short-circuits to default
[flags.MaintenanceMode]
type = "boolean"
default = false
enabled = false
```

Route-level gating ties a flag to an endpoint. Proxy returns 404 (not 403) when the flag is disabled — the endpoint doesn't "exist" for that user:

```toml
[[routes]]
method = "GET"
path = "/lists/{listId}/suggestions"
action = "Todo:Read:List"
resource_param = "listId"
feature_gate = "Todo:AiSuggestions"
```

### Acceptance Criteria

**Types** (in `forgegate_core`, pure, WASM-compatible):

```rust
pub struct FlagStore {
    flags: HashMap<FlagName, FlagDefinition>,
}

pub struct FlagDefinition {
    pub name: FlagName,
    pub flag_type: FlagType,
    pub default: FlagValue,
    pub enabled: bool,                      // kill switch
    pub rollout_percentage: Option<u8>,
    pub rollout_variant: Option<FlagValue>,
    pub overrides: Vec<FlagOverride>,       // sorted by specificity at parse time
}

pub enum FlagType { Boolean, String, Number }

#[derive(Clone, Debug, PartialEq)]
pub enum FlagValue {
    Bool(bool),
    String(String),
    Number(f64),
}

pub struct FlagOverride {
    pub tenant: Option<TenantId>,
    pub user: Option<UserId>,
    pub value: FlagValue,
}
```

**Resolution function** (pure, no I/O):

```rust
fn resolve_single_flag(
    name: &FlagName,
    flag: &FlagDefinition,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
) -> FlagValue {
    // Kill switch
    if !flag.enabled { return flag.default.clone(); }

    // Overrides (pre-sorted: user+tenant=3 > user=2 > tenant=1)
    for ov in &flag.overrides {
        let user_matches = ov.user.as_ref().map_or(true, |u| u == user_id);
        let tenant_matches = match (&ov.tenant, tenant_id) {
            (Some(t), Some(tid)) => t == tid,
            (Some(_), None) => false,
            (None, _) => true,
        };
        if user_matches && tenant_matches {
            return ov.value.clone();
        }
    }

    // Rollout
    if let Some(pct) = flag.rollout_percentage {
        let name_str = name.to_string(); // "MaintenanceMode" or "Todo:AiSuggestions"
        let bucket = deterministic_bucket(&name_str, tenant_id, user_id);
        if bucket < pct {
            return flag.rollout_variant.clone()
                .unwrap_or(FlagValue::Bool(true));
        }
    }

    // Default
    flag.default.clone()
}
```

- Overrides sorted by specificity at parse time (not at eval time)
- `deterministic_bucket` hashes `(flag_name, tenant_id, user_id)` → 0..99
- Same inputs always produce the same bucket (deterministic, no randomness)
- Different flag names produce different buckets for the same user (independent rollouts)

**Proxy integration:**

- Feature-gated routes: if `feature_gate` is set on a route and the flag evaluates to false/disabled, return 404 before authorization check
- `X-ForgeGate-Features` header injected on all proxied requests, containing JSON of all evaluated flags:
  ```
  X-ForgeGate-Features: {"Todo:AiSuggestions":true,"Todo:MaxUploadMb":100,"Todo:PremiumAi":false}
  ```
- Debug endpoint `GET /.well-known/forgeguard/flags?user_id=X&tenant_id=Y` returns all flag evaluations with resolution reasons (default, rollout, tenant_override, user_override, user_tenant_override, disabled)
- Health check includes `flags_count` field

**Config validation at startup:**
- `rollout_percentage` must be 0-100
- `type` must be "boolean", "string", or "number"
- `default` and override `value` must match the declared type
- `rollout_variant` must match the declared type
- Warn (don't fail) on overrides with no tenant and no user (matches everything, shadows default)
- Unknown flag name in `feature_gate` on a route → startup error

### Tests

Override resolution hierarchy:
- User+tenant override wins over tenant-only override (`Billing:BetaBilling`: acme=true, charlie+acme=false → charlie gets false)
- User override wins over rollout (`NewDashboard`: 10% rollout, qa_alice always true)
- Tenant override wins over rollout and default
- Kill switch (`enabled = false`) ignores all overrides and rollout
- String variant: tenant override returns the variant string, not the default
- Numeric flag: tenant override returns the overridden number

Rollout behavior:
- Deterministic: same (flag, tenant, user) always produces the same result
- Distribution: 25% rollout gives ~25% ± 3% of 10,000 test users (statistical, stable with deterministic hash)
- Independence: different flag names produce different rollout buckets for the same user population

Edge cases:
- Nonexistent flag → `None`
- Flag with no overrides and no rollout → always returns default
- Boolean rollout with no `rollout_variant` → defaults to `true`
- `rollout_percentage = 0` → nobody gets the rollout
- `rollout_percentage = 100` → everyone gets the rollout

Config validation:
- `rollout_percentage = 150` → rejected at parse time
- `type = "boolean"`, `default = "not a bool"` → rejected
- `feature_gate = "nonexistent_flag"` on a route → startup error

TOML round-trip:
- Full example `forgegate.toml` parses without errors
- All flags from the TODO demo config are present and correctly typed

### Where This Lives

| What | Where | Why |
|------|-------|-----|
| `FlagStore`, `FlagDefinition`, `FlagValue`, `FlagOverride`, `resolve_single_flag`, `deterministic_bucket` | `forgegate_core` (pure) | No I/O. Must compile to WASM for future SDK use. |
| TOML deserialization (`RawFlagConfig`) | `forgegate_core` (pure) | serde + toml are pure. |
| Route-level gating, header injection, debug endpoint | `forgegate_proxy` (binary) | Wires flag store into request lifecycle. |

Feature flags are a module in `forgegate_core` for now. If they grow (remote sync, experimentation, analytics), they split into `forgegate_flags_core` later.

---

## Issue Priority and Parallelism

```
Week 1:  #1 (core) + #8a (Cognito infra) in parallel
         #2 (authn-core) + #3 (authz-core) can start after #1
         #10 (feature flags) can start after #1

Week 2:  #4 (authn I/O) + #5 (authz I/O) in parallel (after their core deps)
         #4 integration tests unblocked once #8a lands
         #8b (Verified Permissions infra) can start once #8a is done
         #6 (config) in parallel
         #10 (feature flags) finishes — pure crate work done, proxy integration ready

Week 3:  #5 integration tests unblocked once #8b lands
         #7 (proxy binary) — everything wires together (authn + authz + flags + config)
         #9 (e2e demo) — the milestone
```

All Layer 1 issues (#1, #2, #3, #10) can be one-developer work. #4 and #5 can be done in parallel by two developers. #7 is the integration point where authn, authz, and feature flags all meet in the Pingora `ProxyHttp` implementation. #8a (Cognito infra) is independent and should start immediately — it's the long pole that unblocks #4 integration tests and #8b.

**Platform note:** The proxy (#7) is Linux-only (Pingora). macOS developers run it via Docker (`docker-compose.yml` provided in #9). All pure crates (#1, #2, #3, #10) and the I/O crates (#4, #5) compile on macOS — only the `forgegate_proxy` binary requires Linux.

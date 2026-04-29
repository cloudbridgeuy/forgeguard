# forgeguard-axum

ForgeGuard authentication and authorization middleware for
[Axum](https://crates.io/crates/axum). This crate runs the ForgeGuard auth
pipeline in-process -- no sidecar proxy required. It evaluates identity
resolution, authorization policies, and feature flags on every request, then
injects the results as Axum request extensions that your handlers can extract.

Requires **Axum 0.8+**.

## Quick Start

```rust,no_run
# use std::sync::Arc;
# use std::collections::HashMap;
# use forgeguard_axum::{ForgeGuard, ForgeGuardIdentity, ForgeGuardFlags, forgeguard_layer};
# use forgeguard_authn_core::{IdentityChain, StaticApiKeyResolver};
# use forgeguard_authn_core::static_api_key::ApiKeyEntry;
# use forgeguard_authz_core::{PolicyDecision, PolicyEngine, StaticPolicyEngine};
# use forgeguard_core::{FlagConfig, ProjectId, QualifiedAction, UserId, TenantId};
# use forgeguard_http::{DefaultPolicy, HttpMethod, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMapping, RouteMatcher};
# use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};
use axum::{Router, routing::get, middleware};

// 1. Define your routes
let routes = vec![
    RouteMapping::new(
        "GET".parse().unwrap(),
        "/api/items".to_string(),
        QualifiedAction::parse("myapp:read:items").unwrap(),
        None,  // resource_param
        None,  // feature_gate
    ),
];

// 2. Define public routes (no auth required)
let public_routes = vec![
    PublicRoute::new(
        "GET".parse().unwrap(),
        "/health".to_string(),
        PublicAuthMode::Anonymous,
    ),
];

// 3. Build the pipeline config
let pipeline_config = PipelineConfig::new(PipelineConfigParams {
    route_matcher: RouteMatcher::new(&routes).unwrap(),
    public_route_matcher: PublicRouteMatcher::new(&public_routes).unwrap(),
    flag_config: FlagConfig::default(),
    project_id: ProjectId::new("my-project").unwrap(),
    default_policy: DefaultPolicy::Deny, // reject unmatched routes
    debug_mode: false,
    auth_providers: vec!["api-key".to_string()],
    membership_resolver: None,
});

// 4. Build the identity chain (who is the caller?)
let mut keys = HashMap::new();
keys.insert("sk-alice-admin".to_string(), ApiKeyEntry::new(
    UserId::new("alice").unwrap(),
    Some(TenantId::new("acme").unwrap()),
    vec![],
));
let identity_chain = IdentityChain::new(vec![
    Arc::new(StaticApiKeyResolver::new(keys)),
]);

// 5. Build the policy engine (is the caller allowed?)
//    StaticPolicyEngine is for dev/testing -- use VpPolicyEngine
//    (AWS Verified Permissions) in production.
let policy_engine: Arc<dyn PolicyEngine> = Arc::new(
    StaticPolicyEngine::new(PolicyDecision::Allow),
);

// 6. Wire it all together
let fg = Arc::new(ForgeGuard::new(pipeline_config, identity_chain, policy_engine));

let app: Router = Router::new()
    .route("/health", get(health))
    .route("/api/items", get(list_items))
    .layer(middleware::from_fn_with_state(fg, forgeguard_layer));

// Handlers use extractors to access auth context
async fn health() -> &'static str {
    "ok"
}

async fn list_items(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    ForgeGuardFlags(flags): ForgeGuardFlags,
) -> String {
    match identity {
        Some(id) => format!("Hello, {}!", id.user_id()),
        None => "Hello, anonymous!".to_string(),
    }
}
```

## Concepts

`ForgeGuard` bundles three things the auth pipeline needs:

| Component | What it does | Key type |
|-----------|-------------|----------|
| **`PipelineConfig`** | Route matching, public routes, feature flags, default policy | `forgeguard_proxy_core::PipelineConfig` |
| **`IdentityChain`** | Resolves credentials to identities (JWT, API keys) | `forgeguard_authn_core::IdentityChain` |
| **`PolicyEngine`** | Authorization decisions (allow/deny per action) | `forgeguard_authz_core::PolicyEngine` |

### Pipeline Config

Defines which routes your app has, which are public, and what happens to
unmatched routes:

- **Routes** (`RouteMapping`) -- map `(method, path)` to a `QualifiedAction`
  like `"myapp:read:items"` for policy evaluation.
- **Public routes** (`PublicRoute`) -- bypass auth entirely (`Anonymous`) or
  try auth but don't require it (`Opportunistic`).
- **Default policy** -- `Deny` rejects unmatched routes; `Passthrough` allows
  them.

### Identity Chain

A chain of resolvers tried in order. The first resolver that can handle the
credential type owns the outcome. Built-in resolvers:

- `StaticApiKeyResolver` -- in-memory API key lookup (dev/testing)
- `CognitoJwtResolver` -- AWS Cognito JWT validation (production, in
  `forgeguard_authn` crate)

### Policy Engine

Decides whether an authenticated identity can perform an action. Implementations:

- `StaticPolicyEngine` -- returns a fixed decision (dev/testing, behind
  `test-support` feature)
- `VpPolicyEngine` -- AWS Verified Permissions with Cedar policies (production,
  in `forgeguard_authz` crate)

### Feature Flags

Feature flags are evaluated per-request based on the caller's identity (user,
tenant, groups). The resolved flags are injected into request extensions and
available via the `ForgeGuardFlags` extractor.

Pass a `FlagConfig` when building `PipelineConfig`. Use `FlagConfig::default()`
for no flags, or build one with flag definitions:

```rust,no_run
# use forgeguard_core::{FlagConfig, FlagDefinition, FlagDefinitionParams, FlagOverride, FlagValue, FlagType, FlagName, TenantId};
// Boolean flag -- off by default, on for a specific tenant
let name = FlagName::parse("myapp:dark-mode").unwrap();
let def = FlagDefinition::new(FlagDefinitionParams {
    flag_type: FlagType::Boolean,
    default: FlagValue::Bool(false),
    enabled: true,
    overrides: vec![FlagOverride::new(
        Some(TenantId::new("acme").unwrap()),
        None,
        None,
        FlagValue::Bool(true),
    )],
    rollout_percentage: None,
    rollout_variant: None,
});

let flag_config = FlagConfig::new([(name, def)].into_iter().collect());
// Pass flag_config to PipelineConfig::new(...)
```

In your handler, read the resolved flags:

```rust,no_run
# use forgeguard_axum::ForgeGuardFlags;
async fn my_handler(ForgeGuardFlags(flags): ForgeGuardFlags) -> String {
    let dark_mode = flags
        .as_ref()
        .map(|f| f.enabled("myapp:dark-mode"))
        .unwrap_or(false);
    format!("dark_mode={dark_mode}")
}
```

Flag types: `Boolean`, `String`, `Number`. Overrides can target a specific
tenant, user, or group. Rollout percentage enables gradual rollouts based on
a hash of user+tenant. Routes can be gated on a flag via `feature_gate` --
if the flag is disabled for the caller, the route returns 404.

## Configuration File

Instead of building the pipeline config programmatically, you can load it from
a `forgeguard.toml` file using `forgeguard_http::load_config`. This is the same
format the ForgeGuard proxy uses:

```toml
project_id = "my-project"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://127.0.0.1:3000"
default_policy = "deny"

# --- Authentication ---

[auth]
chain_order = ["jwt", "api-key"]

# JWT (AWS Cognito)
# [authn.jwt]
# jwks_url = "https://cognito-idp.<region>.amazonaws.com/<pool-id>/.well-known/jwks.json"
# issuer   = "https://cognito-idp.<region>.amazonaws.com/<pool-id>"
# audience = "<your-app-client-id>"

# Static API keys (dev/testing)
[[api_keys]]
key = "sk-test-alice-admin"
user_id = "alice"
tenant_id = "acme-corp"
groups = ["admin"]

# --- Authorization ---

# AWS Verified Permissions (production)
# [authz]
# policy_store_id = "<your-policy-store-id>"
# cache_ttl_secs = 300
# cache_max_entries = 10000

# --- Routes ---

[[routes]]
method = "GET"
path = "/api/items"
action = "myapp:read:items"

[[routes]]
method = "POST"
path = "/api/items"
action = "myapp:create:items"

[[public_routes]]
method = "GET"
path = "/health"
auth_mode = "anonymous"

# --- Feature Flags ---

# [features.flags."myapp:dark-mode"]
# type = "boolean"
# default = false
# enabled = true
# [[features.flags."myapp:dark-mode".overrides]]
# tenant = "acme-corp"
# value = true

# [features.flags."myapp:max-upload-mb"]
# type = "number"
# default = 50
# enabled = true
# [[features.flags."myapp:max-upload-mb".overrides]]
# tenant = "acme-corp"
# value = 100
```

Load it and build `ForgeGuard`:

```rust,no_run
# use std::path::Path;
# fn example() -> Result<(), Box<dyn std::error::Error>> {
let proxy_config = forgeguard_http::load_config(Path::new("forgeguard.toml"))?;
// proxy_config provides: routes, public_routes, auth chain, flags, etc.
// Use its accessors to build PipelineConfig, IdentityChain, and PolicyEngine.
# Ok(())
# }
```

See `examples/todo-app/forgeguard.toml` for a complete example with JWT, API
keys, Verified Permissions, feature flags, policies, and inline policy tests.

## Extractors

The middleware injects auth context into request extensions. Use these
extractors in your handlers:

- **`ForgeGuardIdentity(Option<Identity>)`** -- the resolved identity, or
  `None` for anonymous/public requests.
- **`ForgeGuardFlags(Option<ResolvedFlags>)`** -- evaluated feature flags, or
  `None` if no flag config is present.

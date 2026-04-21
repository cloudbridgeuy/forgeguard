# Authentication Wiring

How identity resolvers are configured, constructed, and wired into the proxy.

## Config Sections

### `[authn.jwt]` — Cognito JWT

```toml
[authn.jwt]
jwks_url = "https://cognito-idp.<region>.amazonaws.com/<pool>/.well-known/jwks.json"
issuer   = "https://cognito-idp.<region>.amazonaws.com/<pool>"
# Optional overrides (sensible defaults provided):
# audience = "client-id"
# user_id_claim = "sub"
# cache_ttl_secs = 3600
```

JWT resolution is identity-only: the token proves `sub`. Org context
(`tenant_id`) and group membership are resolved per-request from the
`X-ForgeGuard-Org-Id` header + DynamoDB membership lookup, not from JWT claims.

Phase 5b pipeline outcomes: `Ok(Some(Membership))` → identity enriched and
pipeline continues; `Ok(None)` → HTTP 403 "Not a member"; `Err(ResolveError)`
→ HTTP 500 "Internal Server Error" (I/O failure such as DynamoDB down — the
full error is logged by the resolver before returning, never leaked to the
caller).

### `[[api_keys]]` — Static API Keys (demo/dev only)

```toml
[[api_keys]]
key = "sk-test-alice-admin"
user_id = "alice"
tenant_id = "acme-corp"        # optional
groups = ["admin"]              # optional, defaults to []
```

### `[auth]` — Chain Order

```toml
[auth]
chain_order = ["jwt", "api-key"]
```

The proxy tries resolvers in order; first match wins.

## Architecture (FCIS Split)

```
Pure (no I/O)                           I/O
─────────────                           ────
authn-core:                             authn:
  IdentityResolver trait                  CognitoJwtResolver (JWKS fetch)
  Credential enum                           → principal_kind: User
    (Bearer | ApiKey | SignedRequest)     Ed25519SignatureResolver (key lookup + verify)
  Identity struct                           → principal_kind: Machine
    (includes principal_kind field)
  IdentityChain (resolver chain)        proxy/main.rs:
  StaticApiKeyResolver (HashMap)          build_identity_chain() — constructs
    → principal_kind: User                  resolvers from ProxyConfig
  SigningKeyStore trait
  InMemorySigningKeyStore               control-plane/app.rs:
                                          dynamodb_router() — wires
core:                                       [CognitoJwtResolver, Ed25519SignatureResolver]
  PrincipalKind (User | Machine)
  PrincipalRef (user_id + kind)         http:
                                          build_query() — Identity + MatchedRoute
http:                                       → PrincipalRef (kind from principal_kind)
  RawJwtConfig → JwtConfig                → PolicyQuery for authz layer
  RawApiKeyEntry → ApiKeyConfig
  extract_credential() — header → Credential
```

`PrincipalKind` is set at resolver time and propagates through the pipeline:

```
Resolver sets principal_kind
  → Identity.principal_kind()
    → build_query() → PrincipalRef::new() or PrincipalRef::machine()
      → PrincipalRef.vp_entity_type(project)
        → VP IsAuthorized call
```

## Config Parsing Flow

1. TOML → `RawAuthnConfig` + `Vec<RawApiKeyEntry>` (serde)
2. `TryFrom<RawProxyConfig>` validates:
   - `jwks_url` is a valid URL
   - `issuer` is non-empty
   - Each API key's `user_id`, `tenant_id`, `groups` are valid domain types
3. `ProxyConfig` exposes `jwt_config()` and `api_keys()` getters
4. `build_identity_chain()` reads config and constructs resolver instances

## Key Files

| File | Role |
|------|------|
| `crates/http/src/config_raw.rs` | Raw serde structs: `RawAuthnConfig`, `RawJwtConfig`, `RawApiKeyEntry` |
| `crates/http/src/config.rs` | Validated types: `JwtConfig`, `ApiKeyConfig` + parsing + tests |
| `crates/http/src/credential.rs` | `extract_credential()` — maps HTTP headers to `Credential` enum |
| `crates/authn/src/config.rs` | `JwtResolverConfig` (resolver's own config, built from `JwtConfig`) |
| `crates/authn/src/resolver.rs` | `CognitoJwtResolver` implementation |
| `crates/authn/src/ed25519_resolver.rs` | `Ed25519SignatureResolver` implementation |
| `crates/authn-core/src/static_api_key.rs` | `StaticApiKeyResolver` implementation |
| `crates/authn-core/src/signing_key_store.rs` | `SigningKeyStore` trait + `InMemorySigningKeyStore` |
| `crates/proxy/src/main.rs` | `build_identity_chain()` — wires resolvers from config |
| `crates/control-plane/src/app.rs` | `dynamodb_router()` — wires `[CognitoJwtResolver, Ed25519SignatureResolver]` |
| `crates/control-plane/src/signing_key_store.rs` | `DynamoSigningKeyStore` — DynamoDB-backed `SigningKeyStore` |

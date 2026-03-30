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
# tenant_claim = "custom:org_id"
# groups_claim = "cognito:groups"
# cache_ttl_secs = 3600
```

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
  Credential enum (Bearer | ApiKey)
  Identity struct                       proxy/main.rs:
  IdentityChain (resolver chain)          build_identity_chain() — constructs
  StaticApiKeyResolver (HashMap)            resolvers from ProxyConfig

http:
  RawJwtConfig → JwtConfig (Parse Don't Validate)
  RawApiKeyEntry → ApiKeyConfig (validates UserId/TenantId/GroupName)
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
| `crates/authn/src/config.rs` | `JwtResolverConfig` (resolver's own config, built from `JwtConfig`) |
| `crates/authn/src/resolver.rs` | `CognitoJwtResolver` implementation |
| `crates/authn-core/src/static_api_key.rs` | `StaticApiKeyResolver` implementation |
| `crates/proxy/src/main.rs` | `build_identity_chain()` — wires resolvers from config |

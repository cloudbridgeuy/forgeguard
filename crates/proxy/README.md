# forgeguard_proxy

Pingora-based auth-enforcing reverse proxy. This is an **I/O binary crate**.

Sits in front of upstream services and enforces authentication, authorization, and feature flag gating on every request.

## Classification

**Binary / I/O** -- depends on `pingora`, `forgeguard_authn`, `forgeguard_authz`, and AWS SDKs.

## Request Lifecycle

```
HTTP Request
  |
  v
Health check? --yes--> 200 OK
  |
  no
  v
Public route? --anonymous--> skip auth --> route match
  |                          |
  not-public/opportunistic   opportunistic (try auth, never reject)
  |
  v
Extract credential (Bearer / X-API-Key)
  |
  v
Resolve identity (IdentityChain)
  |
  v
Evaluate feature flags (pure)
  |
  v
Match route (RouteMatcher)
  |
  v
Feature gate check --disabled--> 404
  |
  v
Evaluate policy (PolicyEngine)
  |
  allowed --> proxy to upstream with X-ForgeGuard-* headers
  denied  --> 403
```

## Usage

```sh
forgeguard-proxy run --config forgeguard.toml
```

### CLI Options

| Flag | Env | Description |
|------|-----|-------------|
| `--config` | `FORGEGUARD_CONFIG` | Path to config file (default: `forgeguard.toml`) |
| `--listen` | `FORGEGUARD_LISTEN` | Override listen address |
| `--upstream` | `FORGEGUARD_UPSTREAM` | Override upstream URL |
| `--default-policy` | `FORGEGUARD_DEFAULT_POLICY` | Override default policy (`passthrough` or `deny`) |
| `--verbose` | `FORGEGUARD_VERBOSE` | Enable debug logging |

Precedence: CLI flag > env var > config file.

## Dependencies

| Crate | Role |
|-------|------|
| `forgeguard_http` (pure) | Config loading, route matching, credential extraction, header injection |
| `forgeguard_authn_core` (pure) | `IdentityChain`, `Identity`, `Credential` types |
| `forgeguard_authz_core` (pure) | `PolicyEngine` trait, `PolicyQuery`, `PolicyDecision` |
| `forgeguard_core` (pure) | `evaluate_flags`, `FlagConfig`, typed IDs |
| `forgeguard_authn` (I/O) | `CognitoJwtResolver` |
| `forgeguard_authz` (I/O) | `VpPolicyEngine` (AWS Verified Permissions) |
| `pingora-proxy` | `ProxyHttp` trait, HTTP proxy runtime |

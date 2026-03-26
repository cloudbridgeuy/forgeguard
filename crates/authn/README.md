# forgeguard_authn

Authentication I/O crate — Cognito JWT identity resolver.

## Classification

**I/O crate** — depends on `reqwest` (JWKS fetch), `jsonwebtoken` (signature verification), and `tokio` (async runtime). Implements the `IdentityResolver` trait from `forgeguard_authn_core`.

## Public API

- `CognitoJwtResolver` — implements `IdentityResolver` for Cognito JWTs
- `JwtResolverConfig` — configuration with JWKS URL, issuer, audience, claim mappings
- `Error` / `Result<T>` — crate error types

## Dependencies

- `forgeguard_core` — shared primitives (`UserId`, `TenantId`, `GroupName`)
- `forgeguard_authn_core` — `IdentityResolver` trait, `Identity`, `Credential`, `JwtClaims`
- `reqwest` — HTTP client for JWKS endpoint
- `jsonwebtoken` — JWT decoding and RS256 verification
- `tokio` — async runtime (RwLock for JWKS cache)

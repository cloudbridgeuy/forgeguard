# forgeguard_authn

Authentication I/O crate — Cognito JWT and Ed25519 signed-request identity resolvers.

## Classification

**I/O crate** — depends on `reqwest` (JWKS fetch), `jsonwebtoken` (signature verification), and `tokio` (async runtime). Implements the `IdentityResolver` trait from `forgeguard_authn_core`.

## Public API

- `CognitoJwtResolver` — implements `IdentityResolver` for Cognito JWTs (`Credential::Bearer`)
- `JwtResolverConfig` — configuration with JWKS URL, issuer, and (optional) audience
- `Ed25519SignatureResolver<S>` — implements `IdentityResolver` for BYOC proxy signed requests (`Credential::SignedRequest`)
- `Error` / `Result<T>` — crate error types

## JWT identity is sub-only

`CognitoJwtResolver` returns an `Identity` carrying only `user_id` (the `sub`
claim) and `PrincipalKind::User`. It does **not** read `custom:org_id` or
`cognito:groups`. Org selection and group roles are resolved per-request by
the proxy pipeline's Phase 5b from the `X-ForgeGuard-Org-Id` header plus a
`MembershipResolver` lookup (see `forgeguard_proxy_core`).

## Ed25519SignatureResolver

Generic over any `S: SigningKeyStore`. Verification steps:

1. Extract `org_id` from `X-ForgeGuard-Org-Id` (in `identity_headers`)
2. Look up the public key via `S::get_key(org_id, key_id)`
3. Rebuild the canonical payload from `trace_id`, `timestamp`, and `identity_headers`
4. Verify the Ed25519 signature
5. Validate timestamp drift (default ≤ 5 minutes; configurable via `with_max_drift`)
6. Return `Identity(user_id=key_id, tenant_id=org_id, resolver="ed25519")`

The control plane wires `Ed25519SignatureResolver<DynamoSigningKeyStore>` into the `IdentityChain` when `--store=dynamodb` and auth are both configured.

## Dependencies

- `forgeguard_core` — shared primitives (`UserId`, `TenantId`, `GroupName`)
- `forgeguard_authn_core` — `IdentityResolver` trait, `Identity`, `Credential`, `JwtClaims`, `SigningKeyStore`, Ed25519 primitives
- `reqwest` — HTTP client for JWKS endpoint
- `jsonwebtoken` — JWT decoding and RS256 verification
- `tokio` — async runtime (RwLock for JWKS cache)

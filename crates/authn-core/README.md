# forgeguard_authn_core

Identity resolution types and traits for ForgeGuard. This is a **pure crate** — no I/O dependencies.

Owns `Credential` (protocol-agnostic input), `Identity` (resolved, trusted output), the `IdentityResolver` trait, `IdentityChain` orchestrator, `StaticApiKeyResolver`, `JwtClaims` DTO, and the Ed25519 signing primitives + `SigningKeyStore` trait. I/O resolvers (Cognito JWT validation, Ed25519 key lookup) live in the `forgeguard_authn` I/O crate.

## Identity and PrincipalKind

`Identity` carries a `principal_kind: PrincipalKind` field that distinguishes human users from machine principals. It is set by each resolver at resolution time and propagated downstream:

| Resolver | `principal_kind` |
|----------|-----------------|
| `CognitoJwtResolver` | `User` |
| `StaticApiKeyResolver` | `User` |
| `Ed25519SignatureResolver` | `Machine` |

`PrincipalKind` flows through `Identity` → `build_query()` (in `forgeguard_http`) → `PrincipalRef`, where it drives Cedar entity type selection in VP authorization calls (`User` → `{ns}::user`, `Machine` → `{ns}::Machine`).

## Credential Variants

| Variant | Source | Resolved by |
|---------|--------|-------------|
| `Credential::Bearer(token)` | `Authorization: Bearer <token>` | `CognitoJwtResolver` |
| `Credential::ApiKey(key)` | `X-API-Key: <key>` | `StaticApiKeyResolver` |
| `Credential::SignedRequest { .. }` | Four `X-ForgeGuard-*` headers | `Ed25519SignatureResolver` |

`Credential::SignedRequest` carries: `key_id`, `timestamp` (Unix millis), `signature` (`v1:{base64}`), `trace_id`, and `identity_headers` (all remaining `X-ForgeGuard-*` headers, including `X-ForgeGuard-Org-Id`).

## SigningKeyStore Trait

```rust
pub trait SigningKeyStore: Send + Sync {
    fn get_key(
        &self,
        org_id: &str,
        key_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifyingKey>> + Send + '_>>;
}
```

Implementations look up an active Ed25519 public key by organization and key ID. Returns a ready-to-use `VerifyingKey` or an error (key not found, key revoked, parse failure).

| Implementation | Backend | Used by |
|---------------|---------|---------|
| `InMemorySigningKeyStore` | `HashMap<(org_id, key_id), VerifyingKey>` | Tests, dev mode |
| `DynamoSigningKeyStore` | DynamoDB (control-plane crate) | Production |

# forgeguard_authn_core

Identity resolution types and traits for ForgeGuard. This is a **pure crate** — no I/O dependencies.

Owns `Credential` (protocol-agnostic input), `Identity` (resolved, trusted output), the `IdentityResolver` trait, `IdentityChain` orchestrator, `StaticApiKeyResolver`, `JwtClaims` DTO, and the Ed25519 signing primitives + `SigningKeyStore` trait. I/O resolvers (Cognito JWT validation, Ed25519 key lookup) live in the `forgeguard_authn` I/O crate.

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

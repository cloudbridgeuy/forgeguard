# forgeguard_authn_core

Identity resolution types and traits for ForgeGuard. This is a **pure crate** — no I/O dependencies.

Owns `Credential` (protocol-agnostic input), `Identity` (resolved, trusted output), the `IdentityResolver` trait, `IdentityChain` orchestrator, `StaticApiKeyResolver`, and `JwtClaims` DTO. I/O resolvers (Cognito JWT validation, token introspection) live in the `forgeguard_authn` I/O crate.

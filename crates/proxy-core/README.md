# forgeguard_proxy_core

Auth pipeline types and pure logic for ForgeGuard proxy. This is a **pure crate** — no I/O dependencies.

Owns `PipelineOutcome` (the closed result enum for auth pipeline runs) and `PipelineConfig`. Protocol adapters pattern-match on `PipelineOutcome` to produce framework-specific responses. I/O concerns (upstream communication, identity resolution, authorization checks) live in the `forgeguard_proxy` and `forgeguard_proxy_saas` I/O crates.

## Pipeline Phases

The pipeline runs the following phases in order. Any phase may terminate early with a `PipelineOutcome` that the adapter renders.

1. Route match (resolve `RouteMatch` from method + path).
2. Public-route short-circuit (pass-through if the route is declared anonymous).
3. Credential extraction from headers.
4. Feature-flag gates (maintenance mode, auth bypasses).
5. **Identity resolution** — invoke the `IdentityResolver` chain (JWT, signed request, static API key).
6. **Phase 5b — Membership enrichment** (new): when the resolved identity is a user whose `tenant_id` is not yet set, read the `X-ForgeGuard-Org-Id` header, parse it into `OrganizationId`, call `MembershipResolver::resolve(user_id, org_id)`, and replace the identity with a copy carrying the resolved `TenantId` and the groups returned by the resolver. Missing header on a credential-required route → `400`; invalid header → `400`; non-member → `403`; machine principals skip this phase entirely.
7. Feature flags (request-scoped).
8. Authorization — invoke `PolicyEngine::evaluate(PolicyQuery)`.
9. Upstream dispatch (handled outside this crate).

## MembershipResolver

```rust
pub trait MembershipResolver: Send + Sync {
    fn resolve(
        &self,
        user_id: &UserId,
        org_id: &OrganizationId,
    ) -> Pin<Box<dyn Future<Output = Option<Membership>> + Send + '_>>;
}
```

Pure trait — implementors perform the I/O (DynamoDB `GetItem` in `forgeguard_control_plane::DynamoMembershipResolver`). Returns `Some(Membership { groups })` when the user belongs to the org, or `None` otherwise. `Membership` is constructed once at resolver boundary (`Membership::new(groups)`) and carried through the rest of Phase 5b.

The resolver is plugged into `PipelineConfig::membership_resolver` and is optional — when `None`, Phase 5b is skipped entirely (the identity keeps whatever `tenant_id` its resolver supplied, if any).

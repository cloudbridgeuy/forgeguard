# Per-request IAM scope via API Gateway + Lambda authorizer

**Date:** 2026-05-19
**Status:** accepted

## Context

The CP today is a Lambda running under a single execution role broad enough to do its job across every tenant: DynamoDB on the whole table, Verified Permissions on `*` (per-tenant store ARNs are runtime per [ADR-0003](./0003-resolution-engine-product-framing.md)), and Cognito admin on the user pool. From an AWS-account perspective the role is unremarkable. From an [ADR-0003](./0003-resolution-engine-product-framing.md)-product perspective it is the largest cross-tenant blast radius in the system: a single handler exploit reaches every tenant's data.

Static role narrowing — tag conditions, ARN enumeration, per-route policies — does not close this. The data the role must reach is partitioned at runtime by `tenant_id`, which is only known once the JWT is verified.

## Decision

Put every CP API route behind API Gateway with a custom Lambda authorizer that produces **per-request temporary credentials scoped to one tenant.**

Request flow:

1. API Gateway receives the request and invokes the authorizer Lambda.
2. The authorizer verifies the Cognito JWT (JWKS, issuer, audience).
3. The authorizer reads `tenant_id` from the verified claim. The CP's `forgeguard.toml` declares `[tenant]` with a `jwt_claim` source; the Cognito Pre-Token-Generation Lambda populates the claim from DDB-backed membership data.
4. The authorizer computes per-tenant ARNs — DDB key prefix `TENANT#{tenant_id}`, VP store ARN derived from `tenant_id`, Cognito user-scoped operations — and builds a session policy document.
5. The authorizer calls `sts:AssumeRole` on a tenant-execution-role with that session policy. STS returns temporary credentials whose effective permissions are the intersection of the role and the session policy.
6. The authorizer returns those credentials in the API Gateway response context.
7. The downstream handler Lambda reads the credentials from the request context and uses them for every DDB, VP, and Cognito call.

Two roles enter the picture:

| Role | Trust | Permissions |
|---|---|---|
| `cp-authorizer-role` | Lambda execution role for the authorizer | `sts:AssumeRole` on the tenant-execution-role, JWKS read |
| `cp-tenant-execution-role` | Assumable only by the authorizer | Broad: DDB on the table, VP on `*`, Cognito admin on the pool |

The broad role still exists — STS session policies can only narrow, not widen. What disappears is *unscoped* runtime access. The handler Lambda's own execution role gets only bootstrapping permissions; all tenant data access flows through the assumed credentials.

The pure decision logic — `build_session_policy(tenant_id, account_id, region, principal_kind) -> SessionPolicy` — lives in `crates/authn-core`. The Lambda binary lands at `crates/fg-lambdas/src/bin/cp_authorizer.rs`.

Machine principals (`PrincipalKind::Machine`, Ed25519-signed via the data-plane proxy) do not flow through API Gateway. They reach the CP through the proxy's existing signed-request path; their tenant scope is enforced by `Ed25519SignatureResolver` and the per-machine role binding, not by this ADR's pattern.

## Relationship to existing ADRs

- **[ADR-0002](./0002-cp-groups-via-effectful-extractor.md)** — orthogonal. The authorizer scopes IAM; the `dynamodb_membership` extractor still runs per-request inside the handler, now through the scoped credentials.
- **[ADR-0003](./0003-resolution-engine-product-framing.md)** — this ADR resolves the per-tenant VP-store `*`-grant critique. Per-tenant VP stores remain (schema divergence requires it); the broad IAM grant on the tenant-execution-role is acceptable because runtime credentials are scoped per request. The `tenant_id` claim this ADR consumes is sourced via the CP's `[tenant]` declaration (resolution-engine framing); the previous ADR-0001 captured the same mechanic and has been destroyed as configuration-level.

## Consequences

- Cross-tenant blast radius from a handler exploit collapses from "every tenant" to "the tenant whose JWT was in the request." This is the durable answer to the per-org-VP-store `*`-grant critique.
- CP middleware Phase 5b stops being a scope-enforcement step and becomes group-attribute resolution only.
- Every request pays one `sts:AssumeRole`. Mitigation: the authorizer caches credentials in-process keyed on `(sub, tenant_id)` and refreshes before expiry. API Gateway's authorizer response cache must include `tenant_id` in its key, or be disabled — caching a tenant-A response and replaying it for tenant-B must be impossible by construction.
- Session policy size is bounded by STS limits. The policy builder owns the budget; complex scopes that exceed inline limits must be expressed as managed-policy ARNs passed through `PolicyArns`. Worth measuring before the pattern lands.
- Requests whose **Required-slot manifest** does not include `principal.tenant_id` — e.g., `/api/v1/me` and `/api/v1/me/memberships`, where the route's principal source resolves identity but no tenant context is required — get a dedicated session policy permitting only self-scoped reads. The authorizer treats this as a first-class case, not an error. Whether a route requires tenant scope is determined by the route's manifest at config-load, not by ad-hoc handler logic.
- The pattern generalizes. The worker Lambda and any future CP-adjacent Lambda adopt the same shape — API Gateway + authorizer + tenant-scoped credentials becomes the CP-wide standard.
- CDK changes: HTTP API (or REST API if `requestContext` features dictate) in front of every CP route, the authorizer Lambda, the two roles, and the trust policy on the tenant-execution-role limiting `sts:AssumeRole` to the authorizer.
- Reversal cost is moderate. Rolling back means re-broadening the handler's execution role, dropping the authorizer, and restoring direct Lambda URLs. The pure session-policy builder survives reversal as dead code.

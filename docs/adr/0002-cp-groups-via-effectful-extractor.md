# CP-dogfood: groups via effectful DynamoDB extractor

**Date:** 2026-05-26
**Status:** accepted

## Context

A common SaaS pattern is to bake the user's roles/groups into the JWT alongside identity claims. The cost is a staleness window equal to the access-token TTL: revoking a group only takes effect on the next refresh. For an operator dashboard where role changes need to bite immediately, that window is unacceptable.

Under the resolution-engine framing ([ADR-0003](./0003-resolution-engine-product-framing.md)), "where group membership lives" is a choice among **Source catalogue** entries — `jwt_claim`, `dynamodb_membership`, `callback`, or any future addition. This ADR documents the CP-dogfood choice and the trade-off rationale, as a worked example for customers facing the same decision.

## Decision

The CP-dogfood `forgeguard.toml` uses the `dynamodb_membership` **effectful extractor** to resolve group membership per request.

- Table key shape: `PK = USER#{sub}`, `SK = ORG#{tenant_id}`.
- Inverted GSI1 (`PK = ORG#{tenant_id}`, `SK = USER#{sub}`) supports listing users per tenant.
- An in-memory cache with a ~30 s TTL fronts the lookup; the CP invalidates the cache on writes to group memberships.
- JWT carries only identity (`sub`) and (when applicable) `tenant_id`. Group attributes never enter the token.

The data-plane proxy is configured separately and may consume customer-issued JWTs that *do* carry role claims — that is a different customer's source choice, not contradicted by this ADR.

## Consequences

- Group changes propagate within ~30 s of the underlying DDB write — no token-refresh dance, no SPA ↔ CP signaling.
- The CP gains a hot-path dependency on DDB. Brief outages ride through the cache; longer outages degrade authz, which is acceptable (the CP is degraded anyway).
- JWT size stays small and bounded — a user with many group memberships does not inflate every API call.
- This is one source choice among several. A customer whose dashboard tolerates a token-lifetime staleness window can configure `jwt_claim` instead; a customer with custom membership logic can use `callback`. The choice is per-customer.
- Reversing the CP-dogfood choice (e.g., to `jwt_claim`) would require adding groups to the Cognito Pre-Token-Generation trigger, adding a refresh-on-mutation signal between CP and SPA, and reworking the authz pipeline to be claim-driven. Within the resolution-engine framing this is a configuration change, not an architectural one.

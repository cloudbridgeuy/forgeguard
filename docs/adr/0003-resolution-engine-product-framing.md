# ForgeGuard product framing: resolution engine + IdP, with DSL patterns over Cedar

**Date:** 2026-05-26
**Status:** accepted

## Context

The previous ADR-0003 ("IdP-first, IAM-shaped AAA on Cedar," 2026-05-19) declared five product claims, of which Claim #1 ("Tenant is the universal primitive") turned out to be wrong: tenancy is a common shape, not a universal one. The other four claims survived but needed reframing once we sharpened what ForgeGuard fundamentally *is*.

The reframe started by asking: what is the single thing ForgeGuard does that, if we got it right, every other concern would compose around? Answer — it turns `(HTTP request, customer config)` into a Cedar `IsAuthorized` request. That is the **resolution engine**. Everything else — the IdP, the DSL patterns, the enforcement strategies, the dashboard — composes around it.

This ADR replaces the previous 0003 in full. The full vocabulary (Resolution engine, Cedar request, Decision layer, Extractor, Source, Slot, Required-slot manifest, Authoring layers, DSL pattern, Tenancy sugar, Mandatory extractor set, Principal chain, Action scope, Action name, Engine invariants) lives in [CONTEXT.md § Glossary](../../CONTEXT.md#glossary).

## Decision

ForgeGuard is six things:

### 1. A resolution engine, with the decision layer separable

ForgeGuard's central function is to turn `(HTTP request, customer config)` into a Cedar request `(principal, action, resource, context, entities)`. The engine is pure — no I/O, no decision-making. The **decision layer** (Verified Permissions, Cedar-as-library, mock) takes the Cedar request and returns Allow/Deny.

The split is the load-bearing architectural decision: it lets customers, integrators, and open-source contributors plug new decision backends without touching the engine. The pure/effectful split inside extractors mirrors this one layer down — pure extractors work in any enforcement strategy (proxy, axum middleware, WASM, FFI); effectful extractors require host capabilities.

### 2. Customer authoring is two layers, both targeting Cedar

| Layer | What it is | Required-slot manifest source |
|---|---|---|
| **Layer 1: raw Cedar** | Customer writes Cedar `permit` / `forbid` directly | Static analysis of the policies |
| **Layer 2: DSL patterns** | Higher-level grammars in `forgeguard.toml` that compile to Cedar | Emitted by-construction during compilation |

DSL patterns ship with ForgeGuard. The current catalogue:

- **RBAC** — roles with `member` ⊂ `admin` ⊂ `owner` inheritance; compiles to Cedar permits.
- **Tenancy sugar** (opt-in) — `[tenant]` declaration auto-creates the principal-side extractor, defaults `resource.tenant_id` to inherit from `principal.tenant_id`, and auto-appends `when { principal.tenant_id == resource.tenant_id }` to DSL-compiled policies. Per-resource opt-out via `tenant_scope = "global"`.

Future patterns (ABAC sugar, sharing-grant sugar, ReBAC adapter) follow the same shape: own grammar in `forgeguard.toml`, own Cedar compilation, own required-slot manifest emission.

Raw Cedar is the documented escape hatch for any pattern the DSL does not express.

### 3. The hosted IdP is the primary commercial product

The first thing a customer gets is a hosted Identity Provider: login surface, OIDC endpoints, ForgeGuard-issued access tokens. Cognito is the current implementation; customers never see it as Cognito. Federation (SAML, OIDC, social) is on the roadmap — table-stakes for B2B, protocol details deferred to a follow-on ADR.

The IdP and the resolution engine are **decoupled**. A customer with their own IdP can use ForgeGuard's resolution engine via the proxy or axum middleware, configuring `[[principal_sources]]` to consume their own JWTs. The hosted IdP is the lead commercial offering; the resolution engine is what's underneath.

The self-hostable proxy (`crates/proxy`, `crates/proxy-saas`) is the **deployment escape hatch** for customers who need enforcement to run in their own infrastructure (regulatory, latency, residency). It is not the marketing lead.

### 4. `forgeguard.toml` is the canonical authoring artifact

A customer's entire AAA layer — action catalog, resource type schema, roles, Cedar policies/templates, per-tenant overrides, route definitions, extractors, principal chain — is declared in `forgeguard.toml`. The Dashboard UI and Management API are CRUD wrappers that produce/consume the same TOML. There is no second source of truth. Power users (and AI agents) author the TOML directly; non-technical admins use the UI. GitOps workflows are first-class — customers connect their repo, ForgeGuard pulls on push.

ForgeGuard's own CP dogfoods this: [`forgeguard.toml`](../../forgeguard.toml) at the repo root is the CP's authz config, and the public reference example for customers.

### 5. Three enforcement strategies, one compiled bundle

Customers choose how to plug enforcement into their app:

1. **`proxy`** — sidecar/gateway binary, no app changes.
2. **`forgeguard_axum`** — Axum middleware embedded in a Rust app.
3. **`forgeguard_core` / FFI bindings** — direct library use from Rust, Python (PyO3), or WASM.

All three consume the same compiled enforcement bundle (routes, action catalog, policy store ID, JWKS URL, extractor manifest) served from the CP. The choice is operational, not architectural — the customer's `forgeguard.toml` is identical regardless. Pure extractors work in all three strategies; effectful extractors require host capabilities (DDB access, callback infrastructure).

### 6. Tenancy is opt-in, not universal

Multi-tenant authorization is **one DSL pattern** (the Tenancy sugar), not a product axiom. Customers without `[tenant]` declared get flat per-resource authorization — `principal.id`, `resource.id`, resource attributes inline. ForgeGuard supports flat models just as well as multi-tenant ones; the engine does not impose tenancy.

When `[tenant]` is declared, the wire-format claim is `tenant_id` by default (customer-configurable). The display name in any UI is independent: ForgeGuard's CP renders its Tenants as "Organizations"; a customer's TODO app may render them as "Workspaces." Internal code and docs always say `tenant`.

## Relationship to other ADRs

- **Previous ADR-0001** (PTG-derived JWT tenant claim) — **destroyed**. The decision is now configuration-level: the CP-dogfood `forgeguard.toml` declares `[tenant]` with a `jwt_claim` source, populated by a Cognito Pre-Token-Generation Lambda. No decision-shaped content remains; the integrity invariant (JWT signature is the trust boundary for claim-derived slots) is captured in the **Engine invariants** entry of CONTEXT.md.
- **ADR-0002** ([CP-dogfood: groups via effectful DynamoDB extractor](./0002-cp-groups-via-effectful-extractor.md)) — replaces the previous "Groups never in JWT" ADR. The trade-off rationale is preserved, reframed as a Source catalogue choice.
- **ADR-0004** ([Per-request IAM scope via API Gateway + Lambda authorizer](./0004-api-gateway-authorizer-pattern.md)) — survives. The per-tenant IAM-scoping decision is independent of the engine framing. References to the destroyed ADR-0001 updated to point at the CP's `[tenant]` configuration.

## Consequences

- The codebase rename from `org_id` to `tenant_id` continues incrementally. The CP's internal naming (`OrganizationId` in DDB, `Organization` entity type) stays as a display-name artifact; no flag-day migration.
- Every future DSL pattern (ABAC, sharing, ReBAC adapter) ships as a Layer 2 compiler emitting Cedar + manifest, not as a new product axiom. The catalogue grows; the framing does not.
- The two-layer authoring split is what makes the product extensible without invalidating prior config: customers adopt new DSL patterns one at a time and drop into raw Cedar where the DSL does not reach.
- The CP's `forgeguard.toml` becomes a public reference example. This raises the bar on its quality and stability (breaking changes there break customer onboarding) and means every change to the CP's authz model is dual-purpose: dogfood correctness *and* documentation.
- The third A — **Auditing** — remains a placeholder. The product framing claims AAA; the auditing surface is currently absent. A future ADR (or design doc) must define what the customer-facing audit log looks like, where it lives, and how customers query/export it.
- Federation (SAML, OIDC-IdP-of-IdP, social) is deferred to its own ADR but is implied by the IdP-first claim. The open question is *which* protocols and *how* they're configured, not *whether* they exist.
- Reversal cost is the highest of any ADR in this set. Flipping back to "tenant is universal" would invalidate the locked Required-slot manifest mechanic, the per-resource `tenant_scope` knob, and the principle that policies declare what they need. Flipping back to "ForgeGuard is just an authz API, no IdP" would invalidate the hosted-login surface, the multi-tenant Cognito provisioning, and the commercial product framing. Either reversal is a multi-quarter pivot.

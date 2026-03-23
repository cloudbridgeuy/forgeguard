# ForgeGate — Discussion Summary

## Origin: A Question About AWS IAM

The conversation started with a straightforward question: **does AWS support creating custom actions (like `namespace:action`) in IAM policies?** The answer was no — IAM actions are defined by AWS services, not by users. This led to the discovery of **Amazon Verified Permissions**, a service that lets developers define their own permission models using the Cedar policy language, with custom principals, actions, and resources.

## Pivot: Could a Product Be Built Around This?

The key insight was that Verified Permissions + Cognito together provide all the primitives of a full IAM-like system — but they're painful to wire up manually. The idea emerged: **build a product that lets any developer create their own version of AWS-style authentication and authorization for their own backends.**

## Shaping the Product: Three Layers

The discussion identified that previous designs were conflating three distinct concerns that need to be separate:

1. **Design time (Schema)** — A declarative model defining resources, actions, roles, and API shape. Not application code — it's a config file or IDL that the platform ingests to provision Cedar schemas, Cognito resources, and policy stores.

2. **Admin time (AdminClient)** — A management API for runtime operations: creating users, assigning roles, enabling feature flags, managing tenants. Used by back-office tools and dashboards — never in the request hot path.

3. **Runtime (Guard)** — A thin enforcement layer that only does two things: check permissions and check feature flags. Runs in the app's process or as a proxy.

## The Smithy Connection

Recognizing that the latest AWS SDKs follow a **types + commands + `send()`** pattern (powered by Smithy, AWS's open-source interface definition language), the discussion converged on using Smithy as the schema language for ForgeGate.

The developer defines their API model in Smithy IDL, annotated with custom ForgeGate traits (`@authorize`, `@authResource`, `@featureGate`). From this single source of truth, the platform generates:

- **Cedar schema and policies** for Verified Permissions
- **Typed client SDKs** (Python, TypeScript, etc.) with auth middleware baked in — just like the AWS SDK
- **Server guard configuration** mapping routes to authorization actions

This means the schema defines both the permission model AND the API surface, enabling full SDK generation.

## UI-First Configuration

A critical evolution: Smithy is the engine, not the interface. Most developers will never write Smithy directly. ForgeGate provides a **visual dashboard** that generates Smithy behind the scenes — the same way most AWS users never see CloudFormation YAML.

The dashboard has a **Model Studio** where developers configure resources, actions, endpoints, roles, and feature flags through forms and visual builders. Under the hood, a **Model Engine** translates these domain operations into correct, idiomatic Smithy AST mutations, applying best practices automatically (typed IDs, pagination on list endpoints, `@readonly` on GETs, proper HTTP bindings).

The system is **bidirectional**: UI edits generate Smithy, and hand-edited `.smithy` files are parsed back into the UI. Developers can "eject" at any point to view and edit raw Smithy. Features the UI doesn't support are shown as read-only blocks, never lost.

The adoption ladder: **UI for onboarding, Smithy for power users, Cedar for experts.** Each layer exists but only surfaces when needed.

## Beyond CRUD: Custom Actions and RPC Operations

The model supports three categories of operations:

1. **Lifecycle operations** (auto-generated standard CRUD) — `GetDocument`, `ListDocuments`, `CreateDocument`, `DeleteDocument`
2. **Custom actions on resources** (developer-defined domain verbs) — `PublishDocument`, `ArchiveDocument`, `TransferOwnership`. These are the operations that make real applications different from generic CRUD: `approve`, `escalate`, `refund`, `rollback`.
3. **Service-level RPC operations** (no resource context) — `GenerateReport`, `BulkImport`, `CalculatePricing`. Pure verbs that don't belong to any resource.

The UI, API, and Smithy output all reflect this three-tier structure. The role matrix shows CRUD, custom actions, and service operations as separate columns.

## Feature Flags as a Natural Extension

The authorization engine was extended to support **feature flags and A/B testing per tenant**. The key insight: a feature flag answers the same question as a permission ("can this entity do this thing?"), just with different intent (rollout vs. access control).

Feature flags are evaluated locally in the proxy/wrapper using synced configuration, not per-request calls to Verified Permissions — keeping costs negligible.

## The AI Security Angle

The discussion identified a major differentiator: **ForgeGate makes AI-generated applications secure by construction.** When an AI agent (Cursor, Copilot, Claude) vibe-codes an app, authorization is either absent or fragile. ForgeGate eliminates this by making security structural rather than procedural:

- The **ASGI wrapper** (`forgegate run`) intercepts every request before it reaches the app — unauthorized requests never arrive at handler code
- The **generated SDK** gives consumers typed commands with auth baked in
- The **MCP server** generation lets AI runtime agents call tools within the authorization boundary
- The `.smithy` model serves as context for AI coding agents, guiding them to use the typed SDK

The AI never needs to write security code because security is enforced outside the application.

## Three Deployment Options

The product supports three enforcement mechanisms, all reading from the same Smithy model:

| Option | How It Works | Best For |
|--------|-------------|----------|
| `forgegate run` (ASGI/WSGI wrapper) | Same-process interception, zero infra overhead | Python apps, vibe-coded projects |
| Sidecar proxy (container) | Separate container, language-agnostic | Kubernetes, polyglot, existing services |
| Guard SDK (in-app library) | Maximum control, conditional auth logic | Complex apps needing fine-grained control |

## Control Plane / Data Plane Split

The architecture splits into two clearly separated concerns:

**Control Plane (ForgeGate SaaS):** Policy compilation, schema management, SDK generation, dashboard, billing. Hosted and operated by ForgeGate. Contains no customer user data.

**Data Plane (Customer's AWS Account):** Cognito user pools, Verified Permissions policy stores, auth proxy/wrapper, cache. Deployed via CDK/Terraform/Helm. All user data, tokens, and authorization decisions stay in the customer's AWS account.

A lightweight **Data Plane Agent** syncs configuration from the control plane and applies it to AWS resources. It also reports anonymized usage metrics for billing.

## Operations Dashboard

The dashboard is two products in one. Beyond Model Studio (design-time configuration), the **Operations** side handles the full lifecycle of runtime entities:

- **Users** — Directory, profiles, create/invite/disable/delete, import/export
- **Permissions** — Role assignments, direct grants, scoped grants, effective permissions (computed view)
- **Policies** — Auto-generated Cedar from roles, custom hand-written Cedar policies, a guided policy builder for common patterns, and a policy test bench for simulating authorization decisions
- **Feature Flags** — Per-tenant status, targeting rules, rollout percentages, A/B experiments, overrides
- **Tenants** — Lifecycle, settings, per-tenant flags and role overrides
- **Audit & Observability** — Authorization decision logs with full policy evaluation traces, user activity timelines, policy change history

This is what turns ForgeGate from a developer tool into a platform that product managers, support reps, and security engineers use daily — without touching Smithy or code.

## Webhook Event System

The control plane exposes a webhook system that surfaces events on every entity mutation and security-relevant decision. Events include user lifecycle (`user.created`, `user.deleted`), permission changes (`role.assigned`, `permission.granted`), authorization decisions (`authorization.denied`, `authorization.denied.repeated` — aggregated alerts for brute-force patterns), feature flag changes, tenant lifecycle, and model changes.

Every event follows a consistent envelope: `id`, `type`, `timestamp`, `project_id`, `tenant_id`, `actor`, `entity`, `data`, `metadata`. Payloads are HMAC-SHA256 signed for verification. Delivery includes exponential backoff retry with dead-letter handling.

This enables customers to build reactive systems: sync users to their own database, pipe events to Datadog/Splunk, trigger Slack alerts on security anomalies, and provision infrastructure on tenant creation.

## Dogfooding: ForgeGate Protects Itself

The Control Plane API is itself modeled in Smithy and protected by ForgeGate. The dashboard React app uses a ForgeGate-generated SDK to call the control plane. Authorization on the control plane is enforced by ForgeGate's own proxy. The webhook system, the Model Engine API, user management — all protected by the same authorization infrastructure offered to customers. This is the strongest possible proof that the product works.

## Marketplace Billing

The Data Plane Agent calls the **AWS Marketplace Metering Service** (`BatchMeterUsage`) hourly from the customer's account. This means:

- Charges appear on the customer's existing AWS bill alongside Cognito and VP costs
- No separate payment infrastructure needed
- Counts toward the customer's AWS Enterprise Discount Program (EDP) committed spend
- Enterprise procurement is simplified — no new vendor approval required

## Cost Analysis

The underlying AWS costs are remarkably low:

| Scale | MAU | Monthly AWS Cost | Per User |
|-------|-----|-----------------|----------|
| Small | 1K | ~$0.50 | $0.0005 |
| Medium | 50K | ~$685 | $0.014 |
| Large | 500K | ~$8,343 | $0.017 |

The dominant cost at scale is **Cognito MAU charges**, not Verified Permissions (which dropped to $5/million requests in June 2025). This leaves significant margin room for ForgeGate's platform fee while remaining cheaper than Auth0, Clerk, or WorkOS.

## Where We Ended

The product has a clear shape:

1. **A UI-first dashboard** with a visual Model Studio for configuration and an Operations panel for runtime management — Smithy is generated behind the scenes
2. **A Smithy-based schema language** with custom authorization traits, supporting CRUD, custom domain actions, and service-level RPC operations
3. **A control plane SaaS** for policy management, SDK generation, user/role/permission lifecycle, webhooks, and admin tooling — itself protected by ForgeGate
4. **A self-hosted data plane** running in the customer's AWS account
5. **Multiple enforcement mechanisms** (wrapper, sidecar, SDK) all driven by the same model
6. **A webhook event system** surfacing every entity mutation and security-relevant decision
7. **AWS Marketplace distribution** for billing and procurement
8. **An AI security narrative** that positions ForgeGate as infrastructure that makes vibe-coded apps enterprise-secure

## Identity Engine: Rust + Typestate State Machines

The backend is written in Rust. Every Cognito authentication flow (password login, magic link, SMS code, OIDC/social, passkeys, password reset, sign-up) is modeled as an explicit state machine using the typestate pattern — where the current state is encoded as a type parameter and invalid transitions are compile-time errors, not runtime checks.

Cognito's hostile API surface (string-typed challenge names, untyped parameter maps, hidden intermediate states) is fully abstracted behind a typed Cognito Adapter. The developer-facing authentication configuration is declarative (a simple YAML/dashboard section). A Config Reconciler computes the desired Cognito state, diffs it against current, and applies changes in dependency order with rollback on failure. Pre-built, versioned Lambda triggers (for magic links, MFA, token enrichment) are deployed automatically — the customer never writes or debugs Lambda code.

## Append-Only Event Log and Transition Metrics

Every state machine transition is recorded in an append-only event log with timestamps, durations, and side effect traces. Every external call (Cognito API, SES email, SNS SMS, DynamoDB challenge storage) is individually timed and tracked as a side effect record.

This is not optional instrumentation — it's built into the `TransitionRecorder` that wraps every transition method. The event log is persisted on flow completion (success or failure) to DynamoDB (hot, queryable for 90 days) and S3 (cold, compliance retention for years).

Metrics are emitted for every transition: per-transition histograms (latency P50/P95/P99), throughput counters, failure rates, per-side-effect timing, and total flow duration. The dashboard exposes a Flow Inspector that replays any authentication attempt step-by-step, showing exactly what happened, how long each step took, and which side effect caused a failure.

This gives ForgeGate provable security (typestate ensures correctness at compile time), full observability (every transition is measured), and complete auditability (every authentication attempt is a replayable event trace).

## God Mode: Live Flow Monitor

The dashboard includes a God Mode — a real-time operational view of every in-flight authentication flow across all tenants. Operators see every active flow with its current state, age, time-to-live, and health status (color-coded by TTL percentage). Support engineers can inspect a live flow's event trace as it progresses, security engineers can detect anomalies (credential stuffing from one IP, OIDC provider outages causing stuck redirects), and ops can intervene directly — killing abandoned flows or extending timeouts when a user is struggling with MFA on a support call. All God Mode access is itself gated by ForgeGate permissions (tiered: view, view with PII, write) and fully audit-logged.

## Internal Back Office

The back office is ForgeGate's internal operations tool — separate from the customer-facing dashboard. It serves customer success (onboarding tracking, health scores, churn signals), support engineering (ticket management with auto-populated customer context, dashboard impersonation, flow inspector access), and business operations (revenue analytics by tier and deployment model, usage trends, feature adoption, Marketplace metering health, margin tracking).

Customer health is computed from multiple signals: data plane sync freshness, auth success rate, authorization latency, webhook delivery rate, usage trends, and open critical tickets. Tickets are auto-created from health alerts and auto-populated with the customer's recent configuration changes, correlated metrics, sampled failure traces, and a suggested root cause. Support engineers can impersonate customer dashboards (read-only, time-limited, audit-logged, visible to the customer) to debug issues in the customer's own context. The back office is itself protected by ForgeGate with role-based access.

## SDK Architecture: Rust Core + Conformance Tests

The SDK ships in two layers: a ForgeGate client library (token management, signing, caching, Guard, feature flag evaluation, webhook verification) and a per-customer generated API client (types, commands, HTTP serialization). The client library starts as a Rust core distributed via FFI wrappers per language (PyO3 for Python, WASM for TypeScript, CGo for Go). A comprehensive conformance test suite — expressed as language-agnostic JSON fixtures with per-language test runners — defines the behavioral contract. The Rust reference implementation generates the fixtures. Any implementation (FFI or native) that passes all ~90 fixtures is a valid ForgeGate SDK. Native implementations can replace FFI wrappers one language at a time, gated by 100% conformance pass rate. The test suite is the product; the implementation is replaceable.

The name **ForgeGate** captures the dual nature: the forge (Smithy) that builds your gates (access control).

---

## Full Document Index

For the complete documentation set, see [Document Index](00-document-index.md).

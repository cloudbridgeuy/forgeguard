# ForgeGuard — Agentic Context Index

All agentic context references for this project MUST be included in this file.

Actual agentic context documents MUST be kept under [`.claude/context/`](./.claude/context/). Do not add context-document indexes to `CLAUDE.md`; keep `CLAUDE.md` focused on operating guidelines and link back here.

## Context Documents

| Document | Purpose |
| --- | --- |
| [Document Index](./.claude/context/00-document-index.md) | Legacy/seed index for the original ForgeGate documentation set and reading orders. |
| [Discussion Summary](./.claude/context/01-discussion-summary.md) | End-to-end narrative of the original product shape, from IAM question to full authorization infrastructure. |
| [SaaS Integration Guide](./.claude/context/02-technical-saas-integration.md) | Developer guide for using ForgeGuard as a fully managed service. |
| [Self-Hosted Data Plane Guide](./.claude/context/03-technical-self-hosted-data-plane.md) | Developer guide for deploying the data plane in an organization's AWS account. |
| [Multi-Region & DR Architecture](./.claude/context/04-multi-region-dr-architecture.md) | Multi-region deployment constraints, RTO/RPO analysis, and DR architecture. |
| [Control Plane UI Design](./.claude/context/08-technical-control-plane-ui.md) | Dashboard architecture: Model Studio, Operations, God Mode, webhooks, and dogfooding. |
| [Authorization Testing](./.claude/context/09-technical-authorization-testing.md) | Auto-generated authorization test suites, CI/CD integration, and custom test cases. |
| [Identity Engine (Rust)](./.claude/context/11-technical-identity-engine-rust.md) | Typestate state machines, event log, metrics, timeouts, Flow Reaper, and God Mode operations. |
| [Internal Back Office](./.claude/context/12-technical-back-office.md) | Customer management, analytics, support tickets, impersonation, and alerting. |
| [SDK Architecture & Conformance](./.claude/context/13-technical-sdk-architecture-conformance.md) | Rust core + FFI wrappers, JSON conformance fixtures, and native transition path. |
| [Tutorial: TODO App](./.claude/context/14-tutorial-todo-app.md) | End-to-end walkthrough for building a secured multi-tenant TODO API. |
| [Linting and Clippy](./.claude/context/linting-and-clippy.md) | Clippy thresholds, workspace lints, and how they map to design patterns. |
| [Params Struct Rule](./.claude/context/params-struct-rule.md) | Why `#[allow(clippy::too_many_arguments)]` is banned and how the lint enforces it. |
| [Visibility Conventions](./.claude/context/visibility-conventions.md) | `pub(crate)` default, constructor + accessor shape, `testing` Cargo feature for cross-crate fixtures, and Axum tuple-struct PDV exception. |
| [Newtypes](./.claude/context/newtypes.md) | Newtype anatomy, wire-format vs. domain split, validation-at-deserialize, project catalog, and lessons from issue-74. |
| [Commit and Release](./.claude/context/commit-and-release.md) | Conventional commits, version bump logic, and release flow. |
| [xtask lint](./.claude/context/xtask-lint.md) | Lint pipeline checks, flags, architecture, and adding new checks. |
| [xtask Wrapper](./.claude/context/xtask-wrapper.md) | `cargo-xtask` mtime staleness, FCIS module split, hot/cold paths, and `--rebuild`. |
| [Feature Flags](./.claude/context/feature-flags.md) | Flag types, evaluation order, overrides, debug endpoint, and proxy wiring. |
| [Verified Permissions](./.claude/context/verified-permissions.md) | VP integration: action format, Cedar types, CLI, config, and infrastructure. |
| [Container Builds](./.claude/context/container-builds.md) | Distroless images, multi-stage builds, SSL strategy, and health checks. |
| [CORS](./.claude/context/cors.md) | CORS config, origin matching, request flow, and crate placement. |
| [SaaS Architecture](./.claude/context/saas-architecture.md) | Control/data plane split, infra stack, worker saga, and org domain model. |
| [Authn Wiring](./.claude/context/authn-wiring.md) | JWT + API key config, resolver construction, PrincipalKind routing, and FCIS split. |
| [CLI](./.claude/context/cli.md) | `check`, `routes`, `policies`, and `keygen` subcommands; FCIS architecture. |
| [xtask CP Tools](./.claude/context/xtask-control-plane-tools.md) | `seed`, `token`, and `curl` subcommands for end-to-end manual QA. |
| [xtask CP Dev Stack](./.claude/context/xtask-control-plane-dev.md) | `dev` subcommand: dynamodb-local container, AWS env wiring, and SSO prerequisite. |
| [Request Signing](./.claude/context/request-signing.md) | Ed25519 signing: canonical payload, config, key rotation, and crate layout. |
| [Demo App](./.claude/context/demo-app.md) | E2E demo: Python TODO app, native proxy, demo config, and running instructions. |
| [Control Plane](./.claude/context/control-plane.md) | CP scaffold, proxy-config endpoint, OrgStore trait, auth, VP authorization, ETag, draft/configured lifecycle, and testing. |
| [Optimistic Locking](./.claude/context/optimistic-locking.md) | `If-Match` / `412` semantics for organization updates, ETags, conditional GETs, and metrics. |
| [Infra: Control Plane](./.claude/context/infra-control-plane.md) | CDK project, 1Password integration, DynamoDB Global Table, and xtask infra commands. |
| [AWS ARN Formats](./.claude/context/aws-arn-formats.md) | Per-service ARN gotchas and the rule to prefer CDK CFN attribute getters. |
| [Cluster Mode](./.claude/context/cluster.md) | TieredCache, Redis wiring, config, health stats, and future slices. |
| [Dependency Constraints](./.claude/context/dependency-constraints.md) | Pingora version pins, `jsonwebtoken` crypto, and `reqwest` TLS constraints. |
| [CI](./.claude/context/ci.md) | GitHub Actions jobs, toolchain pinning rules, typos, cargo-deny, and cargo-rail allowlists. |

## Local-Only Documents

Plans (`.claude/plans/`) and designs (`.claude/designs/`) are local-only working documents. They are gitignored and MUST NOT be pushed to origin.

If a local-only plan or design becomes durable agentic context, move the context document into `.claude/context/` and add it to this index.

## Glossary


| Term | Definition |
| --- | --- |
| **Organization** | A ForgeGuard customer — the company that subscribes to ForgeGuard to protect their application. Each organization gets its own Cognito user pool and VP policy store. Identified by `OrganizationId`. |
| **Tenant** | An end-user partition within an organization's application. ForgeGuard helps organizations enforce tenant isolation via Cedar policies. Identified by `TenantId`. |
| **Control Plane** | ForgeGuard-operated SaaS: organization management, policy authoring, dashboard, billing. Contains no customer user data. |
| **Data Plane** | The runtime enforcement layer: proxy, identity resolution, authorization decisions. In SaaS mode, operated by ForgeGuard. In BYOC mode, deployed in the organization's AWS account. |
| **BYOC (Bring Your Own Cloud)** | Deployment model where the data plane runs in the organization's AWS account while the control plane remains ForgeGuard SaaS. |
| **Proxy (local — static)** | Single-organization proxy binary in static mode. Reads TOML config, fully self-contained. No control plane dependency. |
| **Proxy (local — connected)** | Single-organization proxy binary in connected mode. Fetches routes, flags, and upstream config from the control plane. Organization provides local AWS resource IDs (Cognito pool, VP store) at startup. The control plane syncs Cedar policies to the org's VP store. |
| **Proxy (SaaS)** | Multi-organization proxy binary operated by ForgeGuard. Resolves organization from request, lazy-loads per-org config via L1 in-memory cache, L2 CloudFront/S3 (SaaS) or authenticated Lambda API (BYOC). |
| **Worker** | Background Lambda binary (`forgeguard_worker`). Dispatches jobs by `FORGEGUARD_WORKER_JOB` env var. Currently: `reconciler` (sync pending DynamoDB records to S3). |


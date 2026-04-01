# ForgeGuard SaaS Architecture

> Control plane / data plane split with BYOC support.

## Overview

ForgeGuard transforms from a single-organization proxy into a SaaS platform. The architecture splits into a **control plane** (operated by ForgeGuard) and a **data plane** (proxy + auth enforcement, operated by ForgeGuard in SaaS mode or by the customer in BYOC mode).

Full design: `.local/plans/2026-04-01-saas-architecture-design.md`

## Deployment Models

| Model | Control Plane | Data Plane | Config Source |
| --- | --- | --- | --- |
| **Local (static)** | None | Customer operates proxy | TOML file |
| **BYOC (connected)** | ForgeGuard SaaS | Customer operates proxy | Control plane API (polled every 30s, ETag) |
| **SaaS** | ForgeGuard SaaS | ForgeGuard operates proxy | S3 via IAM (L1 in-memory cache) |

## Crate Architecture

### proxy-core (pure crate)

Extracted from the proxy binary. Captures the auth pipeline as a pure decision function.

- `PipelineConfig` — per-organization config (routes, flags, upstream, project ID)
- `RequestInput` — abstract request (method, path, headers, client IP)
- `PipelineOutcome` — decision enum: `Health`, `Debug`, `Reject`, `Forward`
- `evaluate_pipeline()` — runs the full auth pipeline
- `PipelineSource` trait — how the proxy resolves config for a request
- `TenantExtractor` trait — extracts `OrganizationId` from a request (subdomain, host, header, path prefix)

### PipelineSource Implementations

| Implementation | Binary | Config source |
| --- | --- | --- |
| `StaticSource` | proxy (BYOC) | TOML file, loaded once |
| `ConnectedSource` | proxy (BYOC) | Control plane API, polled 30s with ETag |
| `MultiOrgSource` | proxy-saas | S3 direct (IAM), L1 in-memory cache, blacklisting |

### forgeguard-axum (lib/ crate)

Axum middleware that uses `proxy-core`. Translates Axum `Request` to `RequestInput`, calls `evaluate_pipeline()`, translates `PipelineOutcome` to Axum `Response`. Used by the control plane for dogfooding.

Published to crates.io with independent semver. Lives in `lib/forgeguard-axum/`.

## AWS Resource Strategy

| Resource | Strategy | Rationale |
| --- | --- | --- |
| Cognito | One user pool per organization | Auth config isolation, separate user directories |
| Verified Permissions | One policy store per organization | Per-org 200 RPS budget, schema isolation |
| Cognito (ForgeGuard's own) | One pool for CP dashboard users | Dashboard authentication |
| VP (ForgeGuard's own) | One store for CP authorization | Membership as Cedar policies |

## Infrastructure Stack

| Component | Service | Cost |
| --- | --- | --- |
| Control plane API | Lambda (ARM/Graviton) | ~$0 (free tier) |
| Org database | DynamoDB Global Tables (on-demand, 3 regions) | ~$0.02-$0.22/mo |
| Config read path (SaaS) | S3 direct via IAM | ~$0 |
| Config read path (BYOC) | Lambda (authenticated) via CloudFront | ~$0 (free tier) |
| Dashboard SPA | CloudFront + S3 | ~$0 (free tier) |
| DNS | Route 53 | $0.50/mo |
| Total | | ~$0.52-$0.72/mo |

## Write-Through Pattern

DynamoDB is the source of truth. S3 is a read-optimized projection.

```
On config write:
  1. Write to DynamoDB with s3_sync = "pending"
  2. Write snapshot to S3
  3. If S3 succeeds: update s3_sync = "synced"
  4. If S3 fails: leave s3_sync = "pending", log warning, return success

Worker (scheduler, every 5 min):
  Scans for pending/stale/error conditions, invokes sub-workers
```

## Worker Architecture (Saga Pattern)

Stateless scheduler + idempotent sub-workers. Per-job-type error handling.

- **Scheduler:** Scans DynamoDB for conditions, invokes sub-workers via async Lambda invoke. Writes nothing. Fails fast.
- **Sub-workers:** Own their state. Double write: intermediate state before attempting work. Always end in a known terminal state.
- **Retry policy:** s3-sync auto-retries (idempotent). email-send never auto-retries (notifies admin instead).
- **Notification worker:** Collects diagnostics (source record, error details, CloudWatch logs) before alerting admin.

## Organization Domain Model

- **Users** exist independently of organizations (Cognito + DynamoDB)
- **Organizations** have lifecycle: `draft → pending_approval → provisioning → active → suspended → deleting → deleted`
- **Membership is authorization:** Roles (owner, admin, member) are VP policy templates in the CP's VP store. Assigning a role = `CreatePolicy`. No membership table.
- **Organization activation** requires manual approval (payment integration deferred)

## Control Plane Authentication

Two client types through the same `forgeguard-axum` middleware:

- **Dashboard users (humans):** Cognito JWT from ForgeGuard's own pool
- **BYOC proxies (machines):** Ed25519 signed headers (#29)

Both resolve to an `Identity`. VP authorizes based on identity type and role.

## Publishing Rules

- `lib/` crates: independent semver, released via `cargo xtask release-lib`
- Published `crates/` deps (`core`, `authn-core`, `authz-core`, `proxy-core`): lock-step versioning, published only when a lib crate releases
- Unpublished crates: `publish = false`, `version = "0.0.0"`

## xtask Commands

```
cargo xtask control-plane
├── infra    (deploy / diff / destroy / status)
├── cedar    (sync / diff / status)
├── lambda   (deploy / build / list)
├── invitations (list / status / resend / create [UNSAFE])
├── jobs     (status / list / stale / retry)
```

## Vertical Slices

See `.local/plans/2026-04-01-saas-architecture-design.md` for the full slice table and dependency graph. Key issues: #29, #32-#42, #45-#46.

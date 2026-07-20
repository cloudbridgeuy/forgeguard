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

## Worker Architecture (Event Log + Cursor)

The go-forward side-effect substrate is the per-org event log, not a saga-ticket
pattern. Org, key, and group mutations append events (`{create_org, update_org}`,
`{generate_org_key, revoke_org_key, rotate_org_key}`, `{put_group, delete_group}`)
onto a monotonically-sequenced, per-org event log (`X-Fg-Revision`, `seq`). Reads
and downstream side effects are derived by replaying the log from a cursor
(`after` u64, exclusive) rather than by a scheduler dispatching stateful saga
tickets. See [control-plane.md § Org CRUD is event-sourced](./control-plane.md#org-crud-is-event-sourced-revision-tokens-113-v1)
for the write path and the events-cursor-replay handler for the read path.

The standalone `forgeguard_worker` Lambda binary (`crates/worker/`) currently
runs one job, dispatched via `FORGEGUARD_WORKER_JOB`: `reconciler` (syncs
pending DynamoDB records to S3).

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

## Vertical Slices and Issue DAG

- **Design doc:** `.local/plans/2026-04-01-saas-architecture-design.md`
- **Issue DAG (dependency graph, parallel waves, all decisions):** `.local/plans/2026-04-01-saas-issue-dag.md`
- **Key issues:** #29, #32-#42, #45-#46
- **Starting points (no dependencies):** #29, #32, #45. #39 can scaffold in parallel.

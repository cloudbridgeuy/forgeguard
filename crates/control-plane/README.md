# forgeguard_control_plane

ForgeGuard control plane API server. This is an **I/O binary crate**.

Serves per-organization proxy configuration to BYOC connected proxies. File-backed config store for development; DynamoDB + S3 in production (future).

Authentication and authorization are handled by the `forgeguard-axum` middleware layer. In dev mode, the default configuration uses `DefaultPolicy::Passthrough` with `StaticPolicyEngine::Allow`, so all requests pass through without auth enforcement.

## Classification

**Binary / I/O** -- depends on `axum`, `tokio`, `tower-http`, `forgeguard-axum`, file I/O.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check -- returns `{"status": "ok"}` |
| `POST` | `/api/v1/organizations` | Create organization (status: Draft) |
| `GET` | `/api/v1/organizations` | List organizations (paginated: `?offset=&limit=`) |
| `GET` | `/api/v1/organizations/{org_id}` | Get organization details |
| `PUT` | `/api/v1/organizations/{org_id}` | Update organization name and/or config |
| `DELETE` | `/api/v1/organizations/{org_id}` | Delete organization |
| `GET` | `/api/v1/organizations/{org_id}/proxy-config` | Per-org proxy config with ETag caching |

### Response Codes (proxy-config)

| Code | Meaning |
|------|---------|
| 200 | Config returned with `ETag` header |
| 304 | Config unchanged (`If-None-Match` matched) |
| 404 | Organization not found |

## Quick Start

A test config with two orgs (`org-acme`, `org-globex`) is included at
`examples/control-plane/orgs.test.json`. No real AWS resources needed.

### 1. Start the control plane

```sh
# Terminal 1 -- start the control plane
cargo run -p forgeguard_control_plane -- \
  --config examples/control-plane/orgs.test.json

# Terminal 2 -- test endpoints
# Health check -> 200
curl -s http://localhost:3001/health | jq .

# Fetch org config -> 200 + ETag
curl -si http://localhost:3001/api/v1/organizations/org-acme/proxy-config

# Unknown org -> 404
curl -si http://localhost:3001/api/v1/organizations/org-unknown/proxy-config

# ETag match -> 304 (paste the ETag from the 200 response above)
curl -si \
  -H 'If-None-Match: "<paste-etag>"' \
  http://localhost:3001/api/v1/organizations/org-acme/proxy-config
```

### 2. With your own orgs

For real AWS resources, copy the sample and fill in your values:

```sh
cp examples/control-plane/orgs.sample.json orgs.json
# Edit orgs.json -- add your project ID, upstream URL, routes, etc.

cargo run -p forgeguard_control_plane -- --config orgs.json
```

The `orgs.json` file is gitignored (contains AWS resource IDs).

### CLI Options

| Flag | Env | Description |
|------|-----|-------------|
| `--config` | `FORGEGUARD_CP_CONFIG` | Path to org config JSON file (required) |
| `--listen` | `FORGEGUARD_CP_LISTEN` | Listen address (default: `127.0.0.1:3001`) |
| `--log-level` | `FORGEGUARD_CP_LOG_LEVEL` | Log level filter (default: `info`) |

## Config File Format

JSON file mapping `org_id` to its organization entry. Each entry has a `name` (display name) and a nested `config` object (`OrgConfig`) with a date-based `version` field:

```json
{
  "organizations": {
    "org-acme": {
      "name": "Acme Corp",
      "config": {
        "version": "2026-04-07",
        "project_id": "todo-demo",
        "upstream_url": "https://api.acme.com",
        "default_policy": "deny",
        "routes": [
          {"method": "GET", "path": "/api/todos", "action": "todo:list:read"}
        ],
        "public_routes": [
          {"method": "GET", "path": "/health", "auth_mode": "anonymous"}
        ],
        "features": {}
      }
    }
  }
}
```

At load time, each org entry is parsed into an `Organization` domain entity (from `forgeguard_core`) with `OrgStatus::Active` status, paired with the `OrgConfig`. The `Organization` entity tracks lifecycle state (8-variant `OrgStatus` enum) and timestamps.

Unknown fields in the config are ignored by serde, so older config files with extra fields will still parse.

## Domain Model

The control plane uses the `Organization` entity from `forgeguard_core` to represent each org. File-loaded orgs are created with `OrgStatus::Active`. The `OrgStore` trait is async with generic handlers (no `dyn` dispatch):

| Type | Location | Purpose |
|------|----------|---------|
| `Organization` | `forgeguard_core` | Domain entity with status lifecycle, timestamps |
| `OrgConfig` | `config.rs` | Versioned proxy configuration (replaces old `OrgProxyConfig`) |
| `OrgRecord` | `store.rs` | Pairs `Organization` + `OrgConfig` + precomputed ETag |
| `OrgStore` trait | `store.rs` | Async trait for org storage backends |
| `InMemoryOrgStore` | `store.rs` | In-memory HashMap behind `tokio::sync::RwLock` |

## ETag Caching

Every org config response includes an `ETag` header (xxHash64 of the canonical JSON). Proxies send `If-None-Match` on subsequent polls and receive `304 Not Modified` when nothing has changed, saving bandwidth.

## Dependencies

| Crate | Role |
|-------|------|
| `forgeguard_core` (pure) | `OrganizationId`, `Organization`, `OrgStatus`, `DefaultPolicy` |
| `forgeguard-axum` | Auth middleware (identity + policy) |
| `axum` | HTTP framework |
| `tower-http` | Middleware (tracing, timeout) |
| `xxhash-rust` | ETag computation |
| `chrono` | Timestamps for `Organization` entity |

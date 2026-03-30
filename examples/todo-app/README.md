# ForgeGuard Demo — TODO App

A multi-tenant TODO API (Python/FastAPI) running behind the ForgeGuard proxy.
The app has **zero ForgeGuard imports** — it reads `X-ForgeGuard-*` headers
injected by the proxy to scope all data by tenant.

## Prerequisites

- Docker + Docker Compose
- AWS credentials configured (`~/.aws/credentials` with `admin` profile)
- ForgeGuard Cognito deployment (`cargo xtask dev setup --cognito`)

## Quick Start

```bash
# From examples/todo-app/
docker compose up --build
```

The proxy listens on `localhost:8080`, the app on `localhost:3000`.

## Demo Scenarios

### 1. Public routes (no credentials)

```bash
# Health check — anonymous
curl http://localhost:8080/health

# Webhook — anonymous
curl -X POST http://localhost:8080/webhooks/github

# Docs — opportunistic (works with or without auth)
curl http://localhost:8080/docs/getting-started
```

### 2. Tenant isolation — acme-corp vs globex-corp

```bash
# Alice (acme-corp admin) — sees acme-corp lists only
curl -H "X-API-Key: sk-test-alice-admin" http://localhost:8080/api/lists

# Dave (globex-corp admin) — sees globex-corp lists only
curl -H "X-API-Key: sk-test-dave-admin" http://localhost:8080/api/lists
```

The proxy asserts each user's tenant. The app scopes data by
`X-ForgeGuard-Tenant-Id`. Alice never sees globex-corp data.

### 3. RBAC within a tenant

```bash
# Bob (acme-corp member) — can create a list
curl -X POST -H "X-API-Key: sk-test-bob-member" http://localhost:8080/api/lists

# Charlie (acme-corp viewer) — try to create (expect 403)
curl -X POST -H "X-API-Key: sk-test-charlie-viewer" http://localhost:8080/api/lists

# Eve (globex-corp viewer) — can read but not create
curl -H "X-API-Key: sk-test-eve-viewer" http://localhost:8080/api/lists
curl -X POST -H "X-API-Key: sk-test-eve-viewer" http://localhost:8080/api/lists
```

### 4. Feature flags (tenant-scoped)

```bash
# AI suggestions — enabled for acme-corp via tenant override
curl -H "X-API-Key: sk-test-alice-admin" http://localhost:8080/api/lists/default/suggestions

# AI suggestions — disabled for globex-corp (no override)
curl -H "X-API-Key: sk-test-dave-admin" http://localhost:8080/api/lists/default/suggestions
```

### 5. Resource-level access

```bash
# Alice can read top-secret (admin + top-secret-readers)
curl -H "X-API-Key: sk-test-alice-admin" http://localhost:8080/api/lists/top-secret

# Charlie cannot read top-secret (viewer only — denied by policy)
curl -H "X-API-Key: sk-test-charlie-viewer" http://localhost:8080/api/lists/top-secret
```

### 6. Debug context

```bash
# See all injected headers
curl -H "X-API-Key: sk-test-alice-admin" http://localhost:8080/debug/context
```

### 7. CLI commands

```bash
# Validate config
cargo run --bin forgeguard -- check --config examples/todo-app/forgeguard.toml

# Show route table
cargo run --bin forgeguard -- routes --config examples/todo-app/forgeguard.toml
```

## API Keys

| Key | User | Tenant | Groups |
|-----|------|--------|--------|
| `sk-test-alice-admin` | alice | acme-corp | admin, top-secret-readers |
| `sk-test-bob-member` | bob | acme-corp | member |
| `sk-test-charlie-viewer` | charlie | acme-corp | viewer |
| `sk-test-dave-admin` | dave | globex-corp | admin |
| `sk-test-eve-viewer` | eve | globex-corp | viewer |

## Architecture

```
Client → proxy:8080 → app:3000
           │
           ├─ Health check    → 200 (no auth)
           ├─ CORS preflight  → 204 (no auth)
           ├─ Public route    → pass through (anonymous/opportunistic)
           ├─ Extract credential (Bearer JWT / X-API-Key)
           ├─ Resolve identity (CognitoJwtResolver / StaticApiKeyResolver)
           ├─ Evaluate feature flags
           ├─ Match route → action
           ├─ Check feature gate
           ├─ Evaluate policy (Verified Permissions)
           ├─ Inject X-ForgeGuard-* headers (user, tenant, groups, features)
           └─ Proxy to upstream (app scopes data by tenant header)
```

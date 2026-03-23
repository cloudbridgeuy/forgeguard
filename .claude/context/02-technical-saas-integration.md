# ForgeGate — Technical Guide: SaaS Integration

> For developers using ForgeGate as a fully managed service. No AWS account required.

---

## Overview

ForgeGate provides authentication, authorization, and feature flags for your application through a single declarative model. In SaaS mode, ForgeGate manages all infrastructure — you define your model, integrate your app, and ForgeGate handles the rest.

## Architecture

```
┌──────────────────────────────────┐
│     ForgeGate Cloud (SaaS)       │
│                                  │
│  ┌──────────┐  ┌──────────────┐ │
│  │ Dashboard │  │ SDK          │ │
│  │ & Admin   │  │ Generation   │ │
│  │ Console   │  │ Engine       │ │
│  └─────┬─────┘  └──────┬──────┘ │
│        │               │        │
│  ┌─────┴───────────────┴─────┐  │
│  │    Managed Auth Engine     │  │
│  │  Cognito + Verified Perms  │  │
│  │  + Feature Flag Engine     │  │
│  └─────────────┬─────────────┘  │
└────────────────┼────────────────┘
                 │
        Authorization API
                 │
┌────────────────┼────────────────┐
│  Your Application                │
│                                  │
│  ┌──────────────────────────┐   │
│  │  ForgeGate Wrapper       │   │
│  │  (forgegate run app:app) │   │
│  └────────────┬─────────────┘   │
│               │                  │
│  ┌────────────┴─────────────┐   │
│  │  Your App (FastAPI, etc) │   │
│  └──────────────────────────┘   │
└──────────────────────────────────┘
```

## Getting Started

### Option A: Visual Dashboard (Recommended for most developers)

No Smithy knowledge required. The dashboard guides you through model creation:

1. **Create a project** at `https://app.forgegate.io` — give it a name
2. **Add resources** — "What things does your app have?" (e.g., Document, Project)
3. **Define actions** — check boxes for standard CRUD, add custom domain actions (e.g., `publish`, `archive`, `transfer`)
4. **Map endpoints** — method + path + which action it requires. Standard CRUD endpoints are auto-generated; customize or add RPC operations
5. **Define roles** — visual permission matrix across all actions
6. **Deploy** — click Push and your auth infrastructure is live

Total time: 5 minutes. The dashboard generates Smithy behind the scenes. You can view and export the generated model at any time via the "View Smithy" button.

### Option B: CLI + Smithy (For developers who prefer code)

### 1. Install the CLI

```bash
pip install forgegate-cli
```

### 2. Create your project

```bash
forgegate init my-api
cd my-api
```

This creates:

```
my-api/
├── model/
│   └── main.smithy       # Your API + authorization model
├── forgegate.yaml         # Project configuration
└── .forgegate/            # Generated artifacts (gitignored)
```

### 3. Define your model

Edit `model/main.smithy` to describe your API, resources, and permissions:

```smithy
$version: "2"
namespace com.myapp

use forgegate.traits#authorize
use forgegate.traits#authResource
use forgegate.traits#featureGate

@httpApiKeyAuth(scheme: "Bearer", name: "Authorization", in: "header")
@restJson1
service MyService {
    version: "2025-01-01"
    resources: [Document, Project]
}

@authResource(namespace: "myapp")
resource Document {
    identifiers: { documentId: DocumentId }
    properties: {
        title: String
        content: String
        ownerId: String
        projectId: ProjectId
    }
    read: GetDocument
    create: CreateDocument
    delete: DeleteDocument
    list: ListDocuments
}

@readonly
@http(method: "GET", uri: "/documents/{documentId}")
@authorize(action: "document:read", resource: "documentId")
operation GetDocument {
    input := for Document {
        @required
        @httpLabel
        $documentId
    }
    output := for Document {
        @required $documentId
        @required $title
        @required $content
        @required $ownerId
    }
}

@http(method: "POST", uri: "/documents")
@authorize(action: "document:write")
operation CreateDocument {
    input := for Document {
        @required $title
        @required $content
        @required $projectId
    }
    output := for Document {
        @required $documentId
        @required $title
    }
}

@idempotent
@http(method: "DELETE", uri: "/documents/{documentId}")
@authorize(action: "document:delete", resource: "documentId")
operation DeleteDocument {
    input := for Document {
        @required
        @httpLabel
        $documentId
    }
}

@readonly
@http(method: "GET", uri: "/documents/{documentId}/summary")
@authorize(action: "document:read", resource: "documentId")
@featureGate(feature: "ai_summaries")
operation GetDocumentSummary {
    input := {
        @required
        @httpLabel
        documentId: DocumentId
    }
    output := {
        @required
        summary: String
    }
}

string DocumentId
string ProjectId
```

### 4. Push your model

```bash
forgegate push

✓ Model validated
✓ Cedar schema generated
✓ Policies synced to managed policy store
✓ Route mappings generated (5 operations)
✓ Python SDK generated → .forgegate/sdk/python/
✓ TypeScript SDK generated → .forgegate/sdk/typescript/
```

### 5. Configure roles and feature flags

```bash
# Define roles
forgegate roles create viewer --permissions "document:read"
forgegate roles create editor --permissions "document:read,document:write"
forgegate roles create admin  --permissions "document:*,project:*"

# Enable a feature flag
forgegate features create ai_summaries --type boolean
forgegate features enable ai_summaries --tenant default
```

Or use the dashboard at `https://app.forgegate.io`.

---

## Custom Actions & Service Operations

Beyond standard CRUD, ForgeGate supports custom domain actions on resources and standalone RPC operations.

### Custom actions on resources

```bash
# Via CLI
forgegate actions create document:publish
forgegate actions create document:archive
forgegate actions create document:transfer

# These generate endpoints like:
# POST /documents/{documentId}/publish
# POST /documents/{documentId}/archive
# POST /documents/{documentId}/transfer
```

Or via the dashboard's "Custom Actions" panel on any resource. Define the action name, input/output fields, and ForgeGate generates the Smithy operation, HTTP binding, and authorization trait.

### Service-level RPC operations

Operations not tied to any resource:

```bash
forgegate operations create report:generate \
  --method POST \
  --path /reports/generate \
  --input "date_range:DateRange,format:string,filters:object" \
  --output "job_id:string,status:string"
```

These appear in the role matrix alongside resource actions, so an `analyst` role can have `report:generate` without any document permissions.

---

## Operations Dashboard

The dashboard provides a full operational UI for managing runtime entities. This is where your team spends day-to-day time after initial setup.

### User Management

- **Directory:** List, search, filter users by tenant, role, or status
- **User detail:** Profile, assigned roles, direct grants, effective permissions (computed), feature flag resolution, and activity timeline
- **Actions:** Create, invite, disable, enable, delete users
- **Bulk:** Import/export user lists

### Permission Management

- **Role assignments:** Assign and revoke roles per user
- **Direct grants:** Grant specific action on specific resource to a user
- **Scoped grants:** Grant action within a context (e.g., "document:write only in project X")
- **Effective permissions:** See the computed result of all roles + grants for any user

### Policy Management

- **Auto-generated policies:** Created from role definitions. Read-only in the UI — edit the role to change them
- **Custom policies:** Write Cedar policies for complex rules the role matrix cannot express (e.g., "owners can publish their own documents")
- **Guided builder:** Create common policy patterns (resource ownership, attribute match, time-based, IP restriction) without writing Cedar
- **Test bench:** Simulate authorization decisions — pick a user, action, and resource, see the decision with full policy evaluation trace

### Audit Log

- **Decision log:** Every authorization decision (allow/deny) with full context
- **Expandable traces:** Click any decision to see which policies were evaluated and why
- **Filters:** By user, action, decision, time range, resource
- **Export:** CSV export for compliance

---

## Webhooks

ForgeGate emits events on every entity mutation and security-relevant decision. Configure webhook endpoints in the dashboard to receive real-time notifications.

### Available events

| Category | Events |
|----------|--------|
| User lifecycle | `user.created`, `user.updated`, `user.deleted`, `user.disabled`, `user.enabled`, `user.login.succeeded`, `user.login.failed` |
| Permission changes | `role.assigned`, `role.revoked`, `permission.granted`, `permission.revoked` |
| Authorization | `authorization.denied`, `authorization.denied.repeated` (5+ denials in 1 min) |
| Feature flags | `feature.enabled`, `feature.disabled`, `feature.rollout_changed`, `feature.experiment_started` |
| Tenants | `tenant.created`, `tenant.updated`, `tenant.deleted` |
| Model changes | `model.pushed`, `model.validated`, `sdk.generated` |
| Policies | `policy.created`, `policy.updated`, `policy.deleted` |

### Consuming webhooks

```python
from forgegate.webhooks import WebhookHandler

handler = WebhookHandler(secret="whsec_a1b2c3d4...")

@app.post("/hooks/forgegate")
async def handle_webhook(request: Request):
    event = handler.verify_and_parse(
        body=await request.body(),
        headers=request.headers,
    )

    match event.type:
        case "user.created":
            await sync_user_to_db(event.data)
        case "role.assigned":
            await notify_user(event.entity.id, event.data)
        case "authorization.denied.repeated":
            await alert_security_team(event)

    return {"ok": True}
```

Payloads are signed with HMAC-SHA256 via the `X-ForgeGate-Signature` header. The SDK handles verification automatically.

---

## Integrating Your Application

### Option A: The Wrapper (Recommended)

The wrapper intercepts all HTTP requests before they reach your application. Your app code contains zero authorization logic.

**Your application code — completely auth-unaware:**

```python
from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/documents/{document_id}")
async def get_document(document_id: str, request: Request):
    user_id = request.headers["X-Auth-User-Id"]
    doc = await db.documents.get(document_id)
    return doc

@app.post("/documents")
async def create_document(request: Request):
    user_id = request.headers["X-Auth-User-Id"]
    body = await request.json()
    doc = await db.documents.insert(**body, owner_id=user_id)
    return doc

@app.delete("/documents/{document_id}")
async def delete_document(document_id: str):
    await db.documents.delete(document_id)
    return {"ok": True}
```

**Run it with the wrapper:**

```bash
# Instead of: uvicorn app:app
forgegate run app:app

✓ Loaded route mappings (5 operations)
✓ Connected to ForgeGate Cloud
✓ Feature flags synced (1 feature)
✓ Listening on :8000
```

Every request is validated and authorized before reaching your handlers. Unauthorized requests receive a 403 response automatically. Feature-gated routes return 404 when the feature is disabled.

**Headers injected into every authorized request:**

| Header | Description | Example |
|--------|-------------|---------|
| `X-Auth-User-Id` | Authenticated user ID | `user_456` |
| `X-Auth-Tenant-Id` | Tenant context | `tenant_acme` |
| `X-Auth-Roles` | Comma-separated roles | `editor,viewer` |
| `X-Auth-Action` | Cedar action that was authorized | `document:read` |
| `X-Auth-Resource-Id` | Resource ID (if applicable) | `doc_123` |
| `X-Feature-*` | Feature flag values | `X-Feature-Ai-Summaries: true` |

### Option B: The Guard SDK

For applications that need in-code authorization control:

```python
from forgegate import Guard

guard = Guard(api_key="fg-runtime-...")

# Simple check
if guard.can(user_id, "document:read", resource_id="doc_123"):
    ...

# Raise on failure
guard.authorize(user_id, "document:write", resource_id="doc_123")
# raises guard.Forbidden

# Check features
if guard.feature_enabled("ai_summaries", tenant="tenant_acme"):
    ...

# Inspect everything at once
info = guard.inspect(user_id, tenant="tenant_acme")
# {
#     "permissions": {"document:read": True, "document:write": True, ...},
#     "features": {"ai_summaries": True, ...}
# }
```

### Option C: FastAPI Middleware

For framework-specific integration:

```python
from fastapi import FastAPI
from forgegate.fastapi import ForgeGateMiddleware

app = FastAPI()
app.add_middleware(ForgeGateMiddleware, api_key="fg-runtime-...")

# Routes are now protected automatically.
# Same X-Auth-* headers are injected.
```

---

## Managing Users and Roles (AdminClient)

The AdminClient is used in admin scripts, back-office tools, or CI/CD — never in the request path.

```python
from forgegate.admin import AdminClient

admin = AdminClient(api_key="fg-admin-...")

# User management
admin.users.create("user_456", email="jane@acme.com")
admin.users.delete("user_789")

# Role management
admin.roles.assign("user_456", "editor")
admin.roles.revoke("user_456", "editor")

# Direct grants (beyond roles)
admin.grant("user_456", "document:share", resource_id="doc_789")
admin.revoke("user_456", "document:share", resource_id="doc_789")

# Scoped permissions
admin.grant("user_456", "document:write", scope={"project": "proj_123"})

# Feature flag management
admin.features.enable("ai_summaries", tenant="tenant_acme")
admin.features.rollout("new_ui", tenant="tenant_acme", percentage=25)
admin.features.experiment("checkout_flow", tenant="tenant_acme", split={
    "control": 50,
    "single_page": 30,
    "multi_step": 20,
})
admin.features.override("ai_summaries", user_id="user_789", enabled=True)
```

---

## Generated Client SDK

When you push your model, ForgeGate generates typed client SDKs that your API consumers use. These follow the AWS SDK v3 pattern: types + commands + `send()`.

```python
# Generated: myapp_sdk (what YOU ship to YOUR users)

from myapp_sdk import MyServiceClient, GetDocument, CreateDocument
from myapp_sdk.types import GetDocumentInput, CreateDocumentInput
from myapp_sdk.auth import api_key

client = MyServiceClient(
    endpoint="https://api.myapp.com",
    credentials=api_key("sk-consumer-key-..."),
)

# Auth is invisible — just like boto3
doc = client.send(GetDocument(GetDocumentInput(document_id="doc_123")))
print(doc.title)

new_doc = client.send(CreateDocument(CreateDocumentInput(
    title="Q3 Report",
    content="...",
    project_id="proj_456",
)))
```

The SDK handles token acquisition, refresh, and request signing automatically. The consumer never thinks about auth.

### Publishing the SDK

```bash
# Python
forgegate sdk publish --lang python --registry pypi

# TypeScript
forgegate sdk publish --lang typescript --registry npm
```

---

## Multi-Tenancy

Tenants are a first-class concept. All authorization decisions are automatically scoped to the tenant.

```yaml
# forgegate.yaml
tenancy:
  enabled: true
  header: "X-Tenant-Id"           # Where to extract tenant from requests
  # OR
  token_claim: "custom:tenant_id" # Extract from JWT claim
```

```bash
# Create tenants
forgegate tenants create tenant_acme
forgegate tenants create tenant_globex

# Features per tenant
forgegate features enable ai_summaries --tenant tenant_acme
forgegate features disable ai_summaries --tenant tenant_globex
```

Tenant isolation is enforced at the Cedar policy level — there is no way for a user in `tenant_acme` to access resources belonging to `tenant_globex`.

---

## Configuration Reference

### forgegate.yaml

```yaml
project: my-api
version: "1.0"

# ForgeGate Cloud connection
api_key_env: FORGEGATE_API_KEY

# Model location
model:
  sources: ["model/"]

# SDK generation
sdk:
  languages: [python, typescript]
  python:
    package_name: myapp_sdk
  typescript:
    package_name: "@myapp/sdk"

# Tenancy
tenancy:
  enabled: true
  header: "X-Tenant-Id"

# Wrapper configuration
wrapper:
  port: 8000
  upstream: "localhost:3000"
  identity:
    provider: forgegate       # managed by ForgeGate
    # OR
    provider: custom
    jwks_url: "https://..."   # Bring your own IdP
```

---

## What ForgeGate Manages For You

In SaaS mode, the following are fully managed:

| Component | Managed By |
|-----------|-----------|
| Cognito user pool | ForgeGate |
| Verified Permissions policy store | ForgeGate |
| Cedar schema and policies | ForgeGate (from your Smithy model) |
| Feature flag state | ForgeGate |
| SDK generation | ForgeGate |
| User directory | ForgeGate |
| Audit logs | ForgeGate (visible in dashboard) |

You are responsible for:

| Component | Your Responsibility |
|-----------|-------------------|
| Application code | Your business logic |
| Database | Your data storage |
| Deployment | Hosting your app + running the wrapper |
| Consumer SDK distribution | Publishing to PyPI/npm |

---

## Authorization Testing

ForgeGate auto-generates a comprehensive test suite from your model — covering every endpoint × role combination, tenant isolation, feature gates, and token edge cases. Run locally or in CI.

```bash
# Test locally
forgegate test connect --port 8000

# Test in CI (GitHub Actions, GitLab CI)
forgegate test run --target http://localhost:3000 --fail-on-error --output junit.xml
```

Custom test cases for business logic (ownership checks, scoped permissions) can be defined in `forgegate-tests.yaml`. For full details, see [Authorization Testing](09-technical-authorization-testing.md).

---

## God Mode: Live Flow Monitor

The dashboard includes a real-time view of every in-flight authentication flow. Support engineers can inspect live flows, security engineers can detect anomalies (credential stuffing, provider outages), and operators can kill abandoned flows or extend timeouts.

Access requires the `operations:god_mode` permission and is fully audit-logged. For full details, see [Control Plane UI Design](08-technical-control-plane-ui.md).

---

## Related Documents

- [Self-Hosted Data Plane Guide](03-technical-self-hosted-data-plane.md) — if you need data sovereignty or compliance control
- [Control Plane UI Design](08-technical-control-plane-ui.md) — full dashboard architecture including Model Studio, Operations, God Mode
- [Authorization Testing](09-technical-authorization-testing.md) — auto-generated test suite and CI/CD integration
- [Identity Engine](11-technical-identity-engine-rust.md) — how authentication flows work under the hood
- [SDK Architecture](13-technical-sdk-architecture-conformance.md) — how the generated SDK and client library are built
- [Tutorial: TODO App](14-tutorial-todo-app.md) — end-to-end example of building a secured app with ForgeGate

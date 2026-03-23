# ForgeGate — Tutorial: Building a Secured TODO App

> A complete walkthrough from zero to a fully authenticated, authorized, and tested TODO API — in under 30 minutes.

---

## What We're Building

A multi-tenant TODO app with:

- Users who belong to organizations (tenants)
- Lists that belong to an organization
- Items within lists
- Roles: `viewer` (read), `member` (read + write), `admin` (everything)
- Custom actions: `complete` an item, `archive` a list, `share` a list with another user
- A feature flag: `ai_suggestions` (AI-powered task suggestions, rolling out to 25% of tenants)
- A generated SDK for consumers of the API

No security code in the application. ForgeGate handles everything.

---

## Step 1: Create a ForgeGate Project

Open `https://app.forgegate.io` and create a new project called `todo-api`.

Or via CLI:

```bash
pip install forgegate-cli
forgegate login
forgegate projects create todo-api
cd todo-api
```

---

## Step 2: Define the Model (Dashboard)

In the dashboard's Model Studio, add three resources:

### Resource: List

Actions: `read`, `create`, `delete`, `archive`, `share`

Attributes:

| Name | Type | Required |
|------|------|----------|
| name | String | yes |
| owner_id | String | yes |
| org_id | String | yes |
| archived | Boolean | no |

### Resource: Item

Actions: `read`, `create`, `update`, `delete`, `complete`

Attributes:

| Name | Type | Required |
|------|------|----------|
| title | String | yes |
| description | String | no |
| list_id | String | yes |
| completed | Boolean | no |
| assigned_to | String | no |

### Resource: Organization

Actions: `read`, `create`, `manage_members`

Attributes:

| Name | Type | Required |
|------|------|----------|
| name | String | yes |

The dashboard auto-generates lifecycle endpoints for each resource. It also creates the custom action endpoints:

```
Auto-generated:
  GET    /lists                    → list:read
  POST   /lists                    → list:create
  GET    /lists/{listId}           → list:read
  DELETE /lists/{listId}           → list:delete
  GET    /lists/{listId}/items     → item:read
  POST   /lists/{listId}/items     → item:create
  GET    /items/{itemId}           → item:read
  PUT    /items/{itemId}           → item:update
  DELETE /items/{itemId}           → item:delete
  GET    /organizations            → organization:read
  POST   /organizations            → organization:create

Custom actions (you add these):
  POST   /lists/{listId}/archive   → list:archive
  POST   /lists/{listId}/share     → list:share
  POST   /items/{itemId}/complete  → item:complete
  POST   /organizations/{orgId}/members → organization:manage_members

Feature-gated:
  GET    /lists/{listId}/suggestions → item:read (gated by ai_suggestions)
```

### Custom Action: Complete Item

Click "+ Custom Action" on the Item resource:

- Name: `complete`
- Path: `/items/{itemId}/complete` (auto-suggested)
- Input: (none beyond item ID)
- Output: `completed_at: DateTime`

### Custom Action: Archive List

- Name: `archive`
- Path: `/lists/{listId}/archive`
- Input: (none beyond list ID)
- Output: `archived_at: DateTime`

### Custom Action: Share List

- Name: `share`
- Path: `/lists/{listId}/share`
- Input: `user_id: String (required)`, `permission: Enum [read, write]`
- Output: `success: Boolean`

### Service Operation: AI Suggestions

Click "+ Service Operation":

- Name: `getSuggestions`
- Namespace: `item`
- Path: `/lists/{listId}/suggestions`
- Method: GET
- Feature gate: `ai_suggestions`
- Input: `listId: String`
- Output: `suggestions: List<SuggestedItem>`

---

## Step 3: Define Roles

In the Roles tab, create the permission matrix:

```
              │ list: │ list: │ list:  │ list:  │ list: │ item: │ item:  │ item: │ item:  │ item:   │ org:  │ org:          │
              │ read  │create │ delete │archive │ share │ read  │ create │update │ delete │complete │ read  │manage_members │
──────────────┼───────┼───────┼────────┼────────┼───────┼───────┼────────┼───────┼────────┼─────────┼───────┼───────────────│
viewer        │  ✅   │  ❌   │   ❌   │   ❌   │  ❌   │  ✅   │   ❌   │  ❌   │   ❌   │   ❌    │  ✅   │      ❌       │
member        │  ✅   │  ✅   │   ❌   │   ❌   │  ❌   │  ✅   │   ✅   │  ✅   │   ✅   │   ✅    │  ✅   │      ❌       │
admin         │  ✅   │  ✅   │   ✅   │   ✅   │  ✅   │  ✅   │   ✅   │  ✅   │   ✅   │   ✅    │  ✅   │      ✅       │
```

Click "Save".

---

## Step 4: Configure Authentication

In the Authentication tab:

- **Email + Password**: Enabled (min 8 chars)
- **Magic Link**: Enabled (15 min expiry)
- **Google Login**: Enabled (paste client ID)
- **MFA**: Optional, TOTP only

ForgeGate handles the Cognito setup, Lambda triggers, and SES configuration.

---

## Step 5: Create a Feature Flag

In the Feature Flags tab:

- Name: `ai_suggestions`
- Type: Boolean
- Default: disabled

We'll enable it per-tenant later.

---

## Step 6: Configure Multi-Tenancy

In Settings:

- Tenancy: Enabled
- Tenant source: JWT claim `custom:org_id`

---

## Step 7: Push the Model

Click "Deploy" in the dashboard, or:

```bash
forgegate push

✓ Model validated
✓ Cedar schema generated (3 resources, 12 actions)
✓ Cedar policies generated (3 roles)
✓ Policy store synced
✓ Route mappings generated (16 endpoints)
✓ Python SDK generated → .forgegate/sdk/python/todo_api_sdk/
✓ TypeScript SDK generated → .forgegate/sdk/typescript/
✓ Authorization test suite generated (94 tests)
```

---

## Step 8: Write the Application

This is a standard FastAPI app. No auth imports, no middleware, no permission checks.

```python
# app.py

from fastapi import FastAPI, Request, HTTPException
from datetime import datetime
from db import Database  # your database layer

app = FastAPI()
db = Database()


# ── Lists ──

@app.get("/lists")
async def list_lists(request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    return await db.lists.find({"org_id": org_id, "archived": False})


@app.post("/lists")
async def create_list(request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    user_id = request.headers["X-Auth-User-Id"]
    body = await request.json()

    list = await db.lists.insert({
        "name": body["name"],
        "owner_id": user_id,
        "org_id": org_id,
        "archived": False,
        "created_at": datetime.utcnow(),
    })
    return list


@app.get("/lists/{list_id}")
async def get_list(list_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    list = await db.lists.find_one({"id": list_id, "org_id": org_id})
    if not list:
        raise HTTPException(404)
    return list


@app.delete("/lists/{list_id}")
async def delete_list(list_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    await db.lists.delete({"id": list_id, "org_id": org_id})
    return {"ok": True}


@app.post("/lists/{list_id}/archive")
async def archive_list(list_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    await db.lists.update(
        {"id": list_id, "org_id": org_id},
        {"archived": True, "archived_at": datetime.utcnow()},
    )
    return {"archived_at": datetime.utcnow().isoformat()}


@app.post("/lists/{list_id}/share")
async def share_list(list_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    body = await request.json()
    await db.shares.insert({
        "list_id": list_id,
        "user_id": body["user_id"],
        "permission": body["permission"],
        "org_id": org_id,
    })
    return {"success": True}


# ── Items ──

@app.get("/lists/{list_id}/items")
async def list_items(list_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    return await db.items.find({"list_id": list_id, "org_id": org_id})


@app.post("/lists/{list_id}/items")
async def create_item(list_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    user_id = request.headers["X-Auth-User-Id"]
    body = await request.json()

    item = await db.items.insert({
        "title": body["title"],
        "description": body.get("description"),
        "list_id": list_id,
        "org_id": org_id,
        "completed": False,
        "assigned_to": body.get("assigned_to"),
        "created_by": user_id,
        "created_at": datetime.utcnow(),
    })
    return item


@app.get("/items/{item_id}")
async def get_item(item_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    item = await db.items.find_one({"id": item_id, "org_id": org_id})
    if not item:
        raise HTTPException(404)
    return item


@app.put("/items/{item_id}")
async def update_item(item_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    body = await request.json()
    await db.items.update(
        {"id": item_id, "org_id": org_id},
        body,
    )
    return await db.items.find_one({"id": item_id})


@app.delete("/items/{item_id}")
async def delete_item(item_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    await db.items.delete({"id": item_id, "org_id": org_id})
    return {"ok": True}


@app.post("/items/{item_id}/complete")
async def complete_item(item_id: str, request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    user_id = request.headers["X-Auth-User-Id"]
    now = datetime.utcnow()

    await db.items.update(
        {"id": item_id, "org_id": org_id},
        {"completed": True, "completed_at": now, "completed_by": user_id},
    )
    return {"completed_at": now.isoformat()}


# ── Organizations ──

@app.get("/organizations")
async def list_orgs(request: Request):
    org_id = request.headers["X-Auth-Tenant-Id"]
    return await db.orgs.find({"id": org_id})


@app.post("/organizations")
async def create_org(request: Request):
    user_id = request.headers["X-Auth-User-Id"]
    body = await request.json()

    org = await db.orgs.insert({
        "name": body["name"],
        "created_by": user_id,
        "created_at": datetime.utcnow(),
    })
    return org


@app.post("/organizations/{org_id}/members")
async def manage_members(org_id: str, request: Request):
    body = await request.json()
    # ForgeGate's AdminClient would handle this through webhooks,
    # but the endpoint needs to exist for the route mapping
    return {"success": True}


# ── Feature-gated: AI Suggestions ──

@app.get("/lists/{list_id}/suggestions")
async def get_suggestions(list_id: str, request: Request):
    # This endpoint only receives requests when ai_suggestions is enabled
    # for this tenant — ForgeGate's proxy returns 404 otherwise.
    org_id = request.headers["X-Auth-Tenant-Id"]

    items = await db.items.find({
        "list_id": list_id,
        "org_id": org_id,
        "completed": False,
    })
    suggestions = ai.suggest_tasks(items)
    return {"suggestions": suggestions}
```

**Notice what's NOT in this code:**

- No `from forgegate import ...` — no auth library imported
- No `@requires_auth` decorators
- No `if user.role == "admin"` checks
- No token validation
- No MFA handling
- No tenant isolation logic (beyond filtering by `org_id` in queries)
- No feature flag checks (the gated endpoint just assumes it's enabled)

The app reads `X-Auth-User-Id`, `X-Auth-Tenant-Id`, and `X-Auth-Roles` from headers. These are injected by ForgeGate's proxy. If they're present, the request is authorized. Period.

---

## Step 9: Run It

```bash
# Start your app
uvicorn app:app --port 3000

# In another terminal — run it through ForgeGate
forgegate run app:app --upstream-port 3000

✓ Loaded route mappings (16 endpoints)
✓ Connected to ForgeGate Cloud
✓ Feature flags synced (1 flag: ai_suggestions)
✓ Authentication: password + magic_link + google
✓ MFA: optional (TOTP)
✓ Tenancy: enabled (JWT claim: custom:org_id)
✓ Listening on :8000

# Your API is now fully authenticated and authorized at :8000
# Direct access on :3000 bypasses auth (use for testing only)
```

---

## Step 10: Create Some Users and Data

```bash
# Via the dashboard or CLI

# Create a tenant
forgegate tenants create acme-org

# Create users
forgegate users create alice --email alice@acme.com --tenant acme-org
forgegate users create bob --email bob@acme.com --tenant acme-org
forgegate users create charlie --email charlie@acme.com --tenant acme-org

# Assign roles
forgegate roles assign alice admin --tenant acme-org
forgegate roles assign bob member --tenant acme-org
forgegate roles assign charlie viewer --tenant acme-org

# Enable AI suggestions for this tenant (25% rollout)
forgegate features enable ai_suggestions --tenant acme-org
```

---

## Step 11: Test It

### Manual test

```bash
# Get a token for alice (admin)
TOKEN=$(forgegate auth token --user alice --tenant acme-org)

# Create a list — should work (admin has list:create)
curl -X POST http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Sprint tasks"}'
# → 201 {"id": "list_001", "name": "Sprint tasks", ...}

# Get a token for charlie (viewer)
TOKEN_CHARLIE=$(forgegate auth token --user charlie --tenant acme-org)

# Try to create a list — should be denied (viewer lacks list:create)
curl -X POST http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_CHARLIE" \
  -H "Content-Type: application/json" \
  -d '{"name": "My list"}'
# → 403 {"error": "Forbidden"}

# Try to read lists — should work (viewer has list:read)
curl http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_CHARLIE"
# → 200 [{"id": "list_001", "name": "Sprint tasks", ...}]
```

### Authorization test suite

```bash
forgegate test connect --port 8000

Running authorization tests...

  Positive tests (12/12) ✅
    admin CAN POST /lists
    admin CAN DELETE /lists/{listId}
    admin CAN POST /lists/{listId}/archive
    admin CAN POST /lists/{listId}/share
    member CAN POST /lists
    member CAN POST /items/{itemId}/complete
    member CAN POST /lists/{listId}/items
    ...

  Negative tests (18/18) ✅
    viewer CANNOT POST /lists
    viewer CANNOT DELETE /lists/{listId}
    viewer CANNOT POST /items/{itemId}/complete
    viewer CANNOT POST /lists/{listId}/archive
    viewer CANNOT POST /lists/{listId}/share
    member CANNOT DELETE /lists/{listId}
    member CANNOT POST /lists/{listId}/archive
    member CANNOT POST /lists/{listId}/share
    ...

  Unauthenticated tests (16/16) ✅
  Tenant isolation tests (8/8) ✅
  Feature gate tests (2/2) ✅
    GET /lists/{listId}/suggestions → 404 when ai_suggestions disabled ✅
    GET /lists/{listId}/suggestions → 200 when ai_suggestions enabled ✅

  Token tests (3/3) ✅

  59/59 passed ✅
```

---

## Step 12: Ship the Generated SDK

ForgeGate generated a typed Python SDK from your model. Your API consumers install it and use it without thinking about auth:

```bash
# Publish the SDK
cd .forgegate/sdk/python
pip install build && python -m build
twine upload dist/*
# → Published to PyPI as todo-api-sdk
```

### What your consumers write:

```python
from todo_api_sdk import TodoApiClient, CreateList, CreateItem, CompleteItem
from todo_api_sdk.types import (
    CreateListInput, CreateItemInput, CompleteItemInput
)
from todo_api_sdk.auth import api_key

# Initialize — auth is invisible
client = TodoApiClient(
    endpoint="https://api.todo-app.com",
    credentials=api_key("sk-consumer-key-..."),
)

# Create a list
my_list = client.send(CreateList(CreateListInput(
    name="Weekend errands"
)))
print(f"Created list: {my_list.list_id}")

# Add items
for task in ["Groceries", "Laundry", "Fix bike"]:
    item = client.send(CreateItem(CreateItemInput(
        list_id=my_list.list_id,
        title=task,
    )))
    print(f"  Added: {item.title} ({item.item_id})")

# Complete an item
client.send(CompleteItem(CompleteItemInput(
    item_id=item.item_id,
)))
print(f"  Completed: {item.title}")
```

The consumer doesn't configure auth, validate tokens, or handle refresh. The SDK does it. They call methods and get typed responses.

---

## Step 13: Set Up Webhooks

In the dashboard, create a webhook to sync TODO data to your analytics pipeline:

- URL: `https://api.todo-app.com/hooks/forgegate`
- Events: `user.created`, `user.deleted`, `role.assigned`, `feature.enabled`

```python
# hooks.py — webhook handler

from forgegate.webhooks import WebhookHandler

handler = WebhookHandler(secret="whsec_...")

@app.post("/hooks/forgegate")
async def handle_webhook(request: Request):
    event = handler.verify_and_parse(
        body=await request.body(),
        headers=request.headers,
    )

    match event.type:
        case "user.created":
            # Provision a default list for new users
            await db.lists.insert({
                "name": "My Tasks",
                "owner_id": event.data["user_id"],
                "org_id": event.tenant_id,
                "archived": False,
            })
        case "role.assigned":
            await analytics.track("role_change", event.data)
        case "feature.enabled":
            if event.data["feature"] == "ai_suggestions":
                await analytics.track("ai_suggestions_enabled", {
                    "tenant": event.tenant_id,
                })

    return {"ok": True}
```

---

## Step 14: Add to CI

```yaml
# .github/workflows/auth-tests.yml
name: Authorization Tests
on: [pull_request]

jobs:
  auth-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start app
        run: |
          docker compose up -d
          sleep 5

      - name: Run ForgeGate authorization tests
        uses: forgegate/test-action@v1
        with:
          target: http://localhost:3000
          api-key: ${{ secrets.FORGEGATE_API_KEY }}
          mode: both
          fail-on-error: true
```

Every PR now validates that authorization is correct. If someone adds a new endpoint and forgets to update the model, the test catches it.

---

## What ForgeGate Did For You

| What you did | What ForgeGate did |
|-------------|-------------------|
| Defined 3 resources, 12 actions in the dashboard | Generated Cedar schema, policies for 3 roles, 16 route mappings |
| Wrote 16 route handlers with zero auth code | Authenticated every request (password, magic link, Google, MFA) |
| Read `X-Auth-User-Id` and `X-Auth-Tenant-Id` from headers | Validated JWT, checked authorization against Cedar policies, injected headers |
| Added `complete`, `archive`, `share` as custom actions | Enforced them identically to CRUD — same role matrix, same proxy |
| Created a feature flag in the dashboard | Gated the `/suggestions` endpoint — returns 404 when disabled |
| Ran `forgegate test connect` | Generated and ran 59 tests covering every endpoint × role combination |
| Published the generated SDK | Your consumers got typed commands with auth baked in |
| Added a webhook handler | Provisioned default lists for new users, tracked analytics |

**What you did NOT do:**

- Write a single line of authentication code
- Write a single line of authorization code
- Configure Cognito, Lambda triggers, or SES
- Write Cedar policies
- Write Smithy (the dashboard generated it)
- Write authorization tests (ForgeGate generated them)
- Worry about token refresh, MFA flows, or OIDC callbacks

**Time breakdown:**

| Step | Time |
|------|------|
| Define model in dashboard | 5 min |
| Define roles | 2 min |
| Configure auth methods | 2 min |
| Write the FastAPI app (business logic only) | 15 min |
| Run `forgegate run` | 10 sec |
| Run authorization tests | 30 sec |
| Publish SDK | 2 min |
| **Total** | **~27 min** |

27 minutes from zero to a multi-tenant, role-based, feature-flagged, fully tested, SDK-equipped TODO API. No security code. No Smithy. No Cedar. Just business logic and a dashboard.

---

## The Generated Smithy (For Reference)

You never wrote this — the dashboard generated it. But it's in your repo at `model/main.smithy` if you ever want to hand-edit:

```smithy
$version: "2"
namespace com.todoapp

use forgegate.traits#authorize
use forgegate.traits#authResource
use forgegate.traits#featureGate

@httpApiKeyAuth(scheme: "Bearer", name: "Authorization", in: "header")
@restJson1
service TodoApiService {
    version: "2025-01-01"
    resources: [List, Item, Organization]
    errors: [ForbiddenError, NotFoundError]
}

@authResource(namespace: "todo")
resource List {
    identifiers: { listId: ListId }
    properties: {
        name: String
        ownerId: String
        orgId: String
        archived: Boolean
    }
    read: GetList
    create: CreateList
    delete: DeleteList
    list: ListLists
    operations: [ArchiveList, ShareList, GetSuggestions]
}

@authResource(namespace: "todo")
resource Item {
    identifiers: { itemId: ItemId }
    properties: {
        title: String
        description: String
        listId: ListId
        completed: Boolean
        assignedTo: String
    }
    read: GetItem
    create: CreateItem
    update: UpdateItem
    delete: DeleteItem
    operations: [CompleteItem]
}

@authResource(namespace: "todo")
resource Organization {
    identifiers: { orgId: OrgId }
    properties: { name: String }
    read: GetOrganization
    create: CreateOrganization
    list: ListOrganizations
    operations: [ManageMembers]
}

// ... (16 operation definitions with @http, @authorize, inline I/O)

@http(method: "POST", uri: "/items/{itemId}/complete")
@authorize(action: "item:complete", resource: "itemId")
operation CompleteItem {
    input := for Item {
        @required @httpLabel
        $itemId
    }
    output := {
        @required
        completedAt: Timestamp
    }
}

@http(method: "POST", uri: "/lists/{listId}/archive")
@authorize(action: "list:archive", resource: "listId")
operation ArchiveList {
    input := for List {
        @required @httpLabel
        $listId
    }
    output := {
        @required
        archivedAt: Timestamp
    }
}

@http(method: "POST", uri: "/lists/{listId}/share")
@authorize(action: "list:share", resource: "listId")
operation ShareList {
    input := {
        @required @httpLabel
        listId: ListId
        @required
        userId: String
        @required
        permission: SharePermission
    }
    output := {
        @required
        success: Boolean
    }
}

@readonly
@http(method: "GET", uri: "/lists/{listId}/suggestions")
@authorize(action: "item:read", resource: "listId")
@featureGate(feature: "ai_suggestions")
operation GetSuggestions {
    input := {
        @required @httpLabel
        listId: ListId
    }
    output := {
        @required
        suggestions: SuggestedItemList
    }
}

enum SharePermission {
    READ = "read"
    WRITE = "write"
}

string ListId
string ItemId
string OrgId
```

This file is the single source of truth. The dashboard reads it. The proxy reads it. The test generator reads it. The SDK generator reads it. You wrote business logic. ForgeGate wrote everything else.

---

## Related Documents

- [SaaS Integration Guide](02-technical-saas-integration.md) — complete reference for all integration options
- [Authorization Testing](09-technical-authorization-testing.md) — full details on testing, CI/CD, custom test cases
- [Control Plane UI Design](08-technical-control-plane-ui.md) — full dashboard documentation including God Mode
- [Identity Engine](11-technical-identity-engine-rust.md) — how authentication flows work under the hood
- [SDK Architecture](13-technical-sdk-architecture-conformance.md) — how the generated SDK is built and tested
- [Discussion Summary](01-discussion-summary.md) — full context on how ForgeGate was designed

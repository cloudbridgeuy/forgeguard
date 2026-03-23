# ForgeGate — Control Plane UI: Technical Design

> Architecture and design of the ForgeGate dashboard, its backing API, the Model Engine, and the webhook event system.

---

## Design Principles

1. **UI-first, Smithy-underneath.** Most developers never see Smithy. The dashboard generates it. Power users can eject at any time.
2. **Bidirectional sync.** UI edits generate Smithy. Hand-edited `.smithy` files parse back into the UI. One source of truth, two views.
3. **Opinionated API, not generic.** The API exposes domain operations ("create a resource"), not AST mutations ("add a shape"). The Model Engine encodes best practices.
4. **Dogfooding.** The Control Plane API is modeled in Smithy, protected by ForgeGate's own proxy, consumed by the dashboard via a ForgeGate-generated SDK.
5. **Two products in one dashboard.** Model Studio (design-time configuration) + Operations (runtime lifecycle management).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  ForgeGate Dashboard (React SPA)                             │
│                                                              │
│  ┌────────────────────────┐  ┌───────────────────────────┐  │
│  │     Model Studio       │  │      Operations           │  │
│  │                        │  │                           │  │
│  │  Resources & Actions   │  │  Users                    │  │
│  │  Endpoints             │  │  Permissions              │  │
│  │  Roles (matrix)        │  │  Policies                 │  │
│  │  Feature Flags (defn)  │  │  Feature Flags (runtime)  │  │
│  │  Smithy Viewer/Editor  │  │  Tenants                  │  │
│  │  SDK & Deploy          │  │  Webhooks                 │  │
│  │                        │  │  Audit Log                │  │
│  │                        │  │  God Mode (live flows)    │  │
│  └────────────┬───────────┘  └──────────────┬────────────┘  │
│               │                              │               │
│               └──────────┬───────────────────┘               │
│                          │                                    │
│            ForgeGate Generated SDK (dogfooding)              │
└──────────────────────────┬───────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────┐
│  Control Plane API                                            │
│  Protected by ForgeGate proxy (forgegate run)                │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                                                        │  │
│  │  Model API                    Operations API           │  │
│  │  ─────────                    ──────────────           │  │
│  │  POST /resources              GET/POST/DELETE /users    │  │
│  │  POST /endpoints              POST /users/{id}/roles    │  │
│  │  POST /roles                  POST /permissions/grant   │  │
│  │  POST /features               POST /policies            │  │
│  │  POST /custom-actions         POST /test-authorization  │  │
│  │  POST /service-operations     GET  /audit-log           │  │
│  │  GET  /model/smithy           POST /webhooks            │  │
│  │  POST /model/validate         GET  /webhooks/{id}/logs  │  │
│  │  POST /model/push                                      │  │
│  │                                                        │  │
│  └─────────────────────────┬──────────────────────────────┘  │
│                            │                                  │
│  ┌─────────────────────────▼──────────────────────────────┐  │
│  │  Model Engine                                          │  │
│  │                                                        │  │
│  │  Domain ops → Smithy AST → Validate → Commit           │  │
│  │  Best practices applied automatically                  │  │
│  │  Bidirectional: Smithy file ↔ UI state                 │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Event Bus                                             │  │
│  │                                                        │  │
│  │  Every mutation → Audit Log + Webhook Dispatcher       │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## Part 1: Model Studio

### Overview

The Model Studio is where developers define their authorization model visually. Every action in the UI translates to a call to the Model API, which passes through the Model Engine to produce correct Smithy.

### 1.1 Resources & Actions

The entry point. Developers define what "things" exist and what can be done with them.

**UI flow:**

- Add a resource (e.g., "Document") — the engine creates a typed ID, `@authResource` trait, and scaffolds standard CRUD operations
- Check boxes for lifecycle actions: read, create, update, delete, list
- Add custom domain actions: `publish`, `archive`, `transfer` — each gets its own permission (`document:publish`), HTTP binding, and input/output definition
- Define attributes (owner_id, project_id, etc.) — used for ABAC policies later

**Model API:**

```
POST /projects/{projectId}/resources
{
    "name": "Document",
    "actions": ["read", "write", "delete"],
    "customActions": [
        {
            "name": "publish",
            "description": "Publish a draft document",
            "inputFields": [],
            "outputFields": [
                {"name": "publishedAt", "type": "Timestamp"},
                {"name": "status", "type": "String"}
            ]
        },
        {
            "name": "transfer",
            "description": "Transfer document ownership",
            "inputFields": [
                {"name": "newOwnerId", "type": "String", "required": true},
                {"name": "notifyPreviousOwner", "type": "Boolean", "default": true}
            ],
            "outputFields": [
                {"name": "success", "type": "Boolean"},
                {"name": "transferredAt", "type": "Timestamp"}
            ]
        }
    ],
    "attributes": [
        {"name": "title", "type": "String", "required": true},
        {"name": "content", "type": "String", "required": true},
        {"name": "ownerId", "type": "String", "required": true},
        {"name": "projectId", "type": "String", "required": true}
    ]
}
```

**Model Engine behavior on `create_resource`:**

1. Creates `DocumentId` string type (best practice: typed IDs)
2. Creates `Document` resource shape with `@authResource(namespace: "<project_namespace>")`
3. Auto-generates lifecycle operations based on checked actions:
   - `GetDocument` — `GET /documents/{documentId}`, `@readonly`, `@authorize(action: "document:read")`
   - `ListDocuments` — `GET /documents`, `@readonly`, `@paginated`, `@authorize(action: "document:read")`
   - `CreateDocument` — `POST /documents`, `@authorize(action: "document:write")`, input excludes ID
   - `DeleteDocument` — `DELETE /documents/{documentId}`, `@idempotent`, `@authorize(action: "document:delete")`
4. Generates custom action operations:
   - `PublishDocument` — `POST /documents/{documentId}/publish`, `@authorize(action: "document:publish")`
   - `TransferOwnership` — `POST /documents/{documentId}/transfer`, `@authorize(action: "document:transfer")`
5. Adds standard error types (`NotFoundError`, `ForbiddenError`) if not already present
6. Wires the resource into the service shape
7. Validates the full model
8. Returns the generated endpoints and any warnings

**Response:**

```json
{
    "resource": {
        "name": "Document",
        "actions": ["read", "write", "delete", "publish", "transfer"]
    },
    "generatedEndpoints": [
        {"name": "GetDocument", "method": "GET", "path": "/documents/{documentId}", "action": "document:read"},
        {"name": "ListDocuments", "method": "GET", "path": "/documents", "action": "document:read"},
        {"name": "CreateDocument", "method": "POST", "path": "/documents", "action": "document:write"},
        {"name": "DeleteDocument", "method": "DELETE", "path": "/documents/{documentId}", "action": "document:delete"},
        {"name": "PublishDocument", "method": "POST", "path": "/documents/{documentId}/publish", "action": "document:publish"},
        {"name": "TransferOwnership", "method": "POST", "path": "/documents/{documentId}/transfer", "action": "document:transfer"}
    ],
    "warnings": []
}
```

### 1.2 Service-Level RPC Operations

Operations not tied to any resource:

```
POST /projects/{projectId}/service-operations
{
    "name": "generateReport",
    "namespace": "report",
    "description": "Generate an analytics report",
    "method": "POST",
    "path": "/reports/generate",
    "inputFields": [
        {"name": "dateRange", "type": "DateRange", "required": true},
        {"name": "format", "type": "ReportFormat", "required": true},
        {"name": "filters", "type": "Object"}
    ],
    "outputFields": [
        {"name": "jobId", "type": "String"},
        {"name": "status", "type": "String"},
        {"name": "estimatedCompletionSeconds", "type": "Integer"}
    ]
}
```

Permission auto-derived: `report:generateReport`. Appears in the role matrix alongside resource actions.

### 1.3 Endpoints

Lists all endpoints (auto-generated + custom). Developers can customize individual endpoints: change the path, adjust input/output fields, add feature gates, or override the auto-generated defaults.

The endpoints screen shows the HTTP method, path, mapped action, and feature gate status in a scannable table. Clicking an endpoint opens an edit form.

### 1.4 Roles (Permission Matrix)

Visual grid: roles as rows, all actions (lifecycle + custom + service) as columns grouped by resource. Click to toggle.

The matrix supports wildcards at the resource level (`document:*`), but the engine expands wildcards to explicit permissions on save — so adding a new action to a resource does not silently grant it to existing roles.

**API:**

```
POST /projects/{projectId}/roles
{
    "name": "publisher",
    "permissions": [
        "document:read",
        "document:write",
        "document:publish",
        "document:archive"
    ]
}
```

The engine validates all referenced actions exist, then generates a Cedar policy template for the role.

### 1.5 Feature Flag Definitions

Define flags with type (boolean, string variants, integer), and optionally gate specific endpoints. Runtime targeting (which tenants, rollout percentages, experiments) is managed in the Operations side.

### 1.6 Smithy Viewer / Editor

Read-only by default — shows the generated Smithy model. Developers can switch to edit mode ("Eject to Smithy") for full control. Changes made in the raw editor are validated by the Model Engine and parsed back into the UI state.

Features the UI doesn't support (custom Cedar conditions, advanced Smithy traits) are shown as read-only blocks in the UI — preserved, visible, but not editable through the visual interface.

### 1.7 Validation Rules

The Model Engine runs validation before every push:

| Rule | Severity | Description |
|------|----------|-------------|
| Every resource has at least a read action | Warning | Resources without read are unusual |
| Every endpoint maps to an existing action | Error | Broken references |
| No orphan resources (defined but no endpoints) | Warning | Likely forgot to wire up |
| Path params have matching resource_param | Warning | Authorization may not scope correctly |
| List endpoints are paginated | Warning | Best practice for scalability |
| Custom actions don't shadow CRUD verbs | Error | `read`, `write`, `delete` conflict with lifecycle |
| Service operations use namespace:action format | Warning | e.g., `report:generate` not just `generate` |
| All role permissions reference existing actions | Error | Broken role definitions |
| Idempotent suggestion for stateless custom actions | Warning | Actions with no input beyond resource ID |

---

## Part 2: Operations

### Overview

The Operations side handles runtime lifecycle — the day-to-day management that product managers, support reps, and security engineers need. Every operation goes through the same ForgeGate-protected API.

### 2.1 User Management

**Directory:**
- List, search, filter by tenant/role/status
- Pagination, sortable columns

**User detail page:**
- Profile (email, tenant, created, last login, MFA status)
- Assigned roles with assignment history (who assigned, when)
- Direct grants (action on specific resource, with optional scope)
- Effective permissions — computed view merging roles + direct grants, showing which role/grant provides each permission
- Feature flag resolution — computed flags for this specific user (combining tenant rules, percentage rollout, overrides)
- Activity timeline — recent authorization decisions for this user

**Actions:**
- Create / invite (email invitation flow)
- Disable / enable (soft toggle, preserves all roles and permissions)
- Delete (hard delete, requires confirmation)
- Import / export (CSV/JSON bulk operations)

**API examples:**

```
POST   /projects/{projectId}/users                    # Create user
GET    /projects/{projectId}/users                    # List users
GET    /projects/{projectId}/users/{userId}           # Get user detail
DELETE /projects/{projectId}/users/{userId}           # Delete user
POST   /projects/{projectId}/users/{userId}/disable   # Disable user
POST   /projects/{projectId}/users/{userId}/enable    # Enable user
POST   /projects/{projectId}/users/{userId}/roles/assign    # Assign role
POST   /projects/{projectId}/users/{userId}/roles/revoke    # Revoke role
POST   /projects/{projectId}/users/{userId}/permissions/grant   # Direct grant
POST   /projects/{projectId}/users/{userId}/permissions/revoke  # Revoke grant
GET    /projects/{projectId}/users/{userId}/effective-permissions  # Computed
GET    /projects/{projectId}/users/{userId}/activity    # Decision timeline
```

### 2.2 Permission Management

Beyond the role matrix (which is in Model Studio), the Operations side handles runtime permission assignments:

- **Role assignment/revocation** — assign roles to individual users
- **Direct grants** — grant a specific action on a specific resource to a user (e.g., "user_456 can share doc_789")
- **Scoped grants** — grant an action within a context (e.g., "user_456 can write documents in project proj_123")
- **Effective permissions** — computed read-only view showing the result of all roles + grants for a user, with attribution (which role or grant provides each permission)

### 2.3 Policy Management

**Auto-generated policies:**
- Created from role definitions in Model Studio
- Read-only in the Operations UI — edit the role to change them
- Visible with full Cedar source for inspection

**Custom policies:**
- For rules that the role matrix cannot express
- Two editors:
  - **Guided builder** — form-based, supports common patterns:
    - Resource ownership (`resource.owner_id == principal`)
    - Attribute match (`resource.X == value`)
    - Tenant match (`resource.tenant == principal.tenant`)
    - Time-based conditions (`context.time > / < / between`)
    - IP restriction (`context.ip in CIDR`)
    - Group membership (`principal in Group::"X"`)
  - **Raw Cedar editor** — full Cedar syntax for anything the guided builder can't express
- Both modes show a live preview of the generated Cedar

**Policy templates:**
- Reusable Cedar patterns with placeholders for principal and resource
- Example: "Resource owner has full access" — template applied per user-resource pair
- Display count of active template-linked policies

**Test bench:**
- Simulate authorization: pick a principal, action, resource, and optional context
- See the decision (ALLOW/DENY) with full policy evaluation trace
- Shows each policy evaluated, whether it matched, and why
- Critical for debugging "why can't user X do Y?" questions

**API examples:**

```
GET    /projects/{projectId}/policies                   # List all policies
POST   /projects/{projectId}/policies                   # Create custom policy
PUT    /projects/{projectId}/policies/{policyId}        # Update policy
DELETE /projects/{projectId}/policies/{policyId}        # Delete policy
POST   /projects/{projectId}/policies/{policyId}/validate  # Validate Cedar
POST   /projects/{projectId}/test-authorization         # Test bench
```

### 2.4 Feature Flags (Runtime)

Runtime targeting and management (definitions are in Model Studio):

- **Per-tenant status** — enable/disable per tenant
- **Percentage rollout** — gradual rollout within a tenant
- **A/B experiments** — multi-variant split with traffic allocation
- **User overrides** — force enable/disable for specific users (QA, beta testers)
- **Targeting rules** — attribute-based conditions (e.g., only `plan: enterprise`)

### 2.5 Tenant Management

- **Tenant list** — all tenants with user count, feature summary
- **Tenant detail** — settings, per-tenant feature flags, per-tenant role overrides
- **Create / update / delete** — full lifecycle

### 2.6 Audit Log

- **Authorization decision log** — every ALLOW/DENY with full context
- **Expandable traces** — click any decision to see policies evaluated, match result, and reason
- **Filters** — by user, action, decision (allow/deny), time range, resource, tenant
- **User activity timeline** — per-user view of all their authorization decisions
- **Policy change history** — who changed what policy, when, with before/after diff
- **Export** — CSV for compliance, or pipe to SIEM via webhooks

### 2.7 God Mode: Live Flow Monitor

God Mode is a real-time operational view of every in-flight authentication flow across all tenants. Think of it as air traffic control for authentication — every active flow visible, every state tracked, every timeout counting down.

**Who uses it:**

- **Support engineers** — "A customer says they're stuck on the login screen. Let me see their flow in real time."
- **Security engineers** — "We're seeing a spike in MFA timeouts from one IP range. Show me all active flows from that subnet."
- **Ops on-call** — "Cognito latency just spiked. How many flows are currently blocked on a Cognito call?"
- **During incidents** — "An OIDC provider is down. How many users are stuck in `redirect_pending`?"

**Access is itself gated by ForgeGate permissions.** God Mode requires the `operations:god_mode` permission — typically granted only to admin and security roles. All access to God Mode is audit-logged. Viewing a specific user's flow is logged with the viewer's identity, the target user's redacted identity, and the timestamp.

#### Live Dashboard

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  God Mode — Live Flow Monitor                           ● 47 active flows   │
│                                                         ↻ Refreshing: 2s    │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Filters: [All tenants ▼] [All flow types ▼] [All states ▼] 🔍 [Search IP] │
│                                                                              │
│  Summary                                                                     │
│  ┌────────────┬────────────┬────────────┬────────────┬────────────────────┐ │
│  │  password   │ magic_link │   oidc     │  sms_code  │  password_reset   │ │
│  │    23 ●     │    12 ●    │    8 ●     │    2 ●     │       2 ●        │ │
│  │  avg 1.2s   │  avg 45s   │  avg 3.8s  │  avg 22s   │    avg 5m        │ │
│  └────────────┴────────────┴────────────┴────────────┴────────────────────┘ │
│                                                                              │
│  Active Flows                                                                │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  Flow ID       │ Type       │ State          │ Age    │ TTL    │ IP  │   │
│  │  ──────────────┼────────────┼────────────────┼────────┼────────┼──── │   │
│  │  flow_a1b2     │ password   │ 🟡 mfa_required│ 45s    │ 2m 15s │ .42│   │
│  │  flow_c3d4     │ magic_link │ 🟢 link_sent   │ 2m 30s │ 12m 30s│ .78│   │
│  │  flow_e5f6     │ magic_link │ 🟢 link_sent   │ 8m 12s │ 6m 48s │ .91│   │
│  │  flow_g7h8     │ oidc       │ 🔵 redirect    │ 15s    │ 9m 45s │ .23│   │
│  │  flow_i9j0     │ password   │ ⚡ authenticatd │ 0.3s   │ 4.7s   │ .55│   │
│  │  flow_k1l2     │ magic_link │ 🔴 link_sent   │ 13m 50s│ 1m 10s │ .67│   │
│  │  flow_m3n4     │ sms_code   │ 🟡 code_sent   │ 1m 20s │ 3m 40s │ .34│   │
│  │  flow_o5p6     │ pwd_reset  │ 🟢 code_sent   │ 12m    │ 48m    │ .89│   │
│  │  ...           │            │                │        │        │     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ● State colors: 🟢 healthy  🟡 >50% TTL  🔴 >80% TTL  ⚡ transient        │
│                                                                              │
│  Alerts (live)                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ ⚠ flow_k1l2: magic_link in link_sent for 13m 50s (max 15m)        │   │
│  │   → 92% of TTL elapsed. User likely abandoned.                      │   │
│  │                                                                      │   │
│  │ ⚠ 5 password flows from 198.51.100.0/24 in last 60s                │   │
│  │   → Possible credential stuffing. [View all →] [Block IP →]        │   │
│  │                                                                      │   │
│  │ ℹ Cognito latency elevated: P99 = 820ms (normal: ~200ms)           │   │
│  │   → 3 flows currently blocked on InitiateAuth                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Throughput (last 5 minutes)                                                 │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  ▂▃▅▇█▇▅▃▂▁▂▃▅▇█▇▅▃▂▁▂▃▅  completions/min: 23                    │   │
│  │  ░░░▒▒░░░░░░░░▒▒░░░░░░░░░  timeouts/min: 2                       │   │
│  │  ░░░░░░░░░░░░░░░░░░░░░░░░  failures/min: 1                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Clicking into a live flow shows its current event trace in real time:

```
┌──────────────────────────────────────────────────────────────┐
│  Live Flow: flow_a1b2                                 [Kill] │
│  Type: password │ State: 🟡 mfa_required │ Age: 48s          │
│  TTL: 2m 12s remaining (state) │ 4m 12s remaining (flow)    │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Principal: j***@acme.com │ Tenant: tenant_acme              │
│  IP: 203.0.113.42 │ User-Agent: Chrome/120 macOS             │
│                                                               │
│  Event trace (live):                                          │
│                                                               │
│  #0  14:32:01.000  Initiated → Authenticated         0.5s   │
│      └── Cognito InitiateAuth                   480ms ✅     │
│                                                               │
│  #1  14:32:01.500  Authenticated → MfaRequired       0.1s   │
│      └── MFA method: TOTP                                    │
│                                                               │
│  ⏳ Waiting for MFA code... (48s elapsed, 2m 12s remaining)  │
│     ████████████████░░░░░░░░░░░░░░░░░ 27% of state TTL      │
│                                                               │
│  Actions:                                                     │
│  [Kill flow] [Extend timeout +5m] [View user →]              │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

#### Kill and Extend actions:

- **Kill flow** — immediately terminates the flow. Records a `manual_kill` event in the event log with the operator's identity. Cleans up side-effect resources. The user sees an "authentication session expired" message and must restart. Requires `operations:god_mode_write` permission.

- **Extend timeout** — adds time to the current state TTL and/or flow max lifetime. Records an `timeout_extended` event in the event log with the operator's identity and the new timeout values. Useful when support is on a call with a user who's struggling with MFA setup. Requires `operations:god_mode_write` permission.

Both actions are audit-logged with full attribution — who did what to which flow, when.

#### Aggregate views for incident response:

```
┌──────────────────────────────────────────────────────────────┐
│  God Mode — State Distribution (live)                         │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  password (23 active)                                         │
│  ├── initiated       ░░░ 2                                   │
│  ├── authenticated   ░ 1 (transient, should clear in <5s)    │
│  ├── mfa_required    ████████ 18  ← most flows waiting here  │
│  └── mfa_verified    ░░ 2 (transient)                        │
│                                                               │
│  magic_link (12 active)                                       │
│  ├── initiated       ░ 1                                     │
│  └── link_sent       ████████████ 11  ← waiting for clicks   │
│                                                               │
│  oidc (8 active)                                              │
│  ├── redirect_pending ████████ 8  ← all waiting on IdP       │
│  └── callback_received 0                                      │
│                                                               │
│  ⚠ 8/8 OIDC flows are in redirect_pending.                   │
│    If IdP is down, these will all timeout in ~8 minutes.      │
│    [View OIDC provider health →]                              │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

```
┌──────────────────────────────────────────────────────────────┐
│  God Mode — Blocked on External Services (live)               │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Currently in a Cognito API call:        3 flows             │
│  ├── InitiateAuth                        2 (avg 650ms)       │
│  └── RespondToAuthChallenge              1 (1.2s so far)     │
│                                                               │
│  Waiting for SES email delivery:         1 flow              │
│  └── SendEmail                           1 (2.1s so far)     │
│                                                               │
│  Waiting for user action:                43 flows            │
│  ├── Magic link click                    11                  │
│  ├── MFA code entry                      18                  │
│  ├── OIDC redirect return                8                   │
│  ├── SMS code entry                      2                   │
│  └── Password reset code                 2                   │
│  └── Email verification                  2                   │
│                                                               │
│  No flows are currently blocked on SNS or DynamoDB.          │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

#### Heatmap: flow lifecycle over time

```
┌──────────────────────────────────────────────────────────────┐
│  God Mode — Flow Heatmap (last 30 minutes)                    │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  14:00    14:10    14:20    14:30 (now)                       │
│  ┊        ┊        ┊        ┊                                │
│  ░░░▒▓███▓▒░░░░▒▓█▓▒░░░░░▒▓████  password (completions)     │
│  ░░░░░░░░░░░░░░▒▓▓▒░░░░░░░░░░░░  password (timeouts)        │
│  ░░░░░▒▒▒░░░░▒▒▓▒░░░░░▒▒▓▒░░░░  magic_link (completions)   │
│  ░░░░░░░▒░░░░░░░░░░░░░░░░░▒░░░░  magic_link (abandoned)     │
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░████  oidc (⚠ all pending)       │
│                                                               │
│  ⚠ OIDC flows stopped completing at 14:25.                   │
│    8 flows now stuck in redirect_pending.                     │
│    Likely: OIDC provider outage.                              │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

#### API backing God Mode

```
GET  /projects/{projectId}/flows/active          # All in-flight flows
GET  /projects/{projectId}/flows/active/summary   # Aggregate counts by type/state
GET  /projects/{projectId}/flows/{flowId}/live    # Single flow detail (SSE stream)
POST /projects/{projectId}/flows/{flowId}/kill     # Manual termination
POST /projects/{projectId}/flows/{flowId}/extend   # Extend timeout

# WebSocket endpoint for real-time updates
WS   /projects/{projectId}/flows/active/stream
```

The live flow list and single-flow detail use **Server-Sent Events (SSE)** or **WebSocket** for real-time updates. The dashboard doesn't poll — it receives push updates as transitions occur.

```smithy
@readonly
@http(method: "GET", uri: "/projects/{projectId}/flows/active")
@authorize(action: "operations:god_mode", resource: "projectId")
operation ListActiveFlows {
    input := {
        @required @httpLabel
        projectId: ProjectId

        @httpQuery("flow_type")
        flowType: String

        @httpQuery("state")
        state: String

        @httpQuery("tenant_id")
        tenantId: TenantId

        @httpQuery("ip_prefix")
        ipPrefix: String
    }
    output := {
        @required
        flows: ActiveFlowList

        @required
        summary: FlowSummary

        @required
        alerts: AlertList
    }
}

@http(method: "POST", uri: "/projects/{projectId}/flows/{flowId}/kill")
@authorize(action: "operations:god_mode_write", resource: "projectId")
operation KillFlow {
    input := {
        @required @httpLabel
        projectId: ProjectId

        @required @httpLabel
        flowId: FlowId

        @required
        reason: String
    }
    output := {
        @required
        killed: Boolean

        @required
        eventLogPersisted: Boolean
    }
}

@http(method: "POST", uri: "/projects/{projectId}/flows/{flowId}/extend")
@authorize(action: "operations:god_mode_write", resource: "projectId")
operation ExtendFlowTimeout {
    input := {
        @required @httpLabel
        projectId: ProjectId

        @required @httpLabel
        flowId: FlowId

        @required
        additionalSeconds: Integer

        extendFlowLifetime: Boolean = true
        extendStateTimeout: Boolean = true
    }
    output := {
        @required
        newFlowExpiry: Timestamp

        @required
        newStateExpiry: Timestamp
    }
}
```

#### Privacy and accountability

God Mode shows **redacted** identity information by default — `j***@acme.com`, `user_***456`. Operators with `operations:god_mode_pii` permission see full values. This permission is separate from `god_mode` and `god_mode_write`, enabling a tiered access model:

| Permission | What it grants |
|-----------|---------------|
| `operations:god_mode` | View live flows with redacted identities |
| `operations:god_mode_pii` | View live flows with full PII (emails, user IDs) |
| `operations:god_mode_write` | Kill flows, extend timeouts |

All three are audit-logged: who viewed God Mode, when, what filters they applied, which flows they inspected, and any write actions taken. The audit entry for a kill includes the operator, the target flow, the flow's event history at time of kill, and the stated reason.

---

## Part 3: Webhook Event System

### Architecture

```
Entity mutation or security event occurs
        │
        ▼
  Internal Event Bus
        │
        ├──► Audit Log (always stored, queryable in dashboard)
        │
        ├──► Webhook Dispatcher
        │       │
        │       ├── Match subscribed webhooks by event type
        │       ├── Apply tenant/custom filters
        │       ├── Sign payload (HMAC-SHA256 with per-webhook secret)
        │       ├── Deliver with configurable timeout
        │       │
        │       └── On failure:
        │           ├── Exponential backoff retry (configurable max)
        │           ├── Dead letter after max retries
        │           ├── Mark webhook as degraded in dashboard
        │           └── Emit internal alert
        │
        └──► Usage Metrics (event counts, delivery latency, failure rate)
```

### Event Categories

| Category | Events | Volume |
|----------|--------|--------|
| User lifecycle | `user.created`, `user.updated`, `user.deleted`, `user.disabled`, `user.enabled`, `user.login.succeeded`, `user.login.failed` | Low-medium |
| Permission changes | `role.assigned`, `role.revoked`, `permission.granted`, `permission.revoked`, `permission.scope_changed` | Low |
| Policy changes | `policy.created`, `policy.updated`, `policy.deleted`, `policy.validated` | Low |
| Authorization | `authorization.denied`, `authorization.denied.repeated` (5+ denials for same user+action in 1 min) | Opt-in, potentially high |
| Feature flags | `feature.enabled`, `feature.disabled`, `feature.rollout_changed`, `feature.experiment_started`, `feature.experiment_stopped` | Low |
| Tenant lifecycle | `tenant.created`, `tenant.updated`, `tenant.deleted` | Low |
| Model changes | `model.pushed`, `model.validated`, `sdk.generated` | Low |
| Operator actions | `flow.killed`, `flow.timeout_extended`, `god_mode.accessed` | Low |

The `authorization.denied.repeated` event is an aggregation — instead of firehosing individual denials, the system detects patterns and emits a single event when the same user hits 5+ denials for the same action within one minute. This catches brute-force attempts and misconfigured clients without flooding webhook consumers.

### Event Envelope

Every event follows a consistent structure:

```json
{
    "id": "evt_a1b2c3d4e5f6",
    "type": "role.assigned",
    "timestamp": "2025-09-15T14:35:00.123Z",
    "project_id": "proj_123",
    "tenant_id": "tenant_acme",
    "actor": {
        "type": "user",
        "id": "admin_jane",
        "ip": "203.0.113.42",
        "source": "dashboard"
    },
    "entity": {
        "type": "user",
        "id": "user_456"
    },
    "data": {
        "role": "publisher",
        "previous_roles": ["editor"],
        "current_roles": ["editor", "publisher"],
        "permissions_added": ["document:publish", "document:archive"]
    },
    "metadata": {
        "request_id": "req_def456"
    }
}
```

Fields: `id` (unique event ID), `type` (dot-separated event type), `timestamp` (ISO 8601), `project_id`, `tenant_id`, `actor` (who/what triggered the event), `entity` (what was affected), `data` (event-specific payload), `metadata` (request context).

### Webhook Configuration

**API:**

```
POST   /projects/{projectId}/webhooks           # Create webhook
GET    /projects/{projectId}/webhooks           # List webhooks
PUT    /projects/{projectId}/webhooks/{id}      # Update webhook
DELETE /projects/{projectId}/webhooks/{id}      # Delete webhook
POST   /projects/{projectId}/webhooks/{id}/test # Test delivery
POST   /projects/{projectId}/webhooks/{id}/rotate-secret  # Rotate signing secret
GET    /projects/{projectId}/webhooks/{id}/deliveries     # Delivery log
```

**Configuration fields:**
- `name` — human-readable label
- `url` — HTTPS endpoint
- `secret` — HMAC-SHA256 signing key (auto-generated, rotatable)
- `events` — array of event types or patterns (`user.*`, `authorization.denied.*`)
- `filter` — optional tenant/attribute filter
- `retry_policy` — exponential backoff, max retries, timeout
- `batch_window` — optional batching interval (default: real-time)

### Signature Verification

Payloads are signed using HMAC-SHA256. The signature is sent in the `X-ForgeGate-Signature` header:

```
X-ForgeGate-Signature: v1=<hex_digest>
X-ForgeGate-Timestamp: <unix_timestamp>
```

Signing input: `{timestamp}.{raw_body}`

The ForgeGate SDK provides a `WebhookHandler` class that handles verification automatically. For manual verification:

```python
import hmac, hashlib, time

def verify_webhook(body: bytes, headers: dict, secret: str) -> bool:
    signature = headers["X-ForgeGate-Signature"]
    timestamp = headers["X-ForgeGate-Timestamp"]

    # Reject stale events (replay protection)
    if abs(time.time() - int(timestamp)) > 300:
        return False

    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.{body.decode()}".encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, f"v1={expected}")
```

### Self-Hosted Event Delivery

For customers running the self-hosted data plane who need events to stay within their AWS account, the Data Plane Agent can emit events directly to an EventBridge bus in the customer's account. This bypasses the control plane webhook system entirely. Sensitive data (user PII, token contents) is never included in events relayed through the control plane.

---

## Part 4: Dogfooding Architecture

### The Control Plane API in Smithy

The ForgeGate Control Plane API is itself modeled in Smithy with ForgeGate traits:

```smithy
$version: "2"
namespace io.forgegate.api

use forgegate.traits#authorize
use forgegate.traits#authResource
use forgegate.traits#featureGate

@httpBearerAuth
@restJson1
service ForgeGateControlPlane {
    version: "2025-01-01"
    resources: [Project, User, Policy, Webhook, Tenant]
    operations: [TestAuthorization]
}

@authResource(namespace: "forgegate")
resource Project {
    identifiers: { projectId: ProjectId }
    operations: [PushModel, ValidateModel, ExportSmithy]
}

@authResource(namespace: "forgegate")
resource User {
    identifiers: { userId: UserId }
    operations: [
        DisableUser, EnableUser,
        AssignRole, RevokeRole,
        GrantPermission, RevokePermission,
        GetEffectivePermissions, GetUserActivity
    ]
}

@authResource(namespace: "forgegate")
resource Policy {
    operations: [ValidatePolicy]
}

@authResource(namespace: "forgegate")
resource Webhook {
    operations: [TestWebhook, RotateSecret, GetDeliveryLog]
}

@http(method: "POST", uri: "/projects/{projectId}/test-authorization")
@authorize(action: "policy:test", resource: "projectId")
operation TestAuthorization {
    input := {
        @required @httpLabel
        projectId: ProjectId
        @required
        principalId: String
        @required
        action: String
        resourceId: String
        context: ContextMap
    }
    output := {
        @required
        decision: Decision
        @required
        evaluatedPolicies: PolicyEvaluationList
        latencyMs: Integer
    }
}
```

### What Dogfooding Proves

- The proxy protecting the Control Plane API uses the same ForgeGate wrapper shipped to customers
- The dashboard React app uses a ForgeGate-generated SDK to call the API
- Role-based access on the dashboard (admin, support, security_auditor) is enforced by ForgeGate's own Cedar policies
- Webhook events for control plane mutations (user created, policy changed) go through the same webhook dispatcher
- The audit log for control plane actions uses the same audit infrastructure

A `support` role in the ForgeGate dashboard might have `user:read` and `policy:test` but not `user:delete` or `policy:write`. A `security_auditor` role has `audit:read` and `policy:test` only. These permissions are defined in the same Smithy model and enforced by the same proxy.

---

## Part 5: Bidirectional Sync

### UI → Smithy

Every UI action calls the Model API, which passes through the Model Engine:

```
UI click "Create Resource: Document"
    → POST /projects/{id}/resources
    → Model Engine: createResource()
    → Smithy AST mutation
    → Validate full model
    → Write .smithy file
    → Sync to data plane (Cedar policies, VP, route mappings)
    → Return generated endpoints + warnings to UI
```

### Smithy → UI

When a developer edits the `.smithy` file directly (in their IDE) and pushes:

```
Developer edits main.smithy in VSCode
    → forgegate push (CLI)
    → Model Engine: parseSmithyFile()
    → Validate against best practices
    → Diff against current model state
    → Update UI state from AST
    → Sync to data plane
    → Dashboard reflects changes on next load
```

### Handling UI-unsupported features

If a developer hand-edits Smithy to add something the UI doesn't support (e.g., a custom Cedar condition via a trait the UI doesn't know about), the UI:

1. Parses it successfully (the Smithy AST handles arbitrary traits)
2. Displays the operation in the endpoints list
3. Shows a badge: "This operation has custom Smithy configuration that can only be edited in the .smithy file"
4. Makes that specific operation read-only in the UI
5. Never loses or modifies the custom content on subsequent UI edits to other parts of the model

The invariant: **the UI never destroys information it doesn't understand.**

---

## Related Documents

- [SaaS Integration Guide](02-technical-saas-integration.md) — developer-facing integration guide
- [Authorization Testing](09-technical-authorization-testing.md) — test suite that complements the policy test bench
- [Identity Engine](11-technical-identity-engine-rust.md) — state machines and event logs that power God Mode and Flow Inspector
- [Internal Back Office](12-technical-back-office.md) — ForgeGate's own internal operations dashboard
- [Tutorial: TODO App](14-tutorial-todo-app.md) — end-to-end example using the dashboard

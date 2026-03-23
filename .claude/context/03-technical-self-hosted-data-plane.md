# ForgeGate — Technical Guide: Self-Hosted Data Plane

> For developers deploying ForgeGate's data plane in their own AWS account while using the ForgeGate control plane SaaS.

---

## Overview

In the self-hosted model, ForgeGate splits into two components:

- **Control Plane (ForgeGate SaaS):** Policy management, SDK generation, dashboard, schema compilation. Hosted and operated by ForgeGate. Contains no customer user data.
- **Data Plane (Your AWS Account):** Cognito, Verified Permissions, the auth proxy, and cache. Deployed and owned by you. All user data, tokens, and authorization decisions stay in your account.

This model is designed for teams that need data sovereignty, compliance control, or simply want their authentication infrastructure running on their own AWS resources.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  ForgeGate Control Plane (SaaS)                       │
│                                                       │
│  ┌───────────┐ ┌──────────────┐ ┌─────────────────┐ │
│  │ Dashboard  │ │ CLI / API    │ │ SDK Generator   │ │
│  │ & Admin    │ │              │ │ (Smithy)        │ │
│  └─────┬──────┘ └──────┬──────┘ └────────┬────────┘ │
│        │               │                 │           │
│  ┌─────┴─────────────┬─┴─────────────────┘           │
│  │  Control Plane API │                               │
│  │                    │                               │
│  │  • Schema → Cedar compilation                     │
│  │  • Role/permission template management            │
│  │  • Feature flag definitions & targeting           │
│  │  • SDK generation & publishing                    │
│  │  • Billing (via Marketplace metering)             │
│  │  • Aggregated analytics (no PII)                  │
│  └────────┬───────────┘                               │
│           │                                            │
└───────────┼────────────────────────────────────────────┘
            │
   Encrypted sync channel
   (Cedar policies, flag configs, schema)
            │
┌───────────┼────────────────────────────────────────────┐
│  Your AWS │Account (Data Plane)                        │
│           ▼                                            │
│  ┌──────────────────────────────────────────────┐     │
│  │  Data Plane Agent (Lambda / Fargate)          │     │
│  │                                               │     │
│  │  • Pulls policy updates from control plane    │     │
│  │  • Syncs Cedar policies → Verified Perms      │     │
│  │  • Syncs identity config → Cognito            │     │
│  │  • Evaluates feature flags locally            │     │
│  │  • Reports usage metrics → Marketplace        │     │
│  └────────┬──────────────┬───────────────┘       │     │
│           │              │                       │     │
│           ▼              ▼                       │     │
│  ┌────────────┐  ┌──────────────┐               │     │
│  │  Cognito   │  │  Verified    │               │     │
│  │  User Pool │  │  Permissions │               │     │
│  │            │  │  Policy Store│               │     │
│  └────────────┘  └──────────────┘               │     │
│                                                  │     │
│  ┌──────────────────────────────────────────┐   │     │
│  │  Auth Proxy / ASGI Wrapper               │   │     │
│  │  (forgegate run / sidecar container)      │   │     │
│  │                                           │   │     │
│  │  Validates tokens → Calls VP → Injects    │   │     │
│  │  X-Auth-* headers → Forwards to app       │   │     │
│  └──────────────────┬───────────────────────┘   │     │
│                     │                            │     │
│                     ▼                            │     │
│  ┌──────────────────────────────────────────┐   │     │
│  │  Your Application (FastAPI, Express, etc) │   │     │
│  └──────────────────────────────────────────┘   │     │
│                                                  │     │
│  ┌──────────────────────────────────────────┐   │     │
│  │  Optional: Redis/Valkey Cache             │   │     │
│  │  (ElastiCache — auth decision caching)    │   │     │
│  └──────────────────────────────────────────┘   │     │
│                                                        │
│  User data, tokens, auth decisions, API traffic        │
│  ─── NEVER LEAVE THIS ACCOUNT ───                     │
└────────────────────────────────────────────────────────┘
```

## Data Boundary

### Crosses the boundary (Control Plane → Data Plane):

- Cedar policy definitions (compiled from Smithy model)
- Role and permission templates
- Feature flag configurations and targeting rules
- Schema updates

All configuration data, signed and encrypted in transit. No user data.

### NEVER crosses the boundary:

- User credentials and passwords
- JWTs and session tokens
- PII (emails, names, attributes)
- Authorization decisions
- API request/response traffic
- Audit logs (stored in your CloudTrail)

---

## Deployment

### Prerequisites

- An AWS account with permissions to create Cognito, Verified Permissions, Lambda/Fargate, and IAM resources
- AWS CLI configured
- A ForgeGate account with a data plane key (`dpk_...`)

### Option A: AWS CDK (Recommended)

```bash
npm install @forgegate/cdk

npx cdk deploy ForgeGateDataPlane \
  --context controlPlaneUrl=https://api.forgegate.io \
  --context dataplaneKey=dpk_abc123 \
  --context region=us-east-1
```

### Option B: Terraform

```hcl
module "forgegate_data_plane" {
  source  = "forgegate/data-plane/aws"
  version = "~> 1.0"

  control_plane_url = "https://api.forgegate.io"
  data_plane_key    = var.forgegate_dpk
  
  # Cognito configuration
  cognito_user_pool_name = "myapp-users"
  
  # Verified Permissions
  policy_store_description = "MyApp authorization"
  
  # Networking
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnets
  
  # Optional: Cache
  enable_cache       = true
  cache_node_type    = "cache.t4g.micro"

  # Marketplace metering (if subscribed via Marketplace)
  marketplace_product_code = "abc123xyz"
}
```

### Option C: Helm (Kubernetes)

```bash
helm repo add forgegate https://charts.forgegate.io
helm install forgegate-dp forgegate/data-plane \
  --set controlPlane.url=https://api.forgegate.io \
  --set controlPlane.key=dpk_abc123 \
  --set aws.region=us-east-1
```

### What the deployment creates:

| Resource | Purpose |
|----------|---------|
| Cognito User Pool | User directory and authentication |
| Cognito App Client(s) | Token issuance for your application |
| Verified Permissions Policy Store | Cedar-based authorization engine |
| Data Plane Agent (Lambda or Fargate) | Syncs config from control plane |
| IAM Roles | Scoped permissions for agent + proxy |
| ElastiCache Redis/Valkey (optional) | Auth decision caching |
| CloudWatch Log Groups | Monitoring and observability |
| Marketplace Metering IAM Role | Usage reporting for billing |

---

## Configuration

### Data Plane Agent

The agent runs on a 30-second sync loop:

```
1. Pull latest state from control plane API
2. Diff Cedar policies against current policy store
3. Apply changes to Verified Permissions (create/update/delete policies)
4. Update Cognito configuration (groups, app clients) if changed
5. Refresh local feature flag cache
6. Report anonymized usage metrics (MAU count, auth request count)
```

The agent is idempotent — running multiple instances is safe. It uses optimistic concurrency to prevent conflicts.

### Connecting Your App

The wrapper/proxy talks directly to Cognito and Verified Permissions in your account:

```bash
# Environment variables for the wrapper
export FORGEGATE_MODE=self-hosted
export FORGEGATE_REGION=us-east-1
export FORGEGATE_COGNITO_USER_POOL_ID=us-east-1_AbCdEf
export FORGEGATE_POLICY_STORE_ID=ps-abc123
export FORGEGATE_CACHE_ENDPOINT=redis://my-cache.abc123.use1.cache.amazonaws.com:6379

# Run your app with the wrapper
forgegate run app:app
```

Or as environment variables in your Kubernetes deployment:

```yaml
containers:
  - name: forgegate-proxy
    image: forgegate/proxy:latest
    env:
      - name: FORGEGATE_MODE
        value: self-hosted
      - name: FORGEGATE_REGION
        value: us-east-1
      - name: FORGEGATE_COGNITO_USER_POOL_ID
        valueFrom:
          secretKeyRef:
            name: forgegate-config
            key: cognito-pool-id
      - name: FORGEGATE_POLICY_STORE_ID
        valueFrom:
          secretKeyRef:
            name: forgegate-config
            key: policy-store-id
      - name: UPSTREAM_URL
        value: "http://localhost:3000"
    ports:
      - containerPort: 8080
  - name: app
    image: my-app:latest
    ports:
      - containerPort: 3000
```

---

## Identity Provider Flexibility

In self-hosted mode, you own the Cognito user pool. This means you can configure it directly:

```bash
# Use Cognito as the IdP (default)
forgegate identity configure --provider cognito

# Or connect an external IdP via Cognito federation
forgegate identity configure --provider oidc \
  --issuer https://accounts.google.com \
  --client-id xxx \
  --client-secret yyy

# Or use your existing IdP — proxy validates JWTs directly
forgegate identity configure --provider custom \
  --jwks-url https://auth.mycompany.com/.well-known/jwks.json
```

The proxy validates tokens regardless of source. The authorization layer (Verified Permissions) is identity-provider agnostic.

---

## AWS Marketplace Billing

If you subscribed via AWS Marketplace, the Data Plane Agent handles metering automatically:

```
Agent (your account)
    │
    ├── Counts MAU (from Cognito CloudWatch metrics)
    ├── Counts authorization requests (from VP CloudWatch metrics)
    │
    └── Calls BatchMeterUsage() hourly
            │
            ▼
        AWS Marketplace Metering Service
            │
            ▼
        Your AWS Bill
        ├── Amazon Cognito           $XXX
        ├── Amazon Verified Perms    $XXX
        ├── ForgeGate Platform       $XXX  ← ForgeGate's fee
        └── Total                    $XXX
```

All charges consolidated on one AWS bill. ForgeGate's platform fee counts toward your AWS Enterprise Discount Program (EDP) committed spend.

---

## Operational Considerations

### Monitoring

The data plane emits CloudWatch metrics:

| Metric | Namespace | Description |
|--------|-----------|-------------|
| `AuthorizationRequests` | `ForgeGate` | Total auth decisions per minute |
| `AuthorizationLatencyP99` | `ForgeGate` | P99 latency of auth decisions |
| `CacheHitRate` | `ForgeGate` | Percentage of cached auth decisions |
| `PolicySyncLatency` | `ForgeGate` | Time to sync policies from control plane |
| `FeatureFlagEvaluations` | `ForgeGate` | Feature flag checks per minute |

### Dashboard & Operations

In self-hosted mode, the ForgeGate dashboard at `app.forgegate.io` remains your control surface for:

- **Model Studio** — Visual resource/endpoint/role configuration, generating Smithy that syncs to your data plane
- **User Management** — Full user directory, role assignment, permission grants (writes to Cognito in your account via the Data Plane Agent)
- **Policy Management** — Custom Cedar policies, guided builder, test bench (applied to VP in your account)
- **Feature Flags** — Per-tenant configuration, targeting, experiments
- **Audit Log** — Authorization decision logs (aggregated from your CloudWatch/CloudTrail, displayed in the dashboard)
- **Webhooks** — Event subscriptions for user lifecycle, permission changes, authorization denials, and model updates

The key difference from SaaS mode: the dashboard talks to the Data Plane Agent in your account, which executes operations against your Cognito and VP. The dashboard never talks to your Cognito or VP directly.

### Webhooks in Self-Hosted Mode

Webhooks originate from the control plane. Events that occur in your data plane (authorization decisions, user logins) are reported by the Data Plane Agent to the control plane as anonymized event triggers, which then fire webhooks to your configured endpoints. Sensitive data (user PII, token contents) is never included in webhook payloads relayed through the control plane — only event types, entity IDs, and metadata.

For customers who need webhook events to stay entirely within their account, the Data Plane Agent can emit events directly to an EventBridge bus in your account, bypassing the control plane webhook system entirely.

### Audit Logging

All Verified Permissions authorization calls are logged to CloudTrail in your account. Each log entry includes the principal, action, resource, and decision — providing a complete audit trail.

### Backup and Recovery

- **Cognito:** User data is managed by AWS with built-in AZ redundancy. Use the Cognito User Profiles Export solution for cross-region backup.
- **Verified Permissions:** Policies are synced from the control plane and can be fully reconstructed from the Smithy model. The control plane is the source of truth.
- **Feature flags:** Configuration is stored in the control plane and re-synced on agent restart.

### Upgrading

The Data Plane Agent and proxy are versioned independently from the control plane:

```bash
# CDK
npx cdk deploy ForgeGateDataPlane  # pulls latest construct version

# Terraform
terraform apply  # module version pinned in source

# Helm
helm upgrade forgegate-dp forgegate/data-plane

# Docker (sidecar proxy)
docker pull forgegate/proxy:latest
```

---

## Comparison: SaaS vs Self-Hosted Data Plane

| Aspect | SaaS Mode | Self-Hosted Data Plane |
|--------|-----------|----------------------|
| User data location | ForgeGate's AWS account | Your AWS account |
| Infrastructure management | ForgeGate manages everything | You manage data plane resources |
| Compliance control | Shared responsibility | Full control over data residency |
| Cost model | ForgeGate subscription only | Your AWS costs + ForgeGate platform fee |
| Setup complexity | Minutes (API key only) | 15-30 min (CDK/Terraform deployment) |
| IdP flexibility | ForgeGate managed Cognito | Full Cognito control + external IdPs |
| Audit logs | Via ForgeGate dashboard | Directly in your CloudTrail |
| Network path | Auth requests route through ForgeGate | Auth requests stay in your VPC |

### When to choose self-hosted:

- You operate in a regulated industry (healthcare, finance, government)
- Company policy requires data to stay in your AWS account
- You need to use your existing Cognito user pool or external IdP
- You want auth decisions to stay within your VPC for latency
- You need CloudTrail audit logs in your own account
- You want to leverage existing AWS committed spend (EDP)

---

## Authorization Testing

Authorization testing works identically in self-hosted mode. The test suite runs against your locally-deployed app and validates enforcement through the proxy and directly:

```bash
forgegate test connect --port 8000 --direct-port 3000 --mode both
```

Tests execute against the Verified Permissions policy store in your account, validating that the Data Plane Agent synced policies correctly. For full details, see [Authorization Testing](09-technical-authorization-testing.md).

---

## God Mode: Live Flow Monitor

In self-hosted mode, God Mode in the dashboard connects to your Data Plane Agent to display in-flight authentication flows. Flow data stays in your account — the dashboard queries the agent, which queries your local flow store. The control plane never sees raw flow data, only the aggregated view needed for the dashboard.

Kill and extend operations are routed through the agent to your local flow store. For full details, see [Control Plane UI Design](08-technical-control-plane-ui.md).

---

## Related Documents

- [SaaS Integration Guide](02-technical-saas-integration.md) — simpler alternative if you don't need data sovereignty
- [Multi-Region & DR Architecture](04-multi-region-dr-architecture.md) — deploying the data plane across multiple regions
- [Control Plane UI Design](08-technical-control-plane-ui.md) — full dashboard architecture
- [Authorization Testing](09-technical-authorization-testing.md) — auto-generated test suite and CI/CD integration
- [Identity Engine](11-technical-identity-engine-rust.md) — how authentication flows work under the hood
- [Tutorial: TODO App](14-tutorial-todo-app.md) — end-to-end example

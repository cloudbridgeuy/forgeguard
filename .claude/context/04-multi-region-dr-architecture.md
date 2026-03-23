# ForgeGate — Multi-Region Deployment & Disaster Recovery

> Technical architecture for deploying ForgeGate's data plane across multiple AWS regions with proper failover.

---

## Honest Constraints

Before presenting the architecture, it's important to acknowledge the real limitations of the underlying AWS services:

1. **Amazon Cognito does not support native cross-region replication.** User pools are regional. There is no built-in mechanism to sync users, groups, or credentials across regions. Passwords cannot be exported or replicated.

2. **Amazon Verified Permissions does not support cross-region replication.** Policy stores are regional, replicated across Availability Zones within a single region only.

3. **These are not ForgeGate limitations — they are AWS service constraints.** Any product built on Cognito and Verified Permissions inherits them.

The architecture below works within these constraints to provide the best achievable resilience, with clear documentation of RPO/RTO tradeoffs.

---

## Architecture Overview

ForgeGate's multi-region strategy uses the following approach:

- **Control Plane:** Deployed in a primary region with a hot standby. Control plane state is stored in DynamoDB Global Tables, providing automatic cross-region replication.
- **Data Plane (Verified Permissions):** The ForgeGate Data Plane Agent independently provisions and syncs policy stores in each region from the control plane. Since the Smithy model is the source of truth, policies can be fully reconstructed in any region.
- **Data Plane (Cognito):** Active-passive with user profile sync via DynamoDB Global Tables. Passwords cannot be replicated — failover requires a password reset flow.
- **Auth Proxy / Wrapper:** Deployed per-region, stateless, reads from local Cognito and VP.

```
                        ┌──────────────────────┐
                        │    Route 53           │
                        │    (latency-based     │
                        │     or failover)      │
                        └──────────┬───────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
          ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
          │  Region A   │ │  Region B   │ │  Region C   │
          │  (Primary)  │ │  (Hot Stby) │ │  (Optional) │
          │             │ │             │ │             │
          │ ┌─────────┐ │ │ ┌─────────┐ │ │             │
          │ │Cognito  │ │ │ │Cognito  │ │ │    ...      │
          │ │User Pool│ │ │ │User Pool│ │ │             │
          │ │(active) │ │ │ │(standby)│ │ │             │
          │ └────┬────┘ │ │ └─────────┘ │ │             │
          │      │      │ │      ▲      │ │             │
          │      ▼      │ │      │      │ └─────────────┘
          │ ┌─────────┐ │ │ ┌────┴────┐ │
          │ │DynamoDB │◄┼─┼─┤DynamoDB │ │
          │ │Global   │─┼─┼►│Global   │ │
          │ │Table    │ │ │ │Table    │ │
          │ │(users)  │ │ │ │(users)  │ │
          │ └─────────┘ │ │ └─────────┘ │
          │             │ │             │
          │ ┌─────────┐ │ │ ┌─────────┐ │
          │ │Verified │ │ │ │Verified │ │
          │ │Perms    │ │ │ │Perms    │ │
          │ │(synced) │ │ │ │(synced) │ │
          │ └─────────┘ │ │ └─────────┘ │
          │             │ │             │
          │ ┌─────────┐ │ │ ┌─────────┐ │
          │ │Proxy/   │ │ │ │Proxy/   │ │
          │ │Wrapper  │ │ │ │Wrapper  │ │
          │ └────┬────┘ │ │ └────┬────┘ │
          │      ▼      │ │      ▼      │
          │ ┌─────────┐ │ │ ┌─────────┐ │
          │ │  App    │ │ │ │  App    │ │
          │ └─────────┘ │ │ └─────────┘ │
          └─────────────┘ └─────────────┘
```

---

## Component-by-Component Strategy

### 1. Verified Permissions: Policy Replication

**Strategy: Agent-driven sync from control plane to each region.**

This is the easiest component to handle. Since the control plane holds the canonical Smithy model and compiled Cedar policies, the Data Plane Agent in each region independently syncs policies to its local policy store.

```
Control Plane
    │
    ├──► Agent (Region A) ──► VP Policy Store (Region A)
    │
    ├──► Agent (Region B) ──► VP Policy Store (Region B)
    │
    └──► Agent (Region C) ──► VP Policy Store (Region C)
```

**RPO: Zero.** All regions have identical policies within the sync interval (30 seconds). Policy changes propagate to all regions independently.

**RTO: Zero.** Each region's VP is already active and serving requests. No failover needed — it's active-active.

**Implementation:**

```hcl
# Each region gets its own Data Plane Agent + VP policy store
module "forgegate_dp_us_east_1" {
  source = "forgegate/data-plane/aws"
  providers = { aws = aws.us_east_1 }
  control_plane_url = "https://api.forgegate.io"
  data_plane_key    = var.forgegate_dpk
}

module "forgegate_dp_eu_west_1" {
  source = "forgegate/data-plane/aws"
  providers = { aws = aws.eu_west_1 }
  control_plane_url = "https://api.forgegate.io"
  data_plane_key    = var.forgegate_dpk
}
```

### 2. Cognito: User Identity Replication

**Strategy: Active-passive with DynamoDB Global Tables for profile sync.**

This is the hard problem. Cognito user pools are strictly regional with no native replication. The approach:

**Primary region:**
- All user signups, profile changes, and password operations happen here.
- A Cognito Post-Confirmation / Post-Authentication Lambda trigger writes user profile data (attributes, groups, metadata) to a DynamoDB Global Table.

**Secondary region(s):**
- A standby Cognito user pool exists with matching configuration (app clients, groups, triggers).
- A DynamoDB Streams trigger on the Global Table invokes a Lambda that creates/updates users in the local Cognito pool.
- Users are created with a temporary password and `FORCE_CHANGE_PASSWORD` status.

**The password problem:**

Cognito does not expose password hashes. There is no way to replicate a user's password to another region. This means:

- **During normal operation:** All auth requests route to the primary region via Route 53. Users authenticate against the primary Cognito pool. Latency is the only tradeoff.
- **During failover:** Users in the secondary region must reset their passwords on first login. The app presents a "verify your identity" flow that triggers a password reset via email/SMS.
- **After recovery:** When the primary region returns, the original passwords still work. Users who reset their passwords during failover will have their new passwords in the secondary pool only. A reconciliation process merges changes back.

**Mitigations for the password problem:**

1. **Passwordless authentication:** If you use email OTP, SMS OTP, or passkeys (WebAuthn) instead of passwords, the failover is seamless. There are no passwords to replicate. ForgeGate recommends passwordless for multi-region deployments.
2. **Token-based session continuity:** If users have long-lived refresh tokens cached client-side, they may not need to re-authenticate during a short failover window.
3. **External IdP federation:** If users authenticate via Google, SAML, or OIDC (e.g., Okta), Cognito is not storing passwords at all. The external IdP is the source of truth, and both regional Cognito pools can federate with it.

**RPO:** User profile data: ~1 second (DynamoDB Global Tables replication). Passwords: not replicated.

**RTO:** Depends on authentication method:

| Auth Method | Failover Experience | RTO |
|-------------|-------------------|-----|
| Passwordless (OTP/Passkeys) | Seamless | < 1 minute |
| External IdP (Google/SAML/OIDC) | Seamless | < 1 minute |
| Username + Password | Password reset required | 5-10 minutes |

### 3. Feature Flags: Local Evaluation

**Strategy: Active-active, no replication needed.**

Feature flag configuration is synced from the control plane to each region's agent independently. Flags are evaluated locally in the proxy — no cross-region dependency.

**RPO: Zero.** **RTO: Zero.** Fully active-active.

### 4. Auth Proxy / Wrapper: Stateless

**Strategy: Active-active, stateless per-region deployment.**

The proxy is stateless. It reads from the local Cognito and local VP in each region. No cross-region communication needed during request processing.

### 5. Cache: Per-Region

**Strategy: Independent cache per region.**

Each region runs its own Redis/Valkey cache for auth decision caching. Caches are not replicated — each warms independently. A cold cache after failover results in briefly higher VP call volume but no correctness issues.

### 6. Webhook Event Delivery

**Strategy: Control plane handles delivery, multi-region resilient.**

Webhook events are dispatched from the control plane, which itself runs on multi-region infrastructure (DynamoDB Global Tables for state, Route 53 for failover). If the control plane's primary region fails, the secondary continues dispatching events.

For self-hosted customers using EventBridge in their own account for events: each region's Data Plane Agent can emit to a regional EventBridge bus. EventBridge rules can fan out to cross-region targets if needed.

**RPO: ~1-5 seconds** (event may be delayed during control plane failover). **RTO: < 5 minutes.** No events are lost — they are queued and delivered after recovery.

---

## DNS and Routing

### Active-Passive (Simpler)

```hcl
resource "aws_route53_health_check" "primary" {
  fqdn              = "api-primary.myapp.com"
  port               = 443
  type               = "HTTPS"
  request_interval   = 10
  failure_threshold  = 3
}

resource "aws_route53_record" "api" {
  name    = "api.myapp.com"
  type    = "A"

  failover_routing_policy {
    type = "PRIMARY"
  }

  alias {
    name    = aws_lb.primary.dns_name
    zone_id = aws_lb.primary.zone_id
  }

  health_check_id = aws_route53_health_check.primary.id
  set_identifier  = "primary"
}

resource "aws_route53_record" "api_secondary" {
  name    = "api.myapp.com"
  type    = "A"

  failover_routing_policy {
    type = "SECONDARY"
  }

  alias {
    name    = aws_lb.secondary.dns_name
    zone_id = aws_lb.secondary.zone_id
  }

  set_identifier = "secondary"
}
```

### Latency-Based (For global users, passwordless only)

If using passwordless auth or external IdPs, you can run active-active with latency-based routing:

```hcl
resource "aws_route53_record" "api_us" {
  name           = "api.myapp.com"
  type           = "A"
  set_identifier = "us-east-1"

  latency_routing_policy {
    region = "us-east-1"
  }

  alias {
    name    = aws_lb.us_east_1.dns_name
    zone_id = aws_lb.us_east_1.zone_id
  }
}

resource "aws_route53_record" "api_eu" {
  name           = "api.myapp.com"
  type           = "A"
  set_identifier = "eu-west-1"

  latency_routing_policy {
    region = "eu-west-1"
  }

  alias {
    name    = aws_lb.eu_west_1.dns_name
    zone_id = aws_lb.eu_west_1.zone_id
  }
}
```

---

## Control Plane Resilience

The ForgeGate control plane itself is designed for high availability:

| Component | Strategy |
|-----------|----------|
| API servers | Multi-AZ deployment behind ALB |
| State storage | DynamoDB Global Tables (multi-region) |
| Smithy models | S3 with cross-region replication |
| SDK artifacts | S3 + CloudFront (global edge caching) |
| DNS | Route 53 with health checks |

**If the control plane goes down:** Data planes continue operating independently. All policies are already synced locally. Feature flags use cached state. New policy changes cannot be deployed until the control plane recovers, but existing authorization continues without interruption.

---

## Summary: RTO/RPO Matrix

| Component | RPO | RTO | Strategy |
|-----------|-----|-----|----------|
| Authorization policies (VP) | 0 | 0 | Active-active, agent-synced per region |
| Feature flags | 0 | 0 | Active-active, local evaluation |
| User profiles (attributes, groups) | ~1s | < 1 min | DynamoDB Global Tables |
| User passwords | N/A | See auth method table | Cannot replicate; mitigate with passwordless |
| Auth proxy | 0 | 0 | Stateless, per-region |
| Auth decision cache | Lost on failover | Warms in minutes | Independent per-region cache |
| Webhook event delivery | ~1-5s | < 5 min | Queued in control plane, delivered after recovery |
| Control plane | ~1s (DDB Global) | < 5 min | Multi-region with Route 53 failover |

---

## Recommendations

1. **Use passwordless authentication** (email OTP, passkeys, or external IdP federation) for any deployment that requires multi-region resilience. This eliminates the password replication problem entirely.

2. **Start with active-passive** if your primary concern is disaster recovery. The secondary region acts as a warm standby with policies pre-synced and Cognito pre-provisioned.

3. **Graduate to active-active with latency routing** once you've validated passwordless auth and are comfortable with the operational model.

4. **Monitor the AWS roadmap** for native Cognito cross-region support. When AWS adds this, ForgeGate will integrate it and the architecture simplifies significantly.

5. **Consider the control plane's independence.** Even during a full regional AWS outage, data planes in unaffected regions continue authorizing requests without interruption. The control plane is not in the critical path for runtime authorization.

---

## Related Documents

- [Self-Hosted Data Plane Guide](03-technical-self-hosted-data-plane.md) — prerequisite: deploying the data plane in your account
- [Identity Engine](11-technical-identity-engine-rust.md) — how authentication state machines handle failover and timeouts
- [Control Plane UI Design](08-technical-control-plane-ui.md) — God Mode for monitoring flows across regions

# ForgeGate — Internal Back Office: Technical Design

> Internal operations dashboard for managing ForgeGate customers, platform analytics, and support.

---

## Overview

The back office is ForgeGate's internal tool — separate from the customer-facing dashboard. It serves three audiences within the ForgeGate team:

- **Customer Success** — Onboarding tracking, health monitoring, churn signals
- **Support Engineering** — Ticket management with deep customer context, direct access to their God Mode and Flow Inspector
- **Business Operations** — Revenue analytics, usage trends, margin tracking, Marketplace metering health

The back office is itself a ForgeGate-protected application. Access is controlled by ForgeGate roles, every action is audit-logged, and customer data access follows the same tiered PII model as God Mode.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  ForgeGate Back Office (internal React SPA)                   │
│                                                               │
│  ┌───────────────┐ ┌──────────────┐ ┌─────────────────────┐ │
│  │  Customers    │ │  Analytics   │ │  Support            │ │
│  │               │ │              │ │                     │ │
│  │  Directory    │ │  Platform    │ │  Tickets            │ │
│  │  Health       │ │  Revenue     │ │  Customer context   │ │
│  │  Onboarding   │ │  Usage       │ │  Impersonation      │ │
│  │  Alerts       │ │  Margins     │ │  Escalation         │ │
│  │  Lifecycle    │ │  Marketplace │ │  Runbooks           │ │
│  └───────┬───────┘ └──────┬───────┘ └──────────┬──────────┘ │
│          │                │                     │            │
│          └────────────────┼─────────────────────┘            │
│                           │                                   │
│              ForgeGate Generated SDK (dogfooding)            │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────┐
│  Back Office API (Rust, protected by ForgeGate)                │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  Customer Management     │  Analytics Engine             │ │
│  │  ──────────────────      │  ────────────────             │ │
│  │  GET  /customers         │  GET /analytics/platform      │ │
│  │  GET  /customers/{id}    │  GET /analytics/revenue       │ │
│  │  GET  /customers/{id}/   │  GET /analytics/usage         │ │
│  │       health             │  GET /analytics/margins       │ │
│  │  GET  /customers/{id}/   │  GET /analytics/marketplace   │ │
│  │       usage              │                               │ │
│  │  POST /customers/{id}/   │  Support Engine               │ │
│  │       impersonate        │  ──────────────               │ │
│  │                          │  GET/POST /tickets            │ │
│  │  Alert Engine            │  GET  /tickets/{id}           │ │
│  │  ────────────            │  POST /tickets/{id}/respond   │ │
│  │  GET  /alerts            │  POST /tickets/{id}/escalate  │ │
│  │  POST /alerts/{id}/ack   │  GET  /tickets/{id}/context   │ │
│  └──────────────────────────┴───────────────────────────────┘ │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  Data Sources                                             │ │
│  │                                                           │ │
│  │  Control Plane DB (customer configs, models, policies)    │ │
│  │  Marketplace Metering (usage, billing)                    │ │
│  │  Event Log Store (flow traces, audit logs)                │ │
│  │  Metrics Pipeline (CloudWatch / Prometheus)               │ │
│  │  Customer Flow Stores (live flows — for God Mode proxy)   │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

---

## Part 1: Customer Management

### Customer Directory

The primary view. Every ForgeGate customer at a glance.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Customers                                  🔍 Search    Total: 347         │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Filter: [All tiers ▼] [All health ▼] [All regions ▼] [Active ▼]           │
│  Sort:   [Revenue ▼]                                                        │
│                                                                              │
│  Customer         │ Tier      │ MAU     │ MRR     │ Health │ Since  │ Region│
│  ─────────────────┼───────────┼─────────┼─────────┼────────┼────────┼────── │
│  Acme Corp        │ Enterprise│ 312K    │ $8,400  │ 🟢     │ Mar 24 │ us-e-1│
│  Globex Inc       │ Team      │ 48K     │ $199    │ 🟢     │ Jun 24 │ eu-w-1│
│  Initech          │ Pro       │ 8.2K    │ $49     │ 🟡     │ Sep 24 │ us-e-1│
│  Umbrella LLC     │ Enterprise│ 890K    │ $22,000 │ 🟢     │ Jan 24 │ us-w-2│
│  Stark Industries │ Team      │ 52K     │ $259    │ 🔴     │ Nov 24 │ eu-w-1│
│  Wayne Ent.       │ Free      │ 450     │ $0      │ 🟢     │ Feb 25 │ us-e-1│
│  Pied Piper       │ Pro       │ 3.1K    │ $49     │ 🟡     │ Jan 25 │ us-w-2│
│  ...                                                                        │
│                                                                              │
│  ● Health: 🟢 healthy  🟡 warning (degraded metrics or approaching limits) │
│            🔴 critical (errors, outages, or churn signal)                   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Customer Detail

Clicking into a customer shows everything ForgeGate knows about them:

```
┌──────────────────────────────────────────────────────────────┐
│  ← Customers    Acme Corp                      [Impersonate]│
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Overview                                                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Tier:        Enterprise (self-hosted data plane)      │   │
│  │ Since:       March 2024                               │   │
│  │ Primary contact: alice@acme.com                       │   │
│  │ Region:      us-east-1 (primary), eu-west-1 (DR)     │   │
│  │ Marketplace: ✅ Subscribed (product code: abc123)     │   │
│  │ Data plane:  ✅ Healthy (last sync: 28s ago)          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Usage (current month)                                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ MAU:                312,450  (↑ 4.2% from last month) │   │
│  │ Auth requests:      23.4M   (↑ 8.1%)                 │   │
│  │ Authorization calls:18.7M   (↓ 2.3%)                 │   │
│  │ Active tenants:     47                                │   │
│  │ Feature flags:      12 (8 enabled, 2 experiments)     │   │
│  │ Custom policies:    23                                │   │
│  │ Webhook endpoints:  4                                 │   │
│  │ SDK languages:      Python, TypeScript                │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Revenue                                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Platform fee:     $8,400/mo (metered via Marketplace) │   │
│  │ Their AWS costs:  ~$5,200/mo (Cognito + VP, est.)     │   │
│  │ Total to them:    ~$13,600/mo                         │   │
│  │ Our margin:       ~$8,350/mo (99.4%)                  │   │
│  │ LTV (to date):    $134,400                            │   │
│  │ Billing status:   ✅ Current                          │   │
│  │                                                      │   │
│  │ Revenue trend:                                        │   │
│  │ ▁▂▃▃▄▅▅▆▆▇▇██  (+68% over 12 months)                │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Model                                                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Resources:    8 (Document, Project, Team, ...)        │   │
│  │ Endpoints:    34 (22 CRUD, 12 custom actions)         │   │
│  │ Roles:        6 (viewer, editor, admin, ...)          │   │
│  │ Last push:    2 days ago                              │   │
│  │ SDK version:  2.4.1 (latest: 2.4.1 ✅)               │   │
│  │ [View model →] [View generated Smithy →]              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Health Signals                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 🟢 Data plane sync:     healthy (28s ago)             │   │
│  │ 🟢 Auth success rate:   99.7% (last 24h)             │   │
│  │ 🟢 Authorization P99:   12ms                         │   │
│  │ 🟡 Webhook delivery:    98.2% (target: 99.5%)        │   │
│  │ 🟢 Cognito health:      all pools responding          │   │
│  │ 🟢 VP health:           policy store healthy          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Recent Activity                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 2h ago   Model pushed (commit: d4e5f6a)               │   │
│  │ 1d ago   New role created: "analyst"                   │   │
│  │ 3d ago   Feature flag "new_dashboard" enabled (100%)   │   │
│  │ 1w ago   OIDC provider "okta" added                    │   │
│  │ 2w ago   Support ticket #1847 resolved                 │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Open Tickets: 1                              [View all →]   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ #1902  "Webhook delivery intermittent"   🟡 P2  3h   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Quick Actions                                                │
│  [Impersonate dashboard] [View God Mode] [View audit log]    │
│  [Open support ticket]   [View metering] [Export usage CSV]  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Customer Health Score

Health is computed from multiple signals:

```rust
pub struct HealthScore {
    pub overall: Health,         // 🟢 🟡 🔴
    pub signals: Vec<HealthSignal>,
}

pub struct HealthSignal {
    pub name: String,
    pub status: Health,
    pub value: String,
    pub threshold: String,
}

pub fn compute_health(customer: &Customer, metrics: &CustomerMetrics) -> HealthScore {
    let mut signals = vec![];

    // Data plane freshness
    signals.push(HealthSignal {
        name: "Data plane sync".into(),
        status: match metrics.last_sync_age {
            d if d < Duration::from_secs(120) => Health::Green,
            d if d < Duration::from_secs(600) => Health::Yellow,
            _ => Health::Red,
        },
        value: format!("{:?} ago", metrics.last_sync_age),
        threshold: "< 2 min green, < 10 min yellow".into(),
    });

    // Auth success rate
    signals.push(HealthSignal {
        name: "Auth success rate".into(),
        status: match metrics.auth_success_rate_24h {
            r if r > 99.0 => Health::Green,
            r if r > 95.0 => Health::Yellow,
            _ => Health::Red,
        },
        value: format!("{:.1}%", metrics.auth_success_rate_24h),
        threshold: "> 99% green, > 95% yellow".into(),
    });

    // Authorization latency
    signals.push(HealthSignal {
        name: "Authorization P99".into(),
        status: match metrics.authz_p99_ms {
            l if l < 50.0 => Health::Green,
            l if l < 200.0 => Health::Yellow,
            _ => Health::Red,
        },
        value: format!("{:.0}ms", metrics.authz_p99_ms),
        threshold: "< 50ms green, < 200ms yellow".into(),
    });

    // Webhook delivery rate
    if metrics.webhook_endpoints > 0 {
        signals.push(HealthSignal {
            name: "Webhook delivery".into(),
            status: match metrics.webhook_success_rate {
                r if r > 99.5 => Health::Green,
                r if r > 95.0 => Health::Yellow,
                _ => Health::Red,
            },
            value: format!("{:.1}%", metrics.webhook_success_rate),
            threshold: "> 99.5% green, > 95% yellow".into(),
        });
    }

    // Usage trend (churn signal)
    signals.push(HealthSignal {
        name: "Usage trend".into(),
        status: match metrics.mau_change_30d_pct {
            c if c > -5.0 => Health::Green,
            c if c > -20.0 => Health::Yellow,
            _ => Health::Red,  // >20% MAU drop = churn risk
        },
        value: format!("{:+.1}% MAU (30d)", metrics.mau_change_30d_pct),
        threshold: "> -5% green, > -20% yellow".into(),
    });

    // Open critical tickets
    if metrics.open_p1_tickets > 0 {
        signals.push(HealthSignal {
            name: "Open P1 tickets".into(),
            status: Health::Red,
            value: format!("{}", metrics.open_p1_tickets),
            threshold: "0 = green".into(),
        });
    }

    let overall = if signals.iter().any(|s| s.status == Health::Red) {
        Health::Red
    } else if signals.iter().any(|s| s.status == Health::Yellow) {
        Health::Yellow
    } else {
        Health::Green
    };

    HealthScore { overall, signals }
}
```

### Onboarding Tracking

New customers go through a pipeline. The back office tracks where each one is:

```
┌──────────────────────────────────────────────────────────────┐
│  Onboarding Pipeline                                          │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Signed Up (12)  → First Model (8)  → First Deploy (5)      │
│  ████████████      ████████           █████                  │
│                                                               │
│  → First Auth (4) → Production (3)   → Healthy (2)          │
│    ████              ███               ██                    │
│                                                               │
│  Stuck in "First Model" for > 3 days:                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pied Piper      signed up 5d ago    last active: 2d  │   │
│  │ Soylent Corp    signed up 4d ago    last active: 4d  │   │
│  │ Hooli           signed up 3d ago    last active: 1d  │   │
│  └──────────────────────────────────────────────────────┘   │
│  [Send onboarding nudge email →]                             │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Churn Alerts

```
┌──────────────────────────────────────────────────────────────┐
│  Churn Risk Alerts                                            │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  🔴 Stark Industries  │ MAU dropped 35% in 30 days          │
│     52K → 33K MAU     │ Last model push: 45 days ago         │
│     No dashboard login in 2 weeks                            │
│     [View customer →]  [Create ticket →]                     │
│                                                               │
│  🟡 Initech           │ Auth error rate spiked to 8%         │
│     Webhook delivery at 87% (degraded)                       │
│     1 open P2 ticket (unresponded 6h)                        │
│     [View customer →]  [View ticket →]                       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Impersonation

Support engineers can view a customer's dashboard as if they were that customer. This is critical for debugging "I can't see my users" or "my policy test bench gives the wrong result" — you see exactly what they see.

Impersonation is:
- Gated by `backoffice:impersonate` permission
- Time-limited (30-minute sessions, renewable)
- Read-only by default (write requires `backoffice:impersonate_write` and a reason)
- Fully audit-logged: who impersonated which customer, when, for how long, and what they viewed
- Visible to the customer in their audit log: "ForgeGate Support viewed your dashboard (ticket #1902)"

```
┌──────────────────────────────────────────────────────────────┐
│  ⚠ IMPERSONATION MODE — Viewing as: Acme Corp               │
│    Operator: support_jane │ Ticket: #1902 │ Expires: 22 min │
│    [End session] [Extend +30m]                               │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  (Customer's dashboard rendered here — their data, their     │
│   model, their users, their God Mode, their audit log)       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## Part 2: Analytics

### Platform Analytics

Aggregate metrics across all customers:

```
┌──────────────────────────────────────────────────────────────┐
│  Platform Analytics                          Period: [30d ▼] │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Customers                                                    │
│  ┌────────────┬────────────┬────────────┬────────────────┐  │
│  │ Total      │ Active     │ New (30d)  │ Churned (30d)  │  │
│  │ 347        │ 298        │ 23         │ 4              │  │
│  │            │ (85.9%)    │ (+7.1%)    │ (-1.2%)        │  │
│  └────────────┴────────────┴────────────┴────────────────┘  │
│                                                               │
│  Usage                                                        │
│  ┌────────────┬────────────┬────────────┬────────────────┐  │
│  │ Total MAU  │ Auth reqs  │ Authz reqs │ Flows/day      │  │
│  │ 4.2M       │ 890M       │ 712M       │ 1.8M           │  │
│  │ (↑ 12%)    │ (↑ 18%)    │ (↑ 15%)    │ (↑ 9%)         │  │
│  └────────────┴────────────┴────────────┴────────────────┘  │
│                                                               │
│  Health                                                       │
│  ┌────────────┬────────────┬────────────┐                   │
│  │ 🟢 Healthy │ 🟡 Warning │ 🔴 Critical│                   │
│  │ 289 (83%)  │ 47 (14%)   │ 11 (3%)    │                   │
│  └────────────┴────────────┴────────────┘                   │
│                                                               │
│  Platform uptime: 99.98% (30d)                               │
│  Avg auth flow duration: 2.1s (P50), 8.4s (P95)             │
│  Avg authorization latency: 4ms (P50), 18ms (P95)           │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Revenue Analytics

```
┌──────────────────────────────────────────────────────────────┐
│  Revenue Analytics                           Period: [MTD ▼] │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  MRR: $127,400  │  ARR: $1.53M  │  Growth: +8.2% MoM        │
│                                                               │
│  By tier:                                                     │
│  ┌──────────────┬────────┬──────────┬──────────────────────┐│
│  │ Tier         │ Count  │ MRR      │ Avg revenue/customer ││
│  ├──────────────┼────────┼──────────┼──────────────────────┤│
│  │ Free         │ 142    │ $0       │ $0                   ││
│  │ Pro          │ 98     │ $4,802   │ $49                  ││
│  │ Team         │ 67     │ $13,333  │ $199                 ││
│  │ Enterprise   │ 40     │ $109,265 │ $2,732               ││
│  └──────────────┴────────┴──────────┴──────────────────────┘│
│                                                               │
│  Self-hosted vs SaaS:                                        │
│  ┌──────────────┬────────┬──────────┬────────────────┐      │
│  │ Model        │ Count  │ MRR      │ Avg margin     │      │
│  ├──────────────┼────────┼──────────┼────────────────┤      │
│  │ SaaS         │ 259    │ $18,135  │ ~62%           │      │
│  │ Self-hosted  │ 88     │ $109,265 │ ~96%           │      │
│  └──────────────┴────────┴──────────┴────────────────┘      │
│                                                               │
│  Top 10 customers by revenue:                                │
│  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ Umbrella LLC          $22,000       │
│  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     Cyberdyne Systems     $18,500       │
│  ▓▓▓▓▓▓▓▓▓▓▓▓         Weyland-Yutani        $14,200       │
│  ▓▓▓▓▓▓▓▓▓▓           Massive Dynamic        $11,800       │
│  ▓▓▓▓▓▓▓▓             Acme Corp              $8,400        │
│  ...                                                         │
│                                                               │
│  Marketplace metering health:                                │
│  ✅ 88/88 self-hosted customers metered successfully         │
│  Last failed meter: none in 30 days                          │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Usage Analytics

```
┌──────────────────────────────────────────────────────────────┐
│  Usage Analytics                             Period: [30d ▼] │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Feature adoption:                                            │
│  ┌──────────────────────────────────┬──────────┬───────────┐│
│  │ Feature                          │ Customers│ % of total ││
│  ├──────────────────────────────────┼──────────┼───────────┤│
│  │ Password auth                    │ 298/298  │ 100%      ││
│  │ Social login (Google/GitHub/etc) │ 187/298  │ 63%       ││
│  │ Magic link                       │ 92/298   │ 31%       ││
│  │ OIDC/SAML SSO                    │ 68/298   │ 23%       ││
│  │ MFA enabled                      │ 145/298  │ 49%       ││
│  │ Feature flags                    │ 201/298  │ 67%       ││
│  │ Custom Cedar policies            │ 89/298   │ 30%       ││
│  │ Webhooks                         │ 156/298  │ 52%       ││
│  │ Custom actions (non-CRUD)        │ 134/298  │ 45%       ││
│  │ Authorization testing            │ 67/298   │ 22%       ││
│  │ SDK generation                   │ 112/298  │ 38%       ││
│  │ God Mode                         │ 44/298   │ 15%       ││
│  │ Multi-region                     │ 12/298   │ 4%        ││
│  └──────────────────────────────────┴──────────┴───────────┘│
│                                                               │
│  Auth flow distribution (platform-wide):                     │
│  ███████████████████████████████████████  password    62%     │
│  ████████████                            magic_link  19%     │
│  ████████                                oidc        13%     │
│  ██                                      sms_code    3%      │
│  ██                                      passkeys    3%      │
│                                                               │
│  Flow outcomes (platform-wide, last 24h):                    │
│  ████████████████████████████████████████ success     94.2%  │
│  ███                                     failed      3.8%   │
│  █                                       abandoned   1.5%   │
│  ░                                       timed out   0.5%   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## Part 3: Support

### Ticket Management

Tickets are created by customers (from their dashboard), by internal team members, or auto-generated from health alerts.

```
┌──────────────────────────────────────────────────────────────┐
│  Support Tickets                    [+ Create]  Open: 23     │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Filter: [Open ▼] [All priority ▼] [All assignee ▼]         │
│                                                               │
│  #1902  Acme Corp              🟡 P2  Webhook delivery       │
│         intermittent failures                                 │
│         Opened 3h ago by alice@acme.com                      │
│         Assigned: support_jane  │ Last response: 1h ago      │
│                                                               │
│  #1899  Stark Industries       🔴 P1  Auth failures spike    │
│         500 errors on password flow                          │
│         Opened 6h ago (auto-generated from health alert)     │
│         Assigned: support_bob   │ Last response: 30m ago     │
│                                                               │
│  #1897  Initech                🟡 P2  Custom Cedar policy    │
│         not working as expected                              │
│         Opened 1d ago by dev@initech.com                     │
│         Assigned: unassigned    │ ⚠ SLA at risk (4h left)   │
│                                                               │
│  ...                                                         │
│                                                               │
│  SLA Status:                                                 │
│  P1: 100% within SLA (target: 1h first response)            │
│  P2: 87% within SLA (target: 4h first response) ⚠          │
│  P3: 95% within SLA (target: 24h first response)            │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Ticket Detail with Customer Context

This is where the back office shines — every ticket has deep context automatically pulled from the customer's data:

```
┌──────────────────────────────────────────────────────────────┐
│  Ticket #1899 — Stark Industries                             │
│  🔴 P1 │ Auth failures spike │ Opened 6h ago                │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Auto-generated from health alert:                           │
│  "Auth success rate dropped below 95% (currently 91.2%)"    │
│                                                               │
│  ── Customer Context (auto-populated) ──                     │
│                                                               │
│  Tier: Team │ MAU: 52K │ Data plane: eu-west-1              │
│  Auth methods: password, google, okta (OIDC)                 │
│  Last model push: 2 days ago                                 │
│  Recent changes:                                             │
│  • 6h ago: Password policy updated (min length 8→12)         │
│  • 2d ago: Model pushed (added "approval" custom action)     │
│                                                               │
│  ── Relevant Metrics ──                                      │
│                                                               │
│  Auth success rate (last 24h):                               │
│  ████████████████████████████░░░░░░░░ 91.2% (was 99.8%)     │
│  Drop started at 08:15 UTC (correlates with password change) │
│                                                               │
│  Failure breakdown:                                           │
│  • InvalidCredentials: 847 (was ~20/day)                     │
│  • All failures are password flow (not OIDC/Google)          │
│  • Concentrated in 3 Cognito user pool app clients           │
│                                                               │
│  ── Flow Inspector (sampled failures) ──                     │
│                                                               │
│  flow_x1y2: password │ Initiated → FAILED (0.4s)            │
│    Cognito: NotAuthorizedException                           │
│  flow_z3a4: password │ Initiated → FAILED (0.3s)            │
│    Cognito: NotAuthorizedException                           │
│  [View more flows →] [Open God Mode for this customer →]    │
│                                                               │
│  ── Likely Root Cause ──                                     │
│  ⚡ Password policy was changed 6h ago (min length 8→12).    │
│     Existing users with 8-11 char passwords can no longer    │
│     authenticate. Cognito enforces the new policy on login   │
│     attempts, not retroactively.                              │
│                                                               │
│  ── Suggested Resolution ──                                  │
│  1. Revert password policy to min length 8                   │
│  2. Trigger password reset for affected users                │
│  3. Gradually enforce new policy via "change password on     │
│     next login" flag                                          │
│                                                               │
│  ── Thread ──                                                │
│                                                               │
│  6h ago  🤖 System: Auto-generated from health alert         │
│  5h30m   👤 support_bob: Investigating. Pulled customer      │
│          context. Correlating with recent config changes.     │
│  5h ago   👤 support_bob: Root cause identified — password   │
│          policy change broke existing users. Reaching out.   │
│  30m ago  👤 support_bob: Customer acknowledged. Reverting   │
│          policy. Will monitor success rate recovery.          │
│                                                               │
│  [Reply] [Escalate to engineering] [Close]                   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Auto-Context Population

When a ticket is opened (manually or via alert), the back office automatically pulls:

- Customer profile (tier, region, data plane status)
- Recent configuration changes (model pushes, policy edits, auth config changes)
- Relevant metrics (auth success rate, latency, error rates)
- Sampled flow traces from the event log that match the failure pattern
- Cognito and VP health status for their region
- A "likely root cause" suggestion based on correlating the timing of config changes with the onset of the issue

This context is generated, not typed by the support engineer. By the time they open the ticket, the investigation is half done.

### Runbooks

Common issues have linked runbooks that guide the support engineer:

```
┌──────────────────────────────────────────────────────────────┐
│  Suggested Runbook: "Auth failure spike after config change"  │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  1. ☐ Check recent config changes (auto-populated above)     │
│  2. ☐ Correlate timing: did failures start after the change? │
│  3. ☐ Sample failed flows in Flow Inspector                  │
│  4. ☐ Identify the specific Cognito error code               │
│  5. ☐ If password policy: check affected user count          │
│  6. ☐ Contact customer with root cause and options            │
│  7. ☐ Monitor recovery after fix applied                     │
│  8. ☐ Close ticket with resolution notes                     │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## Part 4: Access Control

The back office uses ForgeGate's own authorization system with the following roles:

| Role | Permissions | Who |
|------|------------|-----|
| `backoffice:viewer` | View customer list, aggregate analytics | All internal team |
| `backoffice:support` | View customer details, view tickets, respond to tickets, view customer flow inspector | Support engineers |
| `backoffice:impersonate` | Impersonate customer dashboards (read-only) | Senior support, CS leads |
| `backoffice:impersonate_write` | Impersonate with write access (rare, requires reason) | Engineering leads |
| `backoffice:admin` | Full access: create/close tickets, manage alerts, edit customer tiers | Ops managers |
| `backoffice:finance` | Revenue analytics, margin reports, Marketplace metering health | Finance team |

All back office actions are audit-logged and visible in the back office's own audit trail. Customer-facing audit logs show when ForgeGate support accessed their data (with the associated ticket number).

---

## Part 5: API Definition

The back office API is modeled in Smithy, protected by ForgeGate:

```smithy
$version: "2"
namespace io.forgegate.backoffice

use forgegate.traits#authorize
use forgegate.traits#authResource

@httpBearerAuth
@restJson1
service ForgeGateBackOffice {
    version: "2025-01-01"
    resources: [Customer, Ticket, Alert]
    operations: [
        GetPlatformAnalytics
        GetRevenueAnalytics
        GetUsageAnalytics
        ImpersonateCustomer
    ]
}

@authResource(namespace: "backoffice")
resource Customer {
    identifiers: { customerId: CustomerId }
    read: GetCustomer
    list: ListCustomers
    operations: [
        GetCustomerHealth
        GetCustomerUsage
        GetCustomerRevenue
        GetCustomerFlows
        GetCustomerAuditLog
    ]
}

@authResource(namespace: "backoffice")
resource Ticket {
    identifiers: { ticketId: TicketId }
    read: GetTicket
    create: CreateTicket
    list: ListTickets
    operations: [
        RespondToTicket
        EscalateTicket
        CloseTicket
        GetTicketContext
    ]
}

@http(method: "POST", uri: "/customers/{customerId}/impersonate")
@authorize(action: "backoffice:impersonate", resource: "customerId")
operation ImpersonateCustomer {
    input := {
        @required @httpLabel
        customerId: CustomerId

        @required
        reason: String

        @required
        ticketId: TicketId

        writeAccess: Boolean = false
    }
    output := {
        @required
        sessionToken: String

        @required
        expiresAt: Timestamp

        @required
        dashboardUrl: String
    }
}

@readonly
@http(method: "GET", uri: "/analytics/revenue")
@authorize(action: "backoffice:view_revenue")
operation GetRevenueAnalytics {
    input := {
        @httpQuery("period")
        period: AnalyticsPeriod = "30d"
    }
    output := {
        @required
        mrr: Money
        @required
        arr: Money
        @required
        growthRate: Float
        @required
        byTier: TierBreakdownList
        @required
        byModel: ModelBreakdownList
        @required
        topCustomers: CustomerRevenueList
        @required
        marketplaceHealth: MarketplaceHealthSummary
    }
}
```

---

## Part 6: Alerting Rules

The back office has its own alert engine that monitors customer health and platform-level signals:

| Alert | Trigger | Priority | Action |
|-------|---------|----------|--------|
| Auth failure spike | Customer auth success rate < 95% | P1 | Auto-create ticket, page on-call |
| Data plane disconnect | No sync in > 10 min | P1 | Auto-create ticket, alert customer |
| Webhook delivery degraded | Delivery rate < 95% for > 1 hour | P2 | Auto-create ticket |
| MAU drop > 20% | 30-day MAU trend | P3 | Flag for CS review (churn signal) |
| Marketplace metering failure | BatchMeterUsage returns error | P1 | Alert on-call, revenue at risk |
| Customer approaching MAU limit | >90% of tier included MAU | P3 | Notify CS for upsell conversation |
| No model push in 30+ days | Stale model | P3 | CS outreach (engagement signal) |
| Cognito regional issue | Multiple customers in same region degraded | P1 | Platform incident, status page |
| Free tier customer hitting limits | Approaching 1K MAU cap | P3 | Auto-send upgrade nudge email |
| SLA at risk | Ticket approaching SLA deadline without response | P2 | Alert assigned engineer + manager |

Alerts can create tickets, send Slack notifications to internal channels, page on-call via PagerDuty, and send email notifications to customer success managers.

---

## Related Documents

- [Control Plane UI Design](08-technical-control-plane-ui.md) — customer-facing dashboard (what gets impersonated)
- [Identity Engine](11-technical-identity-engine-rust.md) — flow event logs that power the Flow Inspector in support context
- [Financial Analysis](06-financial-analysis.docx) — revenue and margin model that the analytics dashboard displays
- [Authorization Testing](09-technical-authorization-testing.md) — test results visible in customer health context

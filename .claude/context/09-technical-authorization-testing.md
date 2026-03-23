# ForgeGate — Authorization Testing

> Automatically verify that your authorization model is correctly enforced against your running application.

---

## Overview

ForgeGate knows your entire authorization topology: every endpoint, every action, every role, every feature gate, every tenant boundary. From this, it auto-generates a comprehensive test suite that proves your enforcement layer is working correctly — without you writing a single test.

Run it locally during development, in CI on every pull request, or against staging before a release. If authorization breaks, you know before your users do.

---

## How It Works

ForgeGate generates tests from three sources:

1. **Your Smithy model** — endpoints, actions, resource params, feature gates
2. **Your role definitions** — which roles have which permissions
3. **Your custom policies** — ownership rules, scoped grants, ABAC conditions

For every combination of endpoint × role, ForgeGate knows whether the request should be allowed or denied. It generates a positive or negative test accordingly. It also generates tests for unauthenticated access, tenant isolation, feature gates, scoped permissions, and token edge cases.

### Generated Test Categories

| Category | What It Tests | Example |
|----------|--------------|---------|
| Positive | Roles with permission get through | `editor CAN POST /documents` |
| Negative | Roles without permission are blocked | `viewer CANNOT DELETE /documents/{id}` |
| Unauthenticated | No token = 401 | `unauthenticated CANNOT GET /documents` |
| Tenant isolation | Cross-tenant access is blocked | `tenant_A user CANNOT access tenant_B resource` |
| Feature gates | Disabled features return 404 | `GET /documents/{id}/summary → 404 when ai_summaries off` |
| Scoped permissions | Grants respect their scope | `user with write in proj_123 CANNOT write in proj_456` |
| Token edge cases | Expired/malformed tokens rejected | `expired token → 401` |

---

## Quick Start: Local Testing

### 1. Start your app

```bash
uvicorn app:app --port 3000
```

### 2. Connect and run tests

```bash
forgegate test connect --port 3000
```

ForgeGate establishes a secure tunnel from your local machine to the control plane, generates the test suite, provisions temporary test users with the right roles, executes the tests against your running app, and cleans up.

```
✓ Tunnel established (tunnel://proj_123.test.forgegate.io)
✓ Generated 42 tests from model (5 resources, 4 roles)
✓ Provisioned 6 test users

Running authorization tests...

  Positive tests
  ✅ admin CAN GET /documents
  ✅ admin CAN POST /documents
  ✅ admin CAN DELETE /documents/{documentId}
  ✅ admin CAN POST /documents/{documentId}/publish
  ✅ editor CAN GET /documents
  ✅ editor CAN POST /documents
  ✅ editor CAN POST /documents/{documentId}/publish
  ... (12/12 passed)

  Negative tests
  ✅ viewer CANNOT POST /documents
  ✅ viewer CANNOT DELETE /documents/{documentId}
  ✅ viewer CANNOT POST /documents/{documentId}/publish
  ✅ editor CANNOT DELETE /documents/{documentId}
  ✅ analyst CANNOT POST /documents
  ... (18/18 passed)

  Unauthenticated tests
  ✅ unauthenticated CANNOT GET /documents
  ✅ unauthenticated CANNOT POST /documents
  ... (5/5 passed)

  Tenant isolation tests
  ✅ tenant_A user CANNOT GET /documents/{tenant_B_doc}
  ❌ tenant_A user CANNOT GET /export (expected 403, got 200)
  ... (3/4 passed)

  Feature gate tests
  ✅ GET /documents/{id}/summary → 404 when ai_summaries disabled
  ✅ GET /documents/{id}/summary → 200 when ai_summaries enabled
  ... (2/2 passed)

  Token tests
  ✅ expired token → 401
  ✅ malformed token → 401
  ✅ empty auth header → 401
  ... (3/3 passed)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  FAILED: 1 test

  tenant isolation: GET /export
    as: user in tenant_test_A
    resource tenant: tenant_test_B
    Expected: 403
    Got: 200 (response contained 3 documents from tenant_B)

    ⚠ ForgeGate's proxy blocks cross-tenant requests, but
      your application's /export endpoint does not filter
      by tenant in the database query. If the proxy is
      bypassed, data leaks.

    Recommendation: Add tenant filtering in your query:
      db.documents.find({"tenant_id": request.headers["X-Auth-Tenant-Id"]})

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  42 tests: 41 passed, 1 failed
  Cleanup: 6 test users removed

✓ Results uploaded to dashboard (run #47)
```

---

## Test Modes

### Through proxy (default)

Tests hit your app through the ForgeGate proxy/wrapper. This validates that ForgeGate's enforcement is correctly configured — routes map to the right actions, roles have the right permissions, feature gates work.

```bash
forgegate test connect --port 3000
```

### Direct to app (defense-in-depth)

Tests hit your app directly, bypassing the proxy. This validates that your application itself handles authorization gracefully even without ForgeGate in front of it. Catches data leaks that the proxy would normally prevent.

```bash
forgegate test connect --port 3000 --direct-port 3000
```

### Both (recommended for CI)

Run through-proxy first, then direct. Get two perspectives on the same authorization model.

```bash
forgegate test connect --port 3000 --direct-port 3000 --mode both
```

The report clearly labels which tests ran through the proxy and which hit the app directly, so you can see where your proxy-level enforcement catches issues that your app doesn't handle.

---

## CI/CD Integration

### GitHub Actions

```yaml
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
          ./wait-for-healthy.sh localhost:3000

      - name: Run ForgeGate authorization tests
        uses: forgegate/test-action@v1
        with:
          target: http://localhost:3000
          api-key: ${{ secrets.FORGEGATE_API_KEY }}
          mode: both
          fail-on-error: true

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: auth-test-report
          path: forgegate-test-results.xml
```

### GitLab CI

```yaml
auth-tests:
  stage: test
  services:
    - name: myapp:latest
      alias: app
  script:
    - pip install forgegate-cli
    - forgegate test run
        --target http://app:3000
        --api-key $FORGEGATE_API_KEY
        --mode both
        --fail-on-error
        --output junit.xml
  artifacts:
    reports:
      junit: junit.xml
```

### Generic CI (any platform)

```bash
# Start your app however you want, then:
forgegate test run \
    --target http://localhost:3000 \
    --api-key $FORGEGATE_API_KEY \
    --fail-on-error \
    --output junit.xml \
    --output-format junit    # also: json, markdown, tap
```

Exit code is non-zero if any test fails, so your CI pipeline breaks on authorization regressions.

---

## Testing Against Deployed Environments

You don't need a tunnel for apps already reachable over the network:

```bash
# Test staging
forgegate test run --target https://staging.myapp.com

# Test production (read-only tests, no mutations)
forgegate test run --target https://api.myapp.com --safe-mode
```

`--safe-mode` skips any test that would create or modify data (POST, PUT, DELETE). Only GET-based permission checks and 401/403 response validation.

---

## Custom Test Cases

The auto-generated suite covers structural authorization. For business-logic rules (ownership, ABAC, custom Cedar policies), add custom tests in a `forgegate-tests.yaml` file alongside your model:

```yaml
# forgegate-tests.yaml

custom_tests:

  # ── Ownership-based access ──

  - name: "Owner can publish their own document"
    setup:
      - create_user:
          id: "test_owner"
          role: "editor"
          tenant: "test_tenant"
      - create_resource:
          type: "document"
          id: "owned_doc"
          attributes:
            owner_id: "test_owner"
            tenant_id: "test_tenant"
    test:
      as: "test_owner"
      method: POST
      path: /documents/owned_doc/publish
      expect: 200

  - name: "Non-owner cannot publish someone else's document"
    setup:
      - create_user:
          id: "test_other"
          role: "editor"
          tenant: "test_tenant"
      - create_resource:
          type: "document"
          id: "owned_doc"
          attributes:
            owner_id: "test_owner"
            tenant_id: "test_tenant"
    test:
      as: "test_other"
      method: POST
      path: /documents/owned_doc/publish
      expect: 403

  # ── Scoped permissions ──

  - name: "Project-scoped write allowed within scope"
    setup:
      - create_user:
          id: "scoped_user"
          role: "viewer"
          tenant: "test_tenant"
      - grant_permission:
          user: "scoped_user"
          action: "document:write"
          scope:
            project: "proj_allowed"
    test:
      as: "scoped_user"
      method: POST
      path: /documents
      body:
        title: "Test"
        content: "Test content"
        project_id: "proj_allowed"
      expect: 200

  - name: "Project-scoped write denied outside scope"
    test:
      as: "scoped_user"
      method: POST
      path: /documents
      body:
        title: "Test"
        content: "Test content"
        project_id: "proj_forbidden"
      expect: 403

  # ── Bulk endpoint tenant boundary ──

  - name: "Bulk export only returns current tenant's data"
    setup:
      - create_user:
          id: "exporter"
          role: "admin"
          tenant: "tenant_alpha"
      - create_resources:
          type: "document"
          count: 5
          tenant: "tenant_alpha"
      - create_resources:
          type: "document"
          count: 3
          tenant: "tenant_beta"
    test:
      as: "exporter"
      method: GET
      path: /export?format=json
      expect:
        status: 200
        body:
          assert: "length(items) == 5"
          description: "Should only return tenant_alpha's 5 documents, not tenant_beta's 3"

  # ── Time-based policy ──

  - name: "Cannot delete document created less than 30 days ago"
    setup:
      - create_user:
          id: "deleter"
          role: "admin"
          tenant: "test_tenant"
      - create_resource:
          type: "document"
          id: "recent_doc"
          attributes:
            created_at: "now"
            tenant_id: "test_tenant"
    test:
      as: "deleter"
      method: DELETE
      path: /documents/recent_doc
      expect: 403
```

Custom tests run alongside auto-generated tests. Setup steps provision temporary users and resources, and everything is cleaned up after the run.

---

## Dry Run: Generate Without Running

Preview the test suite without executing anything:

```bash
# See what would be tested
forgegate test generate

# Output as markdown for review
forgegate test generate --format markdown > auth-tests.md

# Output as JSON for tooling
forgegate test generate --format json > auth-tests.json
```

Sample output:

```markdown
# ForgeGate Authorization Test Suite
Generated from model: com.myapp v2025-01-01
Total: 42 auto-generated + 5 custom tests

## Positive Tests (12)
- admin CAN GET /documents
- admin CAN POST /documents
- admin CAN DELETE /documents/{documentId}
- admin CAN POST /documents/{documentId}/publish
- admin CAN POST /documents/{documentId}/transfer
- admin CAN POST /reports/generate
- editor CAN GET /documents
- editor CAN POST /documents
- editor CAN POST /documents/{documentId}/publish
- publisher CAN POST /documents/{documentId}/publish
- publisher CAN POST /documents/{documentId}/archive
- analyst CAN POST /reports/generate

## Negative Tests (18)
- viewer CANNOT POST /documents
- viewer CANNOT DELETE /documents/{documentId}
- viewer CANNOT POST /documents/{documentId}/publish
...
```

This is useful for security reviews — hand the generated test plan to an auditor to prove your authorization coverage.

---

## Test Results in the Dashboard

Every test run is stored and visible in the ForgeGate dashboard:

```
┌──────────────────────────────────────────────────────────────┐
│  Test Runs                                         [Run now] │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  #47  CI: PR #89         2 min ago     41/42 ⚠️     [View]  │
│       "Add bulk export endpoint"                              │
│       Failed: tenant isolation on GET /export                 │
│                                                               │
│  #46  CI: main           1 hour ago    42/42 ✅     [View]  │
│       commit: d4e5f6a  "Update role definitions"              │
│                                                               │
│  #45  Manual: staging    3 hours ago   42/42 ✅     [View]  │
│       target: https://staging.myapp.com                       │
│                                                               │
│  #44  CI: PR #87         5 hours ago   39/42 ❌     [View]  │
│       "Add document sharing"                                  │
│       Failed: 3 negative tests (viewer can share)             │
│                                                               │
│  Trend: ████████████████████░░ 95% pass rate (30 days)       │
└──────────────────────────────────────────────────────────────┘
```

Clicking into a run shows the full test report with pass/fail per test, response details on failures, and recommendations.

---

## What Tests Catch in Practice

| Scenario | What Happens | Test That Catches It |
|----------|-------------|---------------------|
| Developer adds a new endpoint but forgets to add it to the Smithy model | Endpoint is reachable without authorization | Unauthenticated test passes when it should fail |
| Role definition grants too much after a refactor | Users gain unintended access | Negative test fails (role can now access what it shouldn't) |
| Feature flag gate misconfigured | Disabled feature is still accessible | Feature gate test returns 200 instead of 404 |
| Tenant filtering missing in a database query | Cross-tenant data leakage | Tenant isolation test returns data from wrong tenant |
| Custom Cedar policy has a logic error | Ownership check doesn't work | Custom test for owner-vs-non-owner fails |
| Proxy bypassed (e.g., internal service call) | App doesn't enforce auth itself | Direct-mode test shows 200 where 403 expected |
| Scoped grant is too broad | User can act outside intended scope | Scope test fails for out-of-scope context |

---

## CLI Reference

```bash
# ── Local testing with tunnel ──
forgegate test connect [options]
  --port <number>           Port your app is running on (required)
  --direct-port <number>    Also test without proxy (defense-in-depth)
  --mode <through-proxy|direct|both>  Test mode (default: through-proxy)
  --only <categories>       Comma-separated: positive,negative,tenant,feature,scope,token,custom
  --exclude <categories>    Skip specific categories
  --timeout <seconds>       Per-test timeout (default: 10)
  --verbose                 Show request/response details for all tests

# ── Testing a reachable target ──
forgegate test run [options]
  --target <url>            URL of the app to test (required)
  --api-key <key>           ForgeGate API key (or FORGEGATE_API_KEY env)
  --mode <through-proxy|direct|both>
  --safe-mode               Skip mutating tests (POST/PUT/DELETE)
  --fail-on-error           Exit code 1 on any failure (for CI)
  --output <path>           Write results to file
  --output-format <fmt>     junit, json, markdown, tap (default: junit)

# ── Preview test suite ──
forgegate test generate [options]
  --format <fmt>            markdown, json, yaml (default: markdown)
  --include-custom          Include custom tests from forgegate-tests.yaml

# ── Dashboard trigger ──
forgegate test trigger [options]
  --target <url>            Run from the control plane against a reachable target
  --notify <webhook>        Send results to a webhook endpoint
```

---

## Debugging Failed Tests with God Mode

When an authorization test fails and you need to understand why, the dashboard's God Mode provides live flow inspection. Start your app, run the failing test, and watch the flow in real time — see which policy was evaluated, what the decision was, and where it diverged from expectations.

For live flow debugging beyond test runs, see [Control Plane UI Design — God Mode](08-technical-control-plane-ui.md).

---

## Related Documents

- [SaaS Integration Guide](02-technical-saas-integration.md) — how to integrate ForgeGate with your app
- [Self-Hosted Data Plane Guide](03-technical-self-hosted-data-plane.md) — testing against a self-hosted deployment
- [Control Plane UI Design](08-technical-control-plane-ui.md) — God Mode, policy test bench, audit log
- [Identity Engine](11-technical-identity-engine-rust.md) — flow event logs that power the Flow Inspector
- [Tutorial: TODO App](14-tutorial-todo-app.md) — end-to-end example including test execution

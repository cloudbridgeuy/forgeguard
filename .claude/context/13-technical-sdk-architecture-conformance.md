# ForgeGate — SDK Architecture: Core, Wrappers, and Conformance Tests

> Rust reference implementation with language wrappers today, native implementations tomorrow — gated by a universal conformance test suite.

---

## Strategy

**Phase 1 (ship fast):** Rust core + thin FFI wrappers per language (PyO3, WASM, CGo). One implementation, multiple distributions. Gets us to market with correct, secure behavior in every language.

**Phase 2 (go native):** Replace FFI wrappers with native implementations one language at a time, prioritized by customer demand. Each native implementation must pass the same conformance test suite that the Rust core passes. If it passes, it ships. If it doesn't, it doesn't.

**The test suite is the product, not the implementation.** The Rust core is the reference implementation that defines correct behavior. The conformance tests codify that behavior in a language-agnostic way. Any implementation — Rust FFI, pure Python, pure Go, pure TypeScript — that passes the conformance suite is a valid ForgeGate SDK.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Conformance Test Suite (language-agnostic)                     │
│                                                                 │
│  Defines correct behavior for:                                  │
│  • Token acquisition, refresh, caching                         │
│  • Request signing                                              │
│  • Authorization checks (Guard)                                │
│  • Feature flag evaluation                                     │
│  • Webhook signature verification                              │
│  • Retry logic                                                  │
│  • Error handling                                              │
│  • Timeout behavior                                            │
│                                                                 │
│  Expressed as: JSON test fixtures + per-language test runners   │
└──────────────────────────┬─────────────────────────────────────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
            ▼              ▼              ▼
   ┌──────────────┐ ┌────────────┐ ┌────────────┐
   │ Rust core    │ │ Pure Python│ │ Pure TS    │
   │ (reference)  │ │ (future)   │ │ (future)   │
   │              │ │            │ │            │
   │ Phase 1:     │ │ Phase 2:   │ │ Phase 2:   │
   │ ships as     │ │ replaces   │ │ replaces   │
   │ FFI wrappers │ │ PyO3       │ │ WASM       │
   │              │ │ wrapper    │ │ wrapper    │
   │ ✅ Tests pass│ │ ✅ Tests   │ │ ✅ Tests   │
   │              │ │    pass    │ │    pass    │
   └──────────────┘ └────────────┘ └────────────┘
```

---

## The Conformance Test Suite

### Design Principles

1. **Language-agnostic test definitions.** Test cases are defined as JSON fixtures — input, expected output, expected behavior. Every language reads the same fixtures.

2. **Per-language test runners.** Each language has a thin test harness that reads the JSON fixtures, calls the SDK under test, and asserts the expected results. The harness is the only language-specific code.

3. **The Rust core generates the fixtures.** The reference implementation runs the test scenarios and records the expected outputs. This ensures the fixtures are always correct and consistent with the reference.

4. **Every behavior is a test case.** Token refresh timing, cache invalidation, retry backoff intervals, signature byte sequences, error codes — all captured as fixtures. No implicit behavior.

### Fixture Structure

```
forgegate-conformance/
├── fixtures/
│   ├── token/
│   │   ├── acquisition.json
│   │   ├── refresh.json
│   │   ├── caching.json
│   │   ├── expiry.json
│   │   └── error_handling.json
│   ├── signing/
│   │   ├── basic_request.json
│   │   ├── with_body.json
│   │   ├── with_query_params.json
│   │   ├── special_characters.json
│   │   └── empty_body.json
│   ├── authorization/
│   │   ├── simple_allow.json
│   │   ├── simple_deny.json
│   │   ├── with_resource.json
│   │   ├── with_context.json
│   │   ├── cache_hit.json
│   │   ├── cache_miss.json
│   │   ├── cache_expiry.json
│   │   └── error_handling.json
│   ├── feature_flags/
│   │   ├── boolean_enabled.json
│   │   ├── boolean_disabled.json
│   │   ├── variant_string.json
│   │   ├── variant_numeric.json
│   │   ├── percentage_rollout.json
│   │   └── user_override.json
│   ├── webhook/
│   │   ├── valid_signature.json
│   │   ├── invalid_signature.json
│   │   ├── expired_timestamp.json
│   │   ├── tampered_body.json
│   │   └── replay_attack.json
│   ├── retry/
│   │   ├── exponential_backoff.json
│   │   ├── max_retries.json
│   │   ├── non_retryable_error.json
│   │   └── retry_after_header.json
│   └── timeout/
│       ├── request_timeout.json
│       ├── connection_timeout.json
│       └── token_refresh_timeout.json
├── runners/
│   ├── rust/       # Reference — generates fixtures + validates
│   ├── python/     # Runs fixtures against Python implementation
│   ├── typescript/ # Runs fixtures against TS implementation
│   ├── go/         # Runs fixtures against Go implementation
│   └── java/       # Runs fixtures against Java implementation
└── README.md
```

### Fixture Format

Each fixture is a self-contained test case:

```json
{
  "suite": "signing",
  "name": "basic_get_request",
  "description": "Sign a simple GET request with no body",
  "input": {
    "method": "GET",
    "path": "/documents/doc_123",
    "headers": {
      "Accept": "application/json"
    },
    "body": null,
    "credentials": {
      "api_key": "fg-test-key-abc123",
      "timestamp": "2025-09-15T14:32:01Z"
    }
  },
  "expected": {
    "signed_headers": {
      "Authorization": "Bearer fg-test-key-abc123",
      "X-ForgeGate-Timestamp": "1726407121",
      "X-ForgeGate-Signature": "v1=a3f2b8c9d4e5..."
    }
  }
}
```

```json
{
  "suite": "webhook",
  "name": "valid_signature",
  "description": "Verify a valid webhook signature",
  "input": {
    "secret": "whsec_test123",
    "signature": "v1=5d41402abc4b2a76b9719d911017c592",
    "timestamp": "1726407121",
    "body": "{\"type\":\"user.created\",\"data\":{}}",
    "current_time": "1726407150"
  },
  "expected": {
    "valid": true
  }
}
```

```json
{
  "suite": "webhook",
  "name": "expired_timestamp",
  "description": "Reject a webhook with a timestamp older than 5 minutes",
  "input": {
    "secret": "whsec_test123",
    "signature": "v1=5d41402abc4b2a76b9719d911017c592",
    "timestamp": "1726400000",
    "body": "{\"type\":\"user.created\",\"data\":{}}",
    "current_time": "1726407150"
  },
  "expected": {
    "valid": false,
    "error": "timestamp_expired"
  }
}
```

```json
{
  "suite": "authorization",
  "name": "cache_hit_returns_cached_decision",
  "description": "Second authorization call for the same input returns cached result without calling VP",
  "input": {
    "calls": [
      {
        "user_id": "user_456",
        "action": "document:read",
        "resource_id": "doc_123",
        "mock_vp_response": { "decision": "ALLOW", "latency_ms": 15 }
      },
      {
        "user_id": "user_456",
        "action": "document:read",
        "resource_id": "doc_123",
        "note": "same input, should hit cache"
      }
    ]
  },
  "expected": {
    "results": [
      { "allowed": true, "source": "verified_permissions" },
      { "allowed": true, "source": "cache" }
    ],
    "vp_calls_made": 1
  }
}
```

```json
{
  "suite": "feature_flags",
  "name": "percentage_rollout_deterministic",
  "description": "Same user+feature always gets the same rollout decision",
  "input": {
    "feature": "new_dashboard",
    "tenant_id": "tenant_acme",
    "rollout_percentage": 25,
    "users": ["user_001", "user_002", "user_003", "user_004", "user_005",
              "user_006", "user_007", "user_008", "user_009", "user_010"]
  },
  "expected": {
    "decisions": {
      "user_001": false,
      "user_002": true,
      "user_003": false,
      "user_004": false,
      "user_005": true,
      "user_006": false,
      "user_007": false,
      "user_008": true,
      "user_009": false,
      "user_010": false
    },
    "note": "Decisions must be identical across all language implementations. Hash of (feature, tenant, user) determines inclusion."
  }
}
```

```json
{
  "suite": "retry",
  "name": "exponential_backoff_timing",
  "description": "Retry intervals follow exponential backoff with jitter bounds",
  "input": {
    "max_retries": 4,
    "base_delay_ms": 100,
    "max_delay_ms": 5000,
    "responses": [
      { "status": 503 },
      { "status": 503 },
      { "status": 503 },
      { "status": 200, "body": "{\"ok\":true}" }
    ]
  },
  "expected": {
    "total_attempts": 4,
    "success": true,
    "delay_ranges_ms": [
      [80, 120],
      [160, 240],
      [320, 480]
    ],
    "note": "Each delay is base * 2^attempt with ±20% jitter"
  }
}
```

### Test Runners

Each language has a runner that reads fixtures and asserts behavior. The runner is the only code that's language-specific. It's small, auditable, and changes rarely.

**Python runner:**

```python
# runners/python/run_conformance.py

import json
import glob
import sys
from pathlib import Path

# Import whichever implementation is being tested
# This is the ONLY line that changes between FFI and native
from forgegate._forgegate_core import ForgeGateCore  # FFI
# from forgegate._native_core import ForgeGateCore   # future native

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"

class ConformanceRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def run_all(self):
        for fixture_path in sorted(FIXTURES_DIR.rglob("*.json")):
            fixture = json.loads(fixture_path.read_text())
            suite = fixture["suite"]
            name = fixture["name"]

            runner_method = getattr(self, f"run_{suite}", None)
            if not runner_method:
                print(f"  SKIP {suite}/{name} (no runner)")
                continue

            try:
                runner_method(fixture)
                self.passed += 1
                print(f"  ✅ {suite}/{name}")
            except AssertionError as e:
                self.failed += 1
                self.errors.append((suite, name, str(e)))
                print(f"  ❌ {suite}/{name}: {e}")
            except Exception as e:
                self.failed += 1
                self.errors.append((suite, name, f"ERROR: {e}"))
                print(f"  💥 {suite}/{name}: {e}")

        return self.passed, self.failed, self.errors

    def run_signing(self, fixture):
        inp = fixture["input"]
        expected = fixture["expected"]

        core = ForgeGateCore(
            inp["credentials"]["api_key"],
            json.dumps({"timestamp_override": inp["credentials"]["timestamp"]}),
        )

        result = core.sign_request(
            inp["method"],
            inp["path"],
            json.dumps(inp["headers"]),
            inp["body"].encode() if inp["body"] else b"",
        )
        signed = json.loads(result)

        for header, expected_value in expected["signed_headers"].items():
            actual = signed.get(header)
            assert actual == expected_value, \
                f"Header {header}: expected {expected_value}, got {actual}"

    def run_webhook(self, fixture):
        inp = fixture["input"]
        expected = fixture["expected"]

        # Inject current_time for deterministic testing
        result = ForgeGateCore.verify_webhook_with_time(
            inp["secret"],
            inp["signature"],
            inp["timestamp"],
            inp["body"].encode(),
            int(inp["current_time"]),
        )

        assert result == expected["valid"], \
            f"Expected valid={expected['valid']}, got {result}"

    def run_authorization(self, fixture):
        inp = fixture["input"]
        expected = fixture["expected"]

        core = ForgeGateCore("fg-test-key", "{}")
        # Inject mock VP responses
        for i, call in enumerate(inp["calls"]):
            if "mock_vp_response" in call:
                core.mock_vp_response(
                    call["user_id"], call["action"],
                    call.get("resource_id"),
                    json.dumps(call["mock_vp_response"]),
                )

        results = []
        for call in inp["calls"]:
            allowed = core.authorize(
                call["user_id"], call["action"],
                call.get("resource_id"),
            )
            source = core.last_decision_source()
            results.append({"allowed": allowed, "source": source})

        for i, (actual, exp) in enumerate(zip(results, expected["results"])):
            assert actual["allowed"] == exp["allowed"], \
                f"Call {i}: expected allowed={exp['allowed']}, got {actual['allowed']}"
            assert actual["source"] == exp["source"], \
                f"Call {i}: expected source={exp['source']}, got {actual['source']}"

        assert core.vp_calls_made() == expected["vp_calls_made"], \
            f"Expected {expected['vp_calls_made']} VP calls, got {core.vp_calls_made()}"

    def run_feature_flags(self, fixture):
        inp = fixture["input"]
        expected = fixture["expected"]

        core = ForgeGateCore("fg-test-key", json.dumps({
            "feature_flags": {
                inp["feature"]: {
                    "type": "boolean",
                    "rollout_percentage": inp["rollout_percentage"],
                }
            }
        }))

        for user_id, expected_decision in expected["decisions"].items():
            actual = core.feature_enabled(
                inp["feature"], inp["tenant_id"], user_id,
            )
            assert actual == expected_decision, \
                f"User {user_id}: expected {expected_decision}, got {actual}"

    def run_retry(self, fixture):
        inp = fixture["input"]
        expected = fixture["expected"]

        core = ForgeGateCore("fg-test-key", json.dumps({
            "retry": {
                "max_retries": inp["max_retries"],
                "base_delay_ms": inp["base_delay_ms"],
                "max_delay_ms": inp["max_delay_ms"],
            }
        }))

        # Mock server that returns the configured responses
        core.mock_responses(inp["responses"])

        result = core.send_with_retry("GET", "/test", "{}", b"")
        assert result["attempts"] == expected["total_attempts"]
        assert result["success"] == expected["success"]

        # Verify backoff timing is within jitter bounds
        for i, (actual_delay, (min_d, max_d)) in enumerate(
            zip(result["delays_ms"], expected["delay_ranges_ms"])
        ):
            assert min_d <= actual_delay <= max_d, \
                f"Retry {i}: delay {actual_delay}ms not in [{min_d}, {max_d}]"


if __name__ == "__main__":
    runner = ConformanceRunner()
    passed, failed, errors = runner.run_all()

    print(f"\n{'='*50}")
    print(f"Conformance: {passed} passed, {failed} failed")
    if errors:
        print(f"\nFailures:")
        for suite, name, err in errors:
            print(f"  {suite}/{name}: {err}")

    sys.exit(1 if failed > 0 else 0)
```

**The key line is the import.** During Phase 1, the runner imports the PyO3 FFI wrapper. When a native Python implementation is ready, you change one import and run the same tests:

```python
# Phase 1: FFI wrapper
from forgegate._forgegate_core import ForgeGateCore

# Phase 2: native Python (when ready)
# from forgegate._native_core import ForgeGateCore
```

If the native implementation passes all fixtures, it's a valid replacement. If it doesn't, you know exactly which behaviors differ.

### Fixture Generation from Reference

The Rust reference implementation generates (or validates) the fixtures:

```rust
// runners/rust/src/generate_fixtures.rs

/// Run all test scenarios through the Rust core and record
/// the outputs as JSON fixtures. These become the contract.
pub fn generate_fixtures(output_dir: &Path) {
    // Signing
    generate_signing_fixtures(output_dir);
    // Webhook verification
    generate_webhook_fixtures(output_dir);
    // Authorization + caching
    generate_authorization_fixtures(output_dir);
    // Feature flags
    generate_feature_flag_fixtures(output_dir);
    // Retry logic
    generate_retry_fixtures(output_dir);
    // Timeout behavior
    generate_timeout_fixtures(output_dir);
}

fn generate_signing_fixtures(dir: &Path) {
    let core = FgClient::new_for_test("fg-test-key-abc123");

    let cases = vec![
        TestCase {
            name: "basic_get_request",
            description: "Sign a simple GET request with no body",
            method: "GET",
            path: "/documents/doc_123",
            headers: json!({"Accept": "application/json"}),
            body: None,
            timestamp: "2025-09-15T14:32:01Z",
        },
        // ... more cases
    ];

    for case in cases {
        let result = core.sign_request_deterministic(
            case.method, case.path,
            &case.headers, case.body,
            case.timestamp,
        );

        let fixture = json!({
            "suite": "signing",
            "name": case.name,
            "description": case.description,
            "input": {
                "method": case.method,
                "path": case.path,
                "headers": case.headers,
                "body": case.body,
                "credentials": {
                    "api_key": "fg-test-key-abc123",
                    "timestamp": case.timestamp,
                }
            },
            "expected": {
                "signed_headers": result.headers,
            }
        });

        let path = dir.join("signing").join(format!("{}.json", case.name));
        fs::write(path, serde_json::to_string_pretty(&fixture).unwrap())
            .unwrap();
    }
}
```

### CI Pipeline

```yaml
# Every PR runs conformance tests against all implementations

conformance:
  strategy:
    matrix:
      implementation:
        - name: rust-reference
          command: cargo test --manifest-path runners/rust/Cargo.toml
        - name: python-ffi
          command: python runners/python/run_conformance.py
        - name: python-native
          command: python runners/python/run_conformance.py --native
          allow_failure: true  # native impl may be in progress
        - name: typescript-wasm
          command: node runners/typescript/run_conformance.js
        - name: go-cgo
          command: go test ./runners/go/...

  steps:
    - checkout
    - run: ${{ matrix.implementation.command }}

# Fixture regeneration (runs on changes to Rust core)
regenerate-fixtures:
  runs-on: ubuntu-latest
  steps:
    - checkout
    - run: cargo run --bin generate-fixtures -- fixtures/
    - run: |
        if git diff --quiet fixtures/; then
          echo "Fixtures unchanged"
        else
          echo "⚠ Fixtures changed! Review the diff."
          git diff fixtures/
          exit 1
        fi
```

If anyone changes the Rust core behavior, the fixture regeneration step catches it — the diff shows exactly what changed and forces a deliberate review.

---

## Phase Transition: FFI to Native

When it's time to write a native implementation for a language:

### Step 1: Create the native module alongside the FFI wrapper

```
forgegate-python/
├── forgegate/
│   ├── _forgegate_core.so     # PyO3 FFI wrapper (Phase 1)
│   ├── _native_core.py        # Pure Python (Phase 2, in progress)
│   ├── guard.py               # High-level API (unchanged)
│   ├── client.py              # BaseClient (unchanged)
│   └── webhooks.py            # WebhookHandler (unchanged)
```

### Step 2: Run conformance tests against both

```bash
# FFI (should always pass)
FORGEGATE_IMPL=ffi python runners/python/run_conformance.py

# Native (passes more tests as implementation progresses)
FORGEGATE_IMPL=native python runners/python/run_conformance.py
```

### Step 3: Track progress

```
Conformance: python-native
  ✅ signing/basic_get_request
  ✅ signing/with_body
  ✅ signing/with_query_params
  ✅ signing/special_characters
  ✅ signing/empty_body
  ✅ webhook/valid_signature
  ✅ webhook/invalid_signature
  ✅ webhook/expired_timestamp
  ✅ webhook/tampered_body
  ✅ webhook/replay_attack
  ✅ authorization/simple_allow
  ✅ authorization/simple_deny
  ❌ authorization/cache_hit          ← cache not implemented yet
  ❌ authorization/cache_expiry       ← cache not implemented yet
  ✅ feature_flags/boolean_enabled
  ✅ feature_flags/boolean_disabled
  ✅ feature_flags/percentage_rollout
  ❌ retry/exponential_backoff        ← retry not implemented yet
  ...

  Conformance: 15/22 passed (68%)
```

### Step 4: Swap when 100%

When the native implementation passes all conformance tests, swap the import:

```python
# forgegate/__init__.py

import os

if os.environ.get("FORGEGATE_USE_FFI") == "1":
    from forgegate._forgegate_core import ForgeGateCore
else:
    # Default to native when conformance passes 100%
    from forgegate._native_core import ForgeGateCore
```

Ship both in the package initially. Keep the FFI as a fallback. Remove it in a future major version once the native implementation is battle-tested.

---

## What Gets Tested (Conformance Categories)

| Category | # Fixtures | What's Verified |
|----------|-----------|-----------------|
| Signing | ~15 | Signature byte-for-byte match, header ordering, body hashing, special characters, empty body |
| Webhook | ~10 | HMAC-SHA256 verification, timestamp validation, replay protection, tampered body detection |
| Authorization | ~20 | Allow/deny decisions, cache behavior (hit, miss, expiry, invalidation), error handling, context passing |
| Feature Flags | ~15 | Boolean, string variant, numeric, percentage rollout (deterministic hash), user override, tenant scoping |
| Retry | ~10 | Exponential backoff timing (within jitter bounds), max retries, non-retryable errors, Retry-After header |
| Token | ~15 | Acquisition, refresh before expiry, caching, concurrent refresh (no thundering herd), error propagation |
| Timeout | ~5 | Request timeout, connection timeout, token refresh timeout |
| **Total** | **~90** | |

### Determinism is critical

The fixtures require deterministic behavior. For things that are normally non-deterministic (timestamps, jitter, random IDs), the conformance interface accepts overrides:

```rust
// The core exposes a test-mode API that accepts deterministic inputs
pub fn sign_request_deterministic(
    &self,
    method: &str,
    path: &str,
    headers: &str,
    body: Option<&[u8]>,
    timestamp_override: &str,  // No clock dependency
) -> SignResult;

pub fn feature_enabled_with_seed(
    &self,
    feature: &str,
    tenant_id: &str,
    user_id: &str,
    hash_seed: u64,  // Deterministic hash for rollout
) -> bool;
```

Every language wrapper must support these same deterministic inputs so that the fixture outputs are reproducible across implementations.

---

## What the High-Level SDK Looks Like (Unchanged by Implementation)

The developer never sees the core implementation. The high-level API is the same whether FFI or native is underneath:

```python
# This code is identical regardless of implementation

from forgegate import Guard, WebhookHandler

guard = Guard(api_key="fg-runtime-...")

# Authorization
guard.authorize(user_id, "document:read", resource_id="doc_123")

# Feature flags
guard.feature_enabled("ai_summaries", tenant="tenant_acme")

# Webhook verification
handler = WebhookHandler(secret="whsec_...")
event = handler.verify_and_parse(body, headers)
```

```python
# Generated per-customer SDK — also unchanged

from acme_sdk import AcmeClient, GetDocument
from acme_sdk.types import GetDocumentInput

client = AcmeClient(
    endpoint="https://api.acme.com",
    credentials=api_key("sk-..."),
)
doc = client.send(GetDocument(GetDocumentInput(document_id="doc_123")))
```

The conformance test suite guarantees that switching from FFI to native is invisible to every consumer of the SDK.

---

## Summary

| Decision | Rationale |
|----------|-----------|
| Start with Rust core + FFI | Ship secure, correct behavior in every language from day one. One implementation to audit and maintain. |
| JSON conformance fixtures | Language-agnostic test contract. Defines behavior, not implementation. |
| Per-language test runners | Thin adapters that read fixtures and call the SDK. Only code that changes per language. |
| Rust generates the fixtures | Reference implementation is the source of truth. Fixture changes require deliberate review. |
| Native implementations gated by conformance | 100% fixture pass rate required before shipping. No exceptions. |
| FFI stays as fallback | Ship both in the package during transition. Remove FFI in a future major version. |
| Deterministic test inputs | Timestamps, hash seeds, and jitter overrides ensure byte-for-byte reproducibility across implementations. |

The test suite is the product. The implementation is replaceable.

---

## Related Documents

- [Identity Engine](11-technical-identity-engine-rust.md) — the Rust codebase that contains the reference implementation
- [SaaS Integration Guide](02-technical-saas-integration.md) — how developers consume the generated SDK
- [Tutorial: TODO App](14-tutorial-todo-app.md) — end-to-end example including SDK generation and usage

# ForgeGuard — Repository Reconciliation Report

*Version 1.0 — July 2026*
*Purpose: reconcile the existing `cloudbridgeuy/forgeguard` repository (last commit 2026-05-14) against the new document set — Brief v1.4, Report 2 v2.1, and Design A1/A1.1 — and produce a keep/refit/freeze/delete plan with a revised effort estimate. Method: shallow clone, structural inspection, targeted reads of the load-bearing modules.*

---

## What is actually there

Roughly forty thousand lines of Rust across a 17-crate workspace plus an Axum middleware library, with engineering discipline that most funded teams don't have: Functional Core / Imperative Shell enforced at crate boundaries with clippy lints backing it, newtype and typestate conventions documented as context files, an xtask pipeline with its own lint architecture, conventional-commit release tooling, and CDK infrastructure already deployed far enough that the last commit grants a control-plane Lambda write access for per-organization policy-store provisioning. The control plane is the center of gravity (~16.8k LOC over DynamoDB), followed by the core domain crate (~6.4k), an HTTP layer, proxy and proxy-core skeletons (~3.7k combined), the authn/authz pairs, a CLI, and the Axum middleware (~450 LOC). The SDK, FFI, audit, and back-office crates are one-line stubs. Smithy is completely gone — only the README still claims it exists.

The verdict in one sentence: **this is not a failed project to restart; it is a well-built chassis whose authorization heart is the wrong organ** — and the new documents describe exactly the transplant.

## What already conforms to the new documents

More survived than the discovery interview implied, and several brief-v1.4 decisions turn out to have working ancestors in the tree. The FCIS crate split *is* Design A1's shape — `core`/`authz-core`/`authn-core`/`proxy-core` pure, adapters around them. **Organization-scoped Ed25519 signing keys already exist** in the control plane — the header contract's trust model, built before the header contract was specified. **The control plane runs on DynamoDB and Lambda already** — variant A1.1's substrate is not a migration, it is the incumbent. **The TOML structural plane exists and is dogfooded**: `forgeguard.toml` defines the control plane's own schema, RBAC, and tenant scoping, synced via `cargo xtask control-plane cedar sync|diff|status` — which is nothing less than the snapshot compiler's ancestor, complete with a diff command that is shadow-mode's tooling cousin. **Feature flags are a real module in the pure core** with documented evaluation order and proxy wiring — the entitlements-convergence seed. **FGRNs exist as a 557-line validated newtype.** The Organization lifecycle is a typestate machine. Both enforcement bodies have skeletons. Even the empty crates are conforming: `sdk`/`ffi-*` stubs match "SDK-first died," and the empty `audit` crates match "audit is exhaust, not a product to build."

## Where the repo conflicts with Brief v1.4

Four structural conflicts, in order of consequence.

**First, Verified Permissions sits in the hot path.** The `authz` crate is an AWS VP client — every decision is a network call to a hosted AWS service. Under the new fitness criteria this fails three gates at once: footprint (the free tier may not require external services), latency (a hop per decision versus the measured in-process microseconds), and the exit hatch (decisions transiting a vendor's cloud). This is the transplant: the engine wrapper moves to the embedded `cedar-policy` crate behind the store/engine trait, and VP is demoted to exactly what Report 2 classified it as — an optional Class-C backend for AWS-committed enterprises. The good news is that the wound is contained: VP coupling lives in `crates/authz` and a `vp_client` module, the Cedar *type* layer already sits in the pure core, and the recent per-org-policy-store provisioning work maps conceptually onto per-Organization snapshots.

**Second, tenancy is flat.** The current model scopes everything by `org_id` attribute equality — principal's org_id must match resource's org_id. There is no spine, no DAG, no grant edges, no user-boundary rule, no cardinality doctrine, no promotion. The entire core model of Brief v1.4 — the part every subsequent decision hangs off — does not exist in code yet. This is the largest single build item, and it lands in the crate best prepared to receive it (`core`, pure, well-typed).

**Third, the existing FGRN encodes position.** The current format is six-positional — `fgrn:<project>:<tenant>:<namespace>:<resource-type>:<resource-id>` — embedding tenant and namespace into identity, which is precisely the trap the brief's naming section forbids (re-parenting must never rename) and lacks the native-id derivation rule that dissolves the dual-write problem. The 557 lines of segment validation, serde plumbing, and wildcard machinery are reusable; the *format* is not. This is a refit, not a rewrite, but it touches everything that stores names, so it goes early.

**Fourth, the authentication engine is scope the brief federated away.** Nearly 3k LOC of typestate authentication flows and a Cognito/SES/SNS adapter implement the A the brief declared commodity. It works and is well-built; the reconciliation is not deletion but *freeze*: it becomes one federation adapter among possible others, receives no further investment, and the identity-engine ambitions (Flow Reaper, God Mode) documented in the context files are explicitly out of the wedge.

**Absent entirely**, as expected for a pre-reset codebase: the event log and synchronization contract, revision tokens, the decision log (stubs), denies, snapshots with provenance (though `config_version.rs` is a seed), observe mode, delegation chains, and — notably — the middleware authorizes and rejects but does not yet *inject signed headers*, despite the signing keys existing one crate away. The keys and the contract have never been introduced to each other.

One small conflict that costs nothing and signals everything: the repository tagline reads "Simplified **Authentication** for your web services" — literally the wrong A. The brief's wedge is authorization; the README leads with the commodity. Fix the tagline the same day work resumes.

## The plan: keep, refit, freeze, delete

**Keep as-is**: the workspace discipline (lints, newtypes, xtask, visibility conventions, release tooling), the DynamoDB/Lambda control-plane substrate, the Ed25519 key management, the feature-flags core module, the FCIS structure, the CDK infra, the dogfooding pattern.

**Refit**: `core` receives the brief's model — spine, grants, boundary, cardinality, delegation chains — alongside its existing types; FGRN reshapes to `fgrn:{organization}:{type}:{id}` with native-id derivation, keeping its validation machinery; `authz` becomes the trait plus an embedded-Cedar implementation, with the VP client relegated to an optional backend module; the TOML surface and `cedar sync/diff` xtask evolve into the snapshot compiler with provenance; `forgeguard-axum` gains header injection (marrying it to the signing keys), the enforce/observe switch, and the RLS session bridge; `control-plane` gains the event log (TransactWrite counter+event, per A1.1), cursor endpoint, and revision tokens over its existing DynamoDB store.

**Freeze**: `authn`/`authn-core` as the Cognito federation adapter — maintained, not grown. `proxy`/`proxy-core` skeletons — parked until the distributed consistency design exists, per the design's own wary list.

**Delete or leave stubbed**: `sdk`, `ffi-python`, `ffi-wasm` (the brief's header contract made deep SDKs unnecessary; thin verification helpers can live in `lib/`), `back-office` (out of MVP), the stale Smithy claim in the README.

## Revised effort and sequence

Design A1 estimated 10–14 part-time weeks from zero. The chassis changes that estimate's *composition* more than its total: scaffolding, CI, infra, config plumbing, and key management — easily two to three weeks of work — already exist and are better than a fresh start would produce; but the two dominant items were always the core model and the engine, and those remain nearly untouched. Revised estimate: **8–12 part-time weeks to the brief-conformant MVP**, sequenced to put the riskiest transplant first: (1) the model in `core` — spine, grants, FGRN reshape, boundary, chains — with the conformance directory finally earning its `.gitkeep` as the home of model test fixtures; (2) the engine swap — trait, embedded Cedar, VP demoted — validated by porting the session spike's seven assertions into the test suite as the first conformance cases; (3) event log, revision tokens, and cursor endpoint on the existing DynamoDB store; (4) the middleware refit — header injection with the existing keys, observe mode, session bridge; (5) the TOML-to-snapshot compiler evolution with provenance. The n=1 validation month starts after step 4; step 5 can overlap it.

## Closing observation

The May commit log reads like a project that lost sight of its product — and the discovery interview said as much. But the reconciliation shows something more useful: almost nothing built was *wrong*, it was *premature or misaimed*. The signing keys were built before the contract that needs them; the TOML sync before the snapshot model it should compile to; the DynamoDB control plane before the event-sourcing design that justifies it; the flags before the convergence thesis that makes them strategic. The new document set doesn't invalidate the repository — it supplies the missing spine, in both senses. The restart is not `cargo new`; it is a branch named something like `brief-v1.4` and the model landing in `crates/core`.

# ADR-0004: Adopt the Brief v1.4 framing; supersede ADR-0003 (resolution-engine product framing)

- **Status:** Accepted
- **Date:** 2026-07-12
- **Supersedes:** ADR-0003 (resolution-engine product framing — referenced by issues #84 and #104; not present on `main`, and must not be merged from any branch that carries it)
- **Superseded by:** —

## Context

ADR-0003 framed ForgeGuard as a *resolution engine*: `forgeguard.toml`, the dashboard, and the API as interchangeable CRUD wrappers over a single model, with a two-layer authoring scheme in which layer 1 is raw Cedar (policy templates carrying `?principal` / `?resource` slots) and runtime *links* instantiate those templates against concrete entities, executed by AWS Verified Permissions.

In July 2026 the project was re-founded from customer discovery rather than architecture, producing the v1.4 document set (Problem & Product Brief v1.4, Competitive Teardown, Lessons Learned, Report 2 v2.1, Design A1/A1.1, Repository Reconciliation Report — committed under `docs/`). That work was validated by a running engine spike (seven conformance assertions, measured latency) and a computed cost model. The brief is technology-neutral and gate-based; this ADR records why the resolution-engine framing does not survive contact with it.

## Decision

The Brief v1.4 framing replaces the resolution-engine framing. Three of ADR-0003's pillars are invalidated, one instinct is retained in corrected form.

**Invalidated: raw Cedar as an authoring layer.** Under the brief, the evaluation engine is an implementation detail behind the snapshot compiler and the store/engine trait — chosen per engineering design, replaceable, and never exposed as a user-facing authoring surface. Users author the *model* (endpoints, spine selectors, grants, denies, entitlements); the compiler emits engine policy. Exposing raw Cedar with slots would weld the product to one engine's semantics and violate both the brief's technology neutrality and its exit-hatch promise.

**Invalidated: interchangeable CRUD surfaces over one model.** The brief's two planes are deliberately *not* interchangeable. Repo-born structural policy and UI-born operational policy have different owners (developers vs. operators), different change cadences (deploys vs. clicks), different friction profiles (PR review vs. elevated permissions with TTLs, as with denies), and — decisively — provenance determines editability: repo-born rules are read-only in the UI, UI-born rules never touch the repo. Interchangeability was the seed of the four-drifting-systems disease reappearing inside the product; asymmetry is the cure.

**Invalidated: templates-and-links as the sharing primitive, executed by Verified Permissions.** Per-resource scoped permission is a *grant edge* in the spine-plus-grants DAG — live data evaluated against a versioned snapshot at a single grant-store revision — not a policy-template instantiation. And Verified Permissions in the hot path fails three fitness gates at once (footprint, latency, exit hatch); it is demoted to an optional Class-C backend behind the engine trait (Report 2 v2.1).

**Retained, corrected:** ADR-0003's core instinct — `forgeguard.toml` as a canonical, dogfooded authoring surface with sync/diff tooling — survives as the *structural plane*, one of two planes rather than one of three interchangeable wrappers, and its `cedar sync|diff|status` tooling is the ancestor of the snapshot compiler (Phase 5) and of shadow-mode diffing. Issue #104 continues under this corrected framing.

## Consequences

Issues #38, #55, #84, and #102 are closed as superseded (see the triage record). Issue #104 is re-framed and continues. Any branch containing ADR-0003 merges only after removing or amending it to point here. All future design decisions cite the brief's gates, not the resolution-engine framing; where a design decision conflicts with the brief, either the design is wrong or the brief is amended explicitly — never silently (the brief's own rule, now the ADR chain's rule as well).

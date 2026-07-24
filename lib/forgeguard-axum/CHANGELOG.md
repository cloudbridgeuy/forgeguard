# Changelog

All notable changes to `forgeguard-axum` will be documented in this file.

## [Unreleased]

### Changed

- **Non-breaking for this crate's consumers:** `forgeguard_proxy_core::evaluate_pipeline`
  (a separate, lock-step-versioned published crate) gained a breaking 5th
  `EnforcementMode` parameter, `PipelineOutcome::Forward` gained an `effect`
  field, and `PipelineOutcome::Reject` gained `policy_denied` and `record`
  fields, to carry the mode/effect decision. None of this is re-exported
  through `forgeguard-axum`'s own public API, so this crate's surface only
  changed additively (see Added below) — `forgeguard_layer`'s behavior is
  backward compatible: with no `observe()` stamp and no `with_default_mode`
  call, every route still enforces exactly as before.

- **Breaking:** injected header namespace renamed to `X-Fg-*` (e.g.
  `X-Fg-User-Id`, `X-Fg-Tenant-Id`, `X-Fg-Scope-Path`) — previously a longer,
  now-retired `X-<ProjectName>-*` prefix. Any upstream or handler reading the
  old header names must update to the new namespace. The signed canonical
  payload format is unchanged — only header names moved.

### Added

- **RLS session bridge + reference policy templates (#111 V4):** `RlsContext`
  — an infallible `FromRequestParts` extractor projecting the request's
  `DecisionRecord`/`Identity` into three RLS session variables
  (`fg.scope_path`, `fg.granted_ids`, `fg.principal_id`), degrading to empty
  fields when no decision was made. `RlsContext::session_statements(Dialect)`
  builds parameterized `set_config(..., true)` statements (transaction-local,
  `SET LOCAL` semantics) — pure data-in/data-out, running them is the
  embedding app's job.
  - `Dialect` — `#[non_exhaustive]`; `Postgres` is the only variant today.
  - `Statement` — `sql()` / `params()` accessors for one parameterized
    statement.
  - `forgeguard_axum::rls::templates` — four reference Postgres RLS policies
    (`SCOPE`, `SCOPE_WITH_GRANTS`, `GRANTS_ONLY`, `OWNER`) shipped as
    `include_str!` consts, with matching `.sql` files under
    `templates/rls/postgres/` for direct `psql` application. See the
    README's "RLS Session Bridge" section and
    `templates/rls/postgres/README.md`.
  - `DecisionRecord::granted_ids()` (from `forgeguard_authz_core`) — native
    ids of resources directly granted to the principal on the queried
    resource; feeds `fg.granted_ids` above.
- **Extractor semantics:** `ForgeGuardIdentity`, `ForgeGuardFlags`, and
  `ForgeGuardDecision` now read their request extension with `.get().cloned()`
  instead of `.remove()`, so multiple extractors (including the new
  `RlsContext`) can coexist in the same handler without one clearing the
  extension for the others. Removal was never a documented contract.
- **Enforce|Observe per-route mode (#111 V3):** `EnforcementMode` (re-exported
  from `forgeguard_proxy_core`) — `Enforce` (default) rejects a policy deny
  with 403; `Observe` never blocks, forwards regardless, and reports what
  would have happened.
  - `ForgeGuard::with_default_mode(EnforcementMode)` — guard-wide default.
  - `observe()` / `ForgeGuard::observe()` — `axum::Extension<ModeOverride>`
    layer that switches the routes it wraps to observe mode. Ordering
    matters: it must be added after (outer to) `forgeguard_layer` to be
    seen — misordering fails safe to the guard's default mode. See the
    README's "Enforce vs Observe" section for working router shapes,
    including the `.nest()` scoping traps.
  - `Effect` — `Allowed` / `Denied` / `WouldAllow` / `WouldDeny`, the
    enforcement outcome of one evaluated request.
  - `EnforcementOutcome` — `record()` / `mode()` / `effect()` accessors;
    what gets delivered to a `DecisionSink`.
  - `DecisionSink` trait + `ForgeGuard::with_decision_sink(Arc<dyn
    DecisionSink>)` — pluggable outcome recording, called synchronously on
    the request path for every evaluated outcome (nothing recorded for
    public routes or forwards where policy never ran).
  - `TracingDecisionSink` — the default sink; emits one `tracing::info!`
    event per outcome at target `forgeguard::decision`.
- `SigningConfig` — holds an org's Ed25519 key + `KeyId`; construct via
  `SigningConfig::new` or `SigningConfig::from_pkcs8_pem`.
- `ForgeGuard::with_signing(SigningConfig)` — opt in to signing injected
  `X-Fg-*` headers.
- On `Forward`, the middleware now injects `X-Fg-*` identity headers
  (`-User-Id`/`-Tenant-Id`/`-Groups`/`-Auth-Provider`) and, when a
  `DecisionRecord` is present, decision headers (`-Scope-Path`,
  `-Entitlements`, `-Revision`). When `with_signing` is configured and at
  least one header was injected, the signature headers (`-Signature`,
  `-Timestamp`, `-Key-Id`, `-Trace-Id`) are appended, covering every injected
  header.
- Spoofing guard: all `X-Fg-*` header names this middleware can ever inject
  are unconditionally stripped from the inbound request before the
  (possibly empty) injected set is applied — a client cannot smuggle a
  forged identity/decision header through on a route where nothing is
  injected.

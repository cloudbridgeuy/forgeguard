# Changelog

All notable changes to `forgeguard-axum` will be documented in this file.

## [Unreleased]

### Changed

- **Breaking:** injected header namespace converged from `X-ForgeGuard-*` to
  `X-Fg-*` (e.g. `X-Fg-User-Id`, `X-Fg-Tenant-Id`, `X-Fg-Scope-Path`). Any
  upstream or handler reading the old header names must update to the new
  namespace. The signed canonical payload format is unchanged — only header
  names moved.

### Added

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

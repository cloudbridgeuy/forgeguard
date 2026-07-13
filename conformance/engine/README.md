# Engine Conformance Fixtures

JSON fixtures exercising `CedarEngine::decide` end to end (store write →
entity translation → Cedar evaluation → `DecisionRecord`). The harness lives
at `crates/authz-core/tests/conformance.rs`; it walks every `*.json` file in
this directory, builds a `MemoryStore` from it, and asserts each case's
expected decision.

## Fixture schema

```json
{
  "name": "s1-subtree-role",
  "description": "S1: role at org-node grants action on resources anchored below it",
  "organization": "acme",
  "spine": [
    { "id": "root", "parent": null },
    { "id": "finance", "parent": "root" },
    { "id": "finance_ap", "parent": "finance" },
    { "id": "engineering", "parent": "root" }
  ],
  "principals": [
    { "id": "maria", "kind": "human", "anchor": "finance" }
  ],
  "principal_sets": [],
  "grants": [],
  "promotions": [
    { "resource_type": "invoice", "resource_id": "inv_1", "anchor": "finance_ap", "to": "maria", "actions": ["invoice-write"] }
  ],
  "policies": "permit(principal in OrgUnit::\"fgrn:acme:orgunit:finance\", action == Action::\"invoice-write\", resource in OrgUnit::\"fgrn:acme:orgunit:finance\");",
  "cases": [
    { "name": "maria writes invoice under her subtree", "principal": "maria", "action": "invoice-write", "resource_type": "invoice", "resource_id": "inv_1", "expect": "allow" }
  ]
}
```

- **`spine`**: org units in file order, `parent` by `id` (or `null` for the root). Built into a `Spine` via `OrgUnit::try_new`.
- **`principals`**: `kind` is one of `PrincipalKind`'s FromStr strings — `"human"`, `"service"`, `"agent"` (not Cedar's collapsed `User`/`Machine` — see `crates/authz-core/src/engine_cedar/translate.rs`'s module doc for that collapse). `anchor` is a spine `id`.
- **`principal_sets`**: `anchor` is a spine `id`; `members` are principal `id`s.
- **`promotions`**: `PromotedResource` is only mintable through `forgeguard_core::promotion::share`, which also mints the resource's *first* grant — so every promotion entry carries a `to`/`actions` pair, and that share-grant is applied to the store alongside the promotion. This is why a fixture can have an empty top-level `grants` list and still have live grants in the store: the promotion's share-grant already put one there. Use the top-level `grants` list only for *additional* grants beyond the minting share. `anchor` may be a spine `id` or a principal `id` (owner-anchored resources); `to` may be a principal `id` or a `principal_sets` `id` (sharing to a set).
- **`grants`**: additional grants beyond a promotion's own share-grant. `resource_type`/`resource_id` must match an existing promotion's pair. `to` may be a principal `id` or a `principal_sets` `id`.
- **`policies`**: raw Cedar policy text for the snapshot (parsed via `Snapshot::from_policy_text`). FGRN strings embedded here must match `Fgrn`'s `Display` format exactly — `fgrn:{organization}:{kind}:{id}`, where `kind` is `orgunit`/`principal`/`principal-set`/`resource` (see `crates/core/src/fgrn.rs`), and `resource` kind ids are `{resource_type}/{native_id}`.
- **`cases`**: one `SliceQuery`/`DecisionQuery` per case, evaluated at the latest revision. `expect` is `"allow"` or `"deny"`. An optional `"chain"` field lists principal `id`s (actor first) to attach a delegation chain via `DecisionQuery::with_chain` — `chain[0]` must equal `principal`. Each link is evaluated against its own entity slice at the same pinned revision; the decision is Allow iff every link allows.

## Adding a case

Append a fixture to `this directory` and rerun `cargo test -p forgeguard_authz_core --test conformance -- --nocapture` — the harness discovers files automatically, no wiring needed. Keep one JSON file per named case family (`s1-...`, `s2-...`, etc.) as later phases add more.

## The seven S1–S5 conformance assertions

| # | Case | Fixture | Expect |
| - | ---- | ------- | ------ |
| 1 | S1 subtree role allow | `s1-subtree-role.json` (case 1) | Allow |
| 2 | S1 outside-subtree deny | `s1-subtree-role.json` (case 2) | Deny |
| 3 | S2 sharing grant | `s2-sharing-grant.json` | Allow |
| 4 | S3 owner rule | `s3-owner-boundary.json` (case 1) | Allow |
| 5 | S3 boundary opacity | `s3-owner-boundary.json` (case 2) | Deny |
| 6 | S4 deny overrides | `s4-deny-overrides.json` | Deny |
| 7 | S5 chain intersection | `s5-chain-intersection.json` (case 2) | Deny |

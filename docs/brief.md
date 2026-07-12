# ForgeGuard — Problem & Product Brief

*Version 1.4 — July 2026 (amended: anchoring/cardinality, user boundary, data plane, synchronization contract, consistency model, technology neutrality, shadow mode, native delegation, architecture fitness criteria)*
*Status: foundational. This document precedes and constrains all architecture work. When a design decision conflicts with this brief, either the design is wrong or this brief must be amended explicitly — never silently.*
*Technology neutrality: this document specifies the problem, the model, and the contracts — never the technology. No language, framework, policy engine, database, file format, or cryptographic primitive named in an example is a requirement; examples use familiar notations (a TOML-like config syntax, SQL-like predicates) purely to convey shape. Multiple competing engineering designs, using different tools, should each be able to claim conformance to this brief, and the choice among them is made in engineering design documents subordinate to it.*

---

## Why this document exists

The first iteration of ForgeGuard started from a product and went looking for a customer. It accumulated fourteen architecture documents, a Smithy parser spike, an SDK strategy, and a saga engine before it had a validated problem, and momentum died the way it always does when the architecture outruns the need. This brief is the reset: it was produced by interviewing the founding customer — the author — about two real applications where the pain actually occurred, and it works forward from that pain. Everything here is derived from demand. The architecture that follows must be derived from this.

The examples and configuration snippets in this document convey *shape*, not contract. Field names, syntax, and formats are illustrative; the real design will discover its own surface. What is binding is the model they illustrate.

## The problem

Multi-tenant B2B applications have no single place where "who can do what, on which part of the tenant tree, under which entitlement" lives.

This was observed twice, concretely. The first case was a funded startup: a Python microservices platform on EKS behind API Gateway. Auth0 was adopted and it worked — for authentication, and only authentication. Authorization had to be hand-rolled, and it ended up smeared across four disconnected systems: decorators that every microservice had to remember to apply (opt-in security, where one forgotten decorator is a silent hole), row-level security rules duplicating policy logic in SQL, an implicit all-or-nothing-per-tenant convention that lived in tribal knowledge, and — when features needed per-customer rollout — LaunchDarkly, a second paid product acquired specifically because the authorization layer could not express entitlements. Nothing guaranteed these four systems agreed with each other. That is not an authorization system; it is four systems that hopefully coincide.

The second case was a personal project: a Rust/Axum API behind a network load balancer, near-zero budget, and the same fundamental needs. The market offered nothing that fit both cases, which is itself the finding: the gap is not at one price point or one stack.

The bill for the fragmentation arrived on schedule. The startup's tenants were modeled as an organization tree with downward-scoped data access. A customer asked for something that sounded trivial — let a user temporarily scope *down* to a child node to see the app as that level sees it, then scope back up. Every piece needed to grant this already existed, and granting it still required re-architecting the solution, because the authorization model was welded into the application's structure instead of being a layer that could be reconfigured. When policy is data, "view as node X" is a session attribute. When policy is decorators plus RLS plus convention, it is a quarter-long project.

The third A — auditing — deserves candor: it has not hurt yet. What existed was edge metrics pushed to DataDog, which is observability (how much), not audit (who did what to whom), and nobody has yet asked a question it could not answer. Audit is a latent need that becomes acute the day a SOC 2 pursuit or an enterprise security questionnaire arrives. It is real, and it is not the wedge. The first ForgeGuard treated all three A's as equal citizens; the pain is concentrated in one and a half of them, and that misweighting is part of why the product lost its shape.

## What the market sells instead

Auth0, Clerk, and Cognito solve authentication — a genuinely commoditized problem — and stop there, while charging on MAUs, a number the buyer does not control and that does not map to B2B value. Cedar, OPA, and the Zanzibar lineage (SpiceDB, OpenFGA) provide decision *engines* but no multi-tenancy model, no enforcement point, and no operational surface: tenancy is left as an exercise for the reader, which is exactly the exercise that hurt. Products closer to this brief's territory exist — Permit.io, Oso Cloud, Cerbos, WorkOS — and an honest competitive teardown of them is a required next step before serious investment (see Open Questions). The working hypothesis, to be falsified deliberately: none of them make the tenant hierarchy the privileged spine of the model, unify entitlements with permissions at the enforcement point, and offer a structural exit hatch. If that hypothesis is wrong, this brief must change.

## The product

ForgeGuard is an enforcement point with one brain and two bodies.

The brain authenticates both machine-to-machine and human credentials, authorizes each request at the endpoint level against hierarchy-aware policy, and emits a complete decision record as free exhaust of doing its job — which is how the forgotten third A stops being forgotten: audit is not a feature to build later, it is what the enforcement point cannot help producing.

The two bodies serve the two observed customers. For the polyglot microservices world (the EKS startup), the brain ships as an edge proxy sitting at or behind the API gateway, in the hot path of every request. For the single-service world (the personal app), the same brain ships as native middleware embedded in the application's own framework — the founding application's stack first, other frameworks later. Same policies, same decision log, same header contract; only the enforcement form factor differs.

The header contract is arguably the product. On an allowed request, ForgeGuard injects signed headers carrying verified identity, organizational position, and scope — signed with an Organization-scoped key, plus a request-tracking header for correlation:

```
X-Fg-Principal:   fgrn:acme:principal:usr_8f3k2
X-Fg-Scope:       fgrn:acme:orgunit:ou_finance
X-Fg-Entitlements: new_dashboard,exports_v2
X-Fg-Request-Id:  req_01J9ZK...
X-Fg-Signature:   sig:...
```

The consequence is the cure for the four-drifting-systems disease: downstream services stop making access decisions and start trusting a signed context. They do not apply decorators that can be forgotten; they *delete their auth code*. Stated honestly, they delete their decision logic — data-layer filtering for list endpoints remains, but fed by the signed scope header rather than by hand-rolled logic, as the data-plane section specifies. The "view as" feature that once demanded a re-architecture becomes a change in what the scope header asserts for a session.

**Shadow mode is part of the product, not a migration afterthought.** The scariest moment in the customer journey of an enforcement point is turning it on, so every enforcement body supports a per-endpoint switch between `enforce` and `observe`. In observe mode all traffic flows and every request is evaluated and logged as a would-allow or would-deny with full reasons — the same decision record, marked hypothetical. The adoption story writes itself: install, observe for a period, review the would-deny report, flip to enforce endpoint by endpoint. The machinery is deliberately shared: hypothetical evaluation ("what would this decision be under scope X, or for principal chain Y") is the same primitive that powers "view as," policy testing, and pre-merge validation of structural changes — one investment, several product surfaces.

## Personas and the two policy planes

Two personas author policy, and they are not fighting over one config file — they own two different kinds of policy that change at different speeds.

Developers own *structural policy*: the shape of access. Which endpoints exist, what each requires, which authentication methods are acceptable where, which feature slots exist. This lives in declarative policy files, in a repository (the app's or a dedicated one), multi-file for large systems, reviewed in pull requests, versioned with the code whose shape it describes.

Operators — product managers, support, ops — own *operational policy*: the current state of access. Which tenant has which feature, what percentage of a branch is in the A/B test, which customer just got upgraded. This lives in a UI, changes daily, and deploys nothing.

The convergence mechanism: the structural files declare the slots, the UI fills the values. A developer declares in code that a feature named `new_dashboard` exists and gates three endpoints; an operator decides in the UI which tenants have it. The enforcement point evaluates both planes in a single decision. This is the same job LaunchDarkly was bought to do, recognized for what it always was — an entitlements decision, which is an authorization decision wearing a different hat — and pulled back into the one system where all such decisions belong.

```toml
# Structural plane: shape, owned by developers, lives in the repo.

[[endpoint]]
route   = "POST /invoices"
auth    = ["oidc", "m2m"]
require = { role = "billing_admin", scope_at_or_below = true }
feature = "invoicing_v2"          # declares the slot; the UI decides who fills it

[[feature]]
name    = "invoicing_v2"
default = "off"                   # operational plane grants it per tenant/branch
```

## The core model: one graph, a privileged spine

Every ForgeGuard customer gets an **Organization** (capital O — the unit ForgeGuard serves; ForgeGuard itself is multi-tenant over Organizations). The temptation is to model an Organization as a tree, and the first design's instinct went that way. The interview surfaced why a pure tree fails: hierarchy is a tree, but *sharing is a graph*. "Everything below node X" flows down one parent path; "Alice's document, visible to Bob and Carol" is a lateral edge that jumps across the hierarchy. Systems that start with pure trees meet document-sharing requirements and either deform the tree with synthetic nodes — polluting every organizational query, billing calculation, and UI listing with machine-generated fakes — or generalize the model. Google built Zanzibar because Drive sharing could not live in a hierarchy; Cedar models entity parents as a DAG for the same reason.

The ForgeGuard model, stated precisely: **the authorization model is a directed acyclic graph whose hierarchy edges form an enforced tree (the organizational spine); grant edges add lateral access without deforming the spine.**

One graph, two edge types. Hierarchy edges connect org units into a single-rooted tree — every org unit has exactly one parent, and this constraint is enforced — and anchor every principal and every resource somewhere in that spine. Principals come in three native kinds from day one — humans, services (machine-to-machine identities), and agents — and, critically, a principal may also be a **delegation chain**: an agent acting on behalf of a user (`agent:deploy-bot on-behalf-of principal:usr_x`) is itself a first-class principal whose effective scope is the *intersection* of the chain's members' rights, evaluated and logged with the full chain visible. This is not an agent feature bolted on for the market's current obsession; it is the general form of a primitive the model already required — "view as" is simply a self-delegation with a narrowed scope — and making it native means the header contract, the decision log, and the audit story all speak delegation without amendment later. Tenancy, billing, scope inheritance, "view as," and the header contract hang exclusively off the spine, which is what raw Zanzibar leaves everyone to rebuild by convention. Grant edges are lateral, many-to-many, dynamic, and carry a verb: a grant is not a link but a link with an action.

```
grant { resource: fgrn:acme:resource:doc_123,
        actions:  [read],
        to:       principal_set:proj_alpha_readers }
```

The decision engine answers one question — does a permitted path exist from this principal to this action on this resource? — and does not care which edge types the path traverses. The tooling cares a great deal: the spine is what gets visualized, billed, and asserted in signed headers; grants are what a resource's "shared with" panel lists. Applications without multi-tenancy fall out as the degenerate case for free: one root, users as leaves, grant edges doing the real work. Same model, same policy files, same headers.

### Anchoring and cardinality: what gets a node

Not everything gets a node in the DAG, and stating this explicitly is what keeps the graph small, the checks fast, and the synchronization burden minimal. Org units, principals, and principal-sets are always DAG citizens with FGRNs. Application resources, by default, are not: the bulk of them — invoices, rows, messages, documents — live in the application's own database, carrying a single column referencing the FGRN of the node they anchor to. The enforcement decision uses the anchor, which the header contract already delivers. A resource is *promoted* into the DAG only when it becomes exceptional — the moment someone shares it, an individual grant edge is needed, and that act is what mints its FGRN. Sharing is the minting event. This doctrine (independently arrived at by others in the field, who warn against syncing high-cardinality objects into an external authorization store) means ForgeGuard's graph scales with organizational structure and sharing activity, not with the customer's data volume — and it makes the organization's depth plus the resource's type sufficient to answer most access questions without ForgeGuard ever knowing the resource exists.

### Users in the hierarchy, and the boundary rule

Principals are not merely leaves hanging off the spine — they are anchor points in it. A resource created by a user anchors to that user, giving the owner full control over their own creations as ordinary subtree visibility where the subtree root happens to be a person. This collapses what would otherwise be two visibility modes into one mechanism, and it means ownership transfer is re-parenting, a user changing departments carries their resources' effective position in one move, and offboarding is "re-parent the resources, remove the node" — all inherited from the spine's existing machinery.

This elegance exposes one decision that must be explicit: **user nodes are opaque boundaries by default.** Subtree traversal stops at a user node unless the requester is that user, an explicit grant crosses the boundary (every share is a special case), or the resource type declares itself transparent. Without this rule, a user's private drafts would be ambiently visible to everyone scoped at their org unit or above — a data leak built into the defaults. Both behaviors are legitimate and the choice belongs to the resource type: personal documents want opacity; a salesperson's deals should probably be visible through the boundary to the manager's subtree. One declaration per type carries the decision:

```toml
[[resource_type]]
name          = "document"
anchor        = "principal"      # owned things anchor to their creator
user_boundary = "opaque"         # traversal stops at the owner

[[resource_type]]
name          = "deal"
anchor        = "principal"
user_boundary = "transparent"    # the manager's subtree sees through
```

Administrative oversight — takeover of a departed employee's documents, legal hold — does not weaken the default: it is an explicit, logged, elevated act that pierces the boundary, never ambient visibility. Every crossing of a user boundary is therefore either a share by the owner or a recorded administrative action, which keeps the audit story clean. Team-owned resources that belong to no single user and no single branch anchor to a principal-set node, which is just another node in the DAG; the model requires nothing new for them, but the case is named here because it is the one every reviewer probes first.

## The data plane: lists, RLS, and the position table

An enforcement point at the edge decides *whether* a request may reach an endpoint; it cannot, by itself, decide *which rows* a list endpoint returns. This is the known structural weakness of every check-based authorization product — filtering a collection naively means one check per row — and the brief addresses it head-on rather than leaving it for adopters to discover.

The answer reframes a piece of the original war story. The row-level security layer the founding startup built is not part of the fragmentation disease; correctly wired, it is ForgeGuard's data-plane partner. The signed scope header is the bridge: the downstream service sets it as a database session variable, and generic, ForgeGuard-shipped RLS policies consume it. The residual filter for a subtree-visible resource type is then a single predicate plus a small union:

```sql
-- shape, not contract (illustrative pseudo-SQL): the ForgeGuard-shipped data-layer filter for a "subtree" type
WHERE anchor_position <@ current_setting('fg.scope_path')
   OR id = ANY(current_setting('fg.granted_ids'))
```

Subtree containment plus the explicit exception set — which the cardinality doctrine guarantees stays small. For an opaque, principal-anchored type the predicate simplifies further: anchor equals the requester, or the id is in the granted set. The proxy and RLS stop being two drifting systems and become one system enforcing the same spine at two altitudes.

One subtlety is load-bearing: **rows store identity, positions are resolved at read time.** The resource row stores its anchor's FGRN — never its path — because storing position in millions of rows means re-parenting an org unit rewrites all of them, the exact disease FGRNs exist to cure. Position lives in a small synced dimension table, `org_units(fgrn, path)`, including user nodes — low-cardinality by definition, maintained in the application's database from ForgeGuard's spine through the synchronization contract below. The requester's *resolved* scope path travels in the header per request, which is consistent with the naming doctrine: identity never encodes position; requests always carry it.

### The synchronization contract

Everything that must flow between ForgeGuard and the application is carried by one designed mechanism, not a collection of ad-hoc syncs — because a product whose thesis is that access control should live in one designed place cannot ship integration as an exercise for the reader. The primitive is a durable, per-Organization **event log**: every control-plane change — spine mutations, principal lifecycle, resource promotions and grant changes, snapshot activations — appends an event carrying a stable event id and a gap-free, monotonically increasing sequence number. Webhooks are push delivery over that log, with three guarantees: **at-least-once delivery**, **idempotent application** (consumers key on the event id and apply upserts, so redelivery is harmless and the effect is exactly-once), and **replayability** (the log is the source of truth; a consumer can reset its cursor to any sequence point and replay forward — rebuilding a dimension table from zero, recovering from an outage, and bootstrapping a new service are the same operation). The gap-free sequence lets consumers detect missed events without trusting the delivery channel, and payloads are signed with the Organization's key — the same trust model as the header contract. Consumers that prefer pull can poll the cursor endpoint; push and pull read the same log.

Two flows ride this contract as first-class citizens rather than integration afterthoughts. **Principal provisioning**: inbound, an idempotent upsert API keyed by the application's native user identifier, retry-safe by construction, so signup flows tolerate partial failure without invented coordination; outbound, principal lifecycle events on the stream so the application learns of principals created through the UI, SCIM, or another service. **Promotion lifecycle**: an idempotent tombstone API the application calls when a promoted resource is deleted — safe to fire-and-forget precisely because redelivery and repetition are harmless — backed by a reconciliation endpoint listing promoted FGRNs per resource type, against which an SDK-shipped reconciler periodically diffs the application's tables and sweeps whatever best-effort tombstoning missed. Dangling grants are garbage rather than a hole in a permit-only graph, but garbage is still collected by design, not by hope.

Delivery of the exception set starts in the header with a documented size cutoff and graduates to a middleware-cached lookup when a power user's shared-resource set outgrows it — and a resource type whose exception sets are *routinely* large is a signal of misclassification: it wants transparent-subtree visibility or a principal-set grant, not thousands of per-user edges. A query-plan API — "return the residual filter for this principal, action, and resource type" — is the roadmap's eventual generalization of all of the above; it is deliberately not in the MVP.

## Denies: the circuit breaker

The graph is **permit-only and therefore monotonic**: adding an edge never removes access someone else had, evaluation stays cacheable, and every allow in the decision log points at the exact edge that produced it. Denies exist, but not as edges — they are policy rules, evaluated first, in a plane of their own. The mental model: grants are the law, denies are the circuit breaker. A building's lighting is not wired through the breaker panel, but the panel matters enormously when something catches fire.

Denies can be authored from both planes, because their strongest use case is incident response — "this contractor was just terminated, cut everything now" cannot wait for a pull request. The friction is therefore not in *where* denies are created but in *what creating one costs*: every deny, from either surface, requires a stated reason and an expiry (a deny without a death date fails validation — permanent exclusion is correctly modeled by removing grants, not by an eternal override); wielding denies requires an elevated operator permission; and UI-created denies carry a short maximum TTL — on the order of days — long enough to survive the incident, short enough that making the exception permanent forces the pull-request conversation. Evaluation order is fixed: deny rules, then grant paths, then default deny. Since denies are checked first and there are normally zero of them, the happy path pays almost nothing; the cost of the feature scales with its use, which is exactly the desired pressure. Every request blocked by a deny logs the deny's identity, so a misfiring circuit breaker is diagnosable in one log line.

```toml
[[deny]]
id        = "suspend-contractor-bob"
principal = "principal:usr_bob"
resource  = "org:acme.engineering/**"
actions   = ["*"]
reason    = "Offboarding pending legal review, SEC-4412"
expires   = 2026-08-01T00:00:00Z    # mandatory; denies must die
```

## Materialization: snapshots, live grants, provenance

Multiple authoring surfaces feeding one engine only works if merging is principled. The key insight is a frequency mismatch that forbids naive "compile everything into one artifact":

Policy — structural files, feature entitlements, denies — changes rarely: hours to weeks. On every change, all policy sources compile into a **versioned, immutable Policy Snapshot**. Enforcement points evaluate against a specific snapshot version. This buys atomic rollout, instant rollback (repoint to the previous snapshot), and the crown jewel of the audit story: every decision record names the snapshot version that decided it, so any historical decision can be replayed exactly.

Grants — sharing edges — change constantly: every "share this with Carol" is a write. Compiling them into snapshots would recompile a busy Organization hundreds of times a minute and reduce version numbers to noise. Grants are therefore **live data evaluated against the current snapshot**, not compiled into it. This is Zanzibar's proven split: relationship tuples are data; namespace policy is versioned configuration. Unified evaluation, two-tier storage. Every decision records both the snapshot version and the grant state that produced it.

Two invariants are non-negotiable. First, **provenance survives the merge**: every rule in the materialized view carries its origin — file and commit, or UI action with actor and timestamp. The UI renders the merged whole, and provenance determines editability: repo-born rules appear read-only with an "edit in repo" pointer; UI-born rules are click-editable subject to operator permissions. Second, **nobody edits the snapshot**: sources are truth, the snapshot is derived. Violating either invariant reintroduces, inside ForgeGuard itself, the exact drifting-copies disease the product exists to cure.

## Consistency: the New Enemy Problem, named and bounded

Any place where an enforcement decision uses remembered state instead of current state is a window in which revoked access still works — the failure mode the Zanzibar paper named the New Enemy Problem. ForgeGuard's monotonic graph yields a governing asymmetry: every mutation is either **widening** (adding a grant, enabling a feature, adding a set member) or **narrowing** (removing a grant or membership, creating a deny, re-parenting to restrict). Stale widening is a UX complaint — new access takes seconds to appear. Stale narrowing is a security hole. The entire consistency design therefore reduces to enumerating the narrowing paths and bounding their staleness. There are four.

**Denies ride a hot channel.** Denies are the designated revocation tool, and they must not inherit the snapshot pipeline's latency: they are pushed to enforcement points near-real-time and checked ahead of any cached evaluation. Because the deny set is tiny by design, keeping it strongly consistent is nearly free, and it yields a statable guarantee: while an enforcement point is connected, revocation latency is bounded on the order of a second, globally.

**Grant removals ride the event stream — which doubles as the invalidation bus.** Enforcement points cache grant lookups; the synchronization contract's gap-free sequence tells every enforcement point when state has advanced and what to drop. The sequence number is thereby a consistency token in the Zanzibar sense, and it is **public API from day one**: every mutation response returns the resulting revision; any request may carry a minimum-revision demand and be answered with state at least that fresh; applications may store a revision alongside a resource so later checks are causally tied to the content they protect. The default staleness bound for callers who demand nothing is documented and measured, not discovered.

**Every decision evaluates against a single revision — never a mix.** The subtle variant of the problem is old permissions applied to new state: a principal removed from a set at revision 400, a resource shared to that set at 405, and an evaluation that reads the edge at 405 but the membership from a stale 399 cache leaks a resource shared *after* the removal, though each read is individually only seconds stale. The rule is absolute: one decision, one grant-store revision, mirroring the snapshot rule already in force for the policy plane. The decision log records both — snapshot version and grant revision — which is also the forensic half of the same coin: "why did this principal see that resource at 14:32" is answerable by reconstructing the exact state that decided.

**Session-cached exception sets are an invalidation surface.** Per-request headers are safe — their staleness window is one request — but the data plane permits caching a principal's granted-ids set per session, and that cache is a narrowing window of ForgeGuard's own making. Narrowing events on the stream invalidate it, backed by a short TTL.

Two doctrines complete the model. First, freshness is declared where it is needed: endpoints in the structural plane may declare their consistency requirement (`consistency = "strict" | "bounded"`), applying the field's hard-won lesson that strong consistency is necessary only in select circumstances and should be paid for only there. Second, structural reorganization is not revocation: a restrictive re-parenting propagating through the dimension table in seconds is acceptable *because* urgent removal is the deny mechanism's job — one tool for urgency, with an SLO; everything else tolerates seconds.

**Degraded operation is an integration decision with a chosen default.** When an enforcement point cannot refresh — control plane unreachable, stream stalled — the behavior is configurable per Organization and per endpoint, with ForgeGuard exposing the capabilities (serve last-known state, fail closed after a staleness ceiling, or per-endpoint mixtures) and the integrator owning the policy. The shipped default is **serve last-known state indefinitely**: an enforcement point that takes down the customer's API fails the product's availability contract worse than bounded staleness fails its security contract. That default carries two non-negotiable obligations, stated here so the trade-off is honest rather than silent. Degraded state must be loud — surfaced in health metrics, flagged in the signed headers so downstream services can apply their own caution, and stamped into every decision record as the age of the revision that decided. And the deny-latency guarantee holds only while connected; a disconnected enforcement point serves the last deny set it saw, which makes monitoring enforcement-point freshness an explicit part of the integration contract, not an operational nicety.



## Naming: FGRNs and selectors

The first ForgeGuard designed FGRNs — ARN-style resource names — and they did not survive implementation. The autopsy: they were decoration on a model that did not need them, a naming scheme in search of a referent. The current model reverses this completely: grants, denies, provenance records, signed headers, and decision logs all *consume* canonical names. FGRNs are no longer a feature; they are the type system, and they belong on page one of the spec.

They return with one hard-won correction, a trap ARNs themselves fall into: **identity must not encode position.** An FGRN embedding a tree path would mean that re-parenting an org unit renames every descendant, dangling every grant and orphaning every historical log line — in a model whose spine is explicitly designed to be reconfigurable. So the naming layer splits in two:

FGRNs are stable identity: `fgrn:{organization}:{type}:{id}` — immutable for the node's lifetime, surviving any re-parenting. They are what lives in grant edges, decision records, and signed headers. One derivation rule is a requirement, not a convention: **a promoted resource's FGRN incorporates the application's native identifier** (shape: `fgrn:acme:resource:document/doc_123`), so that promotion — the share that mints the FGRN — is a single ForgeGuard-side write requiring no app-side column, mapping, or migration. This rule is what keeps the dual-write problem, the costliest adoption burden in this category, designed out of the ordinary and exceptional paths alike. Selectors are position queries: `org:acme.finance/**` is not a name but a pattern, resolved through hierarchy edges at evaluation time. They are what humans write in structural policy files and what UI pickers generate. The compiler resolves selectors against a snapshot; the decision log records both the selector that matched and the concrete FGRNs it resolved to, keeping resolution reproducible against the snapshot version. Stable names for the machine, path patterns for the humans — the split the original flat design could not support, which is why implementation kept rejecting the organ.

## Business model and pricing

Two adoption conditions came out of the interview as hard requirements, and both constrain architecture, not just price sheets.

Manageable cost, calibrated against the two real customers: the funded startup would have approved anything under roughly $1,000/month without a procurement fight — conveniently under the typical approval threshold — and would have tolerated substantially more as the app succeeded. The personal project needed effectively $0 self-hosted, or a hosted tier around $20–30 with a *hard ceiling* — a capped price, not a meter that can surprise at 3 a.m. That low tier is distribution, not revenue: it is how the next startup's engineer already knows the tool.

No captivity: the exit hatch must be structural, not contractual. The enforcement core is open source and self-hostable; structural policy is plain files in the customer's own repository. Leaving means "stop paying, keep running." The hosted product sells convenience — the operational UI, the managed decision log and snapshot store, the entitlements plane — never hostage-taking. This is the Grafana/GitLab open-core shape, and it doubles as the funnel: the free self-hosted middleware serves the indie persona and seeds the paid control plane for the funded one.

The meter for the paid tier is **tenants (root-level customer organizations), not MAUs and not decisions**. Tenant count scales with the customer's revenue rather than their users' behavior — fifty tenants means fifty paying customers, so the bill feels proportionate — and it is the very unit the product's model is organized around. Per-MAU pricing punishes customer success; per-decision pricing makes teams afraid to put the product in the hot path, the precise opposite of what an enforcement point needs.

## Architecture fitness criteria

The brief is technology-neutral, and pricing depends on the architecture ultimately chosen — which creates an obligation: the demand-side facts (the price ladder, the latency-sensitive hot path, the sovereignty promise) must be converted into measurable criteria that any candidate architecture is tested against. This section is that conversion. Every engineering design claiming conformance must demonstrate these properties with measurements, not assertions; the numeric targets are initial values, marked provisional, to be hardened by the first design's benchmarks — but the *criteria* and the *triggers* are part of the specification.

**Unit economics.** The infrastructure cost of serving one Organization at the entry hosted tier must leave a healthy software margin — provisionally, cost-to-serve at or below one third of the tier price — and the capped indie tier must be servable within its cap under its documented quota, since a capped price with uncapped cost is a time bomb. The self-hosted free tier's operational cost to its *user* must remain near zero: the middleware body must require no mandatory external services beyond what the application already runs.

**Hot-path latency.** Enforcement overhead is bounded and published: provisionally, in-process middleware decisions at single-digit milliseconds p99, and the proxy body's added hop in the low tens of milliseconds p99, both measured against a reference Organization (provisionally: thousands of principals, hundreds of org units, tens of thousands of grant edges) under the single-revision evaluation rule.

**Consistency obligations.** Revocation-by-deny latency at or under one second while connected. Grant-removal propagation within the documented default staleness bound. Degraded operation implemented exactly as the consistency section specifies, including loud staleness signaling. The event log gap-free, replayable from an arbitrary cursor, with idempotent redelivery demonstrated.

**Scale floor and ceiling triggers.** Each design states the Organization size at which its measurements were taken and the size at which they are projected to degrade — because "until when" is part of the answer. A criterion without a stated breaking point is not considered met.

**Re-evaluation triggers.** A measured breach of any criterion in production forces one of exactly two documented actions: amend the design, or amend this brief's targets explicitly. Silent drift — serving the entry tier at a loss, letting p99 creep, weakening the staleness bound in configuration defaults — is the failure mode this section exists to prevent, and it is the same discipline the brief demands of policy applied to the product itself.

## What survived, what died

From the first ForgeGuard, the following survive with their justification now demand-derived rather than aesthetic: the edge-proxy body as one of the two enforcement form factors, policy-as-code files as the structural surface, and FGRNs — reborn with the identity/position split. The first iteration's specific technology choices (implementation language, proxy framework, candidate policy engine) are deliberately *not* carried forward by this document: they may well survive on their own merits, but they must re-earn their place in engineering design documents measured against this brief, not inherit it. The homelab cluster remains the dev/staging ground.

Deliberately dead: the Smithy parser (never matched the product), the SDK-first strategy (the header contract makes deep SDKs unnecessary; thin verification helpers suffice), and the three-equal-A's framing (authentication is federated commodity plumbing; audit is free exhaust; multi-tenant authorization plus entitlements is the wedge and gets the investment).

## MVP and validation path

Build for the customer that verifiably exists: the author. The smallest honest MVP is the native middleware body for the founding application — file-based structural policy, the spine-plus-grants engine in its simplest form, the signed header contract, the per-endpoint enforce/observe switch, a decision log to stdout or object storage, and the synchronization contract's primitive: the per-Organization event log with a cursor endpoint (push webhooks follow shortly after; the log is what makes them trustworthy). No proxy, no UI, no hosted anything. Run it in the personal app on the homelab cluster and live with it. The validation question is blunt: after a month, does hand-rolling auth ever again feel acceptable? That answers with n=1 what fourteen architecture documents could not. The proxy body, the operational UI, and the snapshot service come only after the model survives contact with real requests.

## Open questions and honest risks

This brief records what a discovery interview with one customer established. It should not pretend to more certainty than that. The riskiest assumption is that the n=1 pain generalizes — the "did I miss something?" question is answered for Auth0, Clerk, and Keycloak, but *not yet* for Permit.io, Oso Cloud, Cerbos, and the managed Zanzibar offerings; a rigorous teardown of those, against this brief's model (tenancy spine, entitlements convergence, structural exit hatch), is the first piece of work after the MVP starts. Second risk: performance of live-grant graph evaluation in the hot path at the edge — the snapshot/grant split is designed for cacheability, but the design must prove it under the proxy body's latency budget. Related but now partially de-risked: list-endpoint filtering has a designed answer (the data-plane section), yet its adversarial test remains open — the model must be checked against the real resource inventory of both founding applications for any type whose correct visibility is neither subtree-with-opaque-users nor subtree-seeing-through nor principal-set-anchored; finding one would demand a model amendment before implementation, not after. Third: the choice of evaluation engine — adopted off the shelf or purpose-built — is deliberately outside this document's scope; the model in this brief is the contract, and competing engineering designs may answer the engine question differently while all conforming to it. Fourth: the operational UI's scope has a known tendency to sprawl — it is bounded here to entitlements, grants visibility, denies-behind-glass, and provenance-aware policy browsing, and additions beyond that bound require amending this document.

---

*This brief was produced from a customer-discovery interview conducted in July 2026. The customer was the founder. That is both its strength — the pain is first-hand and concrete — and its known limitation.*

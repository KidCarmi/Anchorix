# H-026 — Trust Governance: Ownership, Grouping, Tagging, Policy Scoping

> **Status:** design / planning only. **No code in this PR.** This
> document is the source of truth for the H-026 implementation PRs
> that follow.
>
> **Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
> this plan and CLAUDE.md disagree, CLAUDE.md wins and this plan is
> revised. The plan deliberately does NOT propose any CLAUDE.md
> amendment; every rule it touches is satisfied inside existing
> constitutional rules (`§4`, `§8.4`, `§9`, `§10`, `§16`, `§17`,
> `§18`, `§19`).

---

## 0. Scope and explicit non-goals

H-026 introduces a **governance substrate** above the existing
certificate operations pipeline. The goal is the design and the
storage foundations that let operators answer five questions at
enterprise scale (50k certs, 10k agents, hundreds of services):

1. Who owns this certificate?
2. Why does Anchorix think that?
3. Which rule matched, and which lower-priority rules lost?
4. Which policy applies, and where did it come from?
5. Why is this certificate non-compliant?

H-026 is the v0.x evolution of Anchorix's mission from a
"Certificate Operations" platform (current v0.1) into a
"**Certificate Operations + Trust Governance Platform**." The
existing operations pipeline (heartbeat, machine inventory,
certificate inventory, findings, recompute, override workflow,
streaming recompute) is preserved unchanged.

### In scope (this plan)

- Product mental model and persona map.
- Data model for tags, services, service groups, agent groups,
  ownership rules, ownership assignments, ownership overrides,
  ownership explanations, policy definitions, policy assignments,
  and policy waivers.
- Deterministic ownership inference engine with explicit
  precedence and explainability.
- Policy scoping with inheritance, precedence, exceptions, and
  explainability.
- REST API surface (read + write + preview).
- Operational workflows for first-deployment and steady-state.
- Safety / correctness model (advisory locks, REPEATABLE READ,
  audit, cross-org isolation, preview-before-apply, rollback).
- Phased roadmap (H-026A → H-026D).
- Risk register and open questions.

### Out of scope (binding, not deferred)

- **Code.** This PR is design-only. The first implementation
  PR is H-026A and is sized < 1000 LOC.
- **CLAUDE.md amendments.** None required.
- **New findings rules.** The v0.1 rule registry
  ([`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §4) stays
  frozen. Owner / policy enrichment is additive on existing
  finding rows; new rules land in a later H-026D PR.
- **Frontend / UI.** No React components, no dashboards. The API
  is the v0.x surface.
- **ADCS / Vault / EJBCA / Smallstep integration.** The provider
  abstraction (`internal/providers/pki`) stays as is.
- **Automation.** No renewal, no revocation, no deployment
  execution. CLAUDE.md §3 (visibility before automation) is
  binding.
- **Notification channels.** No email, no webhook, no Slack.
- **New `go.mod` dependencies.** Everything fits in stdlib +
  the existing pgx / chi / bcrypt set.
- **Multi-tenancy.** Single-org per process per CLAUDE.md §4.
  The schema continues to carry `organization_id` on every row;
  the API stays organization-scoped from the session.
- **CMDB / AD integration.** Future-compatible signals are
  considered in §3; no implementation in H-026.
- **Real-time event push.** Polling / synchronous REST only.
- **AI-assisted classification.** Out of scope for v0.x
  (CLAUDE.md §4).

---

## 1. Product mental model

### 1.1 What Anchorix is becoming

Anchorix v0.1 is a certificate **operations** platform — discover,
inventory, classify risk, surface findings. The visibility-before-
automation philosophy (CLAUDE.md §3) is the founding constraint.

Trust governance is the next layer up. Operations answers *what*
is on the fleet; governance answers *who is responsible*, *what is
allowed*, and *what is violated*. The two layers coexist and
reinforce each other:

```
                  ┌──────────────────────────────────────┐
                  │   Trust Governance (H-026, new)      │
                  │   • ownership inference              │
                  │   • policy scopes + waivers          │
                  │   • governance findings              │
                  └──────────────────────────────────────┘
                                     ▲
                                     │ enrich
                                     │
┌──────────────────────────────────────────────────────────────────┐
│   Certificate Operations (v0.1, unchanged)                       │
│   • agent enrollment + heartbeat                                 │
│   • certificate inventory + observations                         │
│   • findings recompute + override workflow                       │
│   • audit + structured logs                                      │
└──────────────────────────────────────────────────────────────────┘
                                     ▲
                                     │ ingest
                                     │
                  ┌──────────────────────────────────────┐
                  │   Discovery (Windows agent today)    │
                  └──────────────────────────────────────┘
```

The lower layer never depends on the upper layer. Governance is
a consumer of operations data and a producer of derived state;
operations never asks "who owns this?" to decide how to ingest.
This preserves CLAUDE.md §5 (modular monolith, clean module
boundaries) and §10 (provider abstraction independent of governance).

### 1.2 The three concepts that must not be collapsed

A certificate at fleet scale has three orthogonal properties.
Conflating them is the single biggest design risk in this work.

| Concept            | Question it answers                          | Owned by                       | Mutable?                  |
| ------------------ | -------------------------------------------- | ------------------------------ | ------------------------- |
| **Identity**       | *What is this certificate?*                  | `certificates` (v0.1, unchanged) | No (fingerprint-keyed)  |
| **Classification** | *How is it grouped, labeled, tagged?*        | tags, group memberships        | Yes (operator action)     |
| **Ownership**      | *Who is responsible for it?*                 | services, ownership engine     | Yes (rule-driven + override) |

A cert's **identity** is its DER fingerprint and the parsed
metadata the v0.1 ingestion endpoint computes. Identity is
intrinsic and append-only.

A cert's **classification** is the set of tags and groups
attached to it (or to its observing agents). Classification is
operator-curated metadata; it has no truth value.

A cert's **ownership** is the answer to "if this expires
tomorrow, who picks up the page?" Ownership is **derived**: the
inference engine reads identity + classification + signals and
returns a deterministic answer with an explanation.

### 1.3 Why each concept exists

- **Ownership exists** because a 50k-cert inventory makes per-cert
  paging impossible. Findings must route to the right team
  automatically, or findings are noise.
- **Grouping exists** because a 10k-agent fleet shares structure
  (domain controllers, web tier, build hosts). Operators classify
  in bulk, not per machine.
- **Tagging exists** because rigid structures cannot anticipate
  every business dimension (cost center, compliance scope, audit
  tag). Tags are the extension point.
- **Policy scoping exists** because rules apply to *layers* (org
  baseline, service group, service, single cert), and writing N
  per-cert policies for 50k certs is not operationally viable.

### 1.4 Operator personas

Four personas are accommodated explicitly. None is a new role in
the v0.1 RBAC model — the existing `operator` / `admin` split
(see [`AUTH_FOUNDATION.md`](./AUTH_FOUNDATION.md)) covers all four
without a code change. Refining roles is a v0.2 concern
([`EVOLUTION.md`](../architecture/EVOLUTION.md)).

| Persona                  | What they need from H-026                                                                                       |
| ------------------------ | --------------------------------------------------------------------------------------------------------------- |
| **Security operator**    | "Show me unowned certs, ambiguous certs, stale ownership." Triage workflows for findings with owner attribution. |
| **Platform engineer**    | Bulk classification: define agent groups for SCCM-managed fleets, claim hostname patterns for services.          |
| **Service owner** (future-facing) | Visibility into the certs assigned to *their* service; receive findings routed to them.                  |
| **Governance reviewer**  | Audit who set which rule, when; review and grant policy exceptions; produce an explanation for any cert.         |

### 1.5 How operations and governance coexist

Three rules govern the boundary:

1. **Operations is authoritative for state of the world.**
   Ingestion is the only writer of `certificates` and
   `certificate_observations`. Governance reads them.
2. **Governance enriches, never gates.** A cert without an
   identifiable owner is still inventoried, still observed, still
   eligible for the v0.1 finding rules. Lack of ownership is a
   *finding*, not a *reject*.
3. **No silent ownership flips.** Every state transition in
   ownership produces an audit row with severity:"security",
   matching the precedent in
   [`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §8.

---

## 2. Backend architecture

### 2.1 Module placement

Two new domain packages, two new storage packages, no changes to
existing module boundaries. Layering matches
[`PACKAGE_BOUNDARIES.md`](../architecture/PACKAGE_BOUNDARIES.md).

```
backend/internal/
  identity/              NEW — services, service groups, tags (the "who/what" model)
    doc.go
    types.go
    repository.go        (interface, consumer-owned)
    service.go           (CRUD on services/groups/tags + tag assignments)
  governance/            NEW — ownership inference + policy resolution
    doc.go
    ownership/
      engine.go          (deterministic rule evaluator)
      precedence.go      (precedence enum + tiebreaker)
      explanation.go     (winning rule + losing rules)
      rules.go           (rule type + match predicates)
      service.go         (preview, apply, recompute orchestration)
    policy/
      definition.go      (Policy + PolicyRule types)
      resolver.go        (scope chain + merge)
      waiver.go          (exception lifecycle)
    repository.go        (interface, consumer-owned)
  storage/postgres/
    identity_repository.go            NEW
    governance_repository.go          NEW
    governance_ownership_repository.go NEW
    governance_policy_repository.go    NEW
```

`internal/identity` owns the **what/who** vocabulary (services,
service groups, tags). `internal/governance` owns the **derivation**
of ownership and policy effect. The two are separate packages
because identity is operator-curated state with simple CRUD
semantics; governance is recompute-driven derived state with the
same operational shape as `internal/findings` (advisory lock,
streaming pass, REPEATABLE READ, idempotent recompute).

### 2.2 Forbidden imports (per-package narrowing of CLAUDE.md §8.6)

- `internal/identity → internal/governance` — forbidden. Identity
  is a producer; governance is a consumer. The reverse direction
  is the only allowed one.
- `internal/governance → internal/inventory` — forbidden directly.
  Governance reads `certificates` through a consumer-owned
  `inventory.CertificateLister`-style interface placed in
  `internal/governance/ownership/`. The existing inventory
  package is not touched.
- `internal/governance → internal/findings` — forbidden directly.
  Findings enrichment (H-026D) lands as an *adapter* in
  `internal/findings` that calls a `governance.OwnerLookup`
  interface. The governance package never imports findings.
- `internal/httpapi/handlers → internal/storage/postgres` —
  forbidden (CLAUDE.md §8.6). Handlers consume the new domain
  interfaces only.
- `internal/identity → internal/governance` — see above.
- `internal/inventory → internal/identity / internal/governance` —
  forbidden. The inventory pipeline must keep ingesting at fleet
  scale without depending on governance state.

### 2.3 Composition root wiring

Wiring lives in `backend/cmd/anchorix/serve.go`. The order is:

```
config → logger → db → clock → ids
  ↓
audit.Recorder
  ↓
identity.Service               (uses identity.Repository)
  ↓
governance.OwnershipService    (uses governance.Repo + identity.Reader + inventory.CertificateLister)
governance.PolicyService       (uses governance.PolicyRepo + identity.Reader)
  ↓
httpapi.Server                 (hands handlers to the above)
governance.OwnershipScheduler  (background recompute, sibling of findings.Scheduler)
```

No service-locator, no DI container, no autowiring — same
constructor-based DI as the rest of the codebase (CLAUDE.md §8.8).

### 2.4 Why a separate scheduler

`findings.Scheduler` already exists
([`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §7).
Ownership runs in its own scheduler instance because:

- The two recomputes have **different inputs** (findings reads
  `certificates`; ownership reads `certificates` + ownership
  rules + tags + group memberships). Coupling them inflates the
  blast radius of a single tick.
- Different cadences are likely. Findings every 6h is documented;
  ownership likely tracks ingestion more closely (rules change
  rarely, but new certs need an owner promptly).
- Different advisory-lock namespaces keep the locks single-purpose
  and reasonably scoped (CLAUDE.md §18 — bounded retries,
  documented owner). `WithTxLockedOwnership(orgID)` joins
  `WithTxLockedFindings` and `WithTxLockedAgent` in
  `internal/storage/postgres/postgres.go`.

The schedulers DO NOT contend for the same lock. They contend for
the database connection pool, which the existing pgx pool already
manages.

### 2.5 Determinism and idempotency

Every derivation path (ownership recompute, policy resolution
recompute) follows the H-024B pattern:

- Session-scope advisory lock acquired BEFORE the REPEATABLE READ
  transaction opens.
- Paginated input reads with cursor by `(id ASC)`.
- Pure decision functions (`decideOwnership`, `decidePolicy`) live
  next to the engine and consume `(prior, signals, now)`.
- Audit row written inside the same transaction as state changes.
- Idempotent: replaying against unchanged inputs produces zero
  state transitions (`unchanged` counter only).

---

## 3. Data model

### 3.1 Entities at a glance

| Entity                            | Layer       | Purpose                                                                              |
| --------------------------------- | ----------- | ------------------------------------------------------------------------------------ |
| `tags`                            | identity    | Free-form key/value classification metadata. Operator-curated.                       |
| `tag_assignments`                 | identity    | Attach a tag to a target (cert / agent / service / service_group).                   |
| `services`                        | identity    | Named ownership unit. The thing that "owns" a certificate at the business level.     |
| `service_groups`                  | identity    | Hierarchical containers for services (e.g., Payments > Billing > Checkout).          |
| `service_group_memberships`       | identity    | Service → service_group; one service can sit in one direct group in H-026A.          |
| `agent_groups`                    | identity    | Operational grouping of agents (e.g., "Domain Controllers", "PCI Web Tier").         |
| `agent_group_memberships`         | identity    | Static `(agent_id, agent_group_id)` rows. One agent → many groups.                   |
| `ownership_rules`                 | governance  | A pattern (hostname / SAN / agent group / store_location / issuer / tag) → service.  |
| `certificate_ownership`           | governance  | Derived current ownership state, one row per `(org, certificate_id)`.                |
| `certificate_ownership_overrides` | governance  | Operator pin overriding the engine's choice. Always wins.                            |
| `ownership_match_explanations`    | governance  | Snapshot of winning rule + top-K losing rules at recompute time. JSONB.              |
| `policy_definitions`              | governance  | A named bundle of policy rules (e.g., "PCI Baseline 2026").                          |
| `policy_assignments`              | governance  | Bind a policy to a scope (organization / service_group / service / certificate).     |
| `policy_waivers`                  | governance  | Time-bounded exception for a specific (policy_rule, scope) tuple.                    |
| `governance_recompute_runs`       | governance  | Per-org per-pass counters and timing. Audit-style, append-only.                      |

The same H-009 cross-organization safety pattern (composite FK
`(organization_id, …)`) is applied uniformly.

### 3.2 Conventions

- **Naming.** CLAUDE.md §8.4 — domain-explicit names only.
  Forbidden: `data`, `payload`, `meta`, `info`, `manager`, `helper`.
  Allowed: `serviceClaim`, `ownershipDecision`, `policyScopeChain`,
  `taggedTarget`, `ownershipPrecedenceTier`.
- **IDs.** TEXT, server-minted, same `crypto/rand` hex pattern as
  the rest of the codebase (`internal/ids`).
- **Timestamps.** `TIMESTAMPTZ`, set via `clock.Clock` from
  `internal/clock` (CLAUDE.md §8.2 — no direct `time.Now()` in
  business logic).
- **Mutable vs immutable.**
  - Tag definitions, services, service groups, agent groups,
    ownership rules, policy definitions, policy assignments,
    policy waivers — **mutable** (operator-curated CRUD).
  - Tag assignments, group memberships, ownership overrides —
    **mutable** (operator action).
  - Derived state (certificate_ownership,
    ownership_match_explanations, governance_recompute_runs) —
    **append + bounded update**. Recomputes overwrite the current
    explanation; runs are append-only audit.
- **Soft deletes.** Operator-curated rows (services, ownership
  rules) carry `disabled_at TIMESTAMPTZ` instead of physical
  delete. Rationale: explanation rows reference them by id; a
  physical delete would invalidate explanation history. CLAUDE.md
  §16 (no destructive migrations) makes the soft-delete shape the
  natural fit.
- **Migrations.** All schema for H-026 lands in a single
  append-only migration `backend/migrations/0009_trust_governance.sql`
  (H-026A scope). Subsequent phases add 0010, 0011, … each
  documented inline per CLAUDE.md §16.

### 3.3 Tags

```sql
CREATE TABLE tags (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    key             TEXT        NOT NULL,
    value           TEXT        NOT NULL DEFAULT '',
    description     TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at     TIMESTAMPTZ,
    UNIQUE (organization_id, key, value)
);
```

- A "tag" is a `(key, value)` pair scoped to an organization.
  Both `key` and `value` are operator-defined; `value` may be
  empty (the tag acts as a boolean flag).
- Tags are first-class entities so they can be renamed, described,
  and disabled without cascading deletes through assignment rows.
- **Scale.** A pilot org with 200 services × 5 tags each + ~30
  global tags ≈ low thousands. Negligible footprint.

```sql
CREATE TABLE tag_assignments (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    tag_id          TEXT        NOT NULL,
    target_type     TEXT        NOT NULL,           -- 'certificate' | 'agent' | 'service' | 'service_group' | 'agent_group'
    target_id       TEXT        NOT NULL,
    assigned_by     TEXT        NOT NULL,           -- user id; 'system' reserved
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, tag_id, target_type, target_id),
    FOREIGN KEY (organization_id, tag_id) REFERENCES tags(organization_id, id) ON DELETE CASCADE
);
```

- Polymorphic target by `(target_type, target_id)`. The FK is on
  the tag side; integrity for `target_id` is enforced at the
  service layer (resolve `target_type` → repository, then verify
  the id exists in the same organization).
- A composite FK across multiple target tables is not
  expressible cleanly in PostgreSQL; the service-layer check is
  the right trade-off — same pattern used by audit_events.
- **Scale.** 50k certs × 3 tags each = 150k rows. The unique
  index covers the assignment write path.

### 3.4 Services

```sql
CREATE TABLE services (
    id                       TEXT        PRIMARY KEY,
    organization_id          TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug                     TEXT        NOT NULL,           -- 'billing', 'checkout', 'identity-svc'
    display_name             TEXT        NOT NULL,
    description              TEXT        NOT NULL DEFAULT '',
    owner_email              TEXT        NOT NULL DEFAULT '',
    owner_team               TEXT        NOT NULL DEFAULT '',
    business_unit            TEXT        NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at              TIMESTAMPTZ,
    UNIQUE (organization_id, slug)
);
```

- A **service** is the smallest ownership unit. It represents the
  thing that gets paged when a cert expires.
- `slug` is stable and operator-defined; `display_name` is for
  humans.
- `owner_email` / `owner_team` are descriptive only. Routing of
  findings to channels is out of scope for v0.x; the fields exist
  so a future notification provider can use them without a new
  migration.
- Soft-delete via `disabled_at`. A disabled service still exists
  in explanation rows.

### 3.5 Service groups

```sql
CREATE TABLE service_groups (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug            TEXT        NOT NULL,
    display_name    TEXT        NOT NULL,
    parent_id       TEXT,                                    -- self-reference; NULL = root
    description     TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at     TIMESTAMPTZ,
    UNIQUE (organization_id, slug),
    FOREIGN KEY (organization_id, parent_id) REFERENCES service_groups(organization_id, id) ON DELETE RESTRICT
);

CREATE TABLE service_group_memberships (
    organization_id  TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    service_id       TEXT        NOT NULL,
    service_group_id TEXT        NOT NULL,
    assigned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, service_id),               -- one direct group per service in H-026A
    FOREIGN KEY (organization_id, service_id) REFERENCES services(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_group_id) REFERENCES service_groups(organization_id, id) ON DELETE RESTRICT
);
```

- **One direct service_group per service** in H-026A. A service
  participates in its direct group AND every ancestor group via
  `parent_id`. Multi-parent (DAG) is deferred; the schema does
  not preclude it (a future migration can drop the
  `PRIMARY KEY (org, service_id)` constraint and switch to a
  composite key, but only when a real operator need surfaces —
  CLAUDE.md §8.5 forbids speculative abstraction).
- **Cycle prevention.** `service_groups.parent_id` is enforced
  acyclic at the **service layer**, not the SQL layer.
  Validation runs on every write: walk parents, refuse if the
  walk revisits a node. PostgreSQL has no native acyclic
  constraint for self-references.
- **Scale.** Hundreds of services + tens of groups + 3–5 levels
  deep. Sub-millisecond depth-first walks.

### 3.6 Agent groups

```sql
CREATE TABLE agent_groups (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug            TEXT        NOT NULL,
    display_name    TEXT        NOT NULL,
    description     TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at     TIMESTAMPTZ,
    UNIQUE (organization_id, slug)
);

CREATE TABLE agent_group_memberships (
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    agent_id        TEXT        NOT NULL,
    agent_group_id  TEXT        NOT NULL,
    assigned_by     TEXT        NOT NULL,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, agent_id, agent_group_id),
    FOREIGN KEY (organization_id, agent_id) REFERENCES agents(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, agent_group_id) REFERENCES agent_groups(organization_id, id) ON DELETE RESTRICT
);
```

- **One agent → many agent groups.** An agent can be in both
  "Domain Controllers" and "PCI In-Scope" simultaneously.
- The existing `agents.group_name` text column (set by
  deployment package, see [`AGENT_ENROLLMENT.md`](./AGENT_ENROLLMENT.md))
  remains untouched. H-026 does NOT migrate it — it's the
  deployment-time hint, not the operator-curated grouping.
  An operator may use `group_name` as a starting signal for
  ownership rules (§4) but it is not a member of any table.
- **Scale.** 10k agents × 3 groups each = 30k rows.

### 3.7 Ownership rules

```sql
CREATE TABLE ownership_rules (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    name                TEXT        NOT NULL,
    description         TEXT        NOT NULL DEFAULT '',
    service_id          TEXT        NOT NULL,                  -- the service this rule grants ownership to
    precedence_tier     TEXT        NOT NULL,                  -- enum, see §4.2
    priority            INTEGER     NOT NULL,                  -- lower = higher precedence within tier
    match_kind          TEXT        NOT NULL,                  -- 'san_glob' | 'san_regex' | 'subject_cn_glob' | 'agent_group' | 'issuer_dn' | 'store_location' | 'tag'
    match_value         TEXT        NOT NULL,                  -- the pattern / id / tag-key:value, depending on kind
    enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          TEXT        NOT NULL,
    disabled_at         TIMESTAMPTZ,
    UNIQUE (organization_id, name),
    FOREIGN KEY (organization_id, service_id) REFERENCES services(organization_id, id) ON DELETE RESTRICT
);

CREATE INDEX ownership_rules_org_enabled_tier_prio_idx
    ON ownership_rules(organization_id, enabled, precedence_tier, priority, created_at, id)
    WHERE enabled = TRUE;
-- Backs the recompute load: walk rules in deterministic tier/priority/tiebreak order.
```

- `precedence_tier` is the named tier from §4.2 ("explicit",
  "agent_group", "san_pattern", "subject_pattern", "issuer_store",
  "fallback"). The enum is stored as text, validated at the
  service layer, and pinned by tests — the small set of values
  doesn't justify an enum type in v0.x.
- `priority` orders rules **within** a tier; `(precedence_tier,
  priority, created_at, id)` is the global deterministic order.
- `match_kind` + `match_value` carry the rule body. The
  service-layer validator rejects unknown kinds; the engine's
  `apply(rule, cert, context)` switches on the kind. Adding a
  kind later is additive — no schema change.
- **Soft delete via `disabled_at` + `enabled`.** Two columns?
  Yes: `enabled` is the runtime flag (engine reads), `disabled_at`
  is the timestamp (audit reads). The pair lets the operator
  toggle a rule without losing the original disable time.
- **Scale.** A pilot org with 200 services × 3 rules each = 600
  rules. The partial index keeps the recompute load tiny.

### 3.8 Certificate ownership (derived state)

```sql
CREATE TABLE certificate_ownership (
    organization_id          TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    certificate_id           TEXT        NOT NULL,
    service_id               TEXT,                              -- NULL = unowned
    decision                 TEXT        NOT NULL,              -- 'matched' | 'overridden' | 'unowned' | 'ambiguous'
    winning_rule_id          TEXT,                              -- NULL when decision in ('overridden', 'unowned')
    override_id              TEXT,                              -- NULL when decision != 'overridden'
    explanation_id           TEXT        NOT NULL,              -- always points at the latest explanation row
    confidence               TEXT        NOT NULL,              -- 'high' | 'medium' | 'low'
    first_assigned_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_evaluated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_changed_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, certificate_id),
    FOREIGN KEY (organization_id, certificate_id) REFERENCES certificates(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_id) REFERENCES services(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, winning_rule_id) REFERENCES ownership_rules(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, override_id) REFERENCES certificate_ownership_overrides(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, explanation_id) REFERENCES ownership_match_explanations(organization_id, id) ON DELETE RESTRICT
);
```

- **One row per certificate.** Denormalized current ownership;
  the read path never joins through explanation history.
- `decision` is the four-way enum from §4 — UI displays it
  directly.
- `confidence` is a coarse-grained label derived from
  precedence_tier (§4.2). High = explicit assignment or service
  member; Medium = agent_group / san_pattern / subject_pattern;
  Low = issuer_store / fallback.
- `last_changed_at` only bumps on actual transitions (service_id
  or decision change). `last_evaluated_at` bumps on every
  recompute. The split lets operators answer "when did this last
  flip?" (an audit-style question) without re-reading audit_events.
- **Composite FKs everywhere** — the H-009 cross-org safety
  posture used throughout the v0.1 schema.

### 3.9 Certificate ownership overrides

```sql
CREATE TABLE certificate_ownership_overrides (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    certificate_id      TEXT        NOT NULL,
    service_id          TEXT        NOT NULL,                   -- the pinned service; NULL is not allowed (use rule-disable instead)
    reason              TEXT        NOT NULL,                   -- operator's free-text justification, ≤ 1000 bytes
    set_by              TEXT        NOT NULL,
    set_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ,                            -- optional auto-expiry
    cleared_at          TIMESTAMPTZ,
    cleared_by          TEXT,
    cleared_reason      TEXT,
    UNIQUE (organization_id, certificate_id, cleared_at)        -- only one active override per cert
        WHERE cleared_at IS NULL,
    FOREIGN KEY (organization_id, certificate_id) REFERENCES certificates(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_id) REFERENCES services(organization_id, id) ON DELETE RESTRICT
);
```

- The unique constraint with `WHERE cleared_at IS NULL` enforces
  "one active override per cert" while keeping history.
- An override always wins — engine precedence tier "explicit"
  (§4.2) is the override path.
- Clearing an override produces a soft-delete row (set
  `cleared_at`, `cleared_by`, `cleared_reason`) plus an
  `ownership_override_cleared` audit row. The recompute then
  re-derives the cert's owner per §4.

### 3.10 Ownership match explanations

```sql
CREATE TABLE ownership_match_explanations (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    certificate_id      TEXT        NOT NULL,
    decided_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_decision    TEXT        NOT NULL,                   -- mirrors certificate_ownership.decision
    decided_service_id  TEXT,
    winning_rule_id     TEXT,
    losing_rules        JSONB       NOT NULL DEFAULT '[]'::jsonb,   -- ordered list of {rule_id, tier, priority, reason_not_chosen}
    signals_seen        JSONB       NOT NULL DEFAULT '{}'::jsonb,   -- {san, subject_cn, issuer, store_location, agent_ids, agent_groups, tags}
    engine_version      INTEGER     NOT NULL,
    FOREIGN KEY (organization_id, certificate_id) REFERENCES certificates(organization_id, id) ON DELETE CASCADE
);

CREATE INDEX ownership_match_explanations_org_cert_decided_idx
    ON ownership_match_explanations(organization_id, certificate_id, decided_at DESC);
-- Backs "show me the explanation timeline for this cert".
```

- **One row per `(cert, recompute pass that changed the
  decision)`.** Recomputes that re-confirm the existing
  decision do NOT write a new explanation row — they bump
  `certificate_ownership.last_evaluated_at` only. This caps the
  cardinality.
- `losing_rules` is a JSONB array, **bounded** at K=8 entries
  (the K highest-precedence non-winning rules). The bound is a
  binding service-layer constant — JSONB columns must not grow
  unbounded.
- `signals_seen` captures the inputs to the decision — the cert's
  SANs / subject / issuer / store_location, the agents that
  observed it, the agent groups those agents belong to, the tags
  on the cert / agents / observing service. This is the
  "explainable" surface (CLAUDE.md §7.2): an operator can read
  the explanation and reconstruct the engine's reasoning without
  re-running it.
- `engine_version` lets a future engine change render old
  explanations unambiguously.
- **Scale.** 50k certs × ownership flips averaging 2/cert/year ≈
  100k rows/year per org. Negligible; pruning is deferred.

### 3.11 Policy definitions

```sql
CREATE TABLE policy_definitions (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug                TEXT        NOT NULL,
    display_name        TEXT        NOT NULL,
    description         TEXT        NOT NULL DEFAULT '',
    rules               JSONB       NOT NULL,                   -- list of policy_rule objects; see §5
    version             INTEGER     NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          TEXT        NOT NULL,
    disabled_at         TIMESTAMPTZ,
    UNIQUE (organization_id, slug, version)
);
```

- A **policy definition** is a named bundle of rules. Versioning
  is explicit: editing a published policy creates a new
  `(slug, version+1)` row; the previous version stays for
  explanation history.
- `rules` is JSONB. Each rule object has a `kind` (e.g.,
  `min_rsa_bits`, `allowed_issuers`, `max_validity_days`,
  `allowed_eku_set`, `allowed_san_patterns`, `forbid_self_signed`,
  `forbid_unmanaged_deployment`), a `params` object, a stable
  `rule_local_id` (string unique within the policy), and a
  `severity` mapping. The engine parses the JSONB into typed
  rule objects on read; CLAUDE.md §8.4 forbids
  `map[string]any` in domain models, so the parsed shape lives in
  `governance/policy/definition.go`.
- **Scale.** Dozens of definitions per org × tens of rules each.
  Tiny.

### 3.12 Policy assignments

```sql
CREATE TABLE policy_assignments (
    id                       TEXT        PRIMARY KEY,
    organization_id          TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    policy_definition_id     TEXT        NOT NULL,
    scope_kind               TEXT        NOT NULL,              -- 'organization' | 'service_group' | 'service' | 'certificate'
    scope_id                 TEXT        NOT NULL,              -- the org / group / service / certificate id
    assigned_by              TEXT        NOT NULL,
    assigned_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    cleared_at               TIMESTAMPTZ,
    cleared_by               TEXT,
    UNIQUE (organization_id, policy_definition_id, scope_kind, scope_id, cleared_at)
        WHERE cleared_at IS NULL,
    FOREIGN KEY (organization_id, policy_definition_id) REFERENCES policy_definitions(organization_id, id) ON DELETE RESTRICT
);

CREATE INDEX policy_assignments_org_scope_idx
    ON policy_assignments(organization_id, scope_kind, scope_id)
    WHERE cleared_at IS NULL;
```

- An assignment binds one policy definition to one scope.
- Scopes are polymorphic by `(scope_kind, scope_id)`; cross-table
  FK enforcement lives in the service layer (same as
  tag_assignments).
- **A scope may have multiple policy assignments**, all
  evaluated. The merge model in §5.3 defines precedence.

### 3.13 Policy waivers

```sql
CREATE TABLE policy_waivers (
    id                       TEXT        PRIMARY KEY,
    organization_id          TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    policy_definition_id     TEXT        NOT NULL,
    policy_rule_local_id     TEXT        NOT NULL,              -- the per-rule id inside the policy's rules JSONB
    scope_kind               TEXT        NOT NULL,              -- same enum as policy_assignments
    scope_id                 TEXT        NOT NULL,
    reason                   TEXT        NOT NULL,
    granted_by               TEXT        NOT NULL,
    granted_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at               TIMESTAMPTZ NOT NULL,              -- non-NULL; waivers MUST expire
    cleared_at               TIMESTAMPTZ,
    cleared_by               TEXT,
    UNIQUE (organization_id, policy_definition_id, policy_rule_local_id, scope_kind, scope_id, cleared_at)
        WHERE cleared_at IS NULL,
    FOREIGN KEY (organization_id, policy_definition_id) REFERENCES policy_definitions(organization_id, id) ON DELETE RESTRICT
);
```

- Waivers are **rule-scoped, time-bounded** exceptions. A waiver
  cannot be permanent — `expires_at` is NOT NULL.
- The recompute checks `expires_at > now()`; expired waivers stop
  applying without any explicit clear step. The recompute emits
  an `policy_waiver_expired` audit row at expiry; clearing
  explicitly produces `policy_waiver_cleared`.
- **No "permanent waiver" path.** A repeatedly extended waiver is
  fine; a permanent exception requires editing the policy itself
  to drop the offending rule (which is itself an auditable
  policy version bump).

### 3.14 Governance recompute runs

```sql
CREATE TABLE governance_recompute_runs (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    kind                TEXT        NOT NULL,                   -- 'ownership' | 'policy'
    started_at          TIMESTAMPTZ NOT NULL,
    finished_at         TIMESTAMPTZ,
    actor               TEXT        NOT NULL,                   -- user id, 'scheduler', 'preview'
    actor_kind          TEXT        NOT NULL,                   -- 'user' | 'system' | 'preview'
    succeeded           BOOLEAN,
    error_class         TEXT        NOT NULL DEFAULT '',
    evaluated_count     INTEGER     NOT NULL DEFAULT 0,
    changed_count       INTEGER     NOT NULL DEFAULT 0,
    unchanged_count     INTEGER     NOT NULL DEFAULT 0,
    became_owned_count  INTEGER     NOT NULL DEFAULT 0,
    became_unowned_count INTEGER    NOT NULL DEFAULT 0,
    flipped_owner_count INTEGER     NOT NULL DEFAULT 0,
    engine_version      INTEGER     NOT NULL
);

CREATE INDEX governance_recompute_runs_org_kind_started_idx
    ON governance_recompute_runs(organization_id, kind, started_at DESC);
```

- One row per recompute pass. Append-only at the application
  level (no UPDATE except for `finished_at` and the counters on
  the row the pass itself just inserted).
- This is **NOT** the audit_events table; this is a per-pass
  operational record. Audit events still fire on individual
  ownership flips and policy waiver state changes.
- Why a separate table: audit_events is per-state-change; the
  per-pass summary is "this scheduler tick changed N certs"
  which doesn't map cleanly to audit. Operators want both shapes
  for different questions.

### 3.15 Indexes summary

All indexes are intentional and documented inline per CLAUDE.md
§16. The list below restates them as a single audit point.

| Index                                                                                       | Query                                                            |
| ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `tags (organization_id, key, value)` UNIQUE                                                 | Dedup tag definitions.                                            |
| `tag_assignments (organization_id, tag_id, target_type, target_id)` UNIQUE                  | One assignment per `(tag, target)`.                              |
| `tag_assignments (organization_id, target_type, target_id)`                                 | "All tags on this target."                                       |
| `services (organization_id, slug)` UNIQUE                                                   | Service slug lookup.                                              |
| `service_groups (organization_id, slug)` UNIQUE                                             | Service group lookup.                                             |
| `service_groups (organization_id, parent_id)`                                               | Children of a group; ancestor walk.                              |
| `service_group_memberships (organization_id, service_id)` PK                                | "Which group is this service in?"                                |
| `agent_groups (organization_id, slug)` UNIQUE                                               | Agent group lookup.                                              |
| `agent_group_memberships (organization_id, agent_id, agent_group_id)` PK                    | "Which groups is this agent in?"                                 |
| `agent_group_memberships (organization_id, agent_group_id)`                                 | "Which agents are in this group?"                                |
| `ownership_rules (organization_id, enabled, precedence_tier, priority, created_at, id)` partial idx WHERE enabled | Recompute rule walk in deterministic order. |
| `ownership_rules (organization_id, service_id)`                                             | "All rules pointing at this service."                            |
| `certificate_ownership (organization_id, certificate_id)` PK                                | Single-cert lookup.                                              |
| `certificate_ownership (organization_id, service_id)`                                       | "All certs this service owns."                                    |
| `certificate_ownership (organization_id, decision)`                                         | "Show me unowned / ambiguous certs."                             |
| `certificate_ownership_overrides (organization_id, certificate_id, cleared_at)` partial UNIQUE WHERE cleared_at IS NULL | One active override per cert.                |
| `ownership_match_explanations (organization_id, certificate_id, decided_at DESC)`           | Explanation timeline per cert.                                    |
| `policy_definitions (organization_id, slug, version)` UNIQUE                                | Versioned slug lookup.                                            |
| `policy_assignments (organization_id, scope_kind, scope_id)` partial idx WHERE cleared_at IS NULL | "Which policies apply to this scope?"                   |
| `policy_waivers (organization_id, policy_definition_id, policy_rule_local_id, scope_kind, scope_id, cleared_at)` partial UNIQUE WHERE cleared_at IS NULL | One active waiver per `(rule, scope)`. |
| `governance_recompute_runs (organization_id, kind, started_at DESC)`                        | Recent runs per org per kind.                                     |

---

## 4. Ownership inference engine

### 4.1 Signals

The engine reads, per certificate, the following signals (all
already in the v0.1 schema or new H-026 tables):

| Signal               | Source                                                                                   |
| -------------------- | ---------------------------------------------------------------------------------------- |
| Subject CN           | `certificates.subject`                                                                   |
| SAN list             | `certificates.sans` (JSONB)                                                              |
| Issuer DN            | `certificates.issuer`                                                                    |
| Store locations      | `certificate_observations.store_location` (DISTINCT per cert)                            |
| Observing agents     | `certificate_observations.agent_id`                                                      |
| Observing agent groups | `agent_group_memberships` joined with the observing agents                              |
| Cert tags            | `tag_assignments WHERE target_type = 'certificate'`                                      |
| Agent tags           | `tag_assignments WHERE target_type = 'agent'` for observing agents                       |
| Operator override    | `certificate_ownership_overrides WHERE cleared_at IS NULL`                               |
| Direct service membership | A future signal (operator pins a cert to a service via a *different* mechanism than override; see §4.5). Out of scope for H-026A. |

Future signals (deferred, schema-compatible):

- CMDB host → service mapping (provider-fed).
- AD computer-OU → service mapping.
- Cloud-tag projection (AWS Resource Tags, Azure Tags) via a
  `providers/inventory` extension.

The engine never reads these in H-026; the precedence model is
designed so adding them later is a new tier (or a new
`match_kind`) — not a re-shaping of the precedence ladder.

### 4.2 Precedence ladder

Eight tiers, evaluated in order. **First match wins**, with the
deterministic tiebreaker described in §4.3.

| Order | Tier name           | Source                                                                                   | Confidence |
| ----- | ------------------- | ---------------------------------------------------------------------------------------- | ---------- |
| 1     | `explicit`          | Active row in `certificate_ownership_overrides`.                                          | high       |
| 2     | `service_member`    | Direct service membership (future — §4.5 deferred). Reserved tier; no rules in H-026A.   | high       |
| 3     | `agent_group`       | `match_kind = 'agent_group'` rule, where the cert is observed by an agent in that group.  | medium     |
| 4     | `san_pattern`       | `match_kind in ('san_glob', 'san_regex')` matching any SAN of the cert.                  | medium     |
| 5     | `subject_pattern`   | `match_kind = 'subject_cn_glob'` matching the subject CN.                                | medium     |
| 6     | `tag`               | `match_kind = 'tag'` where the cert (or any observing agent) carries the named tag.       | medium     |
| 7     | `issuer_store`      | `match_kind in ('issuer_dn', 'store_location')` for coarse rules (e.g., "everything from internal CA in WebHosting → web-platform"). | low |
| 8     | `fallback`          | Org default (a special pseudo-rule with `match_kind = 'fallback'`, one allowed per org). | low        |

A cert that matches no tier is assigned `decision = 'unowned'`
with `service_id = NULL` and `confidence = 'low'`.

### 4.3 Conflict resolution

Within a tier, multiple rules may match the same cert. The
**deterministic tiebreaker** is:

1. Lowest `priority` (integer; operator-assigned) wins.
2. If `priority` ties: oldest `created_at` wins (earliest
   operator commitment).
3. If `created_at` ties (extremely rare — same-transaction
   creation): lowest lexicographic `id` wins.

Behavior when multiple rules in the **same tier** match with the
same `priority` and the same `created_at`:

- Decision = `ambiguous`.
- `winning_rule_id` = the rule the tiebreaker picked (i.e.,
  lowest id) — operations must keep working.
- All matching rules are recorded in `losing_rules` with a
  `reason_not_chosen = "tied with winner; tiebreaker on id"`.
- A `governance.ambiguous_match` audit row is written at
  severity:"security" so operators can review.
- The cert is queryable via `?decision=ambiguous` for triage.

This explicitly avoids "silent ownership flips" (CLAUDE.md
§7.2): an ambiguous match is highlighted, not hidden.

### 4.4 Engine execution

The engine is the streaming pass that mirrors H-024B's findings
recompute:

```
WithTxLockedOwnership(orgID)               -- session-scope advisory lock
  open REPEATABLE READ transaction         -- single input snapshot

  Phase 1 — load ownership rules
    ListOwnershipRulesForOrg(enabled=true, ORDER BY tier, priority, created_at, id)
    Build in-memory rule index per tier.

  Phase 2 — stream certs by id ASC
    For each page of certs (page_size = 500):
      Load: cert metadata, cert observations (DISTINCT agent_id + store_location),
            agent groups for observing agents, tags on cert + observing agents.
      For each cert:
        Evaluate tiers in order; first match wins (tiebreaker as §4.3).
        Compute decision (matched | overridden | unowned | ambiguous).
        Read prior decision from certificate_ownership.
        If decision unchanged AND service_id unchanged:
          UPDATE certificate_ownership SET last_evaluated_at = now;
          counter[unchanged]++.
        Else:
          INSERT ownership_match_explanations (winning_rule_id, losing_rules, signals_seen).
          UPSERT certificate_ownership (..., explanation_id = new id, last_changed_at = now).
          Emit ownership audit event (see §4.6).
          counter[became_owned | became_unowned | flipped_owner | matched_now_overridden | ...]++.

  Phase 3 — finalize
    Write governance_recompute_runs row with counters.
    Commit.
```

- The pass is **idempotent**: replaying against unchanged inputs
  at the same wall-clock minute produces `unchanged = N`,
  `changed = 0`. Tested via the same byte-identical equivalence
  pattern H-024B established.
- **REPEATABLE READ** is binding: a concurrent ingestion batch
  must NOT be visible mid-pass. The same wiring as
  `WithTxLockedFindingsRepeatableRead`.

### 4.5 Stale ownership, deleted rules, disabled rules

- A **disabled rule** (`enabled = FALSE`) is skipped by the
  engine. Certs that previously matched it are re-evaluated and
  may flip; the flip is audited.
- A **deleted rule** is impossible in H-026: ownership_rules use
  soft delete. `disabled_at IS NOT NULL` plus `enabled = FALSE`.
- An **explanation referencing a disabled rule** stays valid as a
  historical record. The rule row still exists (soft-deleted) so
  the FK in `ownership_match_explanations.winning_rule_id` does
  not break.
- **Stale ownership** is computed at query time:
  `last_evaluated_at < now - threshold` (default 7 days). The
  threshold is a config knob, not a stored column. The
  `GET /ownership/stale` endpoint (§7) drives the alert path.

### 4.6 Audit events

All emitted with `severity:"security"` (CLAUDE.md §9 — governance
state changes are security events).

| Audit action                       | Emitted when                                                                                              |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `ownership.assigned`               | Decision flipped from `unowned` to `matched` (or `overridden`).                                            |
| `ownership.cleared`                | Decision flipped from `matched`/`overridden` to `unowned`.                                                |
| `ownership.flipped`                | Decision stayed `matched` but `service_id` changed.                                                       |
| `ownership.overridden`             | Operator created or replaced an override.                                                                 |
| `ownership.override_cleared`       | Operator cleared an override.                                                                             |
| `ownership.ambiguous_match`        | Decision = `ambiguous` for a cert that was previously deterministic.                                       |
| `ownership.rule_created`           | Operator created an ownership rule.                                                                       |
| `ownership.rule_updated`           | Operator updated an ownership rule (fields and old/new values in metadata).                                |
| `ownership.rule_disabled`          | Operator disabled an ownership rule.                                                                      |
| `ownership.rule_enabled`           | Operator enabled a disabled rule.                                                                         |

Audit rows are written **inside the same transaction** as the
state change. An audit-write failure rolls the entire recompute
back — same pattern as findings recompute.

### 4.7 Engine explainability contract

The engine MUST be able to answer the following, **for any
certificate**, from stored state alone (no re-evaluation):

- The current owner.
- The decision class (matched / overridden / unowned / ambiguous).
- The winning rule (rule id + name + tier + priority).
- The top-K losing rules with reason-not-chosen.
- The signals it considered (SANs, subject, issuer, store
  locations, observing agents, observing agent groups, tags).
- The engine version that produced the decision.
- The timeline of decisions for this cert (audit + explanation
  history).

This is the explainability contract from §1.5 made testable.
Implementation tests pin every bullet — a cert can be picked
arbitrarily and the engine renders an explanation without
touching the rule registry or the inference loop.

---

## 5. Policy scoping

### 5.1 Scope chain

Every certificate has a **scope chain** that determines which
policies apply. The chain is constructed at evaluation time:

```
certificate
  ←  certificate_id direct assignment
service (owner, from §4)
  ←  service_id assignment
service_group (direct, from service_group_memberships)
  ←  service_group_id assignment
service_group_ancestors (recursive parent walk)
  ←  service_group_id assignment for each ancestor
organization
  ←  organization_id assignment (the baseline)
```

The chain is walked **outer to inner** (organization → ancestors
→ direct group → service → cert), so a deeper scope can override
a shallower one (§5.3).

### 5.2 Policy rule shapes

The initial set of supported rule kinds. Adding a kind later is
additive — the JSONB shape grows, the engine learns a new
branch, no schema change.

| Rule kind                       | Params                                                                       | Violation when                                                          |
| ------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `min_rsa_bits`                  | `{ "min": 2048 }`                                                            | `key_alg == RSA AND key_bits < min`                                     |
| `allowed_key_algorithms`        | `{ "allow": ["RSA", "ECDSA"], "min_curve_bits": 256 }`                       | key alg not in allow list, or ECDSA below curve threshold.              |
| `allowed_signature_algorithms`  | `{ "allow": ["SHA256-RSA", "SHA384-RSA", "SHA256-ECDSA"] }`                  | sig alg not in allow list.                                              |
| `allowed_issuers`               | `{ "issuer_dns": ["CN=Internal Issuing CA", "CN=DigiCert ..."] }`            | `certificates.issuer` not in list.                                      |
| `max_validity_days`             | `{ "days": 398 }`                                                            | `not_after - not_before > days`.                                        |
| `forbid_self_signed_leaf`       | `{}`                                                                         | `is_self_signed AND NOT is_ca`.                                         |
| `allowed_san_patterns`          | `{ "globs": ["*.corp.example", "*.svc.corp.example"] }`                      | Any SAN does not match any glob in the list.                            |
| `allowed_ekus`                  | `{ "allow": ["ServerAuth", "ClientAuth"] }`                                  | Any EKU outside the allow set.                                          |
| `require_managed_deployment`    | `{ "stores": ["LocalMachine\\WebHosting"] }`                                  | Observed in a store outside the list (treats other stores as "rogue"). |
| `forbid_unmanaged_issuer`       | `{ "issuer_dns": [...] }`                                                    | Inverse of `allowed_issuers` for the same scope.                        |
| `renewal_sla_days`              | `{ "days": 30 }`                                                             | `not_after - now < days AND no_renewal_in_progress` (future).            |

H-026A ships the JSONB shape and validator only. The
**evaluation engine** lands in H-026D once the engine model is
locked. No findings emitted until H-026D either.

### 5.3 Merging across the scope chain

Multiple policy assignments can target the same scope or
different scopes in the chain. Resolution:

1. **Collect** every policy assignment whose scope is in the
   cert's scope chain.
2. **Order** them by scope depth: organization → service group
   ancestors → direct service group → service → certificate.
   Within the same scope depth, order by `assigned_at ASC` for a
   stable tie-break.
3. **Flatten** each policy's rules into a single ordered list,
   tagged with their originating `(scope_kind, scope_id,
   policy_definition_id, policy_rule_local_id)`.
4. **Merge** rules of the same `kind`:
   - For numeric tighten-down rules (`min_rsa_bits`,
     `max_validity_days`, `renewal_sla_days`): the **strictest**
     value wins (max for min_rsa_bits; min for max_validity_days).
   - For set-allow rules (`allowed_issuers`, `allowed_ekus`,
     `allowed_san_patterns`, `allowed_key_algorithms`,
     `allowed_signature_algorithms`): the **intersection** wins
     (deeper scopes can only further restrict, never broaden).
   - For boolean prohibit rules (`forbid_self_signed_leaf`): once
     set at any scope, applies all the way down (deeper scopes
     cannot lift a prohibition).
   - For deeper-scope rules that don't exist at outer scope:
     applied as-is.
5. **Apply waivers.** For every effective rule, check
   `policy_waivers` for an active row where `scope_kind ∈ chain
   AND policy_rule_local_id = effective_rule.id`. An active
   waiver removes the rule from the effective set; the
   explanation records the waiver id.

### 5.4 Precedence ambiguity

Two assignments at the same scope depth with the same
`assigned_at` are extremely rare but possible. The deterministic
tiebreaker is `policy_assignment.id ASC`. Documented in tests.

### 5.5 Override semantics

- A `certificate`-scope policy assignment is the **only** way to
  loosen a rule below what the service-scope dictates, and only
  by adding a more permissive list rule (which the intersection
  rule above will then NOT loosen — so cert-scope cannot
  effectively loosen anything in H-026D).
- Cert-scope assignments are **prohibited** for booleans like
  `forbid_self_signed_leaf` at the validator level — a future
  loophole here is what waivers exist for.

In other words: **only waivers can loosen**. Policy assignments
can only tighten. This is the design's anti-explosion guard.

### 5.6 Audit events

All severity:"security":

| Audit action                       | Emitted when                                                            |
| ---------------------------------- | ----------------------------------------------------------------------- |
| `policy_definition.created`        | Operator creates a new policy definition.                                |
| `policy_definition.updated`        | Operator publishes a new version (slug, version+1).                      |
| `policy_definition.disabled`       | Operator disables a definition.                                          |
| `policy_assignment.granted`        | Operator binds a policy to a scope.                                      |
| `policy_assignment.cleared`        | Operator clears an assignment.                                           |
| `policy_waiver.granted`            | Operator grants a waiver.                                                |
| `policy_waiver.cleared`            | Operator clears a waiver.                                                |
| `policy_waiver.expired`            | Recompute observes `expires_at <= now()` on a previously-active waiver. |

---

## 6. Findings integration

### 6.1 Principle: enrich, never regenerate

Findings remain derived state over the certificate inventory
([`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §2).
Ownership changes do **not** delete findings, do **not** flip
their status, and do **not** cause `findings.recomputed` rows.

When the next findings recompute runs, it reads ownership state
as a *side input* and stamps each finding row with the cert's
current owner (denormalized for fast operator queries by owner).
If ownership flips between recomputes, the finding row's
denormalized owner is stale by at most one recompute cycle —
acceptable for an audit-style read path.

### 6.2 Schema impact on `findings`

H-026D (not H-026A) adds three additive columns to `findings`:

| Column                       | Type        | Meaning                                                                  |
| ---------------------------- | ----------- | ------------------------------------------------------------------------ |
| `owner_service_id`           | TEXT        | Denormalized current owner at last finding recompute. NULL = unowned.    |
| `owner_decision`             | TEXT        | `matched` / `overridden` / `unowned` / `ambiguous` at recompute time.    |
| `policy_violations`          | JSONB       | `[{policy_definition_id, policy_rule_local_id, severity}, …]`            |

All three are NULL-tolerant and default to NULL / `[]::jsonb`.
The migration is additive (CLAUDE.md §16) and the API exposes
them additively (CLAUDE.md §17) — existing readers continue to
work.

### 6.3 Recompute behavior

- Findings recompute (H-024B's streaming pass) is **not slowed
  down** in the steady state — owner lookup is a single hash-map
  query against the pre-loaded ownership snapshot. The snapshot
  is read once per recompute pass under the same advisory lock.
- The `findings.Service.runDiffStreaming` already loops cert by
  cert; the enrichment step is a lookup + denormalized write,
  not a join.
- Policy violations are **computed during findings recompute**
  (H-026D), not during ownership recompute. The two passes stay
  independent.

### 6.4 New rule_ids (H-026D)

Each rule kind in §5.2 maps to a finding `rule_id` of the form
`policy_<kind>` — e.g. `policy_min_rsa_bits`,
`policy_allowed_issuers`, `policy_max_validity_days`. Each
emits one finding per violating cert with `evidence` containing:

```json
{
  "policy_definition_id": "...",
  "policy_rule_local_id": "...",
  "rule_kind": "min_rsa_bits",
  "actual": 1024,
  "required": 2048,
  "scope_origin": { "kind": "service_group", "id": "..." }
}
```

The existing rule registry (`weak_rsa_key`, etc.) is unchanged.
Policy rules are a parallel family of rule_ids; an operator
filters by `rule_id LIKE 'policy_%'` to see only governance
findings.

### 6.5 Owner-aware finding queries (H-026D)

API extension on `GET /findings`:

| Param                  | Meaning                                                                |
| ---------------------- | ---------------------------------------------------------------------- |
| `owner_service_id`     | Filter to findings whose cert's denormalized owner is this service.    |
| `owner_decision`       | Filter to findings whose cert is `unowned`, `ambiguous`, etc.          |
| `policy_definition_id` | Filter to findings raised by a specific policy.                        |
| `policy_rule_local_id` | Filter further to a specific rule inside that policy.                  |

All additive query parameters per CLAUDE.md §17.

---

## 7. REST API surface

All routes mounted under `/api/v1`, the canonical envelope
described in [`REST_API.md`](../api/REST_API.md) "Conventions".
Operator-only by default (session cookie); agent bearer
credentials are NOT honored on governance endpoints (CLAUDE.md
§8.6 — orthogonal identity axes).

### 7.1 Naming and conventions

- Plural-resource nouns: `/tags`, `/services`, `/service-groups`,
  `/agent-groups`, `/ownership-rules`, `/policies`,
  `/policy-waivers`.
- Read endpoints: `GET <plural>`, `GET <plural>/{id}`.
- Write endpoints: `POST <plural>` (create), `PATCH
  <plural>/{id}` (update), `POST <plural>/{id}/disable`
  (soft-delete), `POST <plural>/{id}/enable` (re-enable).
- Preview endpoints: `POST <plural>/preview` returns a
  read-only summary of "what would happen if I applied this"
  without writing to the DB.
- Cross-org → `404 not_found` (never `403`), matching the
  established v0.1 posture.

### 7.2 Tags

```
GET    /api/v1/tags?cursor=&limit=
POST   /api/v1/tags                         {key, value?, description?}
GET    /api/v1/tags/{id}
PATCH  /api/v1/tags/{id}                    {description?, value?}
POST   /api/v1/tags/{id}/disable
POST   /api/v1/tags/{id}/enable
POST   /api/v1/tags/{id}/assignments        {target_type, target_id}
DELETE /api/v1/tags/{id}/assignments        {target_type, target_id}
GET    /api/v1/tags/{id}/assignments?target_type=&cursor=&limit=
```

Sample `POST /tags` request:

```json
{ "key": "env", "value": "prod", "description": "Production environment" }
```

Sample response:

```json
{
  "id": "01J...",
  "organization_id": "anchorix",
  "key": "env",
  "value": "prod",
  "description": "Production environment",
  "created_at": "2026-05-21T10:00:00Z",
  "disabled_at": null
}
```

### 7.3 Services and service groups

```
GET    /api/v1/services
POST   /api/v1/services                     {slug, display_name, description?, owner_email?, owner_team?, business_unit?}
GET    /api/v1/services/{id}
PATCH  /api/v1/services/{id}
POST   /api/v1/services/{id}/disable
POST   /api/v1/services/{id}/enable
POST   /api/v1/services/{id}/group          {service_group_id}
DELETE /api/v1/services/{id}/group

GET    /api/v1/service-groups
POST   /api/v1/service-groups               {slug, display_name, parent_id?}
GET    /api/v1/service-groups/{id}
PATCH  /api/v1/service-groups/{id}
POST   /api/v1/service-groups/{id}/disable
GET    /api/v1/service-groups/{id}/children
GET    /api/v1/service-groups/{id}/services?cursor=&limit=
```

### 7.4 Agent groups

```
GET    /api/v1/agent-groups
POST   /api/v1/agent-groups                 {slug, display_name, description?}
GET    /api/v1/agent-groups/{id}
PATCH  /api/v1/agent-groups/{id}
POST   /api/v1/agent-groups/{id}/disable
POST   /api/v1/agent-groups/{id}/members    {agent_id}
DELETE /api/v1/agent-groups/{id}/members    {agent_id}
GET    /api/v1/agent-groups/{id}/members?cursor=&limit=
GET    /api/v1/agents/{id}/groups           (the inverse view)
```

### 7.5 Ownership rules

```
GET    /api/v1/ownership-rules?service_id=&precedence_tier=&enabled=&cursor=&limit=
POST   /api/v1/ownership-rules              {name, service_id, precedence_tier, priority, match_kind, match_value, description?}
GET    /api/v1/ownership-rules/{id}
PATCH  /api/v1/ownership-rules/{id}         {priority?, match_value?, description?, enabled?}
POST   /api/v1/ownership-rules/{id}/disable
POST   /api/v1/ownership-rules/{id}/enable
POST   /api/v1/ownership-rules/preview      {tier, match_kind, match_value} → returns affected certs (dry-run)
POST   /api/v1/ownership-rules/{id}/preview → returns affected certs for an existing rule's current shape
```

Sample preview response (no DB writes):

```json
{
  "affected_count": 142,
  "sample_certs": [
    {
      "certificate_id": "01J...",
      "subject": "CN=billing-prod-01.corp.example",
      "current_owner_service_id": "01J...",
      "current_owner_service_slug": "platform-default",
      "would_assign_to_service_id": "01J...",
      "would_assign_to_service_slug": "billing",
      "would_flip": true
    }
  ],
  "would_flip_count": 38,
  "would_newly_assign_count": 104,
  "next_cursor": null
}
```

The preview runs the engine over a synthetic rule set
(existing rules + proposed) under a no-write transaction,
returning the diff. `affected_count` is exact; `sample_certs` is
capped at the page limit.

### 7.6 Certificate ownership read & override

```
GET    /api/v1/certificates/{id}/ownership
GET    /api/v1/certificates/{id}/ownership/explanation?include_history=&cursor=&limit=
POST   /api/v1/certificates/{id}/ownership/override   {service_id, reason, expires_at?}
DELETE /api/v1/certificates/{id}/ownership/override   {reason}
```

Sample `GET /certificates/{id}/ownership`:

```json
{
  "certificate_id": "01J...",
  "decision": "matched",
  "service": {
    "id": "01J...",
    "slug": "billing",
    "display_name": "Billing Service",
    "owner_team": "payments-platform"
  },
  "service_groups": [
    { "id": "01J...", "slug": "payments", "display_name": "Payments" }
  ],
  "winning_rule": {
    "id": "01J...",
    "name": "billing-prod SANs",
    "precedence_tier": "san_pattern",
    "priority": 100,
    "match_kind": "san_glob",
    "match_value": "billing-prod-*.corp.example"
  },
  "confidence": "medium",
  "override": null,
  "first_assigned_at": "2026-04-10T08:30:00Z",
  "last_evaluated_at": "2026-05-21T06:00:00Z",
  "last_changed_at": "2026-04-10T08:30:00Z",
  "engine_version": 1
}
```

Sample `GET /certificates/{id}/ownership/explanation`:

```json
{
  "certificate_id": "01J...",
  "current": {
    "decided_at": "2026-04-10T08:30:00Z",
    "decision": "matched",
    "service_id": "01J...",
    "winning_rule_id": "01J...",
    "losing_rules": [
      { "rule_id": "01J...", "tier": "issuer_store", "priority": 50, "reason_not_chosen": "lower precedence than san_pattern" },
      { "rule_id": "01J...", "tier": "subject_pattern", "priority": 200, "reason_not_chosen": "lower precedence than san_pattern" }
    ],
    "signals_seen": {
      "subject_cn": "billing-prod-01.corp.example",
      "sans": ["billing-prod-01.corp.example", "billing.corp.example"],
      "issuer": "CN=Internal Issuing CA",
      "store_locations": ["LocalMachine\\WebHosting"],
      "agent_ids": ["01J...", "01J..."],
      "agent_groups": [{"id": "01J...", "slug": "pci-web-tier"}],
      "tags": [{"key": "env", "value": "prod"}]
    },
    "engine_version": 1
  },
  "history": [
    { "decided_at": "2026-03-01T00:00:00Z", "decision": "unowned", "winning_rule_id": null }
  ],
  "next_cursor": null
}
```

### 7.7 Policy definitions

```
GET    /api/v1/policies
POST   /api/v1/policies                     {slug, display_name, description?, rules: [...]}
GET    /api/v1/policies/{id}
POST   /api/v1/policies/{id}/versions       {rules: [...]}    -- new version of an existing slug
GET    /api/v1/policies/{slug}/versions
POST   /api/v1/policies/{id}/disable
GET    /api/v1/policies/{id}/assignments
```

### 7.8 Policy assignments and waivers

```
POST   /api/v1/policy-assignments           {policy_definition_id, scope_kind, scope_id}
DELETE /api/v1/policy-assignments/{id}      {reason}
GET    /api/v1/policy-assignments?policy_definition_id=&scope_kind=&scope_id=

POST   /api/v1/policy-waivers               {policy_definition_id, policy_rule_local_id, scope_kind, scope_id, reason, expires_at}
DELETE /api/v1/policy-waivers/{id}          {reason}
GET    /api/v1/policy-waivers?policy_definition_id=&scope_kind=&scope_id=&active_only=
```

### 7.9 Policy preview

```
POST   /api/v1/policies/preview             {policy_definition_id, scope_kind, scope_id}
                                            → returns the merged-effective rules + violation count
                                            without persisting the assignment
```

Sample response:

```json
{
  "scope": { "kind": "service", "id": "01J..." },
  "effective_rules": [
    { "rule_kind": "min_rsa_bits", "params": {"min": 2048}, "origin": {"scope_kind": "organization", "policy_definition_id": "01J...", "policy_rule_local_id": "r1"} },
    { "rule_kind": "allowed_issuers", "params": {"issuer_dns": ["CN=Internal CA"]}, "origin": {"scope_kind": "service_group", "policy_definition_id": "01J...", "policy_rule_local_id": "r3"} }
  ],
  "active_waivers": [
    { "policy_rule_local_id": "r1", "expires_at": "2026-09-01T00:00:00Z", "scope_kind": "service" }
  ],
  "scope_certs_in_scope": 412,
  "would_violate_count": 19,
  "sample_violations": [
    { "certificate_id": "01J...", "rule_kind": "min_rsa_bits", "actual": 1024, "required": 2048 }
  ]
}
```

### 7.10 Operator views

```
GET    /api/v1/certificates?owner_service_id=
GET    /api/v1/certificates?owner_decision=unowned
GET    /api/v1/certificates?owner_decision=ambiguous
GET    /api/v1/certificates?service_group_id=

GET    /api/v1/ownership/unowned?cursor=&limit=        -- same as ?owner_decision=unowned, more explicit
GET    /api/v1/ownership/ambiguous?cursor=&limit=
GET    /api/v1/ownership/stale?older_than=&cursor=&limit=

GET    /api/v1/policy-violations?service_id=&policy_definition_id=&severity=
                                                       -- H-026D, surfaces findings with rule_id LIKE 'policy_%'
```

### 7.11 Recompute (operator-triggered)

```
POST   /api/v1/ownership/recompute              -- mirrors POST /findings/recompute
POST   /api/v1/policies/recompute               -- H-026D
GET    /api/v1/governance/recompute-runs?kind=&cursor=&limit=
```

### 7.12 Pagination, filtering, sorting

Same conventions as v0.1:

- Cursor-based pagination (`cursor`, `limit ≤ 200`).
- Deterministic ordering: every list endpoint has a documented
  `ORDER BY <natural> ASC, id ASC` tuple. Cursor encodes the
  tuple's last value.
- Filters are query parameters; no nested filter DSL.
- Cross-org → `404 not_found`.

### 7.13 Preview-before-apply contract

A `*/preview` endpoint:

- Runs the same evaluation path as the real apply.
- Reads from the same snapshot view (REPEATABLE READ).
- Writes nothing — opens a transaction, runs the engine, rolls
  back.
- Returns the diff (`affected_count`, `sample_certs`,
  `would_flip_count`, `would_newly_assign_count` for ownership;
  `effective_rules`, `would_violate_count` for policy).
- Emits **no** audit row. Preview is read-only by definition.
- Caps response size; large diffs paginate via `cursor`.

The preview endpoint is the **primary safety mechanism** for
operator rollouts at fleet scale. CLAUDE.md §7.1
(operator-controlled) makes "no surprises before commit" a hard
requirement.

### 7.14 Error envelope additions

All within the existing canonical envelope. New codes:

| Code                              | HTTP | Meaning                                                              |
| --------------------------------- | ---- | -------------------------------------------------------------------- |
| `tag_in_use`                      | 409  | Cannot disable a tag still attached to targets.                       |
| `service_in_use`                  | 409  | Cannot disable a service still referenced by ownership rules / overrides. |
| `service_group_has_children`      | 409  | Cannot disable a group with active children.                          |
| `ownership_rule_cycle`            | 400  | (Reserved — rule sets cannot self-reference; placeholder.)            |
| `service_group_cycle`             | 400  | Proposed parent would create a cycle.                                 |
| `policy_definition_in_use`        | 409  | Cannot disable a published policy with active assignments.            |
| `policy_waiver_expired_required`  | 400  | Waiver `expires_at` is required and must be > now.                    |
| `ownership_recompute_in_progress` | 409  | Concurrent recompute for the same org; retry-able.                    |
| `policy_recompute_in_progress`    | 409  | Same as above for policy recompute.                                   |

All additive per CLAUDE.md §17.

### 7.15 Audit policy across endpoints

- All state-changing endpoints write exactly one audit row per
  call (or one per item created), inside the same transaction
  as the change. Audit-write failure → 500 (CLAUDE.md §9).
- All read endpoints, including `*/preview`, write **no** audit
  rows.
- Severity `"security"` is set on every governance state change
  (ownership flips, override grants, rule changes, policy
  changes, waiver grants/clears/expiries).

---

## 8. Operational workflows

The workflows below assume the H-026B–H-026D phases are in
place; H-026A ships only the storage foundations.

### 8.1 First deployment across 2,000 servers

1. Admin creates baseline deployment package (existing v0.1
   flow). Agents enroll, heartbeat, ingest cert inventory.
2. Admin runs `POST /ownership/recompute` (or waits for the
   scheduler). With zero rules, every cert resolves to
   `decision = 'unowned'`. The dashboard shows
   `GET /ownership/unowned` with 50k entries.
3. Admin creates a fallback ownership rule (precedence_tier =
   `fallback`) pointing at a `platform-default` service. Reruns
   recompute. All 50k certs flip to `matched`/`fallback`.
4. Admin creates services for known business areas (`billing`,
   `checkout`, `identity-svc`, …) and ownership rules with
   higher tiers (`san_pattern`, `subject_pattern`). For each
   rule, runs `POST /ownership-rules/preview` BEFORE creating
   it. The preview shows the affected certs; admin confirms.
5. After preview, admin creates the rules. The next recompute
   flips matched certs from `platform-default` to the
   per-service owner. Audit rows surface every flip.
6. Admin runs `GET /ownership/ambiguous` to find certs matched
   by multiple equal-precedence rules. Resolves via priority
   adjustment or override.

### 8.2 Bulk classification (tagging at scale)

1. Operator wants to tag every cert observed in
   `LocalMachine\WebHosting` with `env=prod`.
2. v0.x: `POST /tags` with `{key: env, value: prod}`. Then bulk
   assignment via a future endpoint
   `POST /tags/{id}/bulk-assign-by-filter` (H-026C+).
3. H-026A's tag_assignments shape supports the bulk endpoint
   landing later as a single SQL `INSERT … SELECT` query
   without schema changes.

### 8.3 Unknown-owner triage

1. Operator opens `GET /ownership/unowned`. Sample:
   ```
   { items: [{cert: "...", subject: "CN=foo-legacy-01.corp.example", first_seen_at: "...", observation_count: 1}, ...]}
   ```
2. For each cert, operator inspects the explanation
   (`GET /certificates/{id}/ownership/explanation`) to see what
   signals were available and which rules were close to
   matching.
3. Operator creates a targeted ownership rule (or override the
   specific cert) and runs recompute.

### 8.4 Onboarding a new service / team

1. Admin runs `POST /services` with `{slug: payments-mobile,
   display_name: "Payments Mobile", owner_team: "payments-mobile-team"}`.
2. Admin runs `POST /service-groups/{id}/services` to nest the
   service under `Payments`.
3. Admin runs `POST /ownership-rules/preview` to see which certs
   the new rule (e.g., `san_glob: "*.pm.corp.example"`) would
   claim.
4. Admin runs `POST /ownership-rules` to commit. Next recompute
   flips matched certs to the new owner; audit rows record
   every flip.
5. Service-owner finds findings in
   `GET /findings?owner_service_id=...` after the H-026D
   findings recompute completes (≤ one cycle later).

### 8.5 Rule preview before activation

Already covered in §7.5. The contract: every rule create / edit
SHOULD be preceded by a `*/preview` call. The UI guides the
flow; the API does not enforce it (operators may script bulk
rule creation against the preview semantics).

### 8.6 Ownership conflict resolution

When `decision = 'ambiguous'`:

1. Operator opens the cert's explanation.
2. The losing_rules JSON shows every rule that matched at the
   same priority.
3. Operator either:
   - Adjusts priority on one of the rules (raising or
     lowering its precedence).
   - Creates a more specific rule (higher tier) that wins.
   - Sets an explicit override (`POST /certificates/{id}/ownership/override`).
4. Next recompute resolves the ambiguity. Audit row records the
   transition.

### 8.7 Owner change

An operator can change ownership three ways:

- **Rule edit:** modify priority / match_value / service_id on
  an ownership_rule. Recompute flips affected certs.
- **Override:** pin a specific cert to a specific service via
  `POST /certificates/{id}/ownership/override`. Always wins.
- **Service rename / move:** moving a service between groups
  does not change cert ownership — the cert still points at
  the service id; only the scope chain (and thus effective
  policy) changes.

### 8.8 Policy rollout

1. Admin authors a policy via `POST /policies` with the desired
   rules.
2. Admin runs `POST /policies/preview` against a representative
   scope (e.g., the `payments` service group) to see the
   violation count and sample violations.
3. Admin reviews violations with service owners. Grants waivers
   for known exceptions via `POST /policy-waivers` with
   `expires_at`.
4. Admin commits the assignment via `POST /policy-assignments`.
   Findings recompute (next tick or operator-triggered) emits
   `policy_*` findings for residual violations.
5. Service owners triage findings via the standard
   acknowledge/suppress workflow.

### 8.9 Policy exception / waiver

1. Service owner reports a temporarily-unfixable violation.
2. Governance reviewer creates a waiver via
   `POST /policy-waivers` with `expires_at` ≤ 90 days and a
   `reason`.
3. Next findings recompute observes the waiver and removes the
   affected finding (or marks it `acknowledged_by_waiver`).
4. When `expires_at` hits, the next recompute removes the
   waiver effect and re-emits the finding. Audit row records
   `policy_waiver.expired`.

### 8.10 Rogue certificate investigation

1. Operator searches `GET /certificates?q=` with substring or
   uses `GET /findings?rule_id=policy_allowed_issuers` for
   findings.
2. Looks up cert ownership; sees `decision = 'unowned'` or
   `'ambiguous'`.
3. Inspects observations to find which agents observed it and
   when.
4. Cross-references with `GET /agents/{id}/groups` to identify
   the hosting infrastructure.
5. Either declares it rogue (a finding to be investigated) or
   pins it to a service via override + opens a remediation
   ticket.

### 8.11 Governance review

1. Reviewer runs `GET /audit/events?action=ownership.* &since=...`
   to see ownership state changes in a period.
2. Cross-references with
   `GET /governance/recompute-runs?kind=ownership` for the
   per-pass summary.
3. Inspects specific certs via the explanation endpoint as
   needed.

### 8.12 Expired ownership metadata

Stale ownership: `last_evaluated_at` more than N days old.
Causes:
- Cert no longer observed by any agent (all observations
  `removed_at IS NOT NULL`).
- All ownership rules pointing at the cert were disabled.
- The owning service was disabled.

`GET /ownership/stale?older_than=7d` surfaces these. Operator
either removes the cert from inventory (out of v0.x — inventory
retention is currently forever) or assigns a new owner.

### 8.13 Stale agents

An agent that has not heartbeat in N days:
- Its observations still exist, but `last_seen_at` ages.
- Its memberships in agent groups remain valid for ownership
  inference until the operator removes them.
- The recompute treats the cert's owner as unchanged; freshness
  is a separate concern surfaced via heartbeat-driven views.

---

## 9. Safety, correctness, and scaling

### 9.1 Deterministic rule evaluation

- Engine version is pinned at composition root; every
  recompute carries the version on every explanation row.
- Rule evaluation order is **fully** deterministic: tier →
  priority → created_at → id. No randomness, no hash-map
  iteration order escapes.
- Pure decision functions (`decideOwnership`, `decidePolicy`)
  are unit-tested as functions of `(prior, signals, rules,
  policies, waivers, now)`.

### 9.2 No silent ownership flips

- Every flip writes an audit row inside the recompute
  transaction.
- Same-decision recomputes do **not** write an audit row but
  DO bump `last_evaluated_at`.
- A flip caused by rule disable/enable is audited the same way
  as a flip caused by rule edit.

### 9.3 Auditability

- All state changes severity:"security" per CLAUDE.md §9.
- Audit metadata redaction (logger §6.9 allow-list) — operator
  free-text `reason` fields are persisted but logged with
  length only, not content. Same posture as findings overrides.

### 9.4 Replay / recompute

- Ownership recompute is idempotent against unchanged inputs.
  Pinned by a byte-identical equivalence test (same pattern as
  H-024B).
- Replays at the same `now` are no-ops (`unchanged = N`).
- Replays at a later `now` may re-evaluate waiver expiry —
  expected.

### 9.5 Stale matches, disabled rules

- Disabled rules are excluded from the engine but kept for
  FK referential integrity.
- A disabled rule causes its dependent certs to flip on the
  next recompute. Audited.

### 9.6 Cross-org isolation

- Every table carries `organization_id`.
- Every FK is composite `(organization_id, foreign_id)` — the
  H-009 cross-org safety pattern.
- Every list / read endpoint scopes by the authenticated user's
  org; cross-org ids → `404 not_found`.

### 9.7 Concurrent updates

- `WithTxLockedOwnership(orgID)` serializes recomputes per-org.
- Operator writes to ownership_rules / overrides / assignments
  / waivers do NOT take the recompute lock — they are
  single-row writes with their own row-level locking.
- A recompute that runs while an operator is editing a rule
  sees the rule's state at the snapshot moment (REPEATABLE
  READ); the next recompute sees the updated state.

### 9.8 Performance at enterprise scale

Targets (planning anchors, not SLO commitments — same posture
as [`H024_PERFORMANCE_PLAN.md`](./H024_PERFORMANCE_PLAN.md) §3):

| Dimension                            | v0.x pilot | Fleet target |
| ------------------------------------ | ---------- | ------------ |
| Ownership rules per org              | ≤ 500      | ≤ 5,000      |
| Services per org                     | ≤ 200      | ≤ 1,000      |
| Service groups per org               | ≤ 50       | ≤ 200        |
| Tag assignments per org              | ≤ 100k     | ≤ 500k       |
| Ownership recompute wall-clock       | < 10s      | < 60s        |
| `GET /certificates?owner_*` p95      | < 250ms    | < 500ms      |
| Ownership preview wall-clock         | < 5s       | < 30s        |
| Policy preview wall-clock            | < 5s       | < 30s        |

The streaming pass under REPEATABLE READ matches H-024B's
shape, so the same perf assumptions hold. The recompute is
read-heavy on `certificates`, `certificate_observations`,
`tag_assignments`, `agent_group_memberships`, and
`ownership_rules`; write-heavy only on changed rows of
`certificate_ownership` and `ownership_match_explanations`.

### 9.9 Backfill safety

- The H-026A migration is purely additive: new tables, no
  changes to existing columns.
- H-026A ships **no engine** — the new tables are empty.
- H-026B turns the engine on. The first recompute pass on an
  installed deployment finds every cert at `decision =
  'unowned'`. Operators introduce rules at their own pace; no
  bulk owner is auto-applied.
- This is the explicit "no surprises on first deploy"
  property. The same pattern findings used (recompute is
  opt-in, then scheduled).

### 9.10 Operational rollback

- Each phase (H-026A–H-026D) is an additive migration; rollback
  is achieved by code rollback only (data persists, but the new
  code paths no longer read it).
- Disabling the ownership scheduler via
  `ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED=false` (a new env
  per CLAUDE.md §8.9) halts background recomputes without
  database changes.
- Operator-triggered recompute remains available for manual
  testing even when the scheduler is disabled.

### 9.11 Migration strategy

| Phase    | DB migration                               | Rollback                                                  |
| -------- | ------------------------------------------ | --------------------------------------------------------- |
| H-026A   | `0009_trust_governance.sql` (additive)     | None needed; tables stay, code doesn't use them.          |
| H-026B   | (no new migration)                         | Disable scheduler env knob.                                |
| H-026C   | (no new migration)                         | Code rollback; assignment / rule rows linger harmlessly.   |
| H-026D   | `0010_findings_governance_columns.sql`     | Additive columns nullable; code rollback ignores them.   |

No destructive migrations anywhere. CLAUDE.md §16's two-phase
destructive-migration rule does not apply because nothing is
ever dropped.

### 9.12 Preview-before-apply

Already covered in §7.13. The contract is **the** primary safety
mechanism for high-blast-radius operator actions:

- Ownership rule creation / edit: preview shows affected certs.
- Policy assignment: preview shows violation count.
- Tag bulk assignment (future): preview shows targets.

The preview transaction:
1. Acquires NO advisory lock (read-only).
2. Opens REPEATABLE READ.
3. Inserts the proposed row into an in-memory rule set (not the
   DB).
4. Runs the engine with that synthetic set.
5. Returns the diff vs. the current `certificate_ownership` /
   `findings` state.
6. Rolls back.

---

## 10. Risks and mitigations

| Risk                                                          | Severity | Mitigation                                                                                                                |
| ------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------- |
| Ownership-rule explosion (operators write rule per cert)      | high     | Preview workflow + UX guidance; ambiguity surfacing; precedence tiers that favor inheritance over per-cert rules.          |
| Policy explosion (per-cert policies)                          | high     | Cert-scope assignments are validator-restricted (§5.5); waivers are the loosen-mechanism, not assignments.               |
| Silent ownership flips                                        | high     | Every flip writes severity:"security" audit row; same-decision recomputes do not flip; ambiguity surfacing forces review. |
| Non-deterministic engine                                      | high     | Pure decision functions; tiebreaker chain; engine_version on every explanation; byte-identical equivalence tests.         |
| Cross-org leakage                                             | critical | Composite FKs throughout; service-layer scope check on every polymorphic target; cross-org → 404 posture.                  |
| Recompute pass blocks operator writes                         | medium   | Advisory lock is per-org and only for the recompute pass; CRUD writes are row-level locks.                                |
| Stale explanations referencing disabled rules                 | low      | Soft delete + FK ON DELETE RESTRICT; explanations remain valid.                                                          |
| Tag / target FK integrity (polymorphic target)                | medium   | Validator on every assignment write; integration tests cover the cross-table dispatch.                                  |
| Migration concurrency on installed DB                         | low      | Additive-only; migration tool already serializes per CLAUDE.md §16.                                                       |
| Preview/apply skew (preview shows X, apply does Y)            | medium   | Preview and apply share the same engine code path under the same REPEATABLE READ snapshot model.                          |
| Findings recompute slowed by ownership lookup                 | medium   | Ownership snapshot is loaded once per findings pass; map lookup is O(1) per cert.                                          |
| Engine version drift (old explanations rendered with new engine) | low    | `engine_version` is stored per explanation; the renderer reads the field and adapts.                                        |
| Concurrency: rule edit during recompute                       | low      | REPEATABLE READ snapshot; next recompute picks up the change.                                                              |
| Audit-event amplification (rule churn on bad rule)            | medium   | Same risk as H-019 (cert ingestion); the audit redaction allow-list keeps text bounded; rate-limit is a v0.x concern.    |

---

## 11. Phased roadmap

### 11.1 H-026A — Storage & vocabulary foundations

**Goal:** lay down the data model and minimal CRUD without
activating the inference engine.

**Migration:** `0009_trust_governance.sql` — all tables in §3.
Each table carries inline index intent per CLAUDE.md §16.

**Code (domain):**

- `internal/identity/` package: types, repository interface,
  service with CRUD for tags, services, service groups, agent
  groups, and their assignment / membership tables.
- `internal/governance/` package skeleton: types, repository
  interfaces for ownership_rules, certificate_ownership,
  certificate_ownership_overrides, ownership_match_explanations,
  policy_definitions, policy_assignments, policy_waivers,
  governance_recompute_runs. NO engine implementation.
- `internal/storage/postgres/`: repository implementations for
  the new tables.
- `internal/httpapi/handlers/`: CRUD handlers for tags,
  services, service groups, agent groups. NO ownership /
  policy handlers (those require the engine).

**Tests:**

- Unit tests for service-layer validators (slug rules,
  service_group cycle detection, polymorphic target dispatch).
- Integration tests for each CRUD endpoint, cross-org isolation,
  soft-delete behavior, audit row emission.

**Out of scope for H-026A:**

- Engine code (ownership inference, policy resolution).
- Recompute scheduler.
- `*/preview` endpoints.
- Ownership / policy override and waiver handlers (rows can be
  written via the repository layer for tests, but no HTTP
  surface yet).
- Findings integration.

**LOC budget:** < 1000 LOC including tests. PR title:
`feat(governance): trust governance storage foundations`.

**Reversibility:** complete. Tables are empty; no code reads
them outside the test suite.

### 11.2 H-026B — Ownership inference engine

**Goal:** turn on the engine with preview and explanation APIs.
Dry-run mode default; opt-in to background scheduler.

**Code:**

- `internal/governance/ownership/`:
  - `rules.go` — rule type, match predicates.
  - `precedence.go` — tier enum, tiebreaker.
  - `engine.go` — streaming pass under
    `WithTxLockedOwnership(orgID)` + REPEATABLE READ.
  - `explanation.go` — winning rule + losing-rules snapshot.
  - `service.go` — orchestrator (recompute, preview,
    `applyOverride`).
- `internal/storage/postgres/postgres.go`:
  new `WithTxLockedOwnership` helper (session-scope advisory
  lock, `('ownership-recompute', orgID)` namespace).
- `internal/governance/ownership/scheduler.go`: sibling of
  `findings.Scheduler`. Owns one goroutine, per-org sweep,
  panic-recovery, structured logs. Disabled by default in
  H-026B; enabled per env knob.
- `internal/config`: new knobs
  `ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED` (default `false`)
  and `ANCHORIX_GOVERNANCE_SCHEDULER_INTERVAL` (default `1h`).

**API surface:**

- `POST /api/v1/ownership-rules` + read endpoints (preview is
  the principal write surface, but rule create / disable /
  enable are now exposed).
- `POST /api/v1/ownership-rules/preview`.
- `GET /api/v1/certificates/{id}/ownership`.
- `GET /api/v1/certificates/{id}/ownership/explanation`.
- `POST /api/v1/certificates/{id}/ownership/override`.
- `DELETE /api/v1/certificates/{id}/ownership/override`.
- `POST /api/v1/ownership/recompute`.
- `GET /api/v1/ownership/unowned`, `/ownership/ambiguous`,
  `/ownership/stale`.

**Tests:**

- Pure-function tests for `decideOwnership` over a fixture-built
  cert + signal set.
- Integration test: byte-identical equivalence between a
  "load-all" reference implementation and the streaming engine.
- Integration test: snapshot isolation under concurrent
  ingestion (H-024B pattern).
- Integration test: preview/apply consistency (preview shows X,
  apply produces X).
- Integration test: ambiguous match surfaces correctly.
- Integration test: override always wins.
- Audit test: every state-changing endpoint writes exactly one
  row with severity:"security".

**LOC budget:** < 1500 LOC. Split if larger.

**Reversibility:** disable scheduler env knob halts background
recomputes; manual `POST /ownership/recompute` still works for
diagnostics.

### 11.3 H-026C — Operator workflows

**Goal:** complete the operator-facing surface for tags,
services, and policy authoring; ship the bulk-assignment
ergonomics.

**Code:**

- Bulk tag-assignment endpoint (`POST /tags/{id}/bulk-assign-by-filter`).
- Service group endpoints (write surface for nesting, ancestor
  reads).
- Policy definition + assignment + waiver write endpoints (still
  inert — no engine evaluating them yet).
- Policy preview endpoint (returns the merged-effective rules
  without evaluation against certs).

**No engine** for policy evaluation in H-026C — the API surface
lands first so operators can author policies while H-026D
implements the violation engine.

**LOC budget:** < 1000 LOC.

### 11.4 H-026D — Findings & policy integration

**Goal:** the findings recompute starts emitting policy
violations as findings; existing finding rows get denormalized
owner attribution.

**Migration:** `0010_findings_governance_columns.sql` — additive
columns on `findings` (`owner_service_id`, `owner_decision`,
`policy_violations`).

**Code:**

- `internal/governance/policy/resolver.go`: scope-chain walk,
  merge rules, apply waivers.
- `internal/governance/policy/engine.go`: streaming pass over
  certs (sharing the H-024B page-streaming model), emit
  violations.
- `internal/findings`: enrichment step in the existing
  recompute pass — read ownership snapshot, write
  denormalized columns, write `policy_*` findings.

**API surface:**

- `POST /api/v1/policies/recompute`.
- `GET /api/v1/policy-violations` (a filtered view over
  `findings`).
- Additive query params on `GET /findings`:
  `owner_service_id`, `owner_decision`, `policy_definition_id`,
  `policy_rule_local_id`.

**LOC budget:** < 1500 LOC.

### 11.5 Why this split

The split mirrors the H-024 split rationale: the highest-risk
code (the engine) lives alone in H-026B so review attention
concentrates there. H-026A is "schema + vocabulary" with no
behavior. H-026C is "operator paperwork" with no engine
changes. H-026D is "integration with the existing findings
pipeline" with the engine already proven by H-026B.

Each phase passes its own correctness bar before the next
begins. No phase is blocked on a future phase; H-026A could
ship alone and the platform is unchanged operationally.

---

## 12. Open questions

These do **not** block the design from merging; the
implementation PRs should resolve each before locking the wire.

1. **Direct service membership (precedence tier 2).** The tier
   is reserved but unused in H-026A. Should H-026B implement it
   via a separate `service_memberships` table
   `(service_id, certificate_id)`, or should it be expressed as
   an `ownership_rule` with `match_kind = 'direct_assignment'`?
   Suggestion: drop the tier from H-026B and revisit if
   operators ask for it. Direct assignment is an override in
   practice.

2. **Tag-as-ownership-signal precedence vs. tag-as-classification.**
   The model puts tags at tier 6. A common operator request will
   be "the `service:billing` tag means billing owns this." Should
   that be sugar around an ownership rule or a separate
   first-class mechanism? Suggestion: it stays as a rule —
   the operator can do `POST /ownership-rules { match_kind: 'tag',
   match_value: 'service:billing', service_id: <billing> }` —
   no schema change.

3. **Multi-parent service groups.** Phase deferred. The schema
   permits a future migration. Suggestion: defer until at least
   two operator deployments hit the constraint.

4. **Waiver-by-default vs. acknowledged-by-waiver finding state.**
   When a waiver applies to a finding, should the finding be:
   (a) suppressed by the recompute (similar to operator
   suppress), (b) hidden entirely, or (c) emitted with
   `status = 'waived'`? Suggestion: option (c) — a new status
   value `waived` on findings, additive per CLAUDE.md §17.
   Operators retain visibility; the dashboard filters can hide
   `status=waived` by default.

5. **Stale-ownership threshold.** Should be configurable
   (env knob) or stored per-org? Suggestion: env knob initially;
   per-org config when multi-tenancy lands.

6. **Engine version bumps.** When the engine logic changes
   (e.g., a new precedence tier inserted), should the recompute
   on the next deploy force-flip every cert through a full
   re-evaluation? Suggestion: yes, the first recompute after a
   version bump treats every cert as potentially changed; the
   audit volume is bounded by changed-only-on-real-change in
   the comparison step. Documented in CHANGELOG when the
   version bumps.

7. **Preview cap.** `*/preview` endpoints return `affected_count`
   exactly but cap `sample_certs` at the limit. Should the cap
   be configurable? Suggestion: hard-cap at 200 (same as
   `limit` ceiling on list endpoints). Operators paginate via
   `cursor`.

8. **Policy waiver max TTL.** Should there be a hard upper bound
   on `expires_at - now` (e.g., 365 days)? Suggestion: yes,
   `ANCHORIX_POLICY_WAIVER_MAX_TTL` defaulting to 365 days.
   Renewing a waiver is a separate audited action.

9. **Ownership recompute cadence.** Findings is 6h. Ownership
   could be faster (1h?) because rule edits are operator-driven
   and operators expect quick feedback. Suggestion: 1h default.
   Configurable.

10. **`certificate_ownership` materialization vs. computed
    view.** Currently denormalized into a table. Alternative: a
    materialized view auto-refreshed by the recompute. The
    table approach is more explicit and matches the codebase's
    convention (no materialized views in v0.1). Suggestion:
    table. The trade-off is documented; revisit only if pilot
    measurements show it's a bottleneck.

---

## 13. Constraint check

The plan respects every binding constraint from the briefing
and CLAUDE.md:

- **CLAUDE.md §4 (v0.1 scope).** H-026 lands as v0.x evolution.
  Multi-tenancy stays out; single-org per process preserved.
- **CLAUDE.md §5 (architecture).** Modular monolith preserved;
  one new domain per concern (`identity`, `governance`); no
  microservices, no event bus, no Kubernetes.
- **CLAUDE.md §6 (security).** No private-key transport (the
  agent surface is unchanged). All governance state changes
  audited severity:"security". Cross-org isolation via composite
  FKs.
- **CLAUDE.md §8.4 (naming).** Every entity, function, and type
  is domain-explicit (`ownershipDecision`,
  `policyScopeChain`, `serviceClaim`). Forbidden generic names
  avoided.
- **CLAUDE.md §8.6 (decoupling).** New per-package boundaries
  declared in §2.2 narrow the existing §8.6 rules. Handlers do
  not touch SQL; governance does not import findings.
- **CLAUDE.md §8.8 (DI).** Constructor DI only; composition root
  in `cmd/anchorix/serve.go` wires everything explicitly.
- **CLAUDE.md §8.9 (config).** All new knobs centralized in
  `internal/config`; no scattered `os.Getenv`.
- **CLAUDE.md §8.10 (concurrency).** Scheduler goroutine has a
  documented owner, a cancellation path (`context.Context`),
  and a bounded lifetime. No fire-and-forget.
- **CLAUDE.md §9 (audit).** Every state change writes a row in
  the same transaction. Severity:"security" on all governance
  flows. No tokens / credentials / cert content in logs.
- **CLAUDE.md §10 (provider abstraction).** Future CMDB / AD
  integrations sit behind a provider interface (the existing
  `internal/providers/` shape extends naturally).
- **CLAUDE.md §11 (CI).** No new blocking checks; the existing
  gates (gofmt, vet, govulncheck, CodeQL, etc.) cover the new
  code without modification.
- **CLAUDE.md §16 (migrations).** Append-only. `0009` adds
  tables; `0010` adds nullable columns. No destructive moves.
- **CLAUDE.md §17 (API evolution).** Every new endpoint lives
  under `/api/v1`. Every new query param / field is additive.
  Existing routes' shapes do not change.
- **CLAUDE.md §18 (robustness).** Streaming pass under
  REPEATABLE READ; advisory locks; idempotent recompute;
  bounded retries; deterministic state transitions.
- **CLAUDE.md §19 (engineering discipline).** Every new package
  ships a `doc.go`; per-feature threat-model entries land
  alongside H-026B and H-026D in `docs/security/`; no
  TODO-driven architecture.

---

## 14. References

- [`CLAUDE.md`](../../CLAUDE.md) — engineering constitution.
- [`ROADMAP.md`](../../ROADMAP.md) — phase model; H-026
  positions after v0.1 ships.
- [`CERTIFICATE_INVENTORY.md`](./CERTIFICATE_INVENTORY.md) §3,
  §10 — inventory data model and scale assumptions.
- [`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §3,
  §5, §7, §8 — findings data model, recompute lifecycle,
  scheduler, override workflow that H-026 mirrors.
- [`H024_PERFORMANCE_PLAN.md`](./H024_PERFORMANCE_PLAN.md) §6,
  §9 — streaming-pass + REPEATABLE READ model that
  ownership/policy recompute reuses.
- [`HARDENING_BACKLOG.md`](./HARDENING_BACKLOG.md) — H-024 /
  H-025 entries; H-026 does not displace them.
- [`REST_API.md`](../api/REST_API.md) — wire contract that
  H-026 extends additively.
- [`docs/architecture/EVOLUTION.md`](../architecture/EVOLUTION.md)
  — v0.2 / v0.3 directional sketches; H-026 fits the v0.x
  governance arc.
- [`docs/architecture/PACKAGE_BOUNDARIES.md`](../architecture/PACKAGE_BOUNDARIES.md)
  — package-level forbidden-import rules H-026 honors.
- [`docs/engineering/AGENT_ENROLLMENT.md`](./AGENT_ENROLLMENT.md)
  — deployment-package model that already provides one
  classification signal (`group_name`) reusable by ownership
  rules.

## 15. Status

| Item                                   | Status                          |
| -------------------------------------- | ------------------------------- |
| H-026 plan (this doc)                  | **proposed (this PR)**          |
| H-026A — storage foundations           | not started                      |
| H-026B — ownership inference engine    | not started                      |
| H-026C — operator workflows            | not started                      |
| H-026D — findings & policy integration | not started                      |

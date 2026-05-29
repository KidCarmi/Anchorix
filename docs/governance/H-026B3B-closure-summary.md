# H-026B3B — Ownership Mutations: Phase Closure

> **Status:** closed / stable. Source of truth for rules:
> [`CLAUDE.md`](../../CLAUDE.md). Parent design:
> [`H026B_OWNERSHIP_ENGINE_PLAN.md`](../engineering/H026B_OWNERSHIP_ENGINE_PLAN.md),
> [`H026_TRUST_GOVERNANCE_PLAN.md`](../engineering/H026_TRUST_GOVERNANCE_PLAN.md).
> Threat model: [`H026B_OWNERSHIP_THREAT_MODEL.md`](../security/H026B_OWNERSHIP_THREAT_MODEL.md).

## 0. Merged PRs

| PR | Title | Class |
|----|-------|-------|
| #56 | H-026B3B PR-1 ownership rule mutations | feature |
| #57 | PR-1 hardening | test-only |
| #58 | H-026B3B PR-2 ownership override mutations + immediate single-cert re-derivation | feature |
| #59 | PR-2 hardening | test-only |

B3B is the **operator mutation surface** on top of the B3A read/visibility
surface and the B2 inference engine. It lets operators author the rules
the engine evaluates and pin individual certificates, with every change
audited and applied deterministically.

## 1. What B3B delivered

- **Ownership rule lifecycle** (PR-1): create / update / enable / disable
  operator-authored ownership rules, with full input validation and
  security audit. Identity-shaping fields (name, match_kind, service_id,
  tier) are immutable after creation; update mutates only priority /
  match_value / description.
- **Ownership override lifecycle** (PR-2): create / clear per-certificate
  operator overrides ("pins") with optional expiry, plus **immediate
  single-certificate re-derivation** so the cert's ownership reflects the
  pin (or its removal) before the response returns — no waiting for a
  recompute.
- **Single-cert re-derivation primitive** (`rederiveCertificate`): the
  standalone, bounded analogue of the streaming recompute's per-cert
  decision, reusing the same deterministic `decideOwnership` and §5.1
  state machine, with no fleet sweep.
- **Adversarial hardening** (PRs #57, #59): regression coverage for the
  validation matrix, audit atomicity, deterministic conflicts,
  PATCH-merge semantics, precheck→locked-tx race windows, and target-only
  re-derivation.

## 2. Endpoints added (B3B)

All operator-only; agent bearer credentials are not honored; org-scoped
on the authenticated session; registered only when
`ANCHORIX_GOVERNANCE_API_ENABLED` is true (otherwise 404).

| Method + path | Effect |
|---|---|
| `POST /api/v1/ownership-rules` | Create a rule (201). |
| `PATCH /api/v1/ownership-rules/{id}` | Update mutable fields (priority / match_value / description), PATCH-merge semantics. |
| `POST /api/v1/ownership-rules/{id}/enable` | Enable a rule (idempotent). |
| `POST /api/v1/ownership-rules/{id}/disable` | Disable a rule (idempotent). |
| `POST /api/v1/certificates/{id}/ownership/override` | Create an override + immediate single-cert re-derivation (201). |
| `DELETE /api/v1/certificates/{id}/ownership/override` | Clear the active override + immediate single-cert re-derivation. |

(The `GET` read views and `POST /ownership/recompute` were delivered in
B3A and are unchanged here.)

## 3. Audit actions added (all severity:"security", written in-tx)

| Action | Trigger |
|---|---|
| `ownership.rule_created` | Rule created. |
| `ownership.rule_updated` | Rule mutable fields changed. |
| `ownership.rule_enabled` | Rule enabled. |
| `ownership.rule_disabled` | Rule disabled. |
| `ownership.overridden` | Override created. |
| `ownership.override_cleared` | Override cleared by operator. |

Every successful mutation emits **exactly one** audit row; a failed or
rejected mutation emits **none**. (`ownership.override_expired` and the
`ownership.assigned/cleared/flipped/ambiguous_match` + `bulk_*`
transition rows are recompute-engine actions from B2, not B3B mutation
actions.)

## 4. Validation + error codes added

**Rule mutations** reject, before any write:

- reserved `service_member` tier → `ownership_rule_tier_reserved` (400)
- `explicit` tier / tier↔kind mismatch / unknown match_kind → `bad_request` (400)
- invalid or oversized (`> maxRegexPatternLen`) `san_regex` → `bad_request` (400)
- empty / oversized name, oversized description, out-of-range priority,
  fallback-with-value → `bad_request` (400)
- nonexistent / disabled target service → `ownership_rule_service_not_found` (400)
- nonexistent / disabled agent-group target → `ownership_rule_target_not_found` (400)
- duplicate `(org, name)` → `ownership_rule_conflict` (409)
- unknown / cross-org rule id (update/enable/disable) → `not_found` (404)

**Override mutations** reject:

- missing service / reason, oversized reason → `bad_request` (400)
- nonexistent / disabled pinned service → `ownership_override_service_not_found` (400)
- `expires_at` at or before now → `ownership_override_expiry_in_past` (400)
- nonexistent / cross-org certificate → `not_found` (404) (no enumeration)
- active override already exists → `ownership_override_conflict` (409)
- clear with no active override (incl. cross-org / already-cleared) → `not_found` (404)

Backing sentinels: `ErrInvalidRule`, `ErrServiceMemberReserved`,
`ErrRuleServiceNotFound`, `ErrRuleTargetNotFound`,
`ErrOwnershipRuleAlreadyExists`, `ErrInvalidOverride`,
`ErrOverrideServiceNotFound`, `ErrOverrideExpiryInPast`,
`ErrOverrideCertNotFound`, `ErrOverrideConflict`,
`ErrOwnershipOverrideAlreadyExists`.

## 5. Transaction / locking guarantees

- **Rule mutations** run in a plain `WithTx` (no recompute lock): they are
  single-row writes whose effect is applied by the next recompute under
  REPEATABLE READ. This is the documented eventually-consistent model
  (governance plan §9.7) — interactive rule editing is never blocked
  behind an in-flight sweep.
- **Override mutations** run under `WithTxLockedOwnership(org)` (xact-scope
  advisory lock): the override row write **+** the single-cert
  re-derivation **+** the security audit commit atomically and serialize
  against any in-flight full recompute (governance plan §3.9). The lock
  hold is bounded by single-cert work.
- **Audit atomicity**: in both paths the audit row is written inside the
  same transaction as the state change. An audit-write failure rolls the
  entire mutation back — proven by the hardening suite for create /
  update / enable / disable (rules) and create / clear (overrides),
  including the override's single-cert re-derivation rolling back too.
- **Immediate effect**: override create flips the target cert to
  `overridden`, and clear re-derives it from rules, before the response
  returns — verified against the persisted `certificate_ownership` row.

## 6. Cross-org isolation guarantees

- Every read and write binds the authenticated session's
  `organization_id`; there are no fleet-wide scans (target existence is a
  bounded single-row `SELECT EXISTS`; re-derivation reads one cert's
  signals via PK lookup).
- Cross-org rule / certificate / override ids collapse to `404 not_found`,
  never `403` — foreign-org existence cannot be enumerated. The override
  read and clear return the same shape for a foreign cert as for a wholly
  nonexistent one.
- Cross-org mutation attempts (create against a foreign service, or
  update / enable / disable / clear of a foreign rule or override) are
  rejected and leave the foreign-org rows and audit log untouched —
  pinned by tests.

## 7. Deterministic conflict semantics

- **Rule name conflict**: the `(organization_id, name)` unique constraint
  maps to `ErrOwnershipRuleAlreadyExists` → `409 ownership_rule_conflict`.
  Stable across repeated attempts; a disabled rule still holds its name
  (no resurrection by re-create).
- **Override conflict**: the active partial-unique index
  (`one active override per cert WHERE cleared_at IS NULL`) maps to
  `ErrOverrideConflict` → `409 ownership_override_conflict`. The index is
  the sole, race-proof gate — there is no pre-tx existence check to race
  against. A concurrent two-writer duplicate-create resolves to exactly
  one winner + one deterministic 409, never two active rows, never a 500.

## 8. Hardening coverage (PRs #57, #59)

**Rule mutations (#57):** PATCH omitted-field preservation + explicit
`priority:0` semantics; disabled service / disabled agent-group
rejection on create and update; audit rollback across create / update /
enable / disable; exactly-once security audit per mutation; no audit on
validation failure; duplicate conflict stability (incl. after disable);
malformed / trailing JSON rejection; unknown-field additive-evolution
behavior; deterministic error codes; cross-org isolation; auth 401 +
gate 404.

**Override mutations (#59):** active override appears in the
precheck→tx window (index gate, loser rolls back, no audit); concurrent
duplicate create (exactly-one-winner determinism, no 500); override
cleared/auto-expired in the clear window (zero-row guard → 404, no
audit); pinned service disabled in the window (documented
eventual-consistency: the override commits — an explicit pin outranks a
late service-disable); cert deleted in the window (FK-cascade aborts the
INSERT; full rollback) plus a white-box unit test driving
`rederiveCertificate`'s missing-signals fail-closed branch directly;
target-only re-derivation across 50 certs (no fleet sweep).

All verified against PostgreSQL 16 with the full integration suite green.

## 9. Explicitly out of scope for B3B

- **Preview / apply** ("what would this rule/override change?" dry-run) —
  B3C.
- **Scheduler / background recompute loop** — B4 (the engine's
  `RecomputeScheduled` entry point exists but no loop wires it; the
  scheduler ships dark-by-default).
- **Findings enrichment / policy violation emission** — H-026D.
- **Policy definitions / assignments / waivers** mutations — H-026D.
- **UI / frontend, notification channels** — out of v0.x.
- **Multi-org / multi-tenancy** beyond single-org session scoping.
- **Override auto-expiry execution** is a recompute-engine concern (B2),
  not a B3B mutation; B3B only rejects operator-supplied past expiries
  and frees the slot on clear.

## 10. Remaining backlog / next-phase candidates

Existing governance backlog items (unchanged, none blocking):

- **H-027** — `ownership_match_explanations` retention sweep.
- **H-029** — paginate `ListOverridesExpiringBy`.
- **H-030** — collation-independent recompute stream merge (unreachable
  with server-minted hex ids; documented).

Next-phase candidates (sequenced; do **not** start yet):

- **B3C — Preview / Apply**: dry-run diff of a proposed rule/override
  against current ownership before commit.
- **B4 — Ownership scheduler**: dark-by-default background recompute loop
  (sibling of the findings scheduler), wiring the existing
  `RecomputeScheduled` entry point.
- **H-026D — Findings & policy integration**: owner enrichment on
  findings + policy violation engine.

## 11. Stability verdict

**B3B is stable.** The operator mutation surface for ownership rules and
overrides is complete, validated fail-closed, deterministically
conflict-handled, transactionally atomic with its security audit,
org-isolated with no enumeration, and free of fleet-wide scans. Both
feature PRs were followed by dedicated adversarial hardening passes whose
findings were resolved, and the full integration suite is green against
PostgreSQL 16. No known correctness or security gap remains in the B3B
surface. The ownership engine (B1→B3B) is ready for the operational
layers (B3C preview, B4 scheduler) and the H-026D integration phase to
build on top.

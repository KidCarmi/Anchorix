# H-026B — Ownership Inference Engine: Implementation Plan

> **Status:** design / planning only. **No code in this PR.**
> Source of truth for rules: [`CLAUDE.md`](../../CLAUDE.md). Parent
> design: [`H026_TRUST_GOVERNANCE_PLAN.md`](./H026_TRUST_GOVERNANCE_PLAN.md)
> (this plan refines §2.5, §3.7–§3.10, §3.14, §4, §7.5–§7.6, §7.11,
> §9, §11.2 into an implementable, multi-PR sequence). Where this
> plan and the parent disagree on a detail, this plan is the more
> recent and the parent should be revised to match before H-026B
> merges; where either disagrees with CLAUDE.md, CLAUDE.md wins.

---

## 0. What H-026B is, precisely

H-026B turns on the **ownership inference engine** that A1–A3
prepared the schema, repositories, types, and package skeleton for.
After A1–A3 the `ownership` package contains only `doc.go`. H-026B
fills it with the deterministic engine, the recompute orchestration,
the preview path, the explanation snapshot writer, the background
scheduler, and the operator-facing ownership HTTP surface.

**H-026B owns:**

- the pure decision functions (`decideOwnership`, `applyTiebreaker`)
- the streaming recompute pass under a new
  `WithTxLockedOwnershipRepeatableRead` advisory-lock helper
- preview (dry-run, no writes, no audit)
- override apply (single-cert immediate effect)
- explanation snapshot writing
- the ownership scheduler (sibling of `findings.Scheduler`)
- the ownership read + write HTTP handlers

**H-026B explicitly does NOT touch** (boundary discipline,
CLAUDE.md §8.6, parent §2.2):

- `internal/findings` — no enrichment, no `owner_*` columns. That is
  H-026D. The engine never imports `findings`.
- `internal/governance/policy` — policy resolution + violation
  emission is H-026D. The `policy` package stays a `doc.go` skeleton.
- `internal/identity` write semantics — identity CRUD shipped in
  A2 and is consumed read-only here.
- the `service_member` precedence tier (reserved tier 2). H-026B
  ships it as a **gap in the ladder, never matched** (see §5.4 and
  open question OQ-1). No `service_memberships` table is created.
- any new migration. A1 already shipped `0010_governance_ownership.sql`.
  H-026B is code-only; rollback is the scheduler env knob (§10).

---

## 1. Proposed files and packages

```
backend/internal/governance/ownership/   (currently doc.go only)
  doc.go                 (exists — boundary already declared)
  signals.go             NEW — CertificateSignals value + consumer-owned reader interfaces
  rules.go               NEW — compiledRule, match predicates (glob/regex/agent-group/tag/...)
  precedence.go          NEW — tier ordinal + applyTiebreaker (pure)
  engine.go              NEW — decideOwnership (pure) + streaming recompute orchestration
  explanation.go         NEW — losingRules / signalsSeen JSON builders, engineVersion const
  override.go            NEW — single-cert override apply + auto-expiry handling
  preview.go             NEW — dry-run diff over synthetic rule set
  service.go             NEW — Service: Recompute / RecomputeScheduled / Preview / ApplyOverride / ClearOverride + read methods
  scheduler.go           NEW — sibling of findings.Scheduler
  errors.go              NEW — sentinel errors (ErrOwnershipRecomputeInProgress, ErrOverrideConflict, ...)
  *_test.go              NEW — pure-function + table-driven tests

backend/internal/storage/postgres/
  postgres.go            EDIT — add WithTxLockedOwnership + WithTxLockedOwnershipRepeatableRead
  governance_ownership_repository.go  EDIT — add the engine-walk + signal-load + paged-cert-ownership methods (§4)

backend/internal/governance/
  repository.go          EDIT — extend OwnershipRepository interface with the new methods (§4)
  engine_signals.go      NEW (optional) — shared signal struct if it must be visible to postgres scans

backend/internal/httpapi/handlers/
  ownership_rules.go     NEW — rule CRUD + preview handlers
  ownership_certificate.go NEW — per-cert read / explanation / override handlers
  ownership_views.go     NEW — unowned / ambiguous / stale / recompute / recompute-runs handlers

backend/internal/httpapi/
  router.go              EDIT — route registration (gated by ANCHORIX_GOVERNANCE_API_ENABLED, already exists)

backend/internal/config/
  config.go              EDIT — ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED (default false),
                                ANCHORIX_GOVERNANCE_SCHEDULER_INTERVAL (default 1h),
                                ANCHORIX_OWNERSHIP_BULK_AUDIT_THRESHOLD (default 500),
                                ANCHORIX_OWNERSHIP_STALE_THRESHOLD (default 168h)

backend/cmd/anchorix/serve.go
                         EDIT — construct ownership.Service + ownership.Scheduler, mount handlers

backend/test/integration/
  ownership_recompute_test.go     NEW — equivalence, snapshot isolation, audit atomicity
  ownership_override_test.go      NEW — override precedence + expiry
  ownership_preview_test.go       NEW — preview/apply consistency

docs/security/
  H026B_OWNERSHIP_THREAT_MODEL.md NEW — required by CLAUDE.md §6.10 / §19 before merge
```

`signals.go` is the single most important new boundary artifact: it
declares the **consumer-owned reader interfaces** the engine needs
from inventory + identity, so `ownership` never imports `inventory`
or `identity` (parent §2.2). See §3.

---

## 2. Engine data flow

```
                 ANCHORIX_GOVERNANCE_SCHEDULER_*          POST /ownership/recompute
                          │                                        │
                          ▼                                        ▼
                 ownership.Scheduler ───────────► ownership.Service.Recompute(orgID, actor)
                                                            │
        ┌───────────────────────────────────────────────────┘
        ▼
  WithTxLockedOwnershipRepeatableRead(orgID)         ← session-scope advisory lock,
        │                                               REPEATABLE READ snapshot
        │  Phase 1  load rules (engine-walk order)   ← OwnershipRepository.ListOwnershipRulesForEngine
        │           compile predicates once          ← rules.go (regex compiled here, cached)
        │           load org fallback rule (≤1)
        │
        │  Phase 2  StartRecomputeRun (Succeeded=nil) ← GovernanceRecomputeRunsRepository.StartRecomputeRun
        │
        │  Phase 3  stream certs by id ASC (page 500) ← OwnershipSignalReader.ListCertificateSignalsPaged
        │           per cert:
        │             active override? ──────────────► tier 1 (explicit)
        │             else decideOwnership(signals, compiledRules, now)  [PURE]
        │             read prior ownership row        ← per-page batch GetCertificateOwnershipPaged
        │             diff prior vs decided:
        │               unchanged → bump last_evaluated_at, counter[unchanged]++
        │               changed   → INSERT explanation, UPSERT ownership,
        │                           accumulate audit intent (per-cert OR bulk)
        │             auto-expire overrides whose expires_at <= now
        │
        │  Phase 4  flush audit (per-cert rows below threshold; rollup above)
        │           FinishRecomputeRun (counters, Succeeded=true)
        │           ONE governance.recomputed audit row
        ▼
     COMMIT  (audit + state + run in one tx; any failure → full rollback)
```

The preview path (§7) reuses Phases 1+3 with a **synthetic** rule
set, computes the diff against current state, and **rolls back** —
no run row, no audit, no advisory lock (read-only).

The override apply path (§8) is a *single-cert* slice of Phase 3
under `WithTxLockedOwnership` (READ COMMITTED, xact-scope — single
row, no snapshot needed, mirrors `findings.applyOverride`).

---

## 3. Repository gaps (must be closed in H-026B, the largest hidden cost)

The A1 `OwnershipRepository` is CRUD-shaped. The engine needs reads
that **do not exist yet**. Closing these is the single biggest source
of LOC and risk, and drives the PR split (§13).

### 3.1 Signal loading — the N+1 trap

`CertificateSummary` (inventory) carries **no SANs, no observations,
no observing agents**. Per-cert tag/agent-group lookups via the A2
`identity.Repository` (`ListTagAssignmentsForTarget`,
`ListGroupsForAgent`) are **per-target** calls. Running them per cert
for 50k certs is a 150k+ query N+1 — it blows the < 60s fleet target
(parent §9.8) out of the water.

**Required: a paged signal join.** Add to `OwnershipRepository`
(consumer interface owned by the `ownership` package via a narrow
re-declaration in `signals.go`, implemented in
`governance_ownership_repository.go`):

```go
// Returns one page of per-cert ownership signals, id ASC,
// cursor by certificate id, capped at pageSize. Each row carries
// everything decideOwnership needs so the engine makes ZERO
// per-cert follow-up queries. The join is done in SQL once per
// page, not per cert.
ListCertificateSignalsPaged(ctx, orgID, cursorCertID string, pageSize int) ([]CertificateSignals, error)
```

`CertificateSignals` (new value type, §6 input shape):

| Field | Source | Notes |
|---|---|---|
| `CertificateID` | `certificates.id` | cursor key |
| `SubjectCN` | parsed from `certificates.subject` | engine parses CN out of DN |
| `SANs` | `certificates.sans` JSONB | already stored |
| `IssuerDN` | `certificates.issuer` | |
| `StoreLocations` | `DISTINCT certificate_observations.store_location` | aggregated `array_agg(DISTINCT ...)` |
| `ObservingAgentIDs` | `DISTINCT certificate_observations.agent_id` | active observations only? see OQ-3 |
| `ObservingAgentGroupIDs` | `agent_group_memberships ⋈ observing agents` | aggregated set |
| `CertTags` | `tag_assignments WHERE target_type='certificate'` | `(key,value)` set |
| `AgentTags` | `tag_assignments WHERE target_type='agent'` ⋈ observing agents | `(key,value)` set |

This is the one query in the system that joins inventory +
observations + identity. It lives in the **postgres** layer (the only
place that knows SQL, CLAUDE.md §16); the engine consumes the flat
`CertificateSignals` struct. **The engine still imports neither
`inventory` nor `identity`** — the join result is a governance-owned
value type. Boundary preserved.

> Adversarial note: `array_agg(DISTINCT ...)` over a 50k-cert ⋈
> observations ⋈ memberships ⋈ tag_assignments join must be **paged by
> the driving table** (`certificates`) with `LATERAL` sub-aggregates
> per cert, not a single GROUP BY over the full cross product (which
> materializes the whole fleet). Pin the query plan in an integration
> test with `EXPLAIN` assertions at fixture scale, and verify pages
> are disjoint and ordered.

### 3.2 Engine-walk rule ordering

A1's `ListOwnershipRules` is **deliberately `id ASC`** and its doc
comment forbids the engine from using it (determinism would break).
Add the engine-order method backed by the partial index from 0010:

```go
// Enabled rules only, ordered (precedence_tier ordinal ASC,
// priority ASC, created_at ASC, id ASC) — the §5.1 deterministic
// walk order. precedence_tier is text; ordering must map to the
// LADDER ordinal, not lexical text order, so the SQL uses a CASE
// expression (or the engine sorts in Go after a stable load).
ListOwnershipRulesForEngine(ctx, orgID string) ([]OwnershipRule, error)
```

Recommendation: load enabled rules with the existing partial index
(`enabled, precedence_tier, priority, created_at, id`) and **sort by
ladder ordinal in Go** in `precedence.go`. Lexical SQL ordering of
the tier text (`agent_group` < `explicit` < `fallback` ...) is WRONG;
encoding the ladder in a `CASE` works but the Go sort is easier to
unit-test deterministically and keeps the ordinal definition in one
place (`precedence.go`).

### 3.3 Paged prior-ownership read

Phase 3 needs the prior `certificate_ownership` row per cert to diff.
A1 has `GetCertificateOwnership` (single) only. Per-cert calls are
another N+1. Add:

```go
ListCertificateOwnershipPaged(ctx, orgID, cursorCertID string, pageSize int) ([]CertificateOwnership, error)
```

The engine pages certs and prior-ownership **in lockstep on the same
cursor** (both keyed by certificate id ASC), matching the
`findings.runDiffStreaming` two-cursor walk. Because both are keyed on
`certificate_id` under the same REPEATABLE READ snapshot, a merge-join
in Go avoids a map of the full fleet.

### 3.4 Active-override batch read

Phase 3 must know which certs have an active override **without** a
per-cert `GetActiveOwnershipOverride`. Add:

```go
ListActiveOwnershipOverridesPaged(ctx, orgID, cursorCertID string, pageSize int) ([]CertificateOwnershipOverride, error)
// and, for the auto-expiry sweep:
ListOverridesExpiringBy(ctx, orgID string, now time.Time) ([]CertificateOwnershipOverride, error)
```

### 3.5 Stale view query

`GET /ownership/stale` (parent §8.12) needs:

```go
ListCertificateOwnershipStale(ctx, orgID string, olderThan time.Time, cursorCertID string, limit int) ([]CertificateOwnership, error)
```

(`last_evaluated_at < olderThan`, id-ASC paged). The threshold is a
config knob, not a column (parent §4.5).

### 3.6 Org lister for the scheduler

The scheduler needs `OrganizationLister.ListOrganizationIDs` — this
already exists for `findings.Scheduler`; **reuse the same postgres
implementation**, do not duplicate it. The interface is re-declared
consumer-side in `ownership/scheduler.go` (CLAUDE.md §8.8 — each
consumer owns its own narrow interface; the concrete postgres method
satisfies both).

> **Repository-gap summary:** 6 new read methods + 2 advisory-lock
> helpers. None mutate schema. All are parameterized SQL (CLAUDE.md
> §6.7). This is ~600–800 LOC of repository + scan code alone, which
> is why it gets its own PR (§13, PR-B1).

---

## 4. Exact rule evaluation order (deterministic, binding)

For one certificate, `decideOwnership` evaluates in this exact order.
**First match wins.**

```
0.  AUTO-EXPIRE: if an active override has expires_at <= now,
    treat it as cleared for THIS evaluation (and emit the
    clear in the apply path). It does NOT win tier 1.

1.  TIER 1 explicit:
      active (uncleared, non-expired) override exists
        → decision = overridden, service = override.service_id,
          winning_rule = NULL, override_id = set, confidence = high.
      STOP.

2.  TIER 2 service_member: SKIPPED in H-026B (reserved, never matches).

3.  Walk enabled rules in ladder order:
      tiers 3..8 = agent_group, san_pattern, subject_pattern,
                   tag, issuer_store, fallback.
    Within the rule list (already globally sorted), the FIRST rule
    whose predicate matches the cert's signals is the candidate
    winner. Record EVERY rule that matched (for losingRules + the
    ambiguity check), but evaluation stops scanning at the first
    full tier whose set of matches is non-empty.

4.  AMBIGUITY CHECK + winner selection within the winning tier:
      collect all rules in the SAME tier as the candidate that ALSO
      match. Sort them by (priority ASC, created_at ASC, id ASC).
      Ambiguity is detected on the (priority, created_at) PREFIX only —
      id is deliberately EXCLUDED from the tie test, because id is
      unique and including it would make the ambiguous case
      unreachable (the bug this step guards against):
      - a unique lowest (priority, created_at) — i.e. no other matched
        rule in the tier shares BOTH the winner's priority AND its
        created_at → decision = matched, winning_rule = the rule with
        the lowest (priority, created_at, id).
      - two+ matched rules share the lowest (priority, created_at)
        [same priority AND same created_at — only reachable via
        same-tx rule creation] → decision = ambiguous. winning_rule =
        the lowest id among the tied set, so operations keep working
        deterministically; every OTHER tied rule is recorded in
        losingRules with reason_not_chosen =
        "tied with winner; tiebreaker on id". id breaks the tie for
        WINNER SELECTION but does NOT clear the ambiguous flag — the
        cert is still surfaced via /ownership/ambiguous and emits
        ownership.ambiguous_match.

5.  NO TIER MATCHED:
      decision = unowned, service = NULL, winning_rule = NULL,
      confidence = low.
```

**Determinism guarantees:**
- Rule order is total: `(tierOrdinal, priority, created_at, id)`.
  `id` is the final, always-unique tiebreaker — there is **no path to
  a nondeterministic result**, even on same-`created_at` ties. Note the
  ambiguous flag is **orthogonal** to winner determinism: the winner is
  always deterministic (lowest id), while `ambiguous` is raised purely
  on the `(priority, created_at)` tie — it never makes the result
  nondeterministic, it only marks the cert for operator review.
- Predicates are pure: glob/regex matching, set membership. No clock
  reads inside predicates (the only `now` use is override expiry,
  passed in explicitly).
- Map iteration is never used to pick a winner. `losingRules` is
  built from a **sorted slice**, not a map, so the snapshot is
  byte-stable.
- Confidence is a pure function of the winning tier (parent §3.8):
  explicit/service_member→high, agent_group/san/subject/tag→medium,
  issuer_store/fallback→low.

**Regex safety (adversarial):** `san_regex` rules carry
operator-supplied patterns. Compile once per recompute in `rules.go`;
on compile failure the rule is **skipped + flagged** (an
`ownership.rule_compile_failed` audit row, severity:"security", and
the rule is treated as non-matching for this pass — fail closed,
CLAUDE.md §6.12). A bad regex must never panic the pass or match
everything. Apply a pattern-length cap and reject catastrophic
constructs at rule-create validation time (a service-layer guard),
not at engine time.

---

## 5. Decision state machine

### 5.1 Per-cert decision transition (prior → decided)

The recompute diffs the prior `certificate_ownership.decision` +
`service_id` against the freshly-decided pair. Transitions and the
audit action each emits:

| Prior decision / service | Decided decision / service | Action | Counter |
|---|---|---|---|
| (no row) | unowned | INSERT (unowned), explanation written | unchanged-as-new* |
| (no row) | matched/overridden(svc) | INSERT, explanation | became_owned |
| unowned | matched/overridden(svc) | UPSERT, explanation | became_owned, `ownership.assigned` |
| matched/overridden(svc) | unowned | UPSERT, explanation | became_unowned, `ownership.cleared` |
| matched(svcA) | matched(svcB), A≠B | UPSERT, explanation | flipped_owner, `ownership.flipped` |
| matched(svc) | matched(same svc) | bump last_evaluated_at only | unchanged |
| any non-ambiguous | ambiguous | UPSERT, explanation | changed, `ownership.ambiguous_match` |
| overridden | overridden (expiry hit) → re-derived | UPSERT + clear override | `ownership.override_expired` + consequent flip/clear |

\* The very first recompute on a fresh deploy writes a row for every
cert even when the decision is `unowned`. To keep this from emitting
50k `became_unowned` audit rows on a no-owner fleet, **`unowned` on a
cert with no prior row is NOT an audited transition** — it writes the
ownership + explanation row (so the explainability contract holds) but
emits no audit action and counts as `unchanged`. Only a *transition
into* unowned from a previously-owned state is audited. This is the
"no surprises on first deploy" property (parent §9.9) made precise.

### 5.2 Same-decision recompute is a no-op write-wise except `last_evaluated_at`

Mirrors `findings` "Updated" semantics: re-confirming a decision bumps
`last_evaluated_at` (so `/ownership/stale` works) and does **not**
write a new explanation row (caps explanation cardinality, parent
§3.10). `last_changed_at` only moves on a real transition.

### 5.3 Idempotency

Replaying against unchanged inputs at the same `now` → `unchanged = N,
changed = 0`, **zero** new explanation rows, **zero** audit state-change
rows (one `governance.recomputed` summary row still written). Pinned by
a byte-identical equivalence test (§12), same discipline as H-024B.

### 5.4 service_member tier

Reserved, never matched in H-026B. The ladder ordinal exists so the
ordering is stable, but no rule can carry `precedence_tier =
'service_member'` (the rule-create validator rejects it). Documented
in `precedence.go` and OQ-1. This avoids a half-built tier-2 path.

---

## 6. Explanation snapshot schema

`ownership_match_explanations.losing_rules` and `signals_seen` are
`json.RawMessage` at the type level (A1). H-026B pins their concrete
shapes. Both are written by `explanation.go` from **sorted** inputs so
the bytes are deterministic.

`losing_rules` — JSON array, **bounded at K=8** (binding service-layer
const `maxLosingRules`), the 8 highest-precedence non-winning matched
rules:

```json
[
  { "rule_id": "01J...", "name": "internal-CA-coarse", "tier": "issuer_store",
    "priority": 50, "reason_not_chosen": "lower precedence than san_pattern" },
  { "rule_id": "01J...", "name": "billing-subject", "tier": "subject_pattern",
    "priority": 200, "reason_not_chosen": "lower precedence than san_pattern" }
]
```

`reason_not_chosen` is one of a closed enum of strings (so it is
itself deterministic and testable):
- `"lower precedence than <winning_tier>"`
- `"same tier, lower priority than winner"`
- `"same tier, same priority, later created_at than winner"`
- `"tied with winner; tiebreaker on id"` (the ambiguous case)

`signals_seen` — JSON object capturing the exact inputs:

```json
{
  "subject_cn": "billing-prod-01.corp.example",
  "sans": ["billing-prod-01.corp.example", "billing.corp.example"],
  "issuer": "CN=Internal Issuing CA",
  "store_locations": ["LocalMachine\\WebHosting"],
  "agent_ids": ["01J...", "01J..."],
  "agent_groups": [{ "id": "01J...", "slug": "pci-web-tier" }],
  "tags": [{ "key": "env", "value": "prod", "source": "certificate" }]
}
```

`engine_version` is a package const `engineVersion = 1` in
`engine.go`. Every explanation row carries it. A bump (e.g. inserting
a ladder tier) forces a full re-evaluation on first recompute after
deploy (OQ-6) — the diff still only audits real changes.

**Stale-explanation invariant:** `certificate_ownership.explanation_id`
always points at the *latest* explanation. Soft-deleted (disabled)
rules referenced by `winning_rule_id` in old explanations stay
FK-valid (ON DELETE RESTRICT, rules are never hard-deleted). An
explanation referencing a now-disabled rule is a valid historical
record; the engine simply won't reproduce it next pass.

---

## 7. Preview model

`POST /ownership-rules/preview` (new rule body) and
`POST /ownership-rules/{id}/preview` (existing rule's current shape).

Contract (parent §7.13, made concrete):
1. **No advisory lock.** Read-only; locking would let a slow preview
   stall the org's governance writes.
2. Open REPEATABLE READ tx (consistent snapshot).
3. Load the current enabled rule set; **insert the proposed rule
   in-memory** (or, for `{id}/preview`, use the stored rule). Re-sort
   the synthetic set by ladder order.
4. Stream certs (same `ListCertificateSignalsPaged`), run
   `decideOwnership` with the synthetic set, diff against current
   `certificate_ownership`.
5. Return the diff; **roll back**; **no run row, no audit row**.

Response (exact counts, capped samples):

```json
{
  "affected_count": 142,
  "would_flip_count": 38,
  "would_newly_assign_count": 104,
  "would_unown_count": 0,
  "sample_certs": [
    { "certificate_id": "01J...", "subject": "CN=billing-prod-01.corp.example",
      "current_owner_service_id": "01J...", "current_decision": "matched",
      "would_assign_to_service_id": "01J...", "would_decision": "matched",
      "would_flip": true }
  ],
  "next_cursor": null
}
```

`affected_count` is exact (full stream); `sample_certs` is capped at
`limit ≤ 200` (OQ-7) and paginates via `cursor`.

**Preview is point-in-time, not time-stable** (parent §7.13): apply
takes its own snapshot and is authoritative. No lock is held between
preview and apply. The apply response (§8/§9) is the same diff shape
so the operator can compare expected vs actual and detect drift.

---

## 8. Apply model

There are **three** write paths that change ownership; all are
auditable, all serialize against the recompute via the ownership
advisory lock.

### 8.1 Rule create / update / disable / enable
Single-row writes to `ownership_rules` (A1 repo methods already
exist). Each emits one audit row (`ownership.rule_created` /
`_updated` / `_disabled` / `_enabled`, severity:"security"). These do
**not** themselves recompute — the next scheduler tick (or an explicit
`POST /ownership/recompute`) applies the effect. The handler response
SHOULD nudge the operator to preview-then-recompute. (Rationale: a
rule edit can flip thousands of certs; coupling it to a synchronous
full recompute would make an interactive POST take up to 60s. Keep
the heavy work in the recompute path.)

### 8.2 Override create / clear (immediate, single-cert)
`POST /certificates/{id}/ownership/override` and `DELETE`.
Under `WithTxLockedOwnership(orgID)` (xact-scope, READ COMMITTED —
single row, mirrors `findings.applyOverride`):
1. Insert/clear the override row (partial unique index enforces one
   active override per cert; a conflicting POST → `409
   ownership_override_conflict`, parent §7.14).
2. **Re-derive THIS cert only** in the same tx (single-cert slice of
   the engine) so `certificate_ownership.decision` flips to
   `overridden` (or re-derives on clear) before the response returns —
   immediate operator effect (parent §3.9).
3. Write the explanation row + the `ownership.overridden` /
   `ownership.override_cleared` audit row, all in the same tx. Audit
   failure rolls back.

The single-cert re-derive runs under the same advisory lock as the
full sweep, so it serializes; the lock hold is sub-millisecond (one
cert) and does not meaningfully stall a sweep.

### 8.3 Full recompute (operator-triggered or scheduled)
`POST /ownership/recompute` → `Service.Recompute`. The full Phase 1–4
pass (§2). Returns the run summary (counters) so the operator sees the
blast radius. A second concurrent recompute for the same org blocks on
the advisory lock; if the operator wants non-blocking behavior the
handler can return `409 ownership_recompute_in_progress` on a
`pg_try_advisory_lock` miss (parent §7.14) — **recommend the blocking
wait with a context deadline** instead, matching findings, and reserve
the 409 for an explicit `?nowait=true`.

---

## 9. Recompute lifecycle + transaction model

```
Service.Recompute(ctx, {orgID, actorUserID})         // 409 path optional
 └─ WithTxLockedOwnershipRepeatableRead(orgID):       // session lock + RR snapshot
      run := StartRecomputeRun(kind=ownership, actor, started_at=now, Succeeded=nil)
      load+compile rules (Phase 1)
      stream certs+prior+overrides in lockstep (Phase 3):
          decide, diff, write explanation+ownership, accumulate audit intent,
          auto-expire overrides
      flush audit (per-cert OR bulk rollup, §11)
      FinishRecomputeRun(run, counters, finished_at=now, Succeeded=true)
      Record ONE governance.recomputed audit row (metadata: run_id + counters)
   COMMIT
```

**Atomicity (binding):** the run row's *finish*, all explanation
rows, all ownership upserts, all per-cert/bulk audit rows, and the
`governance.recomputed` summary row commit in **one transaction**. Any
failure (including an audit write) rolls back the entire pass — same
guarantee findings gives (parent §4.6). On rollback the `StartRecomputeRun`
row is rolled back too (it is INSERTed inside the same tx), so there
is no orphan "started, never finished" row. *(If we want a durable
"a pass was attempted and failed" record, `StartRecomputeRun` must run
in a separate committed tx before the locked tx; recommend NOT doing
that in H-026B — keep the single-tx atomic model, surface failures via
structured logs + the scheduler's error log line. Revisit if operators
need failed-run forensics.)*

**Why session-scope lock + RR (not xact-scope):** identical reasoning
to `WithTxLockedFindingsRepeatableRead` (postgres.go:173–222). The RR
snapshot is taken at the first statement of the tx; a session lock
acquired on a borrowed connection *before* `BeginTx` guarantees a
second concurrent recompute snapshots state *after* the first commits,
avoiding duplicate-key races on `certificate_ownership`. **Copy that
helper's structure exactly**, including the hijack-on-unlock-failure
cleanup, under the new namespace `'ownership-recompute'`.

**New advisory-lock namespace:** `hashtext('ownership-recompute')` —
distinct from `'findings-recompute'` and `'cert-inventory'` (parent
§2.4). Ownership and findings recomputes therefore **do not contend on
the lock**; they only share the pgx pool. Ingestion (`cert-inventory`
namespace) is **not** blocked by an ownership recompute — which is
exactly why RR isolation is mandatory (a concurrent ingestion batch
must not be half-visible mid-pass).

---

## 10. Scheduler model + gating

`ownership.Scheduler` is a near-copy of `findings.Scheduler`
(scheduler.go), with these deltas:

- Calls `Service.RecomputeScheduled(ctx, orgID)` (actor=`"scheduler"`,
  actorKind=`system`).
- Config: `ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED` (**default `false`**
  in H-026B — the engine ships dark; operators opt in) and
  `ANCHORIX_GOVERNANCE_SCHEDULER_INTERVAL` (**default `1h`** — rules
  are operator-driven and operators expect quicker feedback than the
  6h findings cadence, OQ-9). Same `MinSchedulerInterval = 30s` floor,
  validated in `internal/config.validate()` at startup (fail closed).
- One goroutine, ctx-cancel honored, per-org panic recovery, no
  immediate-on-start tick (manual POST is the force-now path) — all
  identical to findings, CLAUDE.md §8.10.

**Fail-open vs fail-closed (adversarial):** the findings scheduler
logs-and-continues on a per-org recompute failure (scheduler.go:246).
For ownership the same posture is correct **because ownership is
advisory enrichment, not a gate** (parent §1.5: "governance enriches,
never gates"). A failed ownership recompute leaves the prior
`certificate_ownership` rows intact (the tx rolled back) — stale, not
wrong, and surfaced by `/ownership/stale`. The scheduler must **never**
fail *open* in the sense of writing a partial/guessed ownership: the
transaction atomicity (§9) guarantees all-or-nothing per pass. The
only "fail-open" risk to guard is a *silently disabled* scheduler — so
the disabled state is logged at startup (the config layer logs which
env var produced `false`), and `/ownership/stale` makes staleness
operator-visible regardless of scheduler health.

**Kill switch / rollback:** set
`ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED=false` to halt background
recomputes with zero DB changes (parent §9.10). Manual
`POST /ownership/recompute` still works for diagnostics.

---

## 11. Audit model

All ownership state changes are severity:"security" (CLAUDE.md §9,
parent §4.6). Actions: `ownership.assigned`, `.cleared`, `.flipped`,
`.overridden`, `.override_cleared`, `.override_expired`,
`.ambiguous_match`, `.rule_created/_updated/_disabled/_enabled`,
`.rule_compile_failed` (new, §4), plus the per-pass
`governance.recomputed` summary.

**Audit amplification — the bulk rollup (binding):** the first
`fallback` rule on a 50k-cert org flips 50k certs in one pass. Without
a rollup that is 50k security-severity rows with identical
`occurred_at` — indistinguishable from a real incident, the H-019
alert-fatigue failure mode (parent §4.6).

Rule: within a single pass, audit rows are grouped by
`(from_decision, to_decision, driver_rule_id)`. For any group whose
count exceeds `ANCHORIX_OWNERSHIP_BULK_AUDIT_THRESHOLD` (default 500),
emit **one** `ownership.bulk_assigned` / `ownership.bulk_flipped` row
instead of N per-cert rows:

```json
{ "severity": "security", "run_id": "01J...", "count": 50000,
  "from_decision": "unowned", "to_decision": "matched",
  "driver_rule_id": "01J...", "sample_cert_ids": ["01J...", "... up to 100"] }
```

Per-cert detail stays recoverable: `certificate_ownership.last_changed_at
== run.finished_at` + the explanation table. Small flips (operator
claims 12 certs) still emit per-cert rows — the security signal stays
sharp. The decision is deterministic per pass: a given
`(from,to,driver)` group writes *either* N per-cert rows *or* one
rollup, never a mix.

**Atomicity:** all audit writes are inside the recompute tx (§9).

---

## 12. Tests required

**Pure-function (fast, no DB) — the determinism core:**
- `decideOwnership` table-driven over fixture `CertificateSignals` ×
  rule sets: every tier matches in isolation; first-match-wins across
  tiers; tiebreaker chain (priority → created_at → id); ambiguous
  case; unowned fallthrough; override short-circuit; auto-expired
  override does not win tier 1.
- `applyTiebreaker` — exhaustive over equal/unequal priority &
  created_at & id permutations.
- `confidenceForTier` — every tier maps to the documented label.
- regex/glob predicates — anchoring, case, `\\` store-path escapes,
  catastrophic-pattern rejection, compile-failure → skip+flag.
- explanation builders — `losing_rules` bounded at K=8, sorted,
  byte-stable; `reason_not_chosen` closed enum.

**Integration (real postgres, `backend/test/integration/`):**
- **Byte-identical equivalence:** a load-all reference recompute vs
  the streaming pass produce identical `certificate_ownership` +
  `ownership_match_explanations` for the same fixture (mirrors the
  H-024B test; use `SetStreamingPageSizeForTest`-style knob to force
  multi-page walks at fixture scale).
- **Snapshot isolation:** concurrent ingestion batch commits mid-pass;
  the pass result is unaffected (RR snapshot holds across page
  boundaries).
- **Concurrent recompute safety:** two simultaneous recomputes for one
  org serialize, no duplicate-key on `certificate_ownership`, second
  sees first's writes (the exact race the session-lock fixes).
- **Idempotency:** replay at same `now` → `unchanged=N, changed=0`,
  zero new explanation rows, zero state-change audit rows.
- **Override precedence + expiry:** override beats every tier; cleared
  override re-derives; `expires_at <= now` auto-clears at next pass and
  emits `override_expired` + the consequent flip.
- **Override conflict:** second active-override POST → 409.
- **Ambiguity:** two same-tier same-priority same-created_at rules →
  `ambiguous`, lowest-id winner, both in `losing_rules`,
  `ownership.ambiguous_match` emitted.
- **Preview/apply consistency:** preview shows X; applying the rule +
  recompute under the same (unchanged) state produces X.
- **Audit atomicity:** an injected audit-write failure rolls back the
  entire pass (no ownership/explanation/run rows committed).
- **Bulk rollup:** a fallback rule flipping > threshold certs emits one
  `bulk_assigned` row, not N; a sub-threshold flip emits per-cert rows.
- **First-deploy quiet:** fresh org, first recompute → every cert
  `unowned`, **no** `became_unowned` audit rows, one
  `governance.recomputed`.
- **Cross-org isolation:** recompute for org A never reads/writes org
  B rows; cross-org cert id on the ownership endpoints → 404.
- **Scheduler:** disabled → Run returns immediately; enabled → ticks
  call `RecomputeScheduled`; per-org failure logged, sweep continues;
  ctx-cancel exits promptly.

**HTTP handler tests:** each endpoint — success, cross-org 404,
validation 400, override conflict 409, preview writes nothing/no
audit, recompute returns counters.

**Performance smoke (planning anchor, not a blocking SLO):** the
signal-join query plan at fixture scale (`EXPLAIN` assertion that it
pages by `certificates`, not a full-fleet GROUP BY).

---

## 13. Phased PR split (the safest split — recommended)

**Do NOT ship H-026B as one PR.** The parent §11.2 budgets it at
< 1500 LOC, but the repository-gap reads (§3) alone are ~600–800 LOC,
the engine + orchestration is ~600 LOC, handlers ~500 LOC, scheduler
~250 LOC, plus tests. Realistically ~3500–4500 LOC. Split into four
sequential, independently-mergeable, independently-reversible PRs:

### PR-B1 — repository reads + advisory-lock helpers (no engine)
**The safest first PR.** Pure storage. Lowest risk, unblocks
everything.
- `WithTxLockedOwnership` + `WithTxLockedOwnershipRepeatableRead`
  (copy the findings helpers; new namespace).
- The 6 new `OwnershipRepository` read methods (§3.1–§3.5) +
  `CertificateSignals` type + scans.
- Repository-level integration tests: signal-join correctness +
  disjoint pages + `EXPLAIN` plan; engine-walk order; paged-ownership
  lockstep; stale query; cross-org isolation on every new read.
- **No** engine, **no** handlers, **no** scheduler.
- Reversibility: complete — methods unused by any production path.
- ~700–900 LOC.

### PR-B2 — engine core + recompute (pure + orchestration, no HTTP)
The highest-risk code, **alone**, where review attention concentrates.
- `signals.go`, `rules.go`, `precedence.go`, `engine.go`,
  `explanation.go`, `service.go` (Recompute / RecomputeScheduled only),
  `errors.go`.
- All pure-function tests + the equivalence / snapshot-isolation /
  concurrency / idempotency / ambiguity / bulk-rollup / first-deploy /
  audit-atomicity integration tests.
- Composition: construct `ownership.Service` in `serve.go`; expose
  `POST /ownership/recompute` + `GET /ownership/unowned|ambiguous|stale`
  + `GET /governance/recompute-runs` only (the minimal surface to
  exercise the engine end-to-end). No rule writes, no override, no
  preview yet.
- Reversibility: routes gated by `ANCHORIX_GOVERNANCE_API_ENABLED`;
  no scheduler constructed yet, so no background effect.
- ~900–1100 LOC.

### PR-B3 — overrides + rule CRUD + preview (operator write surface)
- `override.go`, `preview.go`; `service.go` gains
  `ApplyOverride`/`ClearOverride`/`Preview`.
- Handlers: `ownership_rules.go` (create/update/disable/enable +
  preview), `ownership_certificate.go` (read/explanation/override).
- Override-precedence/expiry/conflict, preview/apply-consistency,
  rule-compile-failure, and handler tests.
- Reversibility: API gate; no schema change.
- ~900–1100 LOC.

### PR-B4 — scheduler + config gating
**Last, smallest, dark by default.**
- `scheduler.go`; config knobs; `serve.go` spawns the goroutine.
- Scheduler unit tests (disabled/enabled/failure-continue/ctx-cancel).
- Default `ENABLED=false` — turning it on is a deliberate operator
  action after B1–B3 soak.
- Reversibility: the env knob *is* the rollback.
- ~300–400 LOC.

Each PR carries its own correctness bar; none depends on a future
phase to be safe. The threat model doc
(`docs/security/H026B_OWNERSHIP_THREAT_MODEL.md`) lands in **PR-B2**
(the first PR that touches the security-sensitive decision flow),
required before merge by CLAUDE.md §6.10 / §19.

---

## 14. Adversarial edge cases (explicit answers)

| Concern | Resolution |
|---|---|
| **Rule conflicts** | Total order `(tier, priority, created_at, id)`; `id` is always-unique final tiebreaker — no nondeterministic result reachable. |
| **Concurrent recomputes** | Session-scope advisory lock + RR snapshot; second snapshots after first commits (the findings race, already solved — copy it). |
| **Override expiry** | Auto-cleared at first pass where `expires_at <= now`; emits `override_expired` + consequent flip, in-tx. Engine evaluation treats an expired override as absent (does not win tier 1). |
| **Stale explanations** | `explanation_id` always points at latest; disabled rules kept FK-valid (soft delete, ON DELETE RESTRICT); old explanations are valid history. |
| **Recompute drift (preview vs apply)** | Documented point-in-time semantics; apply takes its own snapshot and is authoritative; apply response is full diff so drift is detectable. No lock held between. |
| **Scheduler fail-open** | Ownership enriches, never gates; failed pass rolls back atomically (stale, not wrong); staleness is operator-visible via `/ownership/stale`; disabled-state logged at startup. |
| **Audit amplification** | Bulk rollup above threshold; per-cert detail recoverable from `last_changed_at == run.finished_at` + explanations. |
| **Pagination consistency** | RR snapshot + id-ASC cursors + lockstep cert/ownership/override merge-join; disjoint-page test. |
| **Deterministic tie-breaking** | `applyTiebreaker` exhaustive test; `losing_rules` built from sorted slice, never map iteration. |
| **Ambiguous ownership** | Surfaced as `decision=ambiguous`, lowest-id winner keeps ops working, `ambiguous_match` audit, `/ownership/ambiguous` triage view. |
| **Bulk onboarding** | First fallback rule → one bulk audit row + 50k explanation rows in one tx (≈10MB, acceptable v0.x); first-deploy unowned is quiet (not audited). |
| **Operator surprise** | Preview-before-apply is the primary safety mechanism; rule edits don't auto-recompute; recompute returns counters; every flip is audited. |
| **Malicious regex** | Compile once, length-cap + reject catastrophic at create-time, skip+flag on compile fail at engine-time — never panic, never match-all. |
| **N+1 at fleet scale** | Single SQL signal-join paged by `certificates`; `EXPLAIN`-pinned; no per-cert follow-up queries. |
| **Cross-org leakage** | Composite FKs (A1); every new read scoped by org; cross-org id → 404; isolation test per new read. |
| **Orphan run rows** | `StartRecomputeRun` is in-tx → rolled back on failure (no orphan). Trade-off: no durable failed-run record; surfaced via logs (revisit if forensics needed). |

---

## 15. Open questions (deltas from parent §12; resolve before locking the wire)

- **OQ-1 (service_member tier):** ship as a never-matched gap in
  H-026B; rule-create validator rejects the tier. Revisit only on
  operator demand. *(Recommend: keep deferred.)*
- **OQ-3 (which observations feed signals):** do removed observations
  (`removed_at IS NOT NULL`) still contribute `store_locations` /
  `agent_ids`? *Recommend: active observations only* for agent-group /
  store signals (a cert no longer on a host shouldn't be owned via that
  host), but keep the cert's intrinsic SAN/subject/issuer signals
  regardless. Pin in the signal-join query + a test.
- **OQ-6 (engine version bump):** first recompute after a bump
  re-evaluates all certs; only real changes audit. Document in
  CHANGELOG on bump.
- **OQ-7 (preview cap):** hard-cap `sample_certs` at 200; `affected_count`
  exact; paginate via cursor.
- **OQ-9 (cadence):** default `1h`; configurable; floor 30s.
- **NEW OQ-B1 (run-row durability):** single-tx model means failed
  passes leave no run row. Accept for H-026B (logs suffice); revisit if
  operators need failed-run forensics — would require a pre-tx committed
  start row.
- **NEW OQ-B2 (recompute 409 vs block):** recommend blocking-with-deadline
  by default (matches findings), `409 ownership_recompute_in_progress`
  only on explicit `?nowait=true`.

---

## 16. Constraint check (H-026B specifics)

- **§4 scope:** no automation, no CA, single-org. Ownership is
  derived enrichment.
- **§8.4 naming:** `decideOwnership`, `applyTiebreaker`,
  `CertificateSignals`, `compiledRule`, `ownershipDecision`,
  `bulkAuditRollup` — domain-explicit, no `manager`/`helper`/`data`.
- **§8.6 / parent §2.2 boundaries:** `ownership` imports neither
  `inventory`, `identity`, `findings`, `httpapi`, nor `storage/postgres`.
  Signal join result is a governance-owned value type; storage owns SQL.
- **§8.8 DI:** constructor wiring in `serve.go`; consumer-owned reader
  interfaces; `Repo.Validate()` fail-closed at construction.
- **§8.9 config:** new knobs centralized in `internal/config`, validated
  at startup, immutable after.
- **§8.10 concurrency:** scheduler goroutine has documented owner,
  ctx-cancel path, bounded lifetime, panic recovery.
- **§9 audit:** every state change in-tx, severity:"security"; bulk
  rollup prevents amplification; reasons logged length-only.
- **§16 DB:** no new migration; reuses 0010; all reads parameterized.
- **§17 API:** all routes under `/api/v1`, additive; canonical error
  envelope; new codes additive.
- **§18 robustness:** RR snapshot, advisory lock, idempotent recompute,
  bounded pages, deterministic state machine, fail-closed on regex
  compile + audit failure.
- **§19 discipline:** `doc.go` already present; threat model in PR-B2;
  no TODO-architecture; engine isolated for review.

---

## 17. Recommended first implementation PR

**PR-B1 — repository reads + advisory-lock helpers.** It is pure
storage, carries zero engine logic, is fully reversible (the methods
are unused until B2 wires them), and de-risks the single largest
hidden cost in H-026B: the fleet-scale signal-join query. Getting the
`ListCertificateSignalsPaged` query plan right — paged by
`certificates`, no full-fleet GROUP BY, disjoint ordered pages,
cross-org safe, `EXPLAIN`-pinned — is the foundation everything else
streams over. Landing and soaking it first means the high-risk engine
PR (B2) builds on a proven, perf-validated read layer instead of
discovering an N+1 or a snapshot bug late.

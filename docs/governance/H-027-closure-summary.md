# H-027 — Ownership Explanation Retention: Phase Closure

> **Status:** closed / **dormant by design**. Source of truth for rules:
> [`CLAUDE.md`](../../CLAUDE.md). Design proposal:
> [`H-027-explanation-retention-design.md`](./H-027-explanation-retention-design.md).
> Builds on the ownership engine (H-026B1→B3B) — see
> [`H-026B3B-closure-summary.md`](./H-026B3B-closure-summary.md).

## 0. Merged PRs

| PR | Title | Class |
|----|-------|-------|
| #61 | H-027 explanation retention design proposal | docs |
| #62 | H-027 PR-1 retention config + pure selection logic | feature (dormant) |
| #63 | H-027 PR-2 paged explanation prune primitive | feature (dormant) |
| #64 | H-027 PR-2 hardening pass | test-only + doc fix |

H-027 is the **storage-retention surface** on top of the H-026B ownership
engine. It bounds the growth of `ownership_match_explanations` while
preserving the current explanation (FK-pinned), the audit trail, and the
B3A read contract. The primitive is fully built, tested, and wired to
config — and **nothing calls it**. Activation is a separate, deliberate
operator decision.

## 1. What H-027 delivered

- **Design proposal** (#61): the hybrid retention policy (latest-N per
  cert OR newer-than-T), per-org isolation, paged execution model, audit
  rollup strategy, and the FK-pinned current-explanation invariant —
  identified as the DB-level safety floor that makes the whole feature
  low-blast-radius.
- **Config + pure selector** (#62): the two retention knobs validated at
  startup, plus `SelectExplanationsToPrune`, the canonical unit-tested
  spec of the prune rule (no I/O, table-driven tests).
- **Bounded SQL prune primitive** (#63): `PruneExplanationsPage`, a
  per-org, per-page repository + service primitive that selects
  eligible explanation ids via a bounded SQL query and deletes them
  under the per-org advisory lock. One call = one bounded page = one
  transaction.
- **Adversarial hardening** (#64): 14 regression tests covering
  cross-cert/current-id rejection, strict-`<` cutoff semantics, pageSize
  clamping, actor attribution, multi-cert audit rollback, cursor
  determinism, empty-candidate quiet path, deep-history boundedness, and
  the operator-vocabulary "do not touch" guarantee. Plus a doc-only fix
  to the prune godoc so it describes the actual bounded algorithm.

## 2. Config knobs added (read at startup, immutable thereafter)

| Variable | Default | Validation |
|---|---|---|
| `ANCHORIX_OWNERSHIP_EXPLANATION_KEEP_N` | `10` | `>= 1` |
| `ANCHORIX_OWNERSHIP_EXPLANATION_MAX_AGE` | `2160h` (90d) | `>= 24h` |

Both live in `internal/config`, are loaded once at startup (CLAUDE.md
§8.9), and fail closed on invalid values. `serve.go` passes them into
`ownership.ServiceConfig.Retention`; if no caller invokes the prune,
the knobs have zero runtime effect. No environment-driven runtime
behavior change.

## 3. Retention policy semantics (hybrid rule)

Per certificate, an explanation row is **prunable iff all three hold**:

1. it is **not** the FK-pinned current explanation; **and**
2. it is **beyond the latest-N** by `(decided_at DESC, id ASC)`; **and**
3. its `decided_at` is **strictly older** than `now − MaxAge`.

Equivalently, kept iff it is the current row **or** within the latest-N
**or** newer than (or exactly at) the cutoff. The current row is always
the newest and always pinned, so it is always inside latest-N and never
eligible.

`SelectExplanationsToPrune` (PR-1) is the canonical, unit-tested spec.
The SQL primitive `ListPrunableExplanationIDs` (PR-2) implements the
same rule, **bounded**. Same input → same selection set, deterministic
and idempotent. Boundary tests pin id-ASC tiebreaker on equal timestamps
and strict-`<` cutoff (at-cutoff rows kept).

## 4. Prune primitive behavior

`Service.PruneExplanationsPage(ctx, orgID, actor, cursorCertID, pageSize)`
returns `{StartCursor, NextCursor, CertsScanned, DeletedCount, Done}`.

- **Outer walk** (`ListCertificateIDsWithExplanationsPaged`):
  distinct `certificate_id` over `ownership_match_explanations`,
  `certificate_id ASC` exclusive of the cursor, `LIMIT pageSize`.
  Backed by `ownership_match_explanations_cert_timeline_idx`
  `(organization_id, certificate_id, decided_at DESC)` — no new index.
- **Per-cert candidate selection** (`ListPrunableExplanationIDs`):
  bounded SQL — `LIMIT keepN` inside the latest-N keep subquery **and**
  `LIMIT prunePerCertLimit` on the outer candidate set, oldest-first
  (`decided_at ASC, id DESC`). The current explanation is excluded by
  a `NOT EXISTS` clause against `certificate_ownership.explanation_id`.
- **DELETE** (`DeleteOwnershipExplanationsForCertificate`): org +
  certificate scoped, with the same `NOT EXISTS` current-guard repeated
  at delete time as belt-and-suspenders with the FK
  `ON DELETE RESTRICT`.
- `pageSize <= 0` → `DefaultExplanationPrunePageSize` (500).
  `pageSize > maxExplanationPrunePageSize` (1000) → clamped to 1000.
  `prunePerCertLimit` defaults to 256 (test override available).
- **Deep-history certs drain across passes**: a cert with thousands of
  prunable rows is reclaimed in bounded batches over successive calls,
  oldest-first, deterministic. There is no in-page Go-level filtering of
  a loaded "newest window" (the discarded design that would have starved
  older rows when a cert had more in-window rows than the window cap).
- **Fail-closed** on empty org id and on a degenerate retention policy
  (`KeepN < 1` or `MaxAge <= 0`).
- Returns nothing actionable beyond the result struct — no scheduler
  hook, no metrics emission, no side channel.

## 5. Transaction / locking guarantees

- **One call = one bounded page = one `WithTxLockedOwnership(org)`
  transaction** (xact-scope advisory lock, READ COMMITTED), shared
  with override mutations and serialized against any in-flight full
  recompute (governance plan §3.9). The lock hold is bounded by the
  page's per-cert candidate caps × pageSize; it is never held across a
  full-org cleanup.
- **No nested or repeated lock acquisition** inside the primitive —
  there is no loop over pages; that responsibility belongs to a future
  caller.
- **Audit atomicity**: the rollup audit row commits in the SAME
  transaction as the deletes. An audit-write failure rolls the **entire
  page's** deletes back (proven by the multi-cert rollback hardening
  test); no partial-deletion-without-audit state is observable.

## 6. Boundedness guarantees (no fleet-wide scan, no unbounded read)

The whole primitive is bounded by construction; the hardening pass
re-pins this concretely:

- Outer cert walk: `LIMIT pageSize` (max 1000 after clamping). EXPLAIN
  shows a `Limit` node and no fleet-wide `Group Key`.
- Per-cert candidate selection: `LIMIT keepN` on the keep subquery
  **and** `LIMIT prunePerCertLimit` on the outer query. EXPLAIN shows a
  `Limit` node, no fleet-wide `Group Key`.
- Per-cert DELETE: bounded by the candidate-id slice size (≤
  `prunePerCertLimit`).
- Page size > max → clamped (1010-cert seed test pins
  `CertsScanned <= 1000`).
- Page size 0 → default (5-cert seed test pins `CertsScanned == fleet`,
  `Done == true`).
- A 100-row deep-history cert with `prunePerCertLimit=10` deletes
  exactly 10 per page across 10 pages, oldest-first — concrete proof
  that the prior unbounded-read regression is gone.

## 7. Current-explanation protection (defense in depth)

The "never delete the current explanation" invariant is enforced **at
five independent layers**:

1. **`certificate_ownership.explanation_id` is `NOT NULL`** — the cert
   always has a current explanation pointer.
2. **FK `ON DELETE RESTRICT`** on that pointer — the database itself
   refuses to delete any row another row points at.
3. **`SelectExplanationsToPrune` excludes `currentExplanationID`** in
   the pure Go spec (PR-1).
4. **`ListPrunableExplanationIDs` `NOT EXISTS` clause** against
   `certificate_ownership` — the SQL primitive never returns the current
   id even when it would otherwise be the oldest candidate (pinned by
   hardening test).
5. **`DeleteOwnershipExplanationsForCertificate` re-applies the same
   `NOT EXISTS` clause** — the delete refuses the current id even if a
   buggy caller passed it in (pinned by hardening test).

Each layer would catch the bug alone; together they make pruning the
current explanation **structurally impossible** without a coordinated
multi-layer regression.

## 8. Cross-org isolation guarantees

- Every `SELECT` and `DELETE` in the primitive binds the authenticated
  session's `organization_id`. There is no cross-org statement.
- The outer cert walk is `WHERE organization_id = $1`. The candidate
  selector is `WHERE organization_id = $1 AND certificate_id = $2`. The
  DELETE adds `AND id = ANY($3)` with the same org/cert scope and the
  current-explanation `NOT EXISTS`.
- The repository-level adversarial test feeds explanation ids from cert
  B into a delete scoped to cert A (same org) → 0 deleted, cert B
  untouched. Cross-cert scope holds even on misuse.
- The service-level cross-org isolation test prunes org A's history with
  an identical fixture in org B → org B's rows and audit log untouched.

## 9. Audit behavior

- **One audit action**: `governance.explanation_pruned`, `severity =
  "security"`, target type `organization`, target id = `organization_id`.
- **One rollup per page that deleted something**. A page that scanned
  certs but found zero candidates (e.g., everything within latest-N)
  emits **no** audit — a no-op page changes no state (CLAUDE.md §6.6).
- **No per-row audit amplification**. The rollup metadata carries
  `{deleted_count, certs_scanned, keep_n, max_age, cursor, next_cursor}`.
- **Actor attribution**: an empty/whitespace `actorUserID` is recorded
  as `(actor=system, actor_type=system)`; a non-empty value is recorded
  as `(actor=<trimmed>, actor_type=user)`.
- **No deletion from `audit_events`, ever.** Every prior ownership
  transition (`ownership.assigned/flipped/cleared/...`) remains
  independently permanent in `audit_events`, so the **decision history**
  of any pruned explanation snapshot is reconstructable from audit alone.

## 10. Hardening coverage (PR #64)

14 adversarial regression tests landed, organized in four groups:

- **Repository-level guards**: cross-cert id rejection, current-id
  rejection in the delete slice, nil/empty-slice safe no-op,
  `ListPrunableExplanationIDs` never returns current.
- **Boundary semantics**: SQL-level strict-`<` cutoff (at-cutoff row
  kept), `pageSize > max` clamped, `pageSize <= 0` defaulted, empty
  actor → `system/system`, provided actor → `user`.
- **Multi-cert atomicity + cursor**: audit-rollback restores deletes
  across every cert touched in the page; cursor resume from `NextCursor`
  hits the next cert range deterministically without re-scanning
  already-pruned certs; empty-candidate page emits no audit.
- **Deep-history boundedness**: 100 prunable rows on one cert with
  `prunePerCertLimit=10` drain across exactly 10 pages, ≤ 10 deleted
  per page.
- **Other-tables guarantee** (extended): `ownership_rules`, `services`,
  `certificate_ownership_overrides`, `tags`, `agent_groups` counts are
  unchanged across a prune (the existing test only pinned
  `certificate_ownership` and `audit_events`).

Plus a documentation-only fix to `PruneExplanationsPage`'s godoc so it
describes the actual bounded SQL algorithm (it still referenced the
pre-blocker-fix unbounded "load timeline + resolve current" shape).

All verified against PostgreSQL 16 with the full integration suite green.

## 11. Dormant status (binding)

**H-027 is dormant.** No code path in production calls
`PruneExplanationsPage`. Specifically:

- **No scheduler / background loop / goroutine** invokes the prune.
- **No HTTP endpoint** exposes a manual operator trigger.
- **No CLI subcommand** exposes it.
- **No findings / policy / recompute path** invokes it.
- The config knobs are wired into `ServiceConfig.Retention` for when a
  caller is added, but until that day they affect **nothing**.

This is intentional. The primitive ships fully built so a later caller
PR has a small, reviewable surface; the activation moment is a separate,
auditable change.

## 12. Explicitly out of scope for H-027

- **Scheduler / background recompute loop** that invokes the prune
  (sibling of the findings scheduler, sibling of the future B4 ownership
  scheduler).
- **Manual operator endpoint** (e.g.
  `POST /api/v1/ownership/explanations/prune`).
- **CLI / UI / dashboards** for retention.
- **Archive / cold storage** of pruned rows (v0.x is hard-delete; the
  forensic record survives in `audit_events` + the FK-pinned current
  explanation).
- **Retention for other tables** (`governance_recompute_runs`,
  overrides, findings, sessions). These are separate concerns.
- **`audit_events` retention or deletion** — never.
- **Per-org configurable retention** (knobs are deployment-global in
  v0.x; per-org config is a multi-tenancy concern, deferred).
- **Config-change audit** for the retention knobs (HARDENING_BACKLOG
  candidate, noted in the design doc §15).
- **Findings / policy integration** of pruned-history awareness.
- **B4 ownership scheduler** wiring — that phase is separate and may
  choose to compose H-027 prune calls into its loop, but H-027 itself
  exposes only the primitive.

## 13. Remaining backlog / next-phase candidates

Sequenced; do **not** start without an explicit decision:

- **H-027-PR3 (optional) — manual operator trigger**. An operator-only
  endpoint that invokes one (or a bounded number of) `PruneExplanationsPage`
  calls per click. Mirrors the B3A recompute-trigger
  auth/lock/audit/`?nowait` pattern. Lets a pilot deployment exercise
  the primitive on real data before any background loop exists.
- **B4 — Ownership scheduler**. The dark-by-default background loop that
  wires both `RecomputeScheduled` and (optionally) the per-org prune
  call. Sibling of the findings scheduler.
- **Config-change audit** for the retention knobs (`ANCHORIX_OWNERSHIP_*`)
  so a deployment that lowers them produces a `severity="security"`
  audit trail (HARDENING_BACKLOG, noted in design §15).
- **H-026D — Findings & policy integration**. Independent of H-027 but
  the next logical engine consumer.

Pre-existing governance backlog (unchanged by H-027):

- **H-029** — paginate `ListOverridesExpiringBy`.
- **H-030** — collation-independent recompute stream merge.

## 14. Stability verdict

**H-027 is stable and dormant.** The retention storage surface is
complete, validated fail-closed, deterministically bounded, audit-atomic
with its DELETE, org-isolated with no enumeration, and structurally
incapable of pruning the FK-pinned current explanation. The prune
primitive is fully built and fully tested, with the canonical pure
spec (PR-1), the bounded SQL implementation (PR-2), and an adversarial
hardening pass (PR-2-hardening) all green against PostgreSQL 16. No
code path invokes it: turning H-027 on is a future, deliberate operator
or scheduler decision, not an automatic behavior change. The ownership
engine (H-026B1→B3B) and the retention surface (H-027) together provide
the **read + decide + bounded-history** floor on which the operational
layers (manual trigger, B4 scheduler, H-026D findings/policy
integration) can build.

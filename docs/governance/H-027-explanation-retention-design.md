# H-027 — Ownership Explanation Retention: Design Proposal

> **Status:** design / proposal only. **No code in this PR.** Source of
> truth for rules: [`CLAUDE.md`](../../CLAUDE.md). Builds on the merged
> ownership engine (H-026B1→B3B) and its closure
> ([`H-026B3B-closure-summary.md`](./H-026B3B-closure-summary.md)).
> Schema: `backend/migrations/0010_governance_ownership.sql`.
>
> This proposal designs **what** the retention strategy is and **how**
> it stays safe. It deliberately stops short of the scheduler / background
> job that would invoke it (out of scope; see §13). Implement only after
> review.

## 1. Problem statement

`ownership_match_explanations` is append-on-change: the recompute writes
a new row only when a certificate's decision actually changes (and the
single-cert re-derivation does the same on override create/clear). For a
stable fleet this is naturally bounded. But during **active
classification rollout** — operators iterating on rules, each iteration
flipping a slice of the fleet — the table grows by potentially tens of
thousands of rows/day. v0.x keeps every row forever; only the
`certificate_ownership.explanation_id` pointer (current explanation) and
the per-cert timeline endpoint reach them. Old rows accumulate with no
prune path.

H-027 designs a **deterministic, per-org, paged retention strategy**
that prunes stale per-certificate explanation history while preserving
the current explanation, the audit trail, and the B3A read contract.

## 2. Tables in scope

**In scope (the only table pruned):**

- `ownership_match_explanations` — per-`(cert, decision-change)`
  snapshots (`losing_rules`, `signals_seen`, `engine_version`, etc.).

**Explicitly NOT pruned (read/reference only):**

- `audit_events` — append-only, never deleted (CLAUDE.md §9; the
  table's BEFORE UPDATE/DELETE triggers forbid it at the DB level).
- `certificate_ownership` — derived current state; one row per cert,
  not history. Its `explanation_id` pins the current explanation.
- `governance_recompute_runs` — per-pass operational record;
  bounded, separate retention concern (not H-027).
- `certificate_ownership_overrides` — soft-deleted, kept for history;
  out of scope.
- `ownership_rules`, `services`, `tags`, `agent_groups`, etc. —
  operator-curated vocabulary; never touched.

## 3. What must never be deleted (hard invariants)

1. **The current explanation of any certificate.** Enforced by the
   existing FK: `certificate_ownership.explanation_id` is `NOT NULL`
   with `ON DELETE RESTRICT` to `ownership_match_explanations`. The
   database itself refuses a DELETE of a pinned explanation — the
   prune is **belt-and-suspenders safe** even against a logic bug, and
   the retention query must additionally exclude it so the prune never
   *attempts* a doomed DELETE.
2. **Any `audit_events` row.** H-027 only deletes from
   `ownership_match_explanations`. No audit deletion, ever.
3. **The explanation a B3A read could currently return as `current`.**
   Same as (1) — the current explanation is always the most recent and
   always pinned.
4. **Cross-org rows.** Every prune is scoped to one
   `organization_id`; no statement may touch another org's rows.

## 4. Retention policy options

| Option | Rule | Pros | Cons |
|---|---|---|---|
| **A. Latest-N per cert** | Keep the N most recent explanations per cert; delete the rest. | Bounded per cert; simple; predictable. | A churny cert and a quiet cert get the same depth; time-blind. |
| **B. Age window** | Keep explanations newer than T; delete older. | Time-aligned with operator memory; simple. | A cert with no recent change could lose *all* non-current history (current is still FK-pinned, so safe, but the timeline collapses to one row). |
| **C. Hybrid (latest-N OR newer-than-T)** | Keep a row if it is in the latest N per cert **OR** newer than T; delete only rows that are both beyond N and older than T. | Keeps recent forensics regardless of churn, AND a minimum depth regardless of age; the current row is always kept (it is both newest and FK-pinned). | Slightly more complex predicate. |

**Recommended: Option C (hybrid).** It is the policy the H-027 backlog
entry already sketched ("keep the latest 10 per cert; prune rows older
than 90 days not in the latest-10 set"). The hybrid is the only option
that satisfies both "an operator can always see the last few decisions"
(forensics) and "old churn eventually goes away" (storage), and it never
risks collapsing a cert's history to a single row prematurely.

## 5. Default retention recommendation

- `ANCHORIX_OWNERSHIP_EXPLANATION_KEEP_N` — default **10**. Minimum
  per-cert explanations always retained, regardless of age.
- `ANCHORIX_OWNERSHIP_EXPLANATION_MAX_AGE` — default **90 days** (2160h).
  Rows beyond the latest-N **and** older than this are eligible for
  deletion.

A row is **deleted** iff: it is NOT the current (FK-pinned) explanation
**AND** it is not within the latest-N for its cert **AND** its
`decided_at` is older than `now − MAX_AGE`. Both knobs live in
`internal/config`, loaded once at startup (CLAUDE.md §8.9), validated
(`KEEP_N ≥ 1`, `MAX_AGE ≥ some floor e.g. 24h`), fail-closed on invalid.

Rationale for the defaults: 10 covers the typical "what were the last few
flips?" triage depth; 90 days aligns with a quarter of operator memory
and common audit windows. Both are tunable per deployment without a
schema change. These are starting points — pilot measurements may adjust.

## 6. Per-org isolation model

- The prune operates **one organization at a time**. The unit of work is
  `prune(organizationID)`; there is no cross-org statement.
- Every DELETE and every supporting SELECT carries
  `WHERE organization_id = $1`, matching the H-009 composite-FK posture
  used throughout governance.
- The caller (the future scheduler, out of scope) iterates orgs and
  invokes the per-org prune under the **per-org ownership advisory lock**
  (`WithTxLockedOwnership(orgID)`), so a prune serializes with recompute
  and override mutations for that org and cannot interleave with a
  decision change mid-prune. Different orgs prune independently.

## 7. Pagination / streaming strategy (no fleet-wide scan)

The prune must never scan the whole table or the whole fleet in one
statement. Two candidate shapes, both paged by certificate:

**7.1 Per-cert paged prune (recommended).**
Walk the org's certificates that *have* explanation history, in
`certificate_id ASC` cursor order, a bounded page of cert ids at a time
(e.g. 500). For each cert in the page, delete its eligible rows
(beyond-N **and** older-than-T, excluding the pinned current). The
per-cert delete is bounded by that cert's history depth. Memory and
statement size stay O(page × per-cert-history), never O(fleet).

The driving cursor is over the **distinct certificate_ids present in the
explanation table for the org** — bounded, index-backed (see §9), and
disjoint/ordered exactly like the recompute's signal/ownership walks
(reusing the established H-026B paging convention and the H-030 ordering
invariant: server-minted hex ids → byte order == collation order).

**7.2 Batched-DELETE-with-LIMIT (alternative).**
A single `DELETE … WHERE id IN (SELECT id … ORDER BY … LIMIT batch)`
loop, batch size bounded, repeated until zero rows affected. Simpler but
the eligibility predicate (latest-N-per-cert) needs a window function,
which is awkward to bound per statement and risks a large sort. Rejected
in favor of 7.1's explicit per-cert paging, which keeps each statement's
working set tied to one cert.

**Determinism:** for a fixed `(now, KEEP_N, MAX_AGE)` and DB state, the
set of deleted rows is identical across runs; re-running after a prune is
a no-op (zero rows eligible). Idempotent, same discipline as recompute.

## 8. Ordering strategy

- **Cert cursor:** `certificate_id ASC` (the prune's outer walk).
- **Within a cert, "latest N":** `decided_at DESC, id ASC` — identical to
  the B3A timeline ordering, so "latest N" the prune keeps == the first N
  the timeline endpoint returns. (`id` is the deterministic tiebreaker on
  equal `decided_at`, matching the explanation read path.)
- The current explanation (FK-pinned) is, by construction, the newest
  row, so it is always inside latest-N and never eligible.

## 9. Indexes required

- **Reuse** `ownership_match_explanations_cert_timeline_idx`
  `(organization_id, certificate_id, decided_at DESC)` — already exists;
  backs both the per-cert latest-N determination and the timeline read.
  No new index needed for the per-cert delete.
- **Possibly add** (decide at implementation, justify in the PR): an
  index supporting the *outer* "distinct certificate_ids with history in
  this org, cursor by id" walk. The timeline index already leads with
  `(organization_id, certificate_id)`, so a loose index scan / `DISTINCT`
  over its prefix likely suffices — **measure with `EXPLAIN` before
  adding anything**, consistent with the H-026B1 binding-query discipline.
  No fleet-wide GROUP BY.
- Any new index is introduced in the same migration that needs it, with
  an inline comment naming the query pattern (CLAUDE.md §16).

## 10. Delete vs archive semantics

- **v0.x: hard DELETE.** Pruned rows are removed, not archived. The
  rows are derived, reproducible state (a recompute regenerates the
  current explanation; historical snapshots are forensic, not
  authoritative). Archiving to cold storage is an over-engineering for
  v0.x and adds a second storage surface to secure.
- **Audit, not per-row.** Each prune pass writes **one**
  `governance.explanation_pruned` audit row per org per pass
  (severity:"security", in the same transaction as the deletes), carrying
  the deleted count + the policy `(KEEP_N, MAX_AGE)` used + the org. No
  per-deleted-row audit (that would re-introduce the amplification H-019
  / the bulk-rollup pattern guard against).
- **The forensic record survives in two places** the prune never
  touches: (a) the current explanation (FK-pinned, always present), and
  (b) `audit_events` — every ownership transition already emitted a
  severity:"security" row (`ownership.assigned/flipped/cleared/...`) at
  the time it happened, so "what changed and when" remains reconstructable
  even after the *explanation snapshot* for that change is pruned.
- **Not a migration.** The prune is a scheduled `DELETE` against existing
  rows, not a schema change (CLAUDE.md §16 two-phase rule does not apply).
  The only migration H-027 might carry is an additive index (§9), if
  measurement justifies one.

## 11. API behavior after retention

The B3A read contract is preserved:

- `GET /certificates/{id}/ownership` and `.../ownership/explanation`
  (current) — **unchanged**: the current explanation is FK-pinned and
  never pruned, so the default (non-history) response is identical
  before and after a prune.
- `GET /certificates/{id}/ownership/explanation?include_history=true` —
  returns the **retained** timeline (current + up to the last `KEEP_N`,
  minus anything aged out beyond N). The cursor-paged walk added in
  B3A/B3A-hardening still works; it simply has fewer rows to page
  through. No endpoint, field, status code, or cursor-format change →
  no `/api/v2` needed (CLAUDE.md §17 additive-only).
- `GET /ownership/{unowned,ambiguous,stale}` and `/ownership-rules` —
  unaffected (they read `certificate_ownership` / `ownership_rules`,
  not explanation history).
- A future API consumer must already treat history as a bounded,
  paginated list (it always was) — retention only reduces depth, never
  changes shape. This should be stated in `docs/api/REST_API.md` when the
  implementation lands.

## 12. Tests required (for the implementation PR, not this one)

- **Retention selection (pure, table-driven):** given a per-cert set of
  explanations with varied `decided_at`, the eligible-for-delete set is
  exactly {not-current} ∩ {beyond latest-N} ∩ {older than MAX_AGE};
  current always kept; latest-N always kept; rows newer than MAX_AGE
  always kept even beyond N.
- **Current explanation never deleted:** prune with aggressive
  (KEEP_N=1, MAX_AGE=0) settings; assert every cert still has its
  FK-pinned current explanation and the FK never errors.
- **Idempotency:** prune, then prune again at the same `now` → second
  pass deletes zero rows, emits a count-0 (or no) audit row per the
  chosen convention.
- **Determinism:** same inputs + DB state → identical deleted set across
  runs.
- **Per-org isolation:** seed two orgs; prune org A; assert org B's
  explanation rows and counts are untouched; no cross-org delete.
- **Pagination / no fleet scan:** seed many certs × deep history; force a
  small page size; assert the prune covers every cert exactly once, and
  pin the per-cert delete plan with `EXPLAIN` (no full-table scan, no
  fleet-wide GROUP BY).
- **Audit:** exactly one `governance.explanation_pruned`
  (severity:"security") per org per pass, with the correct count +
  policy metadata, written in the same tx as the deletes; an injected
  audit failure rolls the deletes back (atomicity).
- **API contract:** before/after a prune, the `current` explanation read
  is byte-identical; `include_history` returns the retained subset and
  still paginates correctly; no 5xx introduced.
- **B3A regression:** the existing explanation read + cursor-walk tests
  still pass against a pruned dataset.
- **Lock behavior:** a prune and a concurrent recompute/override for the
  same org serialize on the advisory lock (no interleave); different orgs
  proceed independently.

## 13. Rollout plan

1. **Config knobs land dormant.** Add `KEEP_N` / `MAX_AGE` to
   `internal/config` with validation; nothing invokes the prune yet.
2. **Prune primitive lands behind no caller.** Implement
   `PruneExplanations(ctx, orgID, now)` on the ownership service +
   repository, fully tested (§12), but wired to **nothing** — no
   endpoint, no scheduler. Reversible: dead code path, zero runtime
   effect.
3. **Manual trigger (optional, decide at review).** Optionally expose an
   operator-only `POST /ownership/explanations/prune` (or fold into the
   existing recompute trigger surface) so the prune can be exercised on a
   pilot DB before any background loop exists. If added, it follows the
   B3A recompute-trigger auth/lock/audit pattern exactly.
4. **Scheduler wiring is a SEPARATE later phase** (the B4 ownership
   scheduler, or a sibling). H-027 does **not** implement it. The prune
   primitive is designed so the scheduler just calls it per org on a
   cadence, dark-by-default, exactly like the findings/ownership
   scheduler precedent.
5. **Default-safe:** until a caller is wired, retention has zero effect;
   turning it on is a deliberate operator action (a manual trigger or,
   later, enabling the scheduler).

## 14. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Pruning the current explanation | critical | FK `ON DELETE RESTRICT` makes it impossible at the DB level; the query also excludes it so it never attempts the delete. |
| Losing the only forensic record of a past change | medium | `audit_events` retains every transition (severity:"security") independently; explanation snapshots are supplementary, not the sole record. |
| Fleet-wide scan / long-held lock | medium | Per-cert paged prune; bounded per-statement working set; advisory lock held only for the pass, releasable; consider per-org time budget when the scheduler lands. |
| Cross-org deletion | critical | Every statement org-scoped; per-org unit of work; isolation test. |
| Audit amplification (per-row prune audit) | medium | One rollup audit row per org per pass, not per deleted row. |
| Arbitrary default window before pilot data | low | Knobs are config, tunable per deployment; defaults documented as starting points. |
| Prune interleaving with recompute (a row created mid-prune gets pruned, or a soon-to-be-current row deleted) | medium | Advisory lock serializes prune with recompute/override per org; REPEATABLE READ snapshot if the prune reads-then-deletes. |

## 15. Abuse cases

- **Operator forces churn to bury history.** Rapid rule edits → many
  flips → many explanations; a prune could erase the intermediate trail.
  Mitigated: every flip's `ownership.*` audit row is permanent in
  `audit_events`, so the *decision history* is not erasable via
  explanation pruning. The explanation *snapshot* (signals/losing-rules)
  is the only thing lost, and the latest-N keeps recent ones.
- **Retention knob set pathologically low to hide recent activity.**
  Config is set once at startup and is itself an operator-trust boundary
  (CLAUDE.md §12); a future config-change audit (HARDENING_BACKLOG
  candidate) would surface it. Floor validation (`KEEP_N ≥ 1`,
  `MAX_AGE ≥ floor`) prevents "keep nothing".
- **Prune-triggered DoS** (if a manual trigger is exposed): same posture
  as the recompute trigger — operator-only, advisory-lock-serialized,
  idempotent (a repeated prune is a no-op).

## 16. Failure modes

- **Audit write fails mid-prune** → whole tx rolls back; no rows deleted,
  no audit row (atomicity, proven by test).
- **Lock contention with an in-flight recompute** → the prune waits for
  the lock (or, if a `?nowait` variant is later offered, returns a
  deterministic "in progress"); it never deletes outside the lock.
- **Pagination cursor drift** → server-minted hex ids guarantee
  byte==collation order (H-030); the per-cert walk is disjoint and
  complete; a row inserted mid-walk for an already-passed cert is simply
  pruned next pass (eventually consistent, never lost-while-current).
- **Invalid config** → startup fails closed (CLAUDE.md §8.9); the prune
  is never constructed with a bad policy.
- **Partial pass interrupted (ctx cancel)** → committed per-page work
  stands; the next pass resumes from the start (idempotent), prunes
  whatever remains eligible.

## 17. Migration requirements

- **No destructive migration.** The prune is a scheduled DELETE of
  derived rows, not DDL.
- **At most one additive migration** — a new index for the outer
  distinct-cert walk **only if** `EXPLAIN` shows the existing timeline
  index is insufficient. If added: append-only, numbered
  `00NN_ownership_explanation_retention_idx.sql`, with an inline comment
  naming the query pattern it serves. Decide at implementation; do not
  add speculatively.
- No change to `ownership_match_explanations` columns or to the
  `certificate_ownership.explanation_id` FK.

## 18. Proposed PR split

- **H-027-PR1 — config + retention selection (no caller).** Add the two
  config knobs (validated, dormant) + the pure retention-selection logic
  + its unit tests. No DB writes, no endpoint. ~small. Fully reversible.
- **H-027-PR2 — prune primitive + repository deletes.** Implement
  `PruneExplanations(ctx, orgID, now)` (per-cert paged DELETE under the
  advisory lock, one rollup audit row, atomic) + the
  repository delete/read methods + the `EXPLAIN`-pinned index decision +
  the full integration suite (§12). Wired to **no caller** — exercised by
  tests only. Reversible (dead path).
- **H-027-PR2-hardening — adversarial pass.** Race windows (prune vs
  recompute vs override), current-explanation-never-deleted under
  aggressive settings, cross-org isolation, audit-rollback, idempotency,
  no-fleet-scan `EXPLAIN`, B3A read regression.
- **(Optional) H-027-PR3 — manual operator trigger.** Only if review
  wants a pilot-exercisable endpoint before the scheduler. Auth/lock/audit
  mirror the B3A recompute trigger.
- **Scheduler wiring is NOT an H-027 PR** — it belongs to the B4
  ownership-scheduler phase and is explicitly out of scope here.

## 19. Explicit out-of-scope items

- **Scheduler / background job** that invokes the prune (B4 / sibling
  phase).
- **Archive / cold storage** of pruned rows (v0.x is hard-delete).
- **Retention for other tables** (`governance_recompute_runs`,
  overrides, findings) — separate concerns.
- **`audit_events` retention or deletion** — never.
- **UI / dashboards** for retention.
- **Policy / findings integration.**
- **Per-org configurable retention** (knobs are deployment-global in
  v0.x; per-org config is a multi-tenancy concern, deferred).
- **Config-change audit** for the retention knobs (a separate
  HARDENING_BACKLOG candidate, noted in §15).

## 20. Stability / readiness note

The critical safety property — "the current explanation can never be
pruned" — is **already enforced by the existing schema** (`NOT NULL` +
`ON DELETE RESTRICT` on `certificate_ownership.explanation_id`), so even
a buggy prune fails closed at the database boundary. Combined with
`audit_events` being independently permanent, the forensic floor is
guaranteed regardless of retention aggressiveness. This makes H-027 a
low-blast-radius addition: it reduces storage of supplementary snapshots
without weakening any correctness, audit, or read guarantee established
in H-026B. Recommend proceeding to H-027-PR1 after this design is
reviewed.

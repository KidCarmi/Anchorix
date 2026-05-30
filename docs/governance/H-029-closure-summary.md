# H-029 — Expiring Override Sweep Pagination: Phase Closure

> **Status:** closed / **dormant by design**. Source of truth for rules:
> [`CLAUDE.md`](../../CLAUDE.md). Design proposal:
> [`H-029-expiring-override-sweep-pagination-design.md`](./H-029-expiring-override-sweep-pagination-design.md).
> Builds on the ownership engine (H-026B1→B3B) — see
> [`H-026B3B-closure-summary.md`](./H-026B3B-closure-summary.md). Related
> retention phase closure:
> [`H-027-closure-summary.md`](./H-027-closure-summary.md).

## 0. Merged PRs

| PR | Title | Class |
|----|-------|-------|
| #66 | H-029 expiring override sweep pagination design | docs |
| #67 | H-029 PR-1 paged expiring override read primitive | feature (dormant) |
| #68 | H-029 PR-1 hardening pass | test-only |
| #69 | H-029 PR-2 expiring override sweep primitive | feature (dormant) |
| #70 | H-029 PR-2 hardening pass | test-only |

H-029 is the **expired-override sweep surface** on top of the H-026B
ownership engine. It bounds the read of expiring overrides (previously
unpaged dead code waiting for B4) and adds a deterministic per-page
clear + re-derive + audit primitive that a future B4 scheduler /
optional manual operator trigger composes. **Nothing in production
invokes either primitive.** Activation is a separate, deliberate
operator decision — not part of this phase.

## 1. What H-029 delivered

- **Design proposal** (#66): two distinct primitives — read-only
  listing vs. mutating sweep — both paged, both per-org, both
  composable by a future caller. Surfaced the framing-changing finding
  that the merged `ListOverridesExpiringBy` had **zero production
  callers**: the H-026B2 recompute auto-clears the per-cert override
  from its cert-stream merge inside `processCert`, not from a list
  call. The design therefore covers both reads and mutations from
  scratch.
- **Paged read primitive** (#67): `ListExpiringOverridesPaged`
  replacing the unpaged `ListOverridesExpiringBy` (removed cleanly —
  zero production callers, single test caller migrated). Bounded,
  index-aligned with the existing partial-unique active-override
  index, page-size defaults + clamps at the repo boundary.
- **Read hardening** (#68): row-content-hashed read-only guard
  (catches in-place UPDATE, not just INSERT/DELETE), cursor
  determinism, cleared-row non-reappearance, boundary EXPLAIN, and a
  reflection-based regression guard asserting the unpaged variant
  cannot reappear.
- **Sweep primitive** (#69): `Service.SweepExpiringOverridesPage` —
  per-org, one bounded page = one `WithTxLockedOwnership(org)` tx;
  composes the PR-1 read with the existing B3A
  `ClearOwnershipOverride` + B3B `rederiveCertificate` + per-override
  `ownership.override_expired` audit. Race-safe
  (`ErrOwnershipOverrideNotFound` → silent no-op); atomic (audit
  failure rolls the page back).
- **Sweep hardening** (#70): rederive-failure rollback,
  non-NotFound-clear-error rollback, `sweep_id` correlation, cursor
  progression past lost-race rows, targeted re-derivation,
  empty-page no-op, plus a source-file forbidden-surface guard so
  router / handler / goroutine / ticker / API-path surfaces cannot
  appear in the dormant primitive without an explicit scope
  expansion.

## 2. Read primitive behavior

`repo.ListExpiringOverridesPaged(ctx, org, now, cursorCertID, pageSize)`
returns a bounded page of **active overrides whose expires_at has
passed**, in deterministic `certificate_id ASC` order.

- **Filter** (the production SQL, exported as
  `postgres.ListExpiringOverridesPagedQuery` for the EXPLAIN test):
  ```
  WHERE organization_id = $1
    AND cleared_at IS NULL
    AND expires_at IS NOT NULL
    AND expires_at <= $2
    AND certificate_id > $3
  ORDER BY certificate_id ASC
  LIMIT $4
  ```
- **Inclusive `<=` cutoff** on `expires_at`: a row at exactly the
  cutoff is returned (pinned at SQL-primitive level so wall-clock
  drift between caller and DB can't perturb the comparison).
- **Cursor**: `certificate_id` exclusive (`> cursor`). Empty cursor
  starts at the lexicographically smallest cert id. A cursor past the
  last cert returns an empty slice without error — the terminal-page
  contract.
- **Bounds at the repo boundary**: `pageSize <= 0` →
  `postgres.DefaultExpiringOverridesPageSize` (500); `pageSize >
  postgres.MaxExpiringOverridesPageSize` (1000) → clamped. The
  service layer adds its own `Default/MaxExpiringOverridesSweepPageSize`
  (same values), so a future caller is bound at both layers.
- **No new index needed**: the existing partial-unique
  `certificate_ownership_overrides_active_idx (organization_id,
  certificate_id) WHERE cleared_at IS NULL` covers the filter + cursor
  + order. EXPLAIN pins `Limit` present + no fleet-wide `Group Key`
  across `pageSize ∈ {1, default, max}`.
- **Read-only**: hardening pins zero side effects on
  `certificate_ownership_overrides` / `certificates` /
  `certificate_ownership` / `audit_events` /
  `ownership_match_explanations` / `services` / `ownership_rules`
  across multiple invocations, using per-row content hashes
  (`md5(to_jsonb(t.*)::text)`), with a positive-control test proving
  the snapshot mechanism is sensitive to in-place UPDATE.

## 3. Sweep primitive behavior

`Service.SweepExpiringOverridesPage(ctx, org, cursorCertID, pageSize)`
returns `{OrganizationID, StartCursor, NextCursor, SweepID,
CertsScanned, ClearedCount, Done}`.

- **One call = one bounded page = one
  `WithTxLockedOwnership(org)` transaction.** Lock held only for the
  page's work; **never** across a full-org sweep (the loop is the
  caller's responsibility, not this primitive's).
- **Per-row work** inside the locked tx:
  1. `ClearOwnershipOverride(org, override_id, "system",
     "auto-expired", now)` — sets `cleared_at` / `cleared_by` /
     `cleared_reason`, freeing the partial-unique active-override
     slot.
  2. `rederiveCertificate(org, cert_id, nil, now)` (B3B) — the cert's
     ownership flips to whatever the rule engine decides without the
     override (matched rule, unowned, etc.). Re-uses B3B's single-cert
     primitive identically to how the operator-initiated
     `ClearOverride` path uses it.
  3. Emit one `ownership.override_expired` audit row.
- **`sweep_id`** is a per-page minted id (`ids.New`, analogous to the
  recompute's `run_id`). Every audit row from one page carries the
  same `sweep_id`; successive pages mint different ids. Operators
  correlate the expirations of one page via this id.
- **Bounds**: `pageSize <= 0` → `DefaultExpiringOverridesSweepPageSize`
  (500). `pageSize > maxExpiringOverridesSweepPageSize` (1000) →
  clamped (proven against a 1010-cert fixture). Service-level
  constants live alongside the sweep primitive in the `ownership`
  package; the repo's PR-1 constants re-clamp at the boundary as
  defense in depth.
- **Targeted re-derivation**: only certs whose overrides this page
  actually cleared are re-derived. A non-target cert's
  `certificate_ownership` row stays byte-identical across the call
  (proven via content-hash snapshot in hardening).
- **Cursor progression** always advances to the last cert id the
  listing read returned for the page — including past rows whose
  clear lost a race (those rows drop out of the active partial index,
  so a later pass naturally won't see them anyway). Done is true when
  the page returned fewer rows than `pageSize`.
- **Fails closed** on empty org id before the lock is acquired.

## 4. Transaction / locking guarantees

- The sweep page runs under `WithTxLockedOwnership(org)` (xact-scope
  advisory lock, READ COMMITTED). The lock serializes the sweep
  against any in-flight recompute, override mutation, or other sweep
  page for that org (governance plan §3.9). The read-only
  `ListExpiringOverridesPaged` is NOT locked — pure read, snapshot-
  consistent with whatever transaction the caller supplies; when the
  sweep wraps it internally, the lock is inherited from the page tx.
- **Lock hold is bounded by page work**: at most pageSize × (one
  clear + one `rederiveCertificate` + one audit row). At the v0.x
  default (500 ceiling) this is comfortable; with the cap at 1000 the
  lock hold is still small relative to a recompute pass.
- **No nested or recursive lock acquisition.** The sweep's per-row
  path calls `rederiveCertificate`, which is the B3B primitive — it
  performs no lock acquisition of its own (the lock is already held
  by the outer page tx).
- **No multi-page loop** in production code. A future caller that
  wants to drain the org's expiring set calls
  `SweepExpiringOverridesPage` in a loop with the returned cursor —
  but H-029 itself only ships the page primitive. The forbidden-
  surface guard prevents this primitive from silently growing such a
  loop.
- **Audit atomicity**: every clear + every `rederiveCertificate` +
  every audit row commits in the SAME transaction as a page. A
  rederive failure, a non-NotFound clear error, or an audit-write
  failure rolls the **entire page back** — proven separately for each
  failure mode by the hardening pass.

## 5. Pagination + cursor guarantees

- **`certificate_id ASC` exclusive** is the single, deterministic
  cursor for both primitives. No compound cursor; no second-key
  tiebreaker — `certificate_id` is unique within active overrides via
  the partial-unique constraint.
- **Empty cursor** starts at the smallest cert id, pinned via
  non-lexicographic insertion order (would fail an "insertion-order"
  bug).
- **Resume contract**: passing the previous page's
  `NextCursor` as the next call's `cursorCertID` returns the next
  bounded slice. Cursor cert is excluded (proven by an explicit
  boundary test on PR-1).
- **Terminal page**: a cursor past the last cert id returns an empty
  slice without error. `Done == true` when the page returned fewer
  than `pageSize` rows.
- **Determinism under equal timestamps**: equal `expires_at` values
  do NOT perturb cert_id ASC order (proven by a tie-break test on
  PR-1).
- **No fleet-wide scan, no unbounded read** at either the cursor or
  the per-cert level: every read is `LIMIT`-bound, EXPLAIN-pinned.
  Backed by the existing partial-unique index — no new index in v0.x.
- **Live-state interaction**: a row cleared between sweep pages
  (operator manual clear, or a concurrent recompute auto-expiry)
  drops out of the active partial index; the cursor walk never
  re-surfaces it. Pinned by a PR-1 hardening test.

## 6. Audit behavior

- **One audit action**: `ownership.override_expired` —
  **deliberately shared with the H-026B2 recompute auto-expiry path**
  so downstream consumers don't have to special-case the source.
- **Per-override, not rollup**. Override cardinality is low by design
  (operator pins); per-row is the right granularity. (Contrast with
  H-027 explanation pruning where deletion cardinality scales with
  fleet × churn and a rollup is mandatory.)
- **Actor attribution**: `actor = "system"`, `actor_type = "system"`.
  The sweep is system-initiated — an operator triggers it via a
  future endpoint or scheduler, but the sweep itself carries no
  end-user identity. Matches the recompute auto-expiry path's
  attribution.
- **Metadata shape**:
  `{severity:"security", sweep_id, override_id, service_id,
  reason:"auto-expired"}`. The recompute path's metadata carries
  `run_id` instead of `sweep_id`; the action is the same so consumers
  that ignore the source still work, but the field difference lets an
  operator distinguish "expired by a recompute pass" from "expired by
  a sweep page" without parsing the action string.
- **Exactly one audit row per successfully cleared override.** A row
  cleared inside the page's tx (page commit succeeds) → one audit
  row. A row that lost a race to a concurrent operator clear → zero
  audit rows from the sweep (the winner's path already audited it
  under the appropriate action — `ownership.override_cleared` for an
  operator clear). A page that scans 0 candidates → mints a
  `sweep_id` but emits zero audit rows.
- **`audit_events` is never deleted** by H-029 (CLAUDE.md §9 +
  H-009 trigger).

## 7. Race semantics

The lock-released window between sweep pages is the only place where
state can shift relative to a sweep's listing read. The contract is:

- **Lost-race silent no-op**: if `ClearOwnershipOverride` returns
  `ErrOwnershipOverrideNotFound` (the row was cleared by a concurrent
  operator or by a recompute auto-expiry between the listing read and
  the per-row clear), the sweep treats it as a **silent no-op**: no
  error, no audit, page continues. Proven by a focused PR-2
  hardening test that operator-clears one of three expired rows
  before the sweep — sweep clears the other two, emits exactly two
  audits, zero for the lost cert.
- **Cursor still advances** past lost-race rows. The page's
  `NextCursor` reflects the last cert id processed regardless of
  whether each row's clear succeeded or was silently skipped.
  Pinned by a PR-2 hardening test that operator-clears the middle of
  a 3-row fixture and asserts `NextCursor == cert-lr-03` (the last
  visible row), not the lost-race row's id.
- **Any other clear error** (not `ErrOwnershipOverrideNotFound`)
  rolls the entire page back. Proven by `failingClearRepo` wrapper
  that injects a synthetic non-NotFound error and asserts page
  rollback (no clears, no audit).
- **Rederive failure** rolls the entire page back — including rows
  whose clears already succeeded earlier in the page. Proven by
  `failingSignalsRepo` wrapper that forces `GetCertificateSignals` to
  error on a specific cert mid-page.
- **Audit-write failure** rolls the entire page back. Proven across
  multiple certs in a single page.

## 8. Boundedness guarantees (no fleet-wide scan, no unbounded read)

The whole stack is bounded by construction; hardening re-pins it
concretely:

- Read query: `LIMIT pageSize` (max 1000 after clamping). EXPLAIN
  shows a `Limit` node and no fleet-wide `Group Key` across
  `pageSize ∈ {1, default, max}`.
- Sweep page: at most pageSize candidate rows, each producing one
  clear + one re-derive + one audit row. Lock hold scales linearly,
  bounded by pageSize × per-row work.
- Cursor walk: each cert visited exactly once across pages (the
  active-partial-index drops cleared rows, so a re-visit is
  unreachable). Empty-org and past-last-cursor pages return empty
  immediately.
- Page-size overshoot: 1010-cert fixture with `pageSize = 100_000`
  proves `CertsScanned <= 1000` (clamp) and `Done == false`.
- Page-size zero / negative: default fallback proven on a small
  fixture (the walk completes in one page rather than scanning
  nothing).
- **No regression vector for an unbounded read**: the unpaged
  `ListOverridesExpiringBy` is removed, and a reflection-based unit
  test asserts the method is absent from both the
  `governance.OwnershipRepository` interface and the
  `*postgres.OwnershipRepository` concrete type. Adding it back fails
  unit tests in CI's `go test ./...` phase, long before any
  integration test would.

## 9. Cross-org isolation guarantees

- Every `SELECT`, `UPDATE`, and audit row binds the org id. The read
  query is `WHERE organization_id = $1 AND ...`. The clear UPDATE is
  `WHERE organization_id = $1 AND id = $2 AND cleared_at IS NULL`.
  The audit row carries `organization_id = $1`. There is no
  cross-org statement anywhere.
- Service-level: `SweepExpiringOverridesPage` takes one
  `organizationID` argument and threads it into every call. Empty
  string is rejected before the lock is acquired.
- Cross-org isolation is pinned twice: (a) on PR-1, with an identical
  fixture in two orgs and a query of each — only the requested org's
  rows are returned; (b) on PR-2, where a sweep of `anchorix` is
  shown to leave another org's expiring overrides and audit log
  untouched.
- Repository-level adversarial guard: feeding `cert_id`s from cert B
  into a delete scoped to cert A (same org) yields 0 rows touched —
  proven via a focused test against the underlying
  `DeleteOwnershipExplanationsForCertificate` shape (H-027 PR-2
  hardening; relevant by symmetry — same H-009 composite-FK pattern).

## 10. Hardening coverage

**PR-1 read hardening (#68):**

- `IsReadOnly`: row-content-hash snapshot proves zero side effects on
  any table the read might plausibly mutate (catches in-place UPDATE,
  not just INSERT/DELETE).
- `ReadOnlyGuardCatchesInPlaceUpdate`: positive control — the
  snapshot mechanism is shown sensitive to a real
  `ClearOwnershipOverride` UPDATE; without this, a future weakening
  of the snapshot would silently make the read-only test vacuous.
- `CursorResumeBoundary`, `EmptyCursorReturnsSmallest`,
  `CursorPastLastReturnsEmpty`, `EqualExpiresAtOrderedByCertID`,
  `ClearedRowDoesNotReappearOnResume`, `ExplainBoundaryShapes`:
  cursor + ordering + boundedness invariants.
- Reflection-based unit guard: `ListOverridesExpiringBy` is absent
  from the interface AND the concrete type. Catches a regression in
  CI's unit phase.

**PR-2 sweep hardening (#70):**

- `RederiveFailureRollsBackPage` (failingSignalsRepo wrapper) +
  `NonNotFoundClearErrorRollsBackPage` (failingClearRepo wrapper):
  every non-silent error path rolls the whole page back.
- `SweepIDConsistentAcrossPage`: every audit row from one page
  carries the same `sweep_id` = `result.SweepID`.
- `DifferentPagesDifferentSweepIDs`: successive pages mint distinct
  `sweep_id`s; on-disk metadata reflects per-page assignment.
- `CursorAdvancesPastLostRaceRows`: `NextCursor` keeps advancing even
  when the middle of a page lost its race.
- `UntouchedCertsAreNotRederived`: non-target cert's
  `certificate_ownership` content hash is byte-identical
  before / after the sweep.
- `EmptyPageEmitsNoAuditNoMutation`: 0 candidates → 0 clears, 0
  audits, sweep_id still minted (call ran).
- Unit-level forbidden-surface guard: the sweep production file's
  source contains none of `HandleFunc`, `http.Handle`, `mux.Handle`,
  `http.HandlerFunc`, `go func(`, `time.Ticker`, `time.NewTicker`,
  `/api/v1`. Catches a regression long before any integration test
  would.

All verified against PostgreSQL 16 with the full ownership +
overrides + expiring + sweep integration suite green.

## 11. Dormant status (binding)

**H-029 is dormant.** No code path in production calls either primitive.
Specifically:

- **No scheduler / background loop / goroutine** invokes the sweep.
- **No HTTP endpoint** exposes a manual operator trigger.
- **No CLI subcommand** exposes it.
- **No findings / policy / recompute path** invokes it.
- **No production caller of `ListExpiringOverridesPaged`** outside of
  the sweep primitive (and the sweep itself has no caller).
- The repo's `ListExpiringOverridesPaged` is the bounded replacement
  for the removed unpaged dead method — adding any caller is a
  separate decision.

The forbidden-surface unit test makes this property **machine-
verifiable** for the sweep file specifically. The primitive ships
fully built so a later caller PR has a small, reviewable surface; the
activation moment is a separate, auditable change.

## 12. Explicitly out of scope for H-029

- **Scheduler / background recompute loop** that invokes the sweep
  (sibling of the findings scheduler, sibling of the future B4
  ownership scheduler).
- **Manual operator endpoint** (e.g.
  `POST /api/v1/ownership/overrides/sweep`) — deferred to optional
  H-029-PR3 or B4.
- **Full-org caller loop** in production code — the loop is the
  caller's responsibility (a future scheduler or manual trigger);
  H-029 ships only the per-page primitive. The forbidden-surface
  guard ensures this primitive does not silently grow such a loop.
- **Soon-to-expire notifications** ("these will drop in 24h") — a
  separate notification surface, not an H-029 concern.
- **Hard delete of long-cleared overrides** — pure history retention;
  if v0.x ever wants it, a separate H-029-style retention design
  applies (deletion target would be cleared rows, not active expired
  ones).
- **Audit retention or rollup of `ownership.override_expired`** —
  per-override cardinality is low by design; rollup is unnecessary.
- **UI / dashboards** for expiring overrides.
- **Policy / findings integration** of expired overrides.
- **Per-org configurable sweep limit** (page size is deployment-global
  in v0.x).
- **`?nowait` variant** of the sweep — analogous to the B3A
  recompute-trigger but not present here. Defer.
- **B4 ownership scheduler** wiring — separate phase; may compose
  H-029 sweep calls into its loop.

## 13. Remaining backlog / next-phase candidates

Sequenced; do **not** start without an explicit decision:

- **H-029-PR3 (optional) — manual operator trigger**. Operator-only
  endpoint that invokes one (or a bounded number of)
  `SweepExpiringOverridesPage` calls per click. Mirrors the B3A
  recompute-trigger and B3B override-clear auth + lock + audit
  patterns. Lets a pilot deployment exercise the primitive on real
  data before any background loop exists.
- **B4 — Ownership scheduler**. The dark-by-default background loop
  that may wire `RecomputeScheduled`, the H-027 retention prune,
  and (optionally) the H-029 sweep. Sibling of the findings
  scheduler.
- **H-026D — Findings & policy integration**. Independent of H-029
  but the next logical engine consumer.

Pre-existing governance backlog (unchanged by H-029):

- **H-030** — collation-independent recompute stream merge.
- **H-027 closure** documented in `H-027-closure-summary.md`.

## 14. Stability verdict

**H-029 is stable and dormant.** The expired-override sweep surface is
complete: a bounded paged read, a per-page mutating sweep that composes
the existing B3A clear + B3B re-derive + B2-shape audit, all under the
per-org advisory lock, all org-scoped, all `LIMIT`-bounded, all
EXPLAIN-pinned. Adversarial hardening covers every failure mode the
design specifies (rederive failure, non-NotFound clear error, audit
failure, lost-race silent no-op) plus the operational invariants
(`sweep_id` correlation, cursor progression past lost-race rows,
targeted re-derivation, empty-page no-op, in-place UPDATE detection).
The forbidden-surface unit test makes the dormant contract machine-
verifiable for the sweep file. No code path invokes either primitive:
turning H-029 on is a future, deliberate operator or scheduler
decision, not an automatic behavior change. The ownership engine
(H-026B1→B3B), the retention surface (H-027), and the override-sweep
surface (H-029) together provide the **read + decide + bounded-history
+ bounded-clear** floor on which the operational layers (manual
trigger, B4 scheduler, H-026D findings/policy integration) can build.

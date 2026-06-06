# B4 — Governance Scheduler Foundation & Adapters: Closure Summary

> **Document type:** roadmap / phase-closure summary. Documentation only.
> It records the *as-merged* state of the B4 Governance Scheduler
> foundation and its two job adapters. It introduces **no** runtime
> behavior, activates **nothing**, and is **not** an implementation PR.
>
> **Authoritative design:** [`B4-governance-scheduler-design.md`](./B4-governance-scheduler-design.md).
> **Primitive closures:** [`H-029-closure-summary.md`](./H-029-closure-summary.md),
> [`H-027-closure-summary.md`](./H-027-closure-summary.md).

---

## 1. Objective

B4 builds the **dormant foundation** for governance maintenance
scheduling: the persistent per-`(org, job)` state, the typed
configuration, the job registry, the synchronous bounded job runner, the
per-`(org, job)` advisory-lock helper, and two thin **job adapters** that
wrap the already-merged dormant maintenance primitives:

- **H-029** — expired ownership-override sweep (`SweepExpiringOverridesPage`).
- **H-027** — explanation-retention prune (`PruneExplanationsPage`).

The objective for B4 is **machinery, not motion**. Every piece a future
tick loop will call exists, is unit/hardening tested, and is wired to
**nothing**. Activation (the loop, the composition-root wiring, the
enable path) is deliberately deferred so that turning governance
maintenance on becomes a small, reviewable, operator-gated step rather
than an emergent behavior of merging adapters.

This honors the platform's core philosophy — **visibility before
automation** — and CLAUDE.md §7.1 (operator-controlled, no magic
automation in v0.1).

---

## 2. Completed PRs / Phases

| Phase | Scope | Status |
|---|---|---|
| **B4 Design** | Architecture, locking, config, audit, rollout design | merged |
| **PR-1** | Scheduler state foundation + config (`scheduler.go`, `internal/config`, migration `0012`) | merged |
| **PR-2** | Job registry + runner skeleton (`maintenance/registry.go`, `maintenance/runner.go`, `maintenance/job.go`) | merged |
| **PR-2 Hardening** | Adversarial tests + dormancy guard for registry/runner | merged |
| **PR-3** | Expired-override-sweep adapter (`maintenance/overridesweep/`) | merged |
| **PR-3 Hardening** | Adversarial tests for the H-029 adapter | merged |
| **PR-4** | Explanation-retention-prune adapter (`maintenance/explanationretention/`) | merged |
| **PR-4 Hardening** | Adversarial tests for the H-027 adapter | merged |

All eight units are merged to `main`. No follow-up implementation work is
in flight within B4 scope.

---

## 3. Final Architecture State

Layering (all under `backend/internal/`):

```
config/                         GovernanceScheduler* fields (typed, default-off)
governance/
  scheduler.go                  SchedulerJob, SchedulerJobStatus, SchedulerCursorStart,
                                consumer-owned SchedulerStateRepository + lock interface
  ownership/
    expiring_overrides_sweep.go H-029 primitive  (SweepExpiringOverridesPage)
    retention_prune.go          H-027 primitive  (PruneExplanationsPage)
  maintenance/                  DORMANT package (PR-2)
    job.go                      Job interface, PageLimits, PageResult
    registry.go                 JobRegistry (immutable), NewJobRegistry, Lookup, Names
    runner.go                   JobRunner, RunDueJob (synchronous, bounded, no goroutine)
    overridesweep/job.go        H-029 adapter  (PR-3)
    explanationretention/job.go H-027 adapter  (PR-4)
storage/postgres/
  governance_scheduler_repository.go
                                SchedulerStateRepository impl + schedulerJobLock
                                (pinned-connection advisory lock)
```

- **Modular monolith, provider-agnostic.** The maintenance layer depends
  only on consumer-owned interfaces; storage owns all SQL (CLAUDE.md §16,
  §8.6).
- **One new table:** `governance_scheduler_job` (migration `0012`),
  primary key `(org_id, job_name)`, default `enabled = FALSE`. It records
  **operational state only** (cursor, next-due, last outcome, backoff),
  never governance effects.
- **Persistence is the only schema footprint.** No API, no UI, no
  config-mutation surface was added.

---

## 4. What Is Now Available But Dormant

Available (constructible, tested) but **invoked by nothing in production**:

- `governance.SchedulerJob` operational-state model and its status enum.
- `maintenance.JobRegistry` + `maintenance.Job` contract.
- `maintenance.JobRunner.RunDueJob` — the synchronous per-due-item engine
  a future tick loop will call once per item.
- `overridesweep.Job` (H-029 adapter) and
  `explanationretention.Job` (H-027 adapter).
- The `schedulerJobLock` advisory-lock helper.
- All `GovernanceScheduler*` config values (parsed, validated at startup,
  then **unused** — wired to no consumer).

Dormant by construction: **no real `Job` is registered**, the runner is
**never called from `serve.go`**, and the config flag gates a loop that
**does not exist yet**.

---

## 5. Scheduler State / Config Foundation (PR-1)

**State** (`backend/internal/governance/scheduler.go`):

- `SchedulerJob` — per-`(org, job)` row: `Enabled`, `Cursor`,
  `NextDueAt`, `LastStartedAt/FinishedAt`, `LastStatus`, `LastError`
  (redacted summary only), `ConsecutiveFailures`.
- `SchedulerJobStatus` — explicit enum: `pending | running | completed |
  partial | error` (CHECK-fenced in migration `0012`). No implicit string
  comparison (CLAUDE.md §18 state machines).
- `SchedulerCursorStart = ""` — the start sentinel; the cursor is an
  **opaque, job-owned** token the scheduler stores and returns verbatim.
- Consumer-owned `SchedulerStateRepository` (load/upsert/`ListDueJobs` +
  `MarkJobStarted/Completed/Partial/Failed`) and the advisory-lock
  interface. Interfaces are owned by the consumer (CLAUDE.md §8.8).

**Config** (`backend/internal/config`): typed fields, validated at
startup, immutable after start, fail-closed (CLAUDE.md §8.9):

| Field | Default | Bound |
|---|---|---|
| `GovernanceSchedulerEnabled` | **false** | bool |
| `GovernanceSchedulerInterval` | 5m | ≥ 1m |
| `GovernanceSchedulerMaxItemsPerTick` | 50 | ≥ 1 |
| `GovernanceSchedulerMaxPagesPerRun` | 20 | ≥ 1 |
| `GovernanceSchedulerMaxRunDuration` | 30s | ≥ 1s |
| `GovernanceSchedulerPageLimit` | 200 | ≥ 1, ≤ primitive max |
| `GovernanceSchedulerPartialRequeueDelay` | 1s | > 0 and < interval |
| `GovernanceSchedulerRetryBase` | 1m | ≥ 1s |
| `GovernanceSchedulerRetryMax` | 1h | ≥ base |

The PR-1 source comment is explicit: these values are *"validated at
startup but wired to NOTHING in B4 PR-1: there is no scheduler loop,
goroutine, ticker, registry, or runner yet."*

---

## 6. Job Registry / Runner (PR-2)

**Registry** (`maintenance/registry.go`):

- `JobRegistry` wraps a private `map[string]Job`, built **once** via
  `NewJobRegistry(jobs ...Job)`. **Immutable after construction** — no
  `Register` method, no runtime mutation, no global registry (CLAUDE.md
  §8.8, §19 "hidden global state").
- Constructor validates: non-nil jobs, non-empty `Name()`, no duplicate
  names. `Lookup` returns `ErrUnknownJob` (fail-closed; an orphan
  persisted job with no registry entry is **inert**, never run).
- `Names()` returns a sorted (deterministic) list.

**Job contract** (`maintenance/job.go`):

```go
type Job interface {
    Name() string
    RunPage(ctx context.Context, organizationID, cursor string, limits PageLimits) (PageResult, error)
}
type PageLimits struct { PageSize int }
type PageResult struct { NextCursor string; Done bool; ItemsScanned int; ItemsChanged int }
```

`ItemsScanned` / `ItemsChanged` are **observational only** (metrics/logs)
— they carry no control-flow meaning. Pagination terminates on `Done`.

**Runner** (`maintenance/runner.go`):

- `JobRunner.RunDueJob(ctx, jobState) (RunReport, error)` — **synchronous
  and bounded; never spawns a goroutine.** It is the machinery a future
  tick loop calls once per due item.
- Per run: acquire the per-`(org, job)` advisory lock (non-blocking
  try); if not acquired → outcome `skipped_locked`. Otherwise run the
  bounded page loop (capped by `MaxPagesPerRun` **and** `MaxRunDuration`),
  persisting the cursor **only after a page commits**, and record the
  outcome via `SchedulerStateRepository`.
- `RunOutcome`: `skipped_locked | completed | partial | error`. On
  `error` the cursor is **not** advanced (the page is re-tried next run).
- Constructor validates all bounds and fails closed on misconfiguration.

In PR-2 the registry is constructed with **no real jobs** — only test
fakes exercise the runner.

---

## 7. Advisory Lock Behavior

Implemented in
`backend/internal/storage/postgres/governance_scheduler_repository.go` as
`schedulerJobLock`.

- **Scope: per `(organization_id, job_name)`.** Guarantees no duplicate
  concurrent execution of the same `(org, job)` across overlapping ticks
  (and, forward-compatibly, across replicas if HA ever arrives).
- **Key derivation:** a Go-side **FNV-64a** hash of
  `"governance-scheduler-job"` + `NUL` + `organizationID` + `NUL` +
  `jobName`, reduced to the `bigint` that single-argument
  `pg_try_advisory_lock` expects. NUL separators prevent
  `("a","bc")`/`("ab","c")` collisions; hashing in Go avoids Postgres
  UTF-8 validation of the composite key.
- **Pinned connection (binding).** Acquire checks out **one dedicated
  `*pgxpool.Conn`** and runs `pg_try_advisory_lock` on it; the lock is
  held on that **same physical session** through the entire page loop and
  released with `pg_advisory_unlock` on **that connection only**. It is
  **never** taken/released through ordinary pool queries — doing so could
  unlock on a different physical session and strand the lock. Acquire and
  release are asserted (test) to observe the same `pg_backend_pid()`.
- **Non-blocking + fail-closed.** `pg_try_advisory_lock` returns
  immediately; a miss → `skipped_locked`, never a block. Release is
  **idempotent**; on unlock failure the helper hijacks and closes the
  TCP connection so session-scoped locks drop, then returns the
  connection to the pool. Session-level scope means an unexpected process
  death self-releases the lock when the session closes — no stuck locks.
- **Orthogonal to the data lock.** This coarse "a runner is working this
  item" guard is **not** held inside the primitive transactions; the
  per-org *ownership* data lock is taken per page by the primitive and
  released per page. The advisory lock never blocks override/ownership
  mutations beyond one page loop, and never blocks reads.

---

## 8. Expired Override Sweep Adapter (PR-3, H-029)

`backend/internal/governance/maintenance/overridesweep/job.go`

- `Job` wraps a consumer-owned `ExpiredOverrideSweeper` interface whose
  sole method is the verbatim H-029 primitive signature
  `SweepExpiringOverridesPage(ctx, organizationID, cursorCertID, pageSize)
  (*ownership.ExpiringOverridesSweepResult, error)`.
- `Name()` → `"expired_override_sweep"`.
- **Result mapping** (`result → PageResult`):
  `NextCursor → NextCursor`, `Done → Done`,
  `CertsScanned → ItemsScanned`, `ClearedCount → ItemsChanged`.
- **Thin and effect-free.** The adapter never mutates scheduler state and
  **emits no audit**; the H-029 primitive owns its transaction, per-org
  ownership lock, and per-override `ownership.override_expired` audit
  rows. The primitive's `SweepID` is the correlation handle a future tick
  loop logs to join scheduler logs ↔ audit rows.

---

## 9. Explanation Retention Prune Adapter (PR-4, H-027)

`backend/internal/governance/maintenance/explanationretention/job.go`

- `Job` wraps a consumer-owned `ExplanationPruner` interface whose sole
  method is the verbatim H-027 primitive signature
  `PruneExplanationsPage(ctx, organizationID, actorUserID, cursorCertID,
  pageSize) (*ownership.ExplanationPruneResult, error)`.
- `Name()` → `"explanation_retention_prune"`.
- **System actor.** The adapter passes `actorUserID = ""`
  (`scheduledActor`) — a scheduled run has no operator identity; the
  primitive records `actor = "system"`.
- **Result mapping** (`result → PageResult`):
  `NextCursor → NextCursor`, `Done → Done`,
  `CertsScanned → ItemsScanned`, `DeletedCount → ItemsChanged`.
- **Thin and effect-free.** No scheduler-state mutation, **no audit** in
  the adapter; H-027 emits **one rollup `governance.explanation_pruned`
  audit row per page that actually deleted rows** (no-op pages emit no
  audit). The H-027 retention selector config
  (`ANCHORIX_OWNERSHIP_EXPLANATION_KEEP_N` / `_MAX_AGE`) already exists
  and is owned by the primitive; the scheduler config does **not**
  re-declare it.

---

## 10. Hardening Coverage

Each adapter PR shipped with a matching adversarial hardening pass; the
maintenance package carries a **dormancy guard** test.

- **`TestMaintenancePackageIsDormant`** (`maintenance/dormancy_test.go`)
  scans every non-test `.go` file in the package and **fails the build**
  if any of these appear: `go func(`, `time.Ticker`, `time.NewTicker`,
  `time.NewTimer`, `func (s *Scheduler) Run`, `SweepExpiringOverridesPage`,
  `PruneExplanationsPage`, `governance/ownership`. (`doc.go` is exempt —
  it documents the boundary by naming these surfaces.)
- **Adapter behavioral tests** (fake primitives): correct primitive
  invoked (positive **and** negative — the sweep adapter must not
  reference the prune primitive and vice-versa); `NextCursor` mapped
  **from the result, not echoed** from the input cursor; exhaustive
  field-mapping tables; statelessness across back-to-back `RunPage`
  calls; error propagation with the cursor left un-advanced; no adapter
  audit.
- **Static guards (mutation-verified):** no `internal/config` import
  (AST), no migration creep (scans `backend/migrations` for the job key),
  forbidden-token spellings.
- Full suites green under `-race`; `gofmt` / `go vet` clean.

---

## 11. Security & Isolation Guarantees

- **Scheduler is still dormant.** No loop, ticker, or goroutine is
  active; nothing runs.
- **Effects and audit remain primitive-owned.** The adapters and runner
  **do not duplicate audit** (CLAUDE.md §9 "duplicate logging layers are
  forbidden"). The runner records only **operational** state transitions
  (`MarkJobStarted/Completed/Partial/Failed`); those are not audit
  events.
- **Bounded / paged work only.** Every run is capped by `MaxPagesPerRun`
  and `MaxRunDuration`; every primitive call is one bounded page in one
  atomic transaction. **No fleet-wide scan of governed data was
  introduced.** The only cross-org read is the bounded, deterministically
  ordered `ListDueJobs` due-selection over *job rows* (never certificate
  or ownership data).
- **Cross-org isolation is required and enforced.** Every repository
  method binds `organization_id`; the advisory-lock key includes both
  org and job; due-selection orders by
  `(next_due_at ASC, organization_id ASC, job_name ASC)`.
- **Advisory locks are per `(org, job)` and require pinned-connection
  behavior** (acquire/hold/release on one physical session — §7).
- **Fail-closed throughout:** unknown job → `ErrUnknownJob`; lock miss →
  `skipped_locked`; invalid config → startup error; primitive error →
  cursor not advanced, retried with backoff.

---

## 12. Operational Constraints

- **Default-off, twice.** Global `GovernanceSchedulerEnabled` defaults
  `false`; per-job `enabled` defaults `FALSE` on first registration. A
  job must be explicitly enabled to ever be due.
- **No operator path in B4.** Enabling a job today means a direct DB
  update to `governance_scheduler_job`; there is no API/UI toggle. An
  enable/disable action **should** emit a `severity: "security"` audit
  event once an operator path exists (forward requirement, not built).
- **Single-instance reality (v0.1).** HA is out of scope (CLAUDE.md §13);
  the advisory lock primarily guards overlapping ticks within one
  process, while remaining correct for multiple replicas unchanged.
- **Cursor semantics:** persisted only after a page commits; opaque to
  the scheduler; reset to `SchedulerCursorStart` on cycle completion.
- **Stateless control plane.** Restartable at any time; state lives in
  `governance_scheduler_job`; session advisory locks self-release on
  disconnect.

---

## 13. Explicit Non-Goals / Not Activated Yet

The following are **deliberately absent** as of B4 closure:

- **Scheduler is still dormant.**
- **No loop / ticker / goroutine is active.**
- **No `serve.go` (composition-root) wiring exists.** `serve.go` wires
  the H-022 `FindingsScheduler` and the ownership engine, but constructs
  **none** of: `JobRegistry`, `JobRunner`, `overridesweep.Job`,
  `explanationretention.Job`, the `SchedulerStateRepository`, or the
  advisory-lock helper. (A source comment explicitly warns against wiring
  the scheduler without a feature-flag gate.)
- **No API / UI trigger exists.** No `/api/v1` route reaches the
  scheduler or adapters.
- **No migration / config mutation beyond the dormant foundation.**
  Migration `0012` adds only the operational-state table; config fields
  are parsed but consumed by nothing.
- **H-027 and H-029 primitives remain dormant** — they are reachable
  **only** if a future scheduler-wiring PR registers the adapters and
  starts a loop. No production runtime path calls them today.
- No automated renewal/revocation/rotation, no built-in CA, no
  multi-tenancy — unchanged v0.1 non-goals (CLAUDE.md §13).

---

## 14. Known Limitations

- **The tick loop does not exist.** B4 delivers the per-item engine
  (`RunDueJob`) but not the orchestrator that selects due items, fans out
  under `MaxItemsPerTick`, and re-arms. That is the first activation step.
- **Audit ↔ scheduler correlation is asymmetric.** H-029 returns a
  `SweepID` that stamps every `ownership.override_expired` row, giving a
  clean join. H-027 returns **no** distinct per-call id, so the prune
  join is only as good as `(org_id, action, occurred_at)` plus the
  scheduler's logged run window. A first-class prune-run id (or a
  context-propagated `RequestID` through `audit.Recorder`) is a separate,
  explicitly-scoped follow-up.
- **No operator control surface.** Enable/disable is DB-only until an
  admin path is built; the security-audit event for that action is a
  forward requirement.
- **Config is validated but inert**, so a misconfiguration can pass
  startup yet have no observable effect until the loop is wired — worth a
  re-validation pass at wiring time.
- **Single-instance assumption** is correct for v0.1 but unexercised
  against real multi-replica contention (design is forward-compatible,
  not yet proven under HA).

---

## 15. Recommended Next Decision Points

Activation is a sequence of small, individually-reviewable steps. Each is
a decision, not an automatic next merge:

1. **Scheduler loop implementation.** Build the tick loop /
   due-selection orchestrator on top of `RunDueJob` — bounded by
   `MaxItemsPerTick`, deterministic ordering, fairness re-arm
   (`PartialRequeueDelay`), retry/backoff. One owning goroutine with a
   documented owner, context cancellation, and graceful drain (CLAUDE.md
   §8.10). This is the moment the dormancy guard's `go func(` /
   `time.Ticker` prohibitions are intentionally relaxed for the loop's
   own package.
2. **Composition-root wiring.** Construct the registry (with the two real
   adapters), runner, repository, and lock helper in `serve.go` behind the
   existing feature-flag gate — and only there.
3. **Enabling config path.** Confirm `GovernanceSchedulerEnabled` gates
   loop startup, and define how per-job `enabled` is toggled (operator
   admin path vs. interim DB procedure), including the
   `severity: "security"` audit event for enable/disable.
4. **Dry-run / observability strategy.** Before any mutation in
   production, decide on a dry-run/report-only mode and finalize the
   structured-log + metrics surface (`tick_started/finished`,
   `run_started/finished`, `skipped_locked`, `run_error`,
   `orphan_job_row`; runs-by-outcome / pages / rows / duration /
   consecutive-failure metrics) so operators can watch before trusting.
5. **Staging rollout plan.** Enable one job for one org in staging,
   validate cursor progress, lock behavior (same-PID acquire/release),
   audit-join, and bounded resource use; then widen.
6. **Another stabilization pass before activation.** A focused
   pre-activation review/hardening sweep — re-validate config at wiring
   time, integration-test the advisory lock under real contention,
   confirm crash/resume idempotency end-to-end — **before** flipping
   `GovernanceSchedulerEnabled` anywhere production-facing.

> **Closure statement.** B4 is complete as a *foundation*. The governance
> maintenance scheduler is fully built and tested up to, but not
> including, the act of running. It stays dormant — no loop, no goroutine,
> no wiring, no trigger — until a future, operator-gated activation PR
> deliberately turns it on.

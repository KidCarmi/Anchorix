# B4 — Governance Scheduler Design

> Status: **DESIGN ONLY — NOT IMPLEMENTED**
>
> This document is a design proposal. It introduces **no production code,
> no goroutines, no tickers, no background loops, no API, no UI, and no
> migrations**. It describes how a future scheduler layer will safely
> invoke the dormant governance maintenance primitives delivered in
> H-027 and H-029 (and, conditionally, recompute primitives implied by
> H-030).
>
> Nothing in this document activates a dormant primitive. Activation
> happens only in the later, separately-reviewed implementation PRs
> enumerated in §17 (PR Split). Until those land and are explicitly
> enabled, the governance maintenance primitives remain dormant.
>
> Binding authority: this design is subordinate to `CLAUDE.md`. Where
> any sketch below appears to conflict with `CLAUDE.md`, `CLAUDE.md`
> wins and this document is wrong and must be corrected.

---

## 1. Purpose and Scope

### 1.1 Problem statement

Three governance maintenance primitives are implemented, hardened, and
closed, but **dormant** — no production code path invokes them:

| Primitive | Phase | Kind | Lock |
|---|---|---|---|
| `SweepExpiringOverridesPage` | H-029 | mutating, paged | `WithTxLockedOwnership` |
| `ListExpiringOverridesPaged` | H-029 | read-only, paged | none (read) |
| `PruneExplanationsPage` | H-027 | mutating, paged | `WithTxLockedOwnership` |
| `GetCertificateOwnershipByCertificateIDs` | H-030 | read-only, batch | none (read) |

Each was deliberately built **paged, per-org, bounded, and fail-closed**
precisely so that a future scheduler could drive them safely. B4 designs
that scheduler.

### 1.2 Goal

Design a **governance scheduler** that:

- runs bounded, paged maintenance work on a recurring basis,
- is strictly **per-org isolated**,
- never performs a fleet-wide scan,
- never holds an org-wide lock across a full-org maintenance pass,
- guarantees **no duplicate concurrent execution** of the same
  `(org, job)` across control-plane replicas,
- is **crash-safe, idempotent, and resumable** via persisted cursors,
- preserves the existing **audit** guarantees of each primitive,
- **fails closed** on every ambiguous condition,
- is **disabled by default** and rolled out incrementally.

### 1.3 Explicitly out of scope for B4 design

The following are named here so reviewers can confirm the boundary. They
are **not** designed in B4 and must not appear in B4 implementation PRs
without a new phase:

- Lifecycle automation (renewal / revocation / rotation) — barred by
  `CLAUDE.md §13`. The scheduler runs **maintenance of governance
  state**, never certificate lifecycle actions.
- Any new HTTP endpoint, API surface, or `/api/v1` change. The scheduler
  is internal. (A future read-only *observability* endpoint may be
  proposed in a later phase; it is **out of scope** here.)
- Any UI.
- A distributed job queue, message bus, or external scheduler (Temporal,
  cron sidecar, K8s CronJob). Barred by `CLAUDE.md §5.1` / `§5.4`
  (modular monolith, no event bus, no Kubernetes in v0.1).
- Cross-org or "global" maintenance jobs.
- Dynamic/runtime job registration (jobs are registered at composition
  time only — see §5).
- Hot-reload of scheduler config (barred by `CLAUDE.md §8.9`).
- Multi-region / HA leader election beyond the single-writer advisory
  lock model in §8. (See §8.5 for the v0.1 single-instance assumption
  and the forward-compatible advisory-lock design.)

---

## 2. Design Principles (derived from CLAUDE.md)

Every decision in this document traces to a binding rule:

1. **Visibility before automation** (`§3`). The scheduler automates only
   *maintenance of already-explained governance state*. It introduces no
   new opaque decisions; every action it takes is one a primitive already
   audits.
2. **Operator-controlled** (`§7.1`). Disabled by default. Every job is
   individually enable/disable-able. The operator can read every job's
   config and status. No "magic".
3. **Bounded work** (`§8.10`, `§18`). Every tick is bounded by max pages
   and max duration. No unbounded loops. No fire-and-forget goroutines.
4. **Fail closed** (`§6.12`, `§18`). Invalid config → refuse to start.
   Lock contention → skip this org/job this tick, do not force.
   Any per-page error → roll back that page (primitive guarantee) and do
   not advance the cursor.
5. **Deterministic** (`§7.6`, `§8.9`). Same inputs + same DB state →
   same scheduling decisions. Time is injected via the clock (`§8.2`).
6. **Cross-org isolation everywhere** (handoff requirement; `§12`). Work
   is selected, locked, paged, and audited strictly per org.
7. **Append-only migrations** (`§16`). The single new table (§7) ships in
   one numbered, append-only migration; indexes documented inline.
8. **Constructor DI only** (`§8.8`). The scheduler, registry, and runner
   are wired in `cmd/anchorix/main.go`. No service locator, no
   reflection, no runtime discovery.
9. **Structured logs + persisted audit** (`§9`). Scheduler operational
   events are structured logs; state-changing governance effects remain
   **audit events emitted by the primitives**, not by the scheduler.

---

## 3. Architecture Overview

### 3.1 Layering

The scheduler is a new domain component under
`backend/internal/governance/maintenance/` (proposed package name:
`maintenance`; final name decided in PR-2, see §13 for the naming
rationale and `CLAUDE.md §8.4` compliance). It depends **only** on:

- governance ownership repository interfaces (the dormant primitives),
- the `audit` recorder interface (read-only use — the scheduler does not
  itself write audit; primitives do),
- `internal/config` (typed, validated config),
- `internal/clock` (injected clock),
- `internal/logger` (canonical structured logger),
- a new **scheduler-state repository interface** (owned by the consumer,
  implemented in `storage/postgres`) for job rows, cursors, and advisory
  locks.

Forbidden edges (restating `CLAUDE.md §8.6` for this package):

- `maintenance → httpapi` — forbidden.
- `maintenance → storage/postgres` concrete types — forbidden; it
  depends on **interfaces** it owns, implemented by the storage layer.
- `httpapi → maintenance` — there is no HTTP surface in B4, so this edge
  does not exist.

### 3.2 Component map

```
cmd/anchorix/main.go                      (composition root: wires + starts/stops)
  └─ governance/maintenance
       ├─ Scheduler        (owns the tick loop; one per process)
       ├─ JobRegistry      (immutable set of registered jobs, built at wiring time)
       ├─ JobRunner        (executes a single (org, job) pass; the page loop)
       ├─ Job (interface)  (one maintenance behavior; e.g. expired-override sweep)
       └─ SchedulerState   (interface; persisted jobs, cursors, advisory locks)
            └─ implemented by storage/postgres
```

`Job` implementations:

- `expiredOverrideSweepJob` → wraps `SweepExpiringOverridesPage` (PR-3).
- `explanationRetentionPruneJob` → wraps `PruneExplanationsPage` (PR-4).
- (conditional) `staleOwnershipRecomputeJob` → see §11; **not** committed
  for B4 unless an existing recompute primitive supports paged, bounded,
  per-org operation. Default: deferred.

### 3.3 Control flow (one tick, prose; no code in B4)

1. Scheduler wakes on its interval (a single owned loop — see §4.1).
2. It asks `SchedulerState` for **due** `(org, job)` work items, bounded
   by a per-tick fan-out cap and ordered deterministically
   (`org_id ASC, job_name ASC`).
3. For each due item, the `JobRunner`:
   a. attempts a **non-blocking** per-`(org, job)` advisory lock (§8);
      if not acquired, it **skips** (another replica/tick owns it) and
      logs a structured `skipped_locked` event;
   b. loads the persisted **cursor** for `(org, job)`;
   c. runs the **bounded page loop** (§6): up to `max_pages_per_tick`
      pages and up to `max_run_duration` wall-clock, calling the
      primitive once per page, persisting the returned cursor after each
      **successful** page;
   d. records the run outcome (`completed` / `partial` / `error` /
      `skipped`) and the next-due time in `SchedulerState`;
   e. releases the advisory lock.
4. Tick ends. Nothing is held between ticks except persisted rows.

No org-wide lock is ever held across the whole page loop — locking is
per page, inside each primitive's `WithTxLockedOwnership` transaction
(§8.3). The advisory lock in step (a) guards **concurrency**, not data,
and is released between ticks.

---

## 4. Scheduler Architecture

### 4.1 The tick loop (designed, not built)

- **Single owned goroutine**, started in `main.go`, owner =
  `Scheduler`. Documented owner, cancellation path (`context.Context`),
  bounded lifetime — satisfies `CLAUDE.md §8.10`.
- Cancellation: the loop selects on `ctx.Done()` and a `time.Ticker`
  channel. On `ctx.Done()` it drains the **current** in-flight page to a
  safe boundary (the active primitive transaction either commits or rolls
  back atomically — no partial page), persists the cursor if the page
  committed, then exits. Satisfies graceful shutdown (`§7.5`, `§18`).
- The ticker interval is config (`§9`), validated at startup, immutable
  after start (`§8.9`).
- **No per-org goroutines** in v0.1. The tick processes due items
  **sequentially** with a bounded per-tick fan-out cap. This keeps
  goroutine ownership trivial and avoids unbounded worker spawning
  (`§8.10`). Concurrency across orgs is a future optimization, explicitly
  out of scope (§1.3); the advisory-lock model (§8) already makes it
  safe to add later without redesign.

### 4.2 Determinism

- All "now" reads go through the injected clock (`internal/clock`),
  never `time.Now()` in the loop body (`CLAUDE.md §8.2`).
- Due-selection ordering is total and stable (`org_id ASC, job_name
  ASC`), so two replicas (or a replay) make the same decisions given the
  same DB state; the advisory lock resolves which one actually runs.

### 4.3 Backpressure / rate limiting

Three independent bounds, all config-driven (§9), all fail-closed at
validation:

1. **Per-tick fan-out cap** (`max_items_per_tick`): max number of
   `(org, job)` items processed in one tick. Excess items remain "due"
   and are picked up next tick in deterministic order — natural
   round-robin fairness across orgs.
2. **Per-run page cap** (`max_pages_per_tick`): max primitive pages per
   `(org, job)` per tick. Bounds DB pressure from any single org.
3. **Per-run duration cap** (`max_run_duration`): wall-clock budget per
   `(org, job)` run; checked between pages, never mid-page.

Optional inter-page delay (`page_pause`, default `0`) provides crude
DB-pressure relief if needed; default off to keep behavior simple.

When any cap is hit, the run ends as **`partial`**, the cursor is
persisted at the last committed page, and the item stays due so the next
tick resumes exactly where it stopped. This is the backpressure
mechanism: work spreads across ticks instead of spiking.

---

## 5. Job Registry

- The registry is an **immutable** map built **once** at composition time
  in `main.go` and passed to the `Scheduler` by constructor
  (`CLAUDE.md §8.8`). No runtime registration, no mutation after start,
  no global registry callers mutate (`§8.8`, `§19` "hidden global
  state").
- A `Job` is identified by a **stable string name** (e.g.
  `"expired_override_sweep"`, `"explanation_retention_prune"`). The name
  is the key in `SchedulerState`, in config, in logs, and in audit
  correlation. Names are domain-explicit per `CLAUDE.md §8.4`.
- The `Job` interface (sketch only — final form in PR-2; illustrative,
  not committed code):

```go
// Job is one bounded, paged, per-org governance maintenance behavior.
// Implementations wrap exactly one dormant primitive and own no state.
type Job interface {
    // Name is the stable registry/config/cursor key.
    Name() string

    // RunPage executes one bounded page for a single org, starting from
    // cursor, and returns the next cursor plus whether more work remains.
    // It MUST be idempotent w.r.t. re-running the same page after a crash
    // that occurred before the cursor was persisted.
    RunPage(ctx context.Context, orgID OrgID, cursor PageCursor) (PageResult, error)
}

type PageResult struct {
    NextCursor PageCursor
    HasMore    bool
    // RowsAffected is for metrics/logging only; semantics owned by the job.
    RowsAffected int
}
```

- A job that is **registered but disabled** (§6.4 enable/disable) is
  never selected as due. Disabling is the safe default for new jobs.

---

## 6. Job Execution Model

### 6.1 The bounded page loop

For a single `(org, job)` run:

```
cursor := load(org, job)
pagesRun := 0
deadline := clock.Now().Add(max_run_duration)
loop:
    if pagesRun >= max_pages_per_tick: outcome = partial; break
    if clock.Now() >= deadline:        outcome = partial; break
    result, err := job.RunPage(ctx, org, cursor)   // ONE primitive page
    if err != nil:                     outcome = error; break  // do NOT advance cursor
    persist(org, job, result.NextCursor)            // cursor advances only on success
    cursor = result.NextCursor
    pagesRun++
    if !result.HasMore:                outcome = completed; break
```

(Prose/pseudocode only — no code lands in B4.)

Key invariants:

- The primitive is called **once per page**. Each call is a self-contained
  `WithTxLockedOwnership` transaction that commits or rolls back
  atomically (H-027 / H-029 guarantee). There is **no** loop-spanning
  transaction and **no** loop-spanning lock.
- The cursor is persisted **only after a page commits**. A crash before
  persistence re-runs that page; the primitives are idempotent for that
  (already-cleared override → `ErrOwnershipOverrideNotFound` silent
  no-op for H-029; already-pruned rows → simply not re-selected for
  H-027). See §10.
- Any primitive error ends the run as `error`, leaves the cursor
  un-advanced, and the item stays due for retry next tick (with backoff,
  §10.3).

### 6.2 Pagination loop boundaries

- **Page size** is a config bound (`page_limit`) passed to the primitive,
  clamped to the primitive's own max (fail closed if config exceeds the
  primitive's documented max — `GetCertificateOwnershipByCertificateIDs`
  already fails closed on oversize input; the scheduler must not rely on
  that and instead validates at startup).
- **Cursor shape** is the certificate-id cursor the primitives already
  use (`certificate_id > cursor`, `ORDER BY certificate_id ASC` for
  H-029). The scheduler treats the cursor as an **opaque, job-owned**
  token (see §7.2) and never interprets it.
- **Completion** is when `HasMore == false`. At that point the cursor is
  **reset** for the next cycle (next due time) per the job's policy
  (§6.5).

### 6.3 Per-org isolation

- Due-selection, locking, paging, cursors, and audit are all keyed by
  `org_id`. There is no query in the scheduler that spans orgs except the
  due-selection scan, which is itself **bounded** (`max_items_per_tick`,
  ordered, cursored across ticks) and selects *job rows*, never
  certificate or ownership data. No fleet-wide scan of governed data ever
  occurs (handoff hard requirement).

### 6.4 Enable / disable model

- Two layers, both fail-safe toward "off":
  1. **Global scheduler switch** (config, default **off**): when off, the
     tick loop is not started at all (`main.go` does not wire it). No
     hidden flag — documented in `internal/config` per `§19`.
  2. **Per-job enabled flag** (persisted in `SchedulerState`, default
     **disabled** on first registration): a registered-but-disabled job
     is never due. Toggling is an operator action (in B4: via direct DB
     update or a future admin path — **no API in B4**; see §1.3 and
     §16).
- A job that is removed from the registry but still has a row in
  `SchedulerState` is **inert** (never selected) and logged once as
  `orphan_job_row`. Rows are not auto-deleted (append-only-friendly,
  operator-visible).

### 6.5 Cycle / re-arm policy

- On `completed`, the job's `next_due_at` is set to
  `clock.Now() + job_interval` and the cursor is reset to the start
  sentinel. On `partial`, `next_due_at` is set to `clock.Now()` (resume
  ASAP, subject to fan-out fairness). On `error`, `next_due_at` uses the
  retry backoff schedule (§10.3).

---

## 7. Persistence Design (one new table)

### 7.1 Rationale for a new table

Cursors, per-job enable state, next-due times, last-run outcomes, and
retry/backoff state must survive process restarts and be visible to
operators (`§7.3` transparency, `§18` resumability). A single, small,
append-friendly table is the minimal footprint. This is the **only**
schema change B4 contemplates, and it ships in one numbered append-only
migration (`CLAUDE.md §16`) — the next number after the current latest
(`0011_governance_policy.sql`), i.e. `0012_*`.

This table is the one place B4 goes beyond the `findings.Scheduler`
precedent (§3.4): the findings scheduler is stateless per tick because a
recompute is a single bounded pass, whereas the H-027/H-029 primitives
are paged and drain an org across many ticks, so the cursor must
persist. Everything else (enable flag, next-due, outcome) is
operational metadata that rides along in the same row at no extra cost.

### 7.2 Proposed table (DDL sketch — lands in PR-1, not in this doc)

```sql
-- backend/migrations/00NN_governance_scheduler_state.sql  (PR-1)
CREATE TABLE governance_scheduler_job (
    org_id        UUID        NOT NULL REFERENCES organizations(id),
    job_name      TEXT        NOT NULL,
    enabled       BOOLEAN     NOT NULL DEFAULT FALSE,   -- default-disabled (§6.4)
    cursor        TEXT,                                 -- opaque, job-owned (§6.2); NULL = start
    next_due_at   TIMESTAMPTZ NOT NULL,
    last_run_at   TIMESTAMPTZ,
    last_outcome  TEXT,                                 -- enum: completed|partial|error|skipped
    last_error    TEXT,                                 -- redacted summary; NULL when clean
    consecutive_failures INTEGER NOT NULL DEFAULT 0,    -- drives backoff (§10.3)
    updated_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, job_name)
);

-- Serves the due-selection scan: "enabled jobs whose next_due_at <= now,
-- ordered deterministically, bounded by max_items_per_tick".
CREATE INDEX governance_scheduler_job_due_idx
    ON governance_scheduler_job (next_due_at)
    WHERE enabled = TRUE;   -- partial index; rationale documented in migration per §16
```

Notes:

- `last_outcome` / `last_error` are **operational state**, not audit. The
  authoritative audit trail of *what governance state changed* remains
  the primitives' own audit events (§12). `last_error` stores a
  **redacted** summary only (`§6.9`, `§9` redaction allow-list).
- The cursor column is `TEXT` and **opaque**: the scheduler stores and
  returns it verbatim; only the `Job` (and the primitive it wraps)
  interpret it. This keeps the table job-agnostic and future-proof.
- Partial index is a PostgreSQL feature → explicit rationale required in
  the migration (`CLAUDE.md §16`): it serves the hot due-selection path
  without scanning disabled rows.

### 7.3 No row mutation that loses history beyond operational fields

The table is **operational state**, not an audit log, so it is mutable
(update-in-place of cursor/next-due/outcome). This does **not** conflict
with the append-only audit rule (`§9`, `§16`): governance *effects* are
audited by the primitives in `audit_events`. The scheduler table records
only "where am I and when do I run next".

---

## 8. Locking / Advisory Lock Strategy

Two distinct locking concerns; do not conflate them.

### 8.1 Data lock (already solved by the primitives)

Each primitive page runs inside `WithTxLockedOwnership`, which takes the
**per-org ownership lock for the duration of that single page only** and
commits/rolls back atomically. The scheduler **inherits** this and adds
nothing. Crucially, this lock is **held per page, never across the page
loop** — directly satisfying the handoff requirement "no long-held org
locks across full-org maintenance".

### 8.2 Concurrency lock (new, scheduler-owned)

To guarantee **no duplicate concurrent execution of the same
`(org, job)`** across replicas and across overlapping ticks, the runner
takes a **PostgreSQL session-level advisory lock** keyed by a hash of
`(org_id, job_name)` *before* the page loop and releases it after:

- `pg_try_advisory_lock(key)` — **non-blocking**. If not acquired →
  another runner owns this `(org, job)` → **skip** (outcome `skipped`,
  structured `skipped_locked` log). Fail-closed toward "don't double-run".
- Released with `pg_advisory_unlock(key)` in all paths (success, error,
  cancellation). Because it is **session-level**, an unexpected process
  death drops the lock automatically when the DB session closes — no
  stuck locks across crashes.
- The advisory lock is **not** held inside the primitive transactions; it
  is a coarse "this runner is working this item" guard, orthogonal to the
  ownership data lock. It is released between ticks (held only during an
  active run), so it never blocks override/ownership *mutations* (H-026B3B
  paths) for longer than one page loop, and never blocks reads at all.

### 8.3 Why advisory lock and not `SELECT … FOR UPDATE` on the job row

A row lock would either block (bad: ties up a connection) or require
`SKIP LOCKED` semantics that conflate "who runs" with "row visibility".
A session advisory lock is the idiomatic Postgres primitive for
"single active worker per logical key", is non-blocking via `try`, and
self-releases on disconnect. The job row itself is updated
transactionally at cursor-persist time (§7), which is a short write, not
a long-held lock.

### 8.4 Lock key derivation

- Deterministic: `key = hash64(org_id || 0x00 || job_name)`. Documented,
  collision-tolerant (a rare collision only over-serializes two unrelated
  items — safe, fail-closed), and reproducible (`§8.11` determinism
  spirit). Final hashing detail decided in PR-2.

### 8.5 v0.1 single-instance reality, forward-compatible design

`CLAUDE.md §13` lists HA clustering as out of scope, so v0.1 runs a
single control-plane instance and the advisory lock primarily guards
**overlapping ticks within one process** (e.g., a long run bleeding into
the next tick). The same mechanism, with no redesign, correctly guards
**multiple replicas** if HA arrives later. We design for it now (`§6.11`
"build for it now") without implementing HA.

---

## 9. Configuration

All config is centralized in `internal/config`, typed, validated at
startup, immutable after start, fail-closed on invalid input
(`CLAUDE.md §8.9`). Proposed env vars (final names finalized in PR-1):

| Env var | Default | Validation | Meaning |
|---|---|---|---|
| `ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED` | `false` | bool | Global on/off. Off → loop not started. |
| `ANCHORIX_GOVERNANCE_SCHEDULER_INTERVAL` | `5m` | `>= 1m` | Tick interval. |
| `ANCHORIX_GOVERNANCE_SCHEDULER_MAX_ITEMS_PER_TICK` | `50` | `>= 1` | Per-tick `(org, job)` fan-out cap. |
| `ANCHORIX_GOVERNANCE_SCHEDULER_MAX_PAGES_PER_RUN` | `20` | `>= 1` | Per-run page cap. |
| `ANCHORIX_GOVERNANCE_SCHEDULER_MAX_RUN_DURATION` | `30s` | `>= 1s` | Per-run wall-clock budget. |
| `ANCHORIX_GOVERNANCE_SCHEDULER_PAGE_LIMIT` | `200` | `>= 1`, `<=` primitive max | Page size passed to primitives. |
| `ANCHORIX_GOVERNANCE_SCHEDULER_PAGE_PAUSE` | `0s` | `>= 0` | Optional inter-page delay. |
| `ANCHORIX_GOVERNANCE_SCHEDULER_RETRY_BASE` | `1m` | `>= 1s` | Backoff base (§10.3). |
| `ANCHORIX_GOVERNANCE_SCHEDULER_RETRY_MAX` | `1h` | `>= base` | Backoff cap (§10.3). |

Naming and parsing follow the existing `ANCHORIX_FINDINGS_SCHEDULER_*`
precedent (`parseBool` / `parseInt` / `parseDuration` in
`internal/config`, validated in a dedicated `validate…` method that
fails closed). Per-job interval (`job_interval` for re-arm, §6.5) is
configured per job;
for B4 the proposed approach is a **per-job typed config struct** in
`internal/config` (e.g. `ExpiredOverrideSweepInterval`,
`ExplanationRetentionInterval`), not a `map[string]any` (barred by
`§8.9`). The H-027 retention selector config
(`ANCHORIX_OWNERSHIP_EXPLANATION_KEEP_N`,
`ANCHORIX_OWNERSHIP_EXPLANATION_MAX_AGE`) **already exists** and is
consumed by `PruneExplanationsPage`; the scheduler does **not**
re-declare it — it only schedules the prune.

Validation is deterministic: same env in → same `*Config` or same
explicit error out (`§8.9`).

---

## 10. Crash, Retry, and Idempotency Model

### 10.1 Crash safety

- The only durable state is `governance_scheduler_job` rows. A crash
  loses at most the in-flight page that had not yet committed; on restart
  the runner resumes from the last persisted cursor and re-runs that
  page.
- The advisory lock self-releases on session death (§8.2), so a crashed
  run leaves no stuck lock.

### 10.2 Idempotency

Re-running a page after a crash must be safe. It is, by primitive design:

- **H-029 sweep**: clearing an already-cleared override yields
  `ErrOwnershipOverrideNotFound` → **silent no-op** (documented H-029
  semantic). Re-derivation is deterministic (`§7.6`). Audit:
  `ownership.override_expired` is emitted **only** for overrides actually
  cleared in the committed transaction, so a no-op re-run emits **no**
  duplicate audit event.
- **H-027 prune**: already-deleted explanation rows are simply not
  re-selected by the retention selector (not-current / beyond-latest-N /
  older-than-max-age). The rollup audit event fires **only when rows are
  actually deleted**, so a re-run over already-pruned data emits no
  spurious audit.
- **H-030 batch lookup** (used by recompute paths): pure read; idempotent
  by nature.

Because the cursor advances only on commit (§6.1), and each primitive
page is atomic, the system has **at-least-once page execution with
idempotent effects** → effectively exactly-once *observable* effects.

### 10.3 Retry / backoff

- On `error`, `consecutive_failures` increments and `next_due_at =
  clock.Now() + min(retry_max, retry_base * 2^(failures-1))` (capped
  exponential backoff; explicit cap per `§8.10` / `§8.11`). On the next
  successful run, `consecutive_failures` resets to 0.
- Backoff is **per `(org, job)`** so one org's failing job does not stall
  others.
- There are **no hidden/implicit retries** inside the loop (`§8.11`,
  `§19`): a page error ends the run; the *scheduler* re-arms with
  backoff. Bounded, explicit, owned.

### 10.4 Idempotency keys

The inventory-upload idempotency keys (`§18`) are an agent→control-plane
concern and are unrelated here. The scheduler's idempotency comes from
cursor-on-commit + primitive idempotency, not from a key. This is called
out so reviewers don't expect an idempotency-key column.

---

## 11. Stale Ownership Recompute (conditional, default DEFERRED)

The handoff lists "stale ownership recompute if supported by existing
primitives" as a candidate job. Assessment:

- A safe recompute job would need a **paged, per-org, bounded** primitive
  that selects candidate certificates (e.g., by staleness/age of last
  derivation) and re-derives them under `WithTxLockedOwnership`,
  emitting audit per change, exactly like H-029.
- H-030 delivered `GetCertificateOwnershipByCertificateIDs` (a bounded
  batch **read**), and H-026B3B delivered **single-cert** re-derivation
  inside override mutations — but neither is a **paged sweep** primitive
  for stale recompute.
- Therefore B4 **does not** design a recompute job against a primitive
  that does not yet exist (would violate "activate dormant primitives
  only"). Recompute is **deferred**: if and when a
  `RecomputeStaleOwnershipPage`-style primitive is delivered (its own
  H-phase, hardened + closed), it slots into this scheduler as just
  another registered `Job` with **zero scheduler changes** beyond
  registry wiring — which is the proof that this architecture is correct.

This deferral is intentional and fail-closed: we do not invent a
primitive to satisfy a scheduler slot.

---

## 12. Audit & Observability

### 12.1 Audit (unchanged authority)

- **Governance state changes are audited by the primitives, not the
  scheduler.** H-029 emits `ownership.override_expired` per cleared
  override; H-027 emits one rollup event per prune page that deleted
  rows. The scheduler adds **no** new audit event type for the *effects*
  — doing so would duplicate the audit layer (`§9` "duplicate logging
  layers are forbidden").
- The scheduler **does** propagate a correlation id into each run so the
  primitive's audit events and the scheduler's operational logs share an
  id (`§9` correlation requirement, extended to background work). A
  server-side-generated `request_id`/run-id stands in for the absent
  `X-Request-Id` since there is no inbound HTTP request.
- Whether the *act of enabling/disabling a job* is itself a
  security-audited event (`§9` lists provider-config-style changes as
  `severity: "security"`) is a **decision for PR-1/PR-2**: recommended
  **yes** — job enable/disable is an operator governance-config change
  and should emit a security audit event when an operator path exists.
  In B4 there is no operator path (no API), so this is documented as a
  forward requirement, not implemented.

### 12.2 Observability (structured logs + metrics)

Structured logs (JSON, `§9` required fields `timestamp, level, event,
request_id, actor, component`; `component = "governance_scheduler"`):

- `tick_started` / `tick_finished` (with due-count, items-processed).
- `run_started` / `run_finished` per `(org, job)` with outcome, pages,
  rows-affected, duration.
- `skipped_locked` when the advisory lock is not acquired.
- `run_error` with **redacted** error summary (`§6.9` allow-list) and a
  remediation hint (`§9` requires error logs to carry a hint).
- `orphan_job_row` when a persisted job has no registry entry.

Metrics (counters/gauges/histograms — exporter choice deferred to
implementation; no new dependency decided in B4):

- runs by outcome, pages processed, rows affected, run duration,
  consecutive-failure gauge per job, due-backlog gauge.

No secrets, tokens, or certificate material in logs/metrics (`§9`,
`§6.9`).

---

## 13. Naming Compliance (CLAUDE.md §8.4)

Proposed names are domain-explicit; **no** generic/AI/`manager`/
`handler`/`processor`/`util`/`claude*` names:

- Package: `maintenance` (under `governance/`). Alternative considered:
  `govsched`. Final pick in PR-2. (Not `scheduler` alone if it reads as a
  generic dumping ground; `governance/maintenance` scopes the
  responsibility — "scheduled governance maintenance".)
- Types: `Scheduler`, `JobRegistry`, `JobRunner`, `Job`, `PageCursor`,
  `PageResult`, `SchedulerState`, `expiredOverrideSweepJob`,
  `explanationRetentionPruneJob`.
- Avoided: `manager`, `service`, `processor`, `worker2`, `data`,
  `payload`, `helper`, `util`.
- `Job` is acceptable as a precise domain noun (a scheduled governance
  job), not a vague abstraction; each implementation wraps exactly one
  named primitive.

The `doc.go` for the new package will declare ownership boundaries,
single responsibility, forbidden imports (`httpapi`, concrete
`storage/postgres`), and architectural role (domain), per `§19`.

---

## 14. Testing Requirements

Per `CLAUDE.md §19` (unit tests at merge; cross-boundary integration
under `backend/test/integration/`):

### 14.1 Unit (per implementation PR)

- **Due selection**: deterministic ordering; respects `enabled`,
  `next_due_at`, `max_items_per_tick`; cross-org isolation (org A's due
  items never include org B's rows).
- **Page loop**: stops at `max_pages_per_tick`; stops at
  `max_run_duration` (via injected clock); advances cursor only on
  success; does **not** advance on error; `completed` vs `partial` vs
  `error` outcomes.
- **Re-arm policy**: `completed` resets cursor + sets interval;
  `partial` resumes ASAP; `error` applies capped backoff and increments/
  resets `consecutive_failures`.
- **Cancellation**: `ctx.Done()` mid-loop exits cleanly after the current
  page boundary; no goroutine leak (leak-checker in tests).
- **Config validation**: every bound fails closed on invalid input;
  deterministic config output.
- **Registry**: immutable; duplicate job names rejected at construction;
  disabled jobs never selected.
- All time via injected clock; no `time.Now()` in business code
  (`§8.2`).

### 14.2 Integration (`backend/test/integration/`)

- Against real PostgreSQL: advisory-lock mutual exclusion — two
  concurrent runners over the same `(org, job)`; exactly one runs, the
  other `skipped_locked`; no double effect, no duplicate audit.
- Crash/resume: kill mid-loop (simulated) → cursor resumes; re-run page
  is a no-op (no duplicate `ownership.override_expired`, no duplicate
  prune rollup).
- End-to-end with **real** H-029 / H-027 primitives over many pages: full
  per-org sweep/prune completes across multiple ticks; per-org isolation
  verified; audit events match exactly the rows changed.
- Migration determinism: `migrate up` on clean DB == `migrate up` on
  existing DB (`§16`).

### 14.3 Forbidden-pattern guards (review-enforced, per §18/§19)

No panic-driven flow, no hidden retries, no fire-and-forget goroutine, no
unbounded spawning, no swallowed errors, no `time.Now()` in logic, no
`http.DefaultClient` (n/a here), no cross-org query of governed data.

---

## 15. Rollout Plan

1. **Ship dormant + disabled.** PR-1 (state/schema) and PR-2 (registry +
   runner skeleton) land with the global switch **off** and every job
   **disabled**. No tick loop runs in production until explicitly
   enabled.
2. **Enable in a non-prod environment first.** Turn on
   `ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED` with conservative caps; observe
   structured logs/metrics; verify audit parity against manual primitive
   runs.
3. **Per-job, per-org enablement.** Enable one job for one org via the
   `governance_scheduler_job.enabled` flag; widen gradually. Backpressure
   caps make a slow ramp safe.
4. **Production enablement** only after integration tests + a non-prod
   soak. Caps tuned conservatively; raise only with evidence.
5. **Reversibility.** Disabling is instant and fail-safe: flip the global
   switch (restart, since config is immutable per `§8.9`) or set per-job
   `enabled = FALSE`. Dormant primitives return to being uninvoked.

---

## 16. Operator Control Surface (B4 boundary)

- **No API, no UI in B4** (`§1.3`). Enable/disable and inspection in B4
  are via the `governance_scheduler_job` table (operator transparency —
  `§7.3`) and structured logs/metrics (§12.2).
- A future **read-only** status endpoint and an **enable/disable** admin
  action are plausible later phases (each with its own threat model under
  `docs/security/` per `§6.10`, and a security audit event per `§9`).
  They are **explicitly out of scope** here and named only so the
  boundary is unambiguous.

---

## 17. PR Split

Matches the handoff's suggested split; each PR is small, with its own
hardening pass, and lands dormant/disabled until §15 enablement.

| PR | Scope | Activation |
|---|---|---|
| **B4 Design doc** (this) | Docs only. | none |
| **B4 PR-1** | Scheduler config + `governance_scheduler_job` migration + `SchedulerState` repo interface & Postgres impl (CRUD on job rows, advisory lock helpers). All dormant. | none |
| **B4 PR-1 hardening** | Threat model (`docs/security/`), config fail-closed tests, migration determinism test, redaction review. | none |
| **B4 PR-2** | `Job` interface, `JobRegistry`, `JobRunner` (page loop), `Scheduler` (tick loop), `main.go` wiring **behind the global switch (default off)**. No jobs registered yet, or registered-but-disabled. | disabled |
| **B4 PR-2 hardening** | Cancellation/leak tests, advisory-lock integration test, deterministic due-selection tests. | disabled |
| **B4 PR-3** | `expiredOverrideSweepJob` wrapping `SweepExpiringOverridesPage`; registered, **disabled by default**. | per-org opt-in |
| **B4 PR-3 hardening** | Crash/resume + audit-parity integration tests for the sweep. | per-org opt-in |
| **B4 PR-4** | `explanationRetentionPruneJob` wrapping `PruneExplanationsPage`; registered, **disabled by default**. | per-org opt-in |
| **B4 PR-4 hardening** | Crash/resume + audit-parity integration tests for the prune. | per-org opt-in |
| **B4 closure summary** | `docs/governance/B4-closure-summary.md`. | n/a |

Stale-ownership recompute (§11) is **not** in this split; it depends on a
future primitive and its own H-phase.

Each implementation PR must carry, per `§19`: documented justification
for every retry/async/external touchpoint, a `doc.go` for the new
package, unit tests at merge, and (for cross-boundary behavior)
integration tests.

---

## 18. Security & Threat Model Pointer

Per `CLAUDE.md §6.10`, the scheduler touches identity-adjacent
governance state (ownership overrides, explanations) and so requires a
short threat model under `docs/security/` **before** the first
state-touching implementation PR merges (PR-3). Key threats to address
there:

- **Double execution / race** → mitigated by non-blocking advisory lock
  (§8) + cursor-on-commit + primitive atomicity.
- **Cross-org leakage** → every query keyed by `org_id`; due-selection
  cannot return another org's governed data; integration test asserts
  isolation.
- **Unbounded work / DoS-by-config** → all caps validated fail-closed
  (§9); partial outcome spreads load (§4.3).
- **Stuck locks after crash** → session-level advisory lock self-releases
  (§8.2).
- **Audit gaps / duplicates** → audit emitted by primitives only, exactly
  for committed effects; idempotent re-runs emit no duplicates (§10.2,
  §12.1).
- **Secret leakage in logs** → `last_error` and all logs redacted via the
  central allow-list (`§6.9`, `§9`).
- **Silent failure** → every error is a structured log with a remediation
  hint + backoff; nothing is swallowed (`§8.5`, `§18`, `§19`).

---

## 19. Open Questions for Design Review

Resolve before PR-1:

1. **Package name**: `governance/maintenance` vs `governance/govsched`
   vs other. (§13)
2. **Per-job interval config shape**: per-job typed fields in
   `internal/config` vs a small typed per-job config registry. Must avoid
   `map[string]any` (`§8.9`). (§9)
3. **Job enable/disable audit**: confirm that enabling/disabling a job
   (once an operator path exists in a later phase) is a `severity:
   "security"` audit event. Recommended **yes**. (§12.1)
4. **Advisory-lock key hashing**: exact 64-bit derivation and
   collision-handling note. (§8.4)
5. **Metrics exporter**: which mechanism, and whether it adds a
   dependency (subject to `CLAUDE.md §11` dependency health gates). (§12.2)
6. **Recompute primitive**: confirm B4 defers stale-ownership recompute
   until a paged primitive exists. Recommended **defer**. (§11)
7. **Shared abstraction vs. sibling**: whether B4 extracts a shared
   scheduler core with `findings.Scheduler` or ships as an independent
   sibling that mirrors its shape (§3.4). Recommended **sibling** for
   v0.1 — the paged/cursor model differs enough that premature
   extraction would be a speculative abstraction (`CLAUDE.md §8.5`);
   revisit extraction only once a third scheduler appears.

---

## 20. Compliance Checklist (handoff hard requirements)

| Requirement | Where satisfied |
|---|---|
| Design only, no production code | Whole doc; `Status` banner |
| No goroutines/tickers/loops yet | §1, §4 (designed, not built) |
| No scheduler implementation yet | §17 (deferred to PRs) |
| No API/UI | §1.3, §16 |
| No migrations unless justified future work | §7 (one table, justified, ships in PR-1 not B4) |
| PostgreSQL + Go | §3, §7, §8 |
| Deterministic behavior | §4.2, §9 |
| Cross-org / per-org isolation everywhere | §6.3, §8, §14, §18 |
| Paged/streaming only, no fleet-wide scan | §6, §6.3 |
| Bounded work per run | §4.3, §6.1 |
| Fail closed | §2.4, §9, §8.2, throughout |
| Auditability preserved | §12.1 |
| No duplicate concurrent execution per org/job | §8.2 |
| No long-held org locks across full-org maintenance | §8.1 (per-page lock only) |
| Backpressure / rate-limit | §4.3 |
| Safe retry / idempotency | §10 |
| How H-027 / H-029 primitives are invoked | §3.2, §5, §6, §10.2 |
| Tests required | §14 |
| Rollout plan | §15 |
| PR split | §17 |
| Explicit out-of-scope | §1.3, §11, §16 |

---

*End of B4 design. Implementation does not begin until this design is
reviewed and accepted.*

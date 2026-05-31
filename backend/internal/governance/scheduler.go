package governance

import (
	"context"
	"errors"
	"time"
)

// This file is the B4 PR-1 dormant scheduler-state foundation:
// domain types + consumer-owned repository/lock interfaces for the
// governance maintenance scheduler. It carries NO scheduler loop, NO
// goroutine, NO ticker, NO job registry, and NO job runner — those
// land in B4 PR-2+. Nothing here invokes the H-027 prune or H-029
// sweep primitives. See docs/governance/B4-governance-scheduler-design.md.

// SchedulerJobStatus is the explicit state-machine label for the most
// recent run of a (organization, job) pair. It is CHECK-fenced in
// migration 0012; these constants are the wire form of that enum and
// MUST match the SQL CHECK exactly (CLAUDE.md §18 — explicit
// enumerated states, no implicit string comparison).
type SchedulerJobStatus string

const (
	// SchedulerJobPending is the initial status of a freshly
	// initialized job row that has never run.
	SchedulerJobPending SchedulerJobStatus = "pending"
	// SchedulerJobRunning is set when a run has started but not yet
	// finished. A crash mid-run leaves this status; the next load
	// observes it and the run is safely re-attempted (the cursor only
	// advances on a committed page, so re-running is idempotent).
	SchedulerJobRunning SchedulerJobStatus = "running"
	// SchedulerJobCompleted means the last run drained the org's
	// eligible work for this job (the primitive reported Done).
	SchedulerJobCompleted SchedulerJobStatus = "completed"
	// SchedulerJobPartial means the last run hit a per-run bound
	// (max pages / max duration) with work remaining; it is re-armed
	// strictly behind not-yet-served due rows for fairness.
	SchedulerJobPartial SchedulerJobStatus = "partial"
	// SchedulerJobError means the last run failed; the cursor is left
	// un-advanced and the row is re-armed on the backoff schedule.
	SchedulerJobError SchedulerJobStatus = "error"
)

// SchedulerCursorStart is the start-sentinel cursor value. The
// maintenance primitives treat an empty certificate-id cursor as
// "begin at the smallest id"; the scheduler stores and replays the
// cursor verbatim and never interprets it.
const SchedulerCursorStart = ""

// SchedulerJob is the persisted per-(organization, job) scheduling
// state. It is operational state, not an audit record — governance
// effects are audited by the maintenance primitives themselves
// (CLAUDE.md §9). One row per (OrganizationID, JobName); the pair is
// the primary key in migration 0012.
type SchedulerJob struct {
	OrganizationID string
	// JobName is the stable registry/config/cursor key (e.g.
	// "expired_override_sweep", "explanation_retention_prune"). It is
	// owned by the future job registry (PR-2); the storage layer
	// treats it as an opaque, org-scoped identifier.
	JobName string
	// Enabled gates selection. A disabled job is never returned by
	// ListDueJobs. Default false (B4 design §6.4).
	Enabled bool
	// Cursor is the opaque, job-owned pagination token. Empty
	// (SchedulerCursorStart) means "start". Advances only after a
	// committed page (completed/partial), never on error.
	Cursor string
	// NextDueAt is when this row is next eligible. Due-selection
	// orders by this ASC.
	NextDueAt time.Time
	// LastStartedAt / LastFinishedAt bracket the most recent run.
	// Zero value means "never".
	LastStartedAt  time.Time
	LastFinishedAt time.Time
	// LastStatus is the explicit state of the most recent run.
	LastStatus SchedulerJobStatus
	// LastError is a redacted error summary; empty when clean.
	LastError string
	// ConsecutiveFailures drives the capped exponential backoff
	// (B4 design §10.3). Reset to 0 on forward progress.
	ConsecutiveFailures int
	UpdatedAt           time.Time
}

// ErrSchedulerJobNotFound is returned by LoadJobState when no
// governance_scheduler_job row matches (organization_id, job_name).
// Cross-org lookups collapse to this sentinel.
var ErrSchedulerJobNotFound = errors.New("governance: scheduler job not found")

// SchedulerStateRepository is the storage contract for the dormant
// governance scheduler state. The concrete implementation lives in
// internal/storage/postgres; this interface is owned by the consumer
// (CLAUDE.md §8.8). It carries persistence primitives only — there is
// no loop, no goroutine, and no primitive invocation in B4 PR-1.
//
// Every method binds organization_id; there is no cross-org statement
// except ListDueJobs, whose scan is deterministically ordered and
// LIMIT-bounded.
type SchedulerStateRepository interface {
	// UpsertJob initializes (or leaves intact) the row for
	// (organizationID, jobName). It is idempotent: an existing row's
	// operational fields (cursor, status, next-due, failures) are
	// NOT clobbered on a repeat call — only a brand-new row is seeded,
	// disabled, with NextDueAt = initialNextDueAt and an empty cursor.
	// This lets the composition root declare the set of (org, job)
	// rows at startup without disturbing live state.
	UpsertJob(ctx context.Context, organizationID, jobName string, initialNextDueAt time.Time) error

	// LoadJobState returns the persisted row for (organizationID,
	// jobName), or ErrSchedulerJobNotFound.
	LoadJobState(ctx context.Context, organizationID, jobName string) (*SchedulerJob, error)

	// ListDueJobs returns enabled rows whose NextDueAt <= now, ordered
	// deterministically by (next_due_at ASC, organization_id ASC,
	// job_name ASC) and bounded by limit. The order is the fairness
	// contract (B4 design §4.3): oldest-due first, so a partial run
	// re-armed at now+partial_requeue_delay sorts behind not-yet-served
	// due rows. limit must be > 0; a non-positive limit returns an
	// error (fail closed).
	ListDueJobs(ctx context.Context, now time.Time, limit int) ([]SchedulerJob, error)

	// MarkJobStarted records the start of a run: last_status=running,
	// last_started_at=startedAt. It does not touch the cursor or
	// next_due_at — those move only at a run boundary.
	MarkJobStarted(ctx context.Context, organizationID, jobName string, startedAt time.Time) error

	// MarkJobCompleted records a fully-drained run: persists the final
	// cursor, last_status=completed, last_finished_at=finishedAt,
	// resets consecutive_failures to 0 and last_error to empty, and
	// sets next_due_at to the next cycle time.
	MarkJobCompleted(ctx context.Context, organizationID, jobName, cursor string, finishedAt, nextDueAt time.Time) error

	// MarkJobPartial records a bounded run with work remaining:
	// persists the advanced cursor, last_status=partial,
	// last_finished_at=finishedAt, resets consecutive_failures (the
	// run made forward progress), and sets next_due_at to
	// finishedAt+partial_requeue_delay so the row re-arms strictly
	// behind not-yet-served due rows (caller supplies the computed
	// nextDueAt; it MUST be strictly after finishedAt).
	MarkJobPartial(ctx context.Context, organizationID, jobName, cursor string, finishedAt, nextDueAt time.Time) error

	// MarkJobFailed records a failed run: last_status=error,
	// last_finished_at=finishedAt, increments consecutive_failures,
	// stores the redacted error summary, and sets next_due_at to the
	// backoff time. The cursor is DELIBERATELY left un-advanced — the
	// failed page is retried from where it was (B4 design §6.1).
	MarkJobFailed(ctx context.Context, organizationID, jobName, redactedError string, finishedAt, nextDueAt time.Time) error
}

// SchedulerJobLock is a held, non-blocking concurrency lock for a
// single (organization, job). It guarantees no duplicate concurrent
// execution of the same pair across overlapping ticks and (forward-
// compatibly) across replicas (B4 design §8.2).
//
// The lock is backed by a PostgreSQL session-level advisory lock held
// on ONE pinned, dedicated connection from acquire through release —
// never via ordinary pool queries (which could unlock on a different
// physical session and strand the lock). Release returns that
// connection to the pool.
//
// The caller MUST call Release exactly once when done. Release is
// safe to call via defer.
type SchedulerJobLock interface {
	// Release drops the advisory lock and returns the pinned
	// connection to the pool. Idempotent: safe to call more than once.
	Release(ctx context.Context) error
}

// SchedulerJobLocker acquires SchedulerJobLock handles. Consumer-owned
// (CLAUDE.md §8.8); the postgres layer implements it.
type SchedulerJobLocker interface {
	// TryLockOrgJob attempts to acquire the (organizationID, jobName)
	// concurrency lock without blocking. On success it returns a held
	// lock (acquired=true) the caller must Release. If another holder
	// owns the lock it returns (nil, false, nil) — the caller skips
	// this (org, job) this tick. A non-nil error is an infrastructure
	// failure (connection acquisition, etc.), distinct from "not
	// acquired".
	TryLockOrgJob(ctx context.Context, organizationID, jobName string) (lock SchedulerJobLock, acquired bool, err error)
}

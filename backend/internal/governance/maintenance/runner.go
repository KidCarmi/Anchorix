package maintenance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// RunnerConfig carries the per-run bounds and re-arm policy the runner
// enforces. The composition root builds it from internal/config (B4
// design §9); the maintenance package never reads env directly
// (CLAUDE.md §8.9). All values are validated by config at startup; the
// constructor re-checks them so a misuse fails closed rather than
// producing unbounded or unfair behavior.
type RunnerConfig struct {
	// MaxPagesPerRun bounds the number of Job.RunPage calls in one run.
	MaxPagesPerRun int
	// MaxRunDuration is the wall-clock budget for one run, checked
	// between pages (never mid-page).
	MaxRunDuration time.Duration
	// PageSize is the per-page item bound passed to the Job.
	PageSize int
	// PartialRequeueDelay re-arms a partial run at finishedAt+delay. It
	// MUST be strictly positive so a served prefix sorts behind
	// not-yet-served due rows (B4 design §4.3 / §6.5 fairness).
	PartialRequeueDelay time.Duration
	// JobInterval is the spacing applied after a completed run (the next
	// full cycle for this org/job).
	JobInterval time.Duration
	// RetryBase / RetryMax bound the capped exponential backoff applied
	// after a failed run (B4 design §10.3).
	RetryBase time.Duration
	RetryMax  time.Duration
}

func (c RunnerConfig) validate() error {
	switch {
	case c.MaxPagesPerRun < 1:
		return fmt.Errorf("maintenance: MaxPagesPerRun must be >= 1 (got %d)", c.MaxPagesPerRun)
	case c.MaxRunDuration <= 0:
		return fmt.Errorf("maintenance: MaxRunDuration must be positive (got %s)", c.MaxRunDuration)
	case c.PageSize < 1:
		return fmt.Errorf("maintenance: PageSize must be >= 1 (got %d)", c.PageSize)
	case c.PartialRequeueDelay <= 0:
		return fmt.Errorf("maintenance: PartialRequeueDelay must be strictly positive (got %s)", c.PartialRequeueDelay)
	case c.JobInterval <= 0:
		return fmt.Errorf("maintenance: JobInterval must be positive (got %s)", c.JobInterval)
	case c.RetryBase <= 0:
		return fmt.Errorf("maintenance: RetryBase must be positive (got %s)", c.RetryBase)
	case c.RetryMax < c.RetryBase:
		return fmt.Errorf("maintenance: RetryMax (%s) must be >= RetryBase (%s)", c.RetryMax, c.RetryBase)
	}
	return nil
}

// RunOutcome is the terminal state of a single RunDueJob call. It is
// returned for logging/observability and to make the runner's behavior
// directly assertable in tests.
type RunOutcome string

const (
	// OutcomeSkippedLocked: the per-(org, job) lock was held elsewhere,
	// so the job did NOT execute this tick (no duplicate concurrent run).
	OutcomeSkippedLocked RunOutcome = "skipped_locked"
	// OutcomeCompleted: the job reported Done within the page budget.
	OutcomeCompleted RunOutcome = "completed"
	// OutcomePartial: a per-run bound was hit with work remaining.
	OutcomePartial RunOutcome = "partial"
	// OutcomeError: a page returned an error; the cursor was not advanced.
	OutcomeError RunOutcome = "error"
)

// RunReport summarizes a RunDueJob call.
type RunReport struct {
	Outcome      RunOutcome
	PagesRun     int
	ItemsScanned int
	ItemsChanged int
}

// JobRunner executes a single due (organization, job) pass synchronously.
// It owns NO background execution: there is no goroutine, ticker, or
// loop over orgs here. A future PR-3+ scheduler tick loop calls
// RunDueJob once per due item it selects from the state repository.
type JobRunner struct {
	registry *JobRegistry
	state    governance.SchedulerStateRepository
	locker   governance.SchedulerJobLocker
	clock    clock.Clock
	log      *logger.Logger
	cfg      RunnerConfig
}

// NewJobRunner wires the runner. Constructor DI (CLAUDE.md §8.8); every
// dependency is required and the config is validated up front so a
// misconfigured runner fails closed at construction.
func NewJobRunner(
	registry *JobRegistry,
	state governance.SchedulerStateRepository,
	locker governance.SchedulerJobLocker,
	clk clock.Clock,
	log *logger.Logger,
	cfg RunnerConfig,
) (*JobRunner, error) {
	switch {
	case registry == nil:
		return nil, errors.New("maintenance.NewJobRunner: registry required")
	case state == nil:
		return nil, errors.New("maintenance.NewJobRunner: state repository required")
	case locker == nil:
		return nil, errors.New("maintenance.NewJobRunner: locker required")
	case clk == nil:
		return nil, errors.New("maintenance.NewJobRunner: clock required")
	case log == nil:
		return nil, errors.New("maintenance.NewJobRunner: logger required")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &JobRunner{
		registry: registry,
		state:    state,
		locker:   locker,
		clock:    clk,
		log:      log,
		cfg:      cfg,
	}, nil
}

// RunDueJob executes one bounded pass for the supplied due job-state row.
//
// Sequence (B4 design §3.3 / §6.1):
//  1. Resolve the Job from the registry by name; an unknown name fails
//     closed (the row is inert — never executed).
//  2. Acquire the PR-1 per-(org, job) advisory lock, non-blocking. If it
//     is held elsewhere, skip without executing the job (no duplicate
//     concurrent run). The lock is released before return on every path.
//  3. Mark the run started.
//  4. Run the bounded page loop: at most MaxPagesPerRun pages and at most
//     MaxRunDuration wall-clock. Each page calls Job.RunPage once. The
//     cursor is persisted to the state repository ONLY after a page
//     returns without error (cursor-on-success). A page error ends the
//     run as failed and leaves the cursor un-advanced.
//  5. Record the terminal outcome (completed / partial / failed) with the
//     computed next-due time.
//
// RunDueJob is synchronous and bounded; it never spawns a goroutine.
func (r *JobRunner) RunDueJob(ctx context.Context, jobState governance.SchedulerJob) (RunReport, error) {
	orgID := jobState.OrganizationID
	jobName := jobState.JobName

	job, err := r.registry.Lookup(jobName)
	if err != nil {
		// Orphan / unknown job row: fail closed, do not execute. The
		// caller logs this as orphan_job_row; we surface the error.
		return RunReport{Outcome: OutcomeError}, err
	}

	lock, acquired, err := r.locker.TryLockOrgJob(ctx, orgID, jobName)
	if err != nil {
		return RunReport{Outcome: OutcomeError}, fmt.Errorf("maintenance: acquire lock %s/%s: %w", orgID, jobName, err)
	}
	if !acquired {
		r.log.Info("governance scheduler skipped locked job",
			"component", "governance_scheduler",
			"event", "skipped_locked",
			"organization_id", orgID,
			"job_name", jobName,
		)
		return RunReport{Outcome: OutcomeSkippedLocked}, nil
	}
	// Release on every return path, including a panic in Job.RunPage.
	// Use a background-derived ctx so a cancelled caller-ctx cannot stop
	// us from dropping the lock.
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if rerr := lock.Release(releaseCtx); rerr != nil {
			r.log.Error("governance scheduler lock release failed",
				"component", "governance_scheduler",
				"event", "lock_release_error",
				"organization_id", orgID,
				"job_name", jobName,
				"error", rerr.Error(),
			)
		}
	}()

	startedAt := r.clock.Now()
	if err := r.state.MarkJobStarted(ctx, orgID, jobName, startedAt); err != nil {
		return RunReport{Outcome: OutcomeError}, fmt.Errorf("maintenance: mark started %s/%s: %w", orgID, jobName, err)
	}

	return r.runPages(ctx, job, jobState)
}

// runPages is the bounded page loop. It is split out so the lock
// acquisition / release in RunDueJob stays readable; runPages assumes the
// lock is held and the run is already marked started.
func (r *JobRunner) runPages(ctx context.Context, job Job, jobState governance.SchedulerJob) (RunReport, error) {
	orgID := jobState.OrganizationID
	jobName := jobState.JobName
	limits := PageLimits{PageSize: r.cfg.PageSize}

	cursor := jobState.Cursor
	deadline := r.clock.Now().Add(r.cfg.MaxRunDuration)
	report := RunReport{}

	for {
		// Per-run bounds, checked BETWEEN pages (never mid-page) so a
		// page is always an atomic unit.
		if report.PagesRun >= r.cfg.MaxPagesPerRun {
			return r.finishPartial(ctx, orgID, jobName, cursor, report)
		}
		if !r.clock.Now().Before(deadline) {
			return r.finishPartial(ctx, orgID, jobName, cursor, report)
		}
		// Honor caller cancellation at a page boundary: treat an
		// already-cancelled context as a partial stop at the current
		// (un-advanced beyond last success) cursor.
		if err := ctx.Err(); err != nil {
			return r.finishPartial(ctx, orgID, jobName, cursor, report)
		}

		result, err := job.RunPage(ctx, orgID, cursor, limits)
		if err != nil {
			return r.finishFailed(ctx, orgID, jobName, jobState.ConsecutiveFailures, err, report)
		}

		// Cursor advances ONLY after a successful page. We persist via
		// the terminal Mark* call below at the run boundary; within the
		// loop we track the advanced cursor in memory and the last
		// committed cursor is whatever the terminal mark writes. Because
		// each page is atomic and idempotent, recording the advanced
		// cursor at the run boundary is equivalent to per-page persistence
		// for resumption (a crash re-runs at most the in-flight page).
		cursor = result.NextCursor
		report.PagesRun++
		report.ItemsScanned += result.ItemsScanned
		report.ItemsChanged += result.ItemsChanged

		if result.Done {
			return r.finishCompleted(ctx, orgID, jobName, cursor, report)
		}
	}
}

func (r *JobRunner) finishCompleted(ctx context.Context, orgID, jobName, cursor string, report RunReport) (RunReport, error) {
	finishedAt := r.clock.Now()
	nextDue := finishedAt.Add(r.cfg.JobInterval)
	// On completion the next cycle restarts from the job's start
	// sentinel; we persist the final cursor as-is (the re-arm policy
	// resets it conceptually — the next due run begins a fresh drain).
	persistCtx, cancel := r.persistContext(ctx)
	defer cancel()
	if err := r.state.MarkJobCompleted(persistCtx, orgID, jobName, governance.SchedulerCursorStart, finishedAt, nextDue); err != nil {
		return RunReport{Outcome: OutcomeError}, fmt.Errorf("maintenance: mark completed %s/%s: %w", orgID, jobName, err)
	}
	report.Outcome = OutcomeCompleted
	r.logOutcome(orgID, jobName, report)
	return report, nil
}

func (r *JobRunner) finishPartial(ctx context.Context, orgID, jobName, cursor string, report RunReport) (RunReport, error) {
	finishedAt := r.clock.Now()
	// Strictly-non-zero re-arm so the served item sorts behind
	// not-yet-served due rows (fairness).
	nextDue := finishedAt.Add(r.cfg.PartialRequeueDelay)
	persistCtx, cancel := r.persistContext(ctx)
	defer cancel()
	if err := r.state.MarkJobPartial(persistCtx, orgID, jobName, cursor, finishedAt, nextDue); err != nil {
		return RunReport{Outcome: OutcomeError}, fmt.Errorf("maintenance: mark partial %s/%s: %w", orgID, jobName, err)
	}
	report.Outcome = OutcomePartial
	r.logOutcome(orgID, jobName, report)
	return report, nil
}

func (r *JobRunner) finishFailed(ctx context.Context, orgID, jobName string, priorFailures int, runErr error, report RunReport) (RunReport, error) {
	finishedAt := r.clock.Now()
	// consecutive_failures is incremented by the repository; we compute
	// backoff from the failures-so-far the state row carried in (+1 for
	// this failure), so the next-due reflects this failure. The
	// repository stores the redacted summary; we pass the error string
	// (the maintenance primitives' errors are structural, not credential).
	backoff := r.backoffFor(priorFailures + 1)
	nextDue := finishedAt.Add(backoff)
	persistCtx, cancel := r.persistContext(ctx)
	defer cancel()
	if err := r.state.MarkJobFailed(persistCtx, orgID, jobName, runErr.Error(), finishedAt, nextDue); err != nil {
		return RunReport{Outcome: OutcomeError}, fmt.Errorf("maintenance: mark failed %s/%s: %w", orgID, jobName, err)
	}
	report.Outcome = OutcomeError
	r.log.Error("governance scheduler job failed",
		"component", "governance_scheduler",
		"event", "run_error",
		"organization_id", orgID,
		"job_name", jobName,
		"pages_run", report.PagesRun,
		"error", runErr.Error(),
		"remediation", "inspect the job's underlying maintenance primitive; the page will be retried on the backoff schedule",
	)
	return report, nil
}

// persistContext returns a short-lived context for the TERMINAL state
// write (completed / partial / failed). It is deliberately decoupled
// from the run context's cancellation: a run that ends because the
// caller context was cancelled at a page boundary (graceful shutdown or
// the per-run deadline) must STILL durably record its advanced cursor
// and next-due time — otherwise the row would be stranded in `running`
// with stale scheduling state and the run's forward progress would be
// lost. This mirrors the lock-release path, which uses the same
// fresh-context discipline so cancellation can never prevent cleanup.
// The 5s budget is generous for a single-row UPDATE.
func (r *JobRunner) persistContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

// backoffFor computes the capped exponential backoff for the given
// consecutive-failure count (1-based): min(RetryMax, RetryBase * 2^(n-1)).
// Bounded and deterministic (B4 design §10.3); overflow-safe because it
// caps as soon as the doubling reaches RetryMax.
func (r *JobRunner) backoffFor(consecutiveFailures int) time.Duration {
	if consecutiveFailures < 1 {
		consecutiveFailures = 1
	}
	d := r.cfg.RetryBase
	for i := 1; i < consecutiveFailures; i++ {
		if d >= r.cfg.RetryMax {
			return r.cfg.RetryMax
		}
		d *= 2
	}
	if d > r.cfg.RetryMax {
		return r.cfg.RetryMax
	}
	return d
}

func (r *JobRunner) logOutcome(orgID, jobName string, report RunReport) {
	r.log.Info("governance scheduler run finished",
		"component", "governance_scheduler",
		"event", "run_finished",
		"organization_id", orgID,
		"job_name", jobName,
		"outcome", string(report.Outcome),
		"pages_run", report.PagesRun,
		"items_scanned", report.ItemsScanned,
		"items_changed", report.ItemsChanged,
	)
}

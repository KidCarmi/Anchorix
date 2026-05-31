package postgres

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// GovernanceSchedulerRepository is the postgres implementation of the
// dormant B4 scheduler state contract
// (governance.SchedulerStateRepository + governance.SchedulerJobLocker).
//
// It carries persistence primitives + a non-blocking concurrency-lock
// helper ONLY. There is no scheduler loop, no goroutine, no ticker, no
// job registry, and no job runner here — those land in B4 PR-2+. No
// method invokes the H-027 prune or H-029 sweep primitives.
//
// Cross-org isolation: every statement binds organization_id. The one
// multi-org read (ListDueJobs) is deterministically ordered and
// LIMIT-bounded; it never returns another org's row except as part of
// the bounded, ordered due set.
type GovernanceSchedulerRepository struct {
	db *DB
}

// NewGovernanceSchedulerRepository wires the repository. CLAUDE.md §8.8.
func NewGovernanceSchedulerRepository(db *DB) *GovernanceSchedulerRepository {
	return &GovernanceSchedulerRepository{db: db}
}

// schedulerLockNamespace prefixes the advisory-lock key derivation for
// the governance scheduler's per-(org, job) concurrency lock. It keeps
// the keyspace DISTINCT from any other advisory lock in the process
// (e.g. the 'ownership-recompute' data lock the maintenance primitives
// take inside their own page transactions) so the scheduler's coarse
// "this runner owns this item" guard never collides with the ownership
// data lock (B4 design §8.2 — the two locks are orthogonal).
const schedulerLockNamespace = "governance-scheduler-job"

// schedulerLockKey derives the 64-bit advisory-lock key for a
// (organizationID, jobName) pair, deterministically, in Go. We hash in
// Go (FNV-64a) rather than via PostgreSQL hashtext for two reasons:
//
//   - the single-argument pg_(try_)advisory_lock(bigint) takes one
//     int64, so a Go-side hash maps cleanly onto it; and
//   - org/job ids are arbitrary text, and a NUL byte separator (needed
//     to keep ("a","bc") distinct from ("ab","c")) is rejected by
//     PostgreSQL's UTF8 text input — hashing in Go sidesteps the
//     encoding entirely.
//
// A rare 64-bit collision only over-serializes two unrelated (org, job)
// pairs, which is safe (fail-closed: at worst one extra skip), so a
// non-cryptographic hash is appropriate.
func schedulerLockKey(organizationID, jobName string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(schedulerLockNamespace))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(organizationID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(jobName))
	return int64(h.Sum64())
}

// UpsertJob seeds the row for (organizationID, jobName) if absent,
// disabled, with the supplied initial next-due time and an empty
// (start-sentinel) cursor. It is idempotent: ON CONFLICT DO NOTHING
// means a repeat call leaves a live row's operational fields
// (cursor / status / next_due_at / failures / enabled) untouched.
func (r *GovernanceSchedulerRepository) UpsertJob(ctx context.Context, organizationID, jobName string, initialNextDueAt time.Time) error {
	if organizationID == "" {
		return errors.New("postgres: scheduler upsert: empty organization id")
	}
	if jobName == "" {
		return errors.New("postgres: scheduler upsert: empty job name")
	}
	const q = `
		INSERT INTO governance_scheduler_job
			(organization_id, job_name, enabled, cursor, next_due_at, last_status, consecutive_failures, updated_at)
		VALUES ($1, $2, FALSE, '', $3, 'pending', 0, now())
		ON CONFLICT (organization_id, job_name) DO NOTHING`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, jobName, initialNextDueAt); err != nil {
		return fmt.Errorf("postgres: scheduler upsert job %s/%s: %w", organizationID, jobName, err)
	}
	return nil
}

// LoadJobState returns the row for (organizationID, jobName) or
// governance.ErrSchedulerJobNotFound.
func (r *GovernanceSchedulerRepository) LoadJobState(ctx context.Context, organizationID, jobName string) (*governance.SchedulerJob, error) {
	const q = `
		SELECT organization_id, job_name, enabled, cursor, next_due_at,
		       last_started_at, last_finished_at, last_status, last_error,
		       consecutive_failures, updated_at
		  FROM governance_scheduler_job
		 WHERE organization_id = $1 AND job_name = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, jobName)
	job, err := scanSchedulerJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrSchedulerJobNotFound
		}
		return nil, fmt.Errorf("postgres: load scheduler job %s/%s: %w", organizationID, jobName, err)
	}
	return job, nil
}

// ListDueJobs returns enabled rows whose next_due_at <= now, ordered
// (next_due_at ASC, organization_id ASC, job_name ASC) and bounded by
// limit. The ordering is the fairness contract (B4 design §4.3). limit
// must be positive — a non-positive limit fails closed.
func (r *GovernanceSchedulerRepository) ListDueJobs(ctx context.Context, now time.Time, limit int) ([]governance.SchedulerJob, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("postgres: list due scheduler jobs: limit must be positive (got %d)", limit)
	}
	const q = `
		SELECT organization_id, job_name, enabled, cursor, next_due_at,
		       last_started_at, last_finished_at, last_status, last_error,
		       consecutive_failures, updated_at
		  FROM governance_scheduler_job
		 WHERE enabled = TRUE AND next_due_at <= $1
		 ORDER BY next_due_at ASC, organization_id ASC, job_name ASC
		 LIMIT $2`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, now, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list due scheduler jobs: %w", err)
	}
	defer rows.Close()

	out := make([]governance.SchedulerJob, 0, limit)
	for rows.Next() {
		job, err := scanSchedulerJob(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan due scheduler job: %w", err)
		}
		out = append(out, *job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate due scheduler jobs: %w", err)
	}
	return out, nil
}

// MarkJobStarted records run start. Does not touch cursor/next_due_at.
func (r *GovernanceSchedulerRepository) MarkJobStarted(ctx context.Context, organizationID, jobName string, startedAt time.Time) error {
	const q = `
		UPDATE governance_scheduler_job
		   SET last_status = 'running', last_started_at = $3, updated_at = now()
		 WHERE organization_id = $1 AND job_name = $2`
	return r.execMark(ctx, "started", organizationID, jobName, q, organizationID, jobName, startedAt)
}

// MarkJobCompleted persists the final cursor, marks completed, resets
// failure state, and sets the next cycle time.
func (r *GovernanceSchedulerRepository) MarkJobCompleted(ctx context.Context, organizationID, jobName, cursor string, finishedAt, nextDueAt time.Time) error {
	const q = `
		UPDATE governance_scheduler_job
		   SET last_status = 'completed', cursor = $3, last_finished_at = $4,
		       next_due_at = $5, consecutive_failures = 0, last_error = NULL,
		       updated_at = now()
		 WHERE organization_id = $1 AND job_name = $2`
	return r.execMark(ctx, "completed", organizationID, jobName, q, organizationID, jobName, cursor, finishedAt, nextDueAt)
}

// MarkJobPartial persists the advanced cursor, marks partial, resets
// failure state (forward progress was made), and sets the re-arm time
// (caller computes finishedAt + partial_requeue_delay).
func (r *GovernanceSchedulerRepository) MarkJobPartial(ctx context.Context, organizationID, jobName, cursor string, finishedAt, nextDueAt time.Time) error {
	const q = `
		UPDATE governance_scheduler_job
		   SET last_status = 'partial', cursor = $3, last_finished_at = $4,
		       next_due_at = $5, consecutive_failures = 0, last_error = NULL,
		       updated_at = now()
		 WHERE organization_id = $1 AND job_name = $2`
	return r.execMark(ctx, "partial", organizationID, jobName, q, organizationID, jobName, cursor, finishedAt, nextDueAt)
}

// MarkJobFailed marks error, increments consecutive_failures, stores
// the redacted error, and sets the backoff next-due. The cursor is
// DELIBERATELY left un-advanced so the failed page is retried.
func (r *GovernanceSchedulerRepository) MarkJobFailed(ctx context.Context, organizationID, jobName, redactedError string, finishedAt, nextDueAt time.Time) error {
	const q = `
		UPDATE governance_scheduler_job
		   SET last_status = 'error', last_finished_at = $3, next_due_at = $4,
		       consecutive_failures = consecutive_failures + 1, last_error = $5,
		       updated_at = now()
		 WHERE organization_id = $1 AND job_name = $2`
	return r.execMark(ctx, "failed", organizationID, jobName, q, organizationID, jobName, finishedAt, nextDueAt, redactedError)
}

// execMark runs a single-row state-transition UPDATE and fails closed
// with ErrSchedulerJobNotFound when no row matched (e.g. a cross-org or
// nonexistent (org, job)) — a state transition against a missing row
// is a caller bug, surfaced rather than silently swallowed.
func (r *GovernanceSchedulerRepository) execMark(ctx context.Context, label, organizationID, jobName, q string, args ...any) error {
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("postgres: mark scheduler job %s %s/%s: %w", label, organizationID, jobName, err)
	}
	if tag.RowsAffected() == 0 {
		return governance.ErrSchedulerJobNotFound
	}
	return nil
}

func scanSchedulerJob(row pgx.Row) (*governance.SchedulerJob, error) {
	var (
		job        governance.SchedulerJob
		status     string
		startedAt  *time.Time
		finishedAt *time.Time
		lastError  *string
	)
	if err := row.Scan(
		&job.OrganizationID, &job.JobName, &job.Enabled, &job.Cursor, &job.NextDueAt,
		&startedAt, &finishedAt, &status, &lastError, &job.ConsecutiveFailures, &job.UpdatedAt,
	); err != nil {
		return nil, err
	}
	job.LastStatus = governance.SchedulerJobStatus(status)
	if startedAt != nil {
		job.LastStartedAt = *startedAt
	}
	if finishedAt != nil {
		job.LastFinishedAt = *finishedAt
	}
	if lastError != nil {
		job.LastError = *lastError
	}
	return &job, nil
}

// --- concurrency lock (pinned dedicated connection) ---

// schedulerJobLock is a held session-level advisory lock backed by ONE
// pinned connection. The connection is acquired before
// pg_try_advisory_lock and held until Release runs pg_advisory_unlock
// on that SAME connection — never via a pool query (B4 design §8.2:
// unlocking on a different physical session would strand the lock).
type schedulerJobLock struct {
	conn           *pgxpool.Conn
	organizationID string
	jobName        string
	released       bool
}

// TryLockOrgJob attempts the non-blocking (organizationID, jobName)
// advisory lock on a freshly-acquired dedicated connection. On success
// it returns a held lock the caller MUST Release. If the lock is held
// elsewhere it returns (nil, false, nil) and releases the connection.
func (r *GovernanceSchedulerRepository) TryLockOrgJob(ctx context.Context, organizationID, jobName string) (governance.SchedulerJobLock, bool, error) {
	if organizationID == "" || jobName == "" {
		return nil, false, errors.New("postgres: scheduler try-lock: empty organization id or job name")
	}
	conn, err := r.db.pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("postgres: acquire connection for scheduler job lock: %w", err)
	}
	lockKey := schedulerLockKey(organizationID, jobName)
	var acquired bool
	if err := conn.QueryRow(ctx,
		`SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&acquired); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("postgres: try advisory lock scheduler %s/%s: %w", organizationID, jobName, err)
	}
	if !acquired {
		// Another holder owns the lock. Release the connection (it
		// holds no lock) and report "not acquired".
		conn.Release()
		return nil, false, nil
	}
	return &schedulerJobLock{conn: conn, organizationID: organizationID, jobName: jobName}, true, nil
}

// Release drops the advisory lock on the pinned connection and returns
// it to the pool. Idempotent. If the unlock SQL fails, the connection
// is hijacked out of the pool and closed so a still-locked connection
// is never handed to a later borrower (closing the TCP connection
// drops every session-scope lock the backend held) — the same
// defensive cleanup the existing session-lock helpers use.
func (l *schedulerJobLock) Release(ctx context.Context) error {
	if l == nil || l.released {
		return nil
	}
	l.released = true

	lockKey := schedulerLockKey(l.organizationID, l.jobName)
	unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := l.conn.Exec(unlockCtx,
		`SELECT pg_advisory_unlock($1)`, lockKey); err != nil {
		if hijacked := l.conn.Hijack(); hijacked != nil {
			closeCtx, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelClose()
			_ = hijacked.Close(closeCtx)
		}
		return fmt.Errorf("postgres: unlock scheduler job %s/%s: %w", l.organizationID, l.jobName, err)
	}
	l.conn.Release()
	return nil
}

// BackendPID returns the PostgreSQL backend process id of the pinned
// connection. It exists so the integration suite can prove acquire and
// release execute on the SAME physical session (B4 hard requirement /
// design §8.2). It is not part of the domain interface — tests assert
// it via the concrete type.
func (l *schedulerJobLock) BackendPID(ctx context.Context) (int32, error) {
	var pid int32
	if err := l.conn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		return 0, fmt.Errorf("postgres: scheduler lock backend pid: %w", err)
	}
	return pid, nil
}

// Compile-time guards: the repository satisfies both consumer-owned
// interfaces, and the lock handle satisfies the lock interface.
var (
	_ governance.SchedulerStateRepository = (*GovernanceSchedulerRepository)(nil)
	_ governance.SchedulerJobLocker       = (*GovernanceSchedulerRepository)(nil)
	_ governance.SchedulerJobLock         = (*schedulerJobLock)(nil)
)

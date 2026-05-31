//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// B4 PR-1 integration tests for the dormant governance scheduler state
// repository + advisory-lock helper. These exercise persistence,
// deterministic due selection, fairness re-arm ordering, cursor
// semantics, backoff, cross-org isolation, upsert idempotency, and the
// pinned-connection advisory lock (including the same-pg_backend_pid
// proof). No scheduler loop, goroutine, or maintenance primitive is
// involved.

const (
	schedJobSweep = "expired_override_sweep"
	schedJobPrune = "explanation_retention_prune"
)

func seedSecondOrg(t *testing.T, db *postgres.DB, orgID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ($1, $2)`, orgID, orgID)
		return err
	}); err != nil {
		t.Fatalf("seed org %s: %v", orgID, err)
	}
}

// enableJob flips a seeded job row to enabled and sets its next_due_at,
// using raw SQL (there is no enable method in PR-1 — operators toggle
// via DB until a later admin path). Tests use it to make rows due.
func enableJob(t *testing.T, db *postgres.DB, orgID, jobName string, nextDueAt time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE governance_scheduler_job SET enabled = TRUE, next_due_at = $3
			  WHERE organization_id = $1 AND job_name = $2`, orgID, jobName, nextDueAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			t.Fatalf("enableJob: expected 1 row, got %d", tag.RowsAffected())
		}
		return nil
	}); err != nil {
		t.Fatalf("enable job %s/%s: %v", orgID, jobName, err)
	}
}

func TestSchedulerUpsertIsIdempotentAndDormant(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	due := time.Now().UTC().Add(time.Hour)

	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, due); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	// Advance the live row, then upsert again — the repeat must NOT
	// clobber operational state.
	if err := repo.MarkJobStarted(ctx, "anchorix", schedJobSweep, time.Now().UTC()); err != nil {
		t.Fatalf("mark started: %v", err)
	}
	if err := repo.MarkJobCompleted(ctx, "anchorix", schedJobSweep, "cert-42",
		time.Now().UTC(), due); err != nil {
		t.Fatalf("mark completed: %v", err)
	}
	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, time.Now().UTC().Add(99*time.Hour)); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	job, err := repo.LoadJobState(ctx, "anchorix", schedJobSweep)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if job.Cursor != "cert-42" {
		t.Fatalf("idempotent upsert clobbered cursor: got %q want cert-42", job.Cursor)
	}
	if job.LastStatus != governance.SchedulerJobCompleted {
		t.Fatalf("idempotent upsert clobbered status: got %q", job.LastStatus)
	}
	// A freshly upserted row is dormant: disabled by default.
	if job.Enabled {
		t.Fatal("seeded job must be disabled by default")
	}
}

func TestSchedulerLoadJobStateNotFound(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	_, err := repo.LoadJobState(context.Background(), "anchorix", "nope")
	if !errors.Is(err, governance.ErrSchedulerJobNotFound) {
		t.Fatalf("want ErrSchedulerJobNotFound, got %v", err)
	}
}

func TestSchedulerDueSelectionDeterministicOrderAndLimit(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedSecondOrg(t, db, "beta-org")
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour) // all due (in the past)

	// Seed + enable four rows with deliberately interleaved due times
	// so the ASC ordering is observable and not insertion order.
	// Expected order: (next_due_at ASC, organization_id ASC, job_name ASC).
	seed := []struct {
		org, job string
		due      time.Time
	}{
		{"anchorix", schedJobPrune, base.Add(30 * time.Second)},
		{"beta-org", schedJobSweep, base.Add(10 * time.Second)},
		{"anchorix", schedJobSweep, base.Add(10 * time.Second)}, // ties beta-org on time; org "anchorix" < "beta-org"
		{"beta-org", schedJobPrune, base.Add(20 * time.Second)},
	}
	for _, s := range seed {
		if err := repo.UpsertJob(ctx, s.org, s.job, base); err != nil {
			t.Fatalf("upsert %s/%s: %v", s.org, s.job, err)
		}
		enableJob(t, db, s.org, s.job, s.due)
	}

	got, err := repo.ListDueJobs(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	want := []struct{ org, job string }{
		{"anchorix", schedJobSweep}, // due+10, org anchorix
		{"beta-org", schedJobSweep}, // due+10, org beta-org
		{"beta-org", schedJobPrune}, // due+20
		{"anchorix", schedJobPrune}, // due+30
	}
	if len(got) != len(want) {
		t.Fatalf("got %d due rows, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].OrganizationID != want[i].org || got[i].JobName != want[i].job {
			t.Fatalf("position %d: got %s/%s, want %s/%s",
				i, got[i].OrganizationID, got[i].JobName, want[i].org, want[i].job)
		}
	}

	// Limit is enforced.
	limited, err := repo.ListDueJobs(ctx, time.Now().UTC(), 2)
	if err != nil {
		t.Fatalf("list due limited: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("limit not enforced: got %d, want 2", len(limited))
	}
	if limited[0].JobName != schedJobSweep || limited[0].OrganizationID != "anchorix" {
		t.Fatalf("limited[0] = %s/%s, want anchorix/%s", limited[0].OrganizationID, limited[0].JobName, schedJobSweep)
	}

	// Non-positive limit fails closed.
	if _, err := repo.ListDueJobs(ctx, time.Now().UTC(), 0); err == nil {
		t.Fatal("limit 0 must fail closed")
	}
}

func TestSchedulerDisabledAndFutureRowsNotDue(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// Disabled row (default) — never due.
	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, now.Add(-time.Hour)); err != nil {
		t.Fatalf("upsert sweep: %v", err)
	}
	// Enabled but due in the future — not due now.
	if err := repo.UpsertJob(ctx, "anchorix", schedJobPrune, now); err != nil {
		t.Fatalf("upsert prune: %v", err)
	}
	enableJob(t, db, "anchorix", schedJobPrune, now.Add(time.Hour))

	got, err := repo.ListDueJobs(ctx, now, 10)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no due rows, got %d", len(got))
	}
}

// TestSchedulerPartialRequeueMovesBehindUnservedDueRows pins the
// fairness contract: after a partial run re-arms an item at
// finishedAt + partial_requeue_delay, the re-armed item sorts AFTER a
// not-yet-served due row whose next_due_at is earlier.
func TestSchedulerPartialRequeueMovesBehindUnservedDueRows(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)

	// Two due rows. "served" is the one we run partial first.
	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, base); err != nil {
		t.Fatalf("upsert sweep: %v", err)
	}
	if err := repo.UpsertJob(ctx, "anchorix", schedJobPrune, base); err != nil {
		t.Fatalf("upsert prune: %v", err)
	}
	// sweep is due slightly earlier (served first); prune is the
	// not-yet-served due row.
	enableJob(t, db, "anchorix", schedJobSweep, base)
	enableJob(t, db, "anchorix", schedJobPrune, base.Add(time.Second))

	// Run sweep partial: re-arm at finishedAt + delay (strictly non-zero).
	finished := time.Now().UTC()
	const partialRequeueDelay = time.Second
	if err := repo.MarkJobStarted(ctx, "anchorix", schedJobSweep, finished); err != nil {
		t.Fatalf("mark started: %v", err)
	}
	if err := repo.MarkJobPartial(ctx, "anchorix", schedJobSweep, "cert-100",
		finished, finished.Add(partialRequeueDelay)); err != nil {
		t.Fatalf("mark partial: %v", err)
	}

	// Now both are due again at a later "now"; the not-yet-served prune
	// (next_due_at = base+1s) must sort BEFORE the re-armed sweep
	// (next_due_at = finished+1s, which is ~now+1s, far later).
	got, err := repo.ListDueJobs(ctx, finished.Add(2*time.Second), 10)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 due rows, got %d", len(got))
	}
	if got[0].JobName != schedJobPrune {
		t.Fatalf("fairness violated: served sweep should sort behind unserved prune; got first = %s", got[0].JobName)
	}
	if got[1].JobName != schedJobSweep {
		t.Fatalf("expected re-armed sweep last; got %s", got[1].JobName)
	}
	// Cursor advanced on the partial run.
	if got[1].Cursor != "cert-100" {
		t.Fatalf("partial run cursor = %q, want cert-100", got[1].Cursor)
	}
}

func TestSchedulerCursorPersistenceSemantics(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// completed persists cursor + resets failures.
	if err := repo.MarkJobCompleted(ctx, "anchorix", schedJobSweep, "cert-A", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("completed: %v", err)
	}
	job, _ := repo.LoadJobState(ctx, "anchorix", schedJobSweep)
	if job.Cursor != "cert-A" || job.LastStatus != governance.SchedulerJobCompleted {
		t.Fatalf("after completed: cursor=%q status=%q", job.Cursor, job.LastStatus)
	}

	// failed leaves the cursor UN-advanced (retry from same place).
	if err := repo.MarkJobFailed(ctx, "anchorix", schedJobSweep, "boom", now, now.Add(time.Minute)); err != nil {
		t.Fatalf("failed: %v", err)
	}
	job, _ = repo.LoadJobState(ctx, "anchorix", schedJobSweep)
	if job.Cursor != "cert-A" {
		t.Fatalf("failed run must not advance cursor: got %q want cert-A", job.Cursor)
	}
	if job.LastStatus != governance.SchedulerJobError {
		t.Fatalf("status after fail = %q, want error", job.LastStatus)
	}
	if job.ConsecutiveFailures != 1 {
		t.Fatalf("consecutive failures = %d, want 1", job.ConsecutiveFailures)
	}
	if job.LastError != "boom" {
		t.Fatalf("last error = %q, want boom", job.LastError)
	}
}

func TestSchedulerBackoffFailureCounting(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	for i := 1; i <= 3; i++ {
		if err := repo.MarkJobFailed(ctx, "anchorix", schedJobSweep, "err", now, now.Add(time.Minute)); err != nil {
			t.Fatalf("fail %d: %v", i, err)
		}
		job, _ := repo.LoadJobState(ctx, "anchorix", schedJobSweep)
		if job.ConsecutiveFailures != i {
			t.Fatalf("after %d failures, count = %d", i, job.ConsecutiveFailures)
		}
	}
	// A successful (partial) run resets the counter (forward progress).
	if err := repo.MarkJobPartial(ctx, "anchorix", schedJobSweep, "cert-X", now, now.Add(time.Second)); err != nil {
		t.Fatalf("partial: %v", err)
	}
	job, _ := repo.LoadJobState(ctx, "anchorix", schedJobSweep)
	if job.ConsecutiveFailures != 0 {
		t.Fatalf("forward progress must reset failures, got %d", job.ConsecutiveFailures)
	}
	if job.LastError != "" {
		t.Fatalf("forward progress must clear last_error, got %q", job.LastError)
	}
}

func TestSchedulerCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedSecondOrg(t, db, "beta-org")
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, now); err != nil {
		t.Fatalf("upsert anchorix: %v", err)
	}
	if err := repo.UpsertJob(ctx, "beta-org", schedJobSweep, now); err != nil {
		t.Fatalf("upsert beta: %v", err)
	}

	// A mark against anchorix must not touch beta-org's row.
	if err := repo.MarkJobCompleted(ctx, "anchorix", schedJobSweep, "cert-anchorix", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("complete anchorix: %v", err)
	}
	beta, err := repo.LoadJobState(ctx, "beta-org", schedJobSweep)
	if err != nil {
		t.Fatalf("load beta: %v", err)
	}
	if beta.Cursor != "" || beta.LastStatus != governance.SchedulerJobPending {
		t.Fatalf("cross-org leak: beta cursor=%q status=%q", beta.Cursor, beta.LastStatus)
	}

	// A mark against a (org, job) that exists only in another org fails
	// closed with not-found (no silent cross-org write).
	err = repo.MarkJobCompleted(ctx, "beta-org", schedJobPrune, "x", now, now.Add(time.Hour))
	if !errors.Is(err, governance.ErrSchedulerJobNotFound) {
		t.Fatalf("mark on nonexistent (org,job) should be ErrSchedulerJobNotFound, got %v", err)
	}
}

// TestSchedulerAdvisoryLockMutualExclusionAndSamePID is the core B4
// hard requirement: the non-blocking lock admits exactly one holder,
// a second concurrent acquire fails, release frees it, and acquire +
// release run on the SAME physical session (pg_backend_pid).
func TestSchedulerAdvisoryLockMutualExclusionAndSamePID(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()

	lock, acquired, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if !acquired {
		t.Fatal("first acquire must succeed")
	}

	// Same-connection proof: acquire and (later) release share a PID.
	concrete, ok := lock.(interface {
		BackendPID(ctx context.Context) (int32, error)
	})
	if !ok {
		t.Fatal("lock handle should expose BackendPID for the same-session proof")
	}
	pidAtAcquire, err := concrete.BackendPID(ctx)
	if err != nil {
		t.Fatalf("pid at acquire: %v", err)
	}

	// A second concurrent acquire of the same (org, job) must fail
	// (non-blocking, lock held).
	lock2, acquired2, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep)
	if err != nil {
		t.Fatalf("second acquire returned error: %v", err)
	}
	if acquired2 {
		_ = lock2.Release(ctx)
		t.Fatal("second concurrent acquire must NOT succeed while lock held")
	}

	// A different (org, job) is independently lockable.
	otherLock, otherAcquired, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobPrune)
	if err != nil || !otherAcquired {
		t.Fatalf("different (org,job) should lock independently: acquired=%v err=%v", otherAcquired, err)
	}

	// PID must be stable on the held connection right before release.
	pidBeforeRelease, err := concrete.BackendPID(ctx)
	if err != nil {
		t.Fatalf("pid before release: %v", err)
	}
	if pidAtAcquire != pidBeforeRelease {
		t.Fatalf("advisory lock changed connections: acquire pid=%d, pre-release pid=%d",
			pidAtAcquire, pidBeforeRelease)
	}

	// Release frees the lock; a subsequent acquire succeeds.
	if err := lock.Release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := otherLock.Release(ctx); err != nil {
		t.Fatalf("release other: %v", err)
	}

	relock, reacquired, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	if !reacquired {
		t.Fatal("acquire after release must succeed")
	}
	// Release is idempotent — calling twice is safe.
	if err := relock.Release(ctx); err != nil {
		t.Fatalf("release relock: %v", err)
	}
	if err := relock.Release(ctx); err != nil {
		t.Fatalf("second release must be a safe no-op: %v", err)
	}
}

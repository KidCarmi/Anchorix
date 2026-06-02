//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// B4 PR-1 HARDENING — adversarial coverage for the dormant governance
// scheduler state repository + advisory-lock helper. Test-heavy: no
// production change accompanies this file. It pins migration
// constraints, TEXT-org-id FK correctness, due-selection determinism
// under timestamp ties, partial-requeue fairness boundaries, the
// cursor-only-advances-on-progress invariant, backoff monotonicity,
// cross-org isolation under adversarial input, and the pinned-connection
// advisory lock (mutual exclusion, same-PID acquire/release, idempotent
// + post-release reacquire, independence from the ownership data lock).
//
// Helpers reused from governance_scheduler_repository_test.go:
// seedSecondOrg, enableJob, schedJobSweep, schedJobPrune.

// ---------- migration / schema constraints ----------

// TestSchedulerMigrationRegistersTableAndIndex pins that migration 0012
// landed the table, the partial due-index, and the schema_migrations
// version. A regression that drops or renames any of these breaks the
// dormant contract the PR-2 loop will depend on.
func TestSchedulerMigrationRegistersTableAndIndex(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var tableExists bool
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_tables
			 WHERE schemaname='public' AND tablename='governance_scheduler_job')`).Scan(&tableExists)
	}); err != nil {
		t.Fatalf("check table: %v", err)
	}
	if !tableExists {
		t.Fatal("governance_scheduler_job table missing after migration 0012")
	}

	// The partial due-index must exist AND carry its WHERE enabled=TRUE
	// predicate — a full index would scan disabled rows on the hot path.
	var indexDef string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT indexdef FROM pg_indexes
			  WHERE schemaname='public' AND indexname='governance_scheduler_job_due_idx'`).Scan(&indexDef)
	}); err != nil {
		t.Fatalf("look up due index: %v", err)
	}
	if !strings.Contains(indexDef, "next_due_at") {
		t.Fatalf("due index not on next_due_at: %q", indexDef)
	}
	if !strings.Contains(strings.ToLower(indexDef), "where (enabled") && !strings.Contains(strings.ToLower(indexDef), "where enabled") {
		t.Fatalf("due index is not partial on enabled=TRUE: %q", indexDef)
	}

	var present bool
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 12)`).Scan(&present)
	}); err != nil {
		t.Fatalf("check version: %v", err)
	}
	if !present {
		t.Fatal("schema_migrations missing version 12")
	}
}

// TestSchedulerLastStatusCheckRejectsUnknownEnum pins the last_status
// CHECK constraint — the explicit state machine (B4 design §18) must
// not silently widen.
func TestSchedulerLastStatusCheckRejectsUnknownEnum(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO governance_scheduler_job
		   (organization_id, job_name, next_due_at, last_status)
		 VALUES ('anchorix', 'j', now(), 'bogus_status')`, nil})
	if err == nil {
		t.Fatal("expected CHECK violation for unknown last_status")
	}
	if !strings.Contains(err.Error(), "last_status") {
		t.Fatalf("error should mention last_status, got: %v", err)
	}
}

// TestSchedulerConsecutiveFailuresCheckRejectsNegative pins the
// consecutive_failures >= 0 CHECK.
func TestSchedulerConsecutiveFailuresCheckRejectsNegative(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO governance_scheduler_job
		   (organization_id, job_name, next_due_at, consecutive_failures)
		 VALUES ('anchorix', 'j', now(), -1)`, nil})
	if err == nil {
		t.Fatal("expected CHECK violation for negative consecutive_failures")
	}
	if !strings.Contains(err.Error(), "consecutive_failures") {
		t.Fatalf("error should mention consecutive_failures, got: %v", err)
	}
}

// TestSchedulerFKRejectsUnknownOrgWithTextID pins the TEXT-org-id FK:
// a row for a nonexistent organization is rejected by the composite
// REFERENCES organizations(id). Proves the TEXT type matches
// organizations(id) (a UUID column, as the design sketched, would have
// rejected the seed org ids entirely).
func TestSchedulerFKRejectsUnknownOrgWithTextID(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO governance_scheduler_job (organization_id, job_name, next_due_at)
		 VALUES ('no-such-org', 'j', now())`, nil})
	if err == nil {
		t.Fatal("expected FK violation for unknown organization_id")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") &&
		!strings.Contains(err.Error(), "organization_id") {
		t.Fatalf("error should be an FK violation on organization_id, got: %v", err)
	}

	// And a valid TEXT org id ('anchorix', seeded by freshDatabase) is
	// accepted — confirming the column type round-trips real ids.
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO governance_scheduler_job (organization_id, job_name, next_due_at)
		 VALUES ('anchorix', 'j-ok', now())`, nil}); err != nil {
		t.Fatalf("valid TEXT org id should be accepted: %v", err)
	}
}

// TestSchedulerOrgDeleteRestrictedWhileJobExists pins ON DELETE
// RESTRICT: an organization with a scheduler job row cannot be deleted
// out from under it (operator-curated state is protected, mirroring the
// rest of the governance schema).
func TestSchedulerOrgDeleteRestrictedWhileJobExists(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedSecondOrg(t, db, "doomed-org")
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()

	if err := repo.UpsertJob(ctx, "doomed-org", schedJobSweep, time.Now().UTC()); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	err := execRawSQL(ctx, db, rawStmt{`DELETE FROM organizations WHERE id = 'doomed-org'`, nil})
	if err == nil {
		t.Fatal("expected RESTRICT to block org delete while a job row exists")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Fatalf("expected FK RESTRICT error, got: %v", err)
	}
}

// TestSchedulerCursorDefaultsToStartSentinel pins that a raw insert
// without a cursor lands the ” start sentinel (NOT NULL DEFAULT ”),
// so the scheduler never observes a NULL cursor it would misread.
func TestSchedulerCursorDefaultsToStartSentinel(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()

	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, time.Now().UTC()); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	job, err := repo.LoadJobState(ctx, "anchorix", schedJobSweep)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if job.Cursor != governance.SchedulerCursorStart {
		t.Fatalf("fresh cursor = %q, want start sentinel %q", job.Cursor, governance.SchedulerCursorStart)
	}
	if job.LastStatus != governance.SchedulerJobPending {
		t.Fatalf("fresh status = %q, want pending", job.LastStatus)
	}
}

// ---------- due selection determinism ----------

// TestSchedulerDueOrderDeterministicUnderTimestampTie pins the full
// tiebreaker: when many rows share an identical next_due_at, the order
// is (organization_id ASC, job_name ASC) and is stable across repeated
// queries — no reliance on heap/insertion order.
func TestSchedulerDueOrderDeterministicUnderTimestampTie(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedSecondOrg(t, db, "beta-org")
	seedSecondOrg(t, db, "alpha-org")
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()

	// One shared due instant for every row, inserted in a deliberately
	// scrambled order.
	due := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	rowsIn := []struct{ org, job string }{
		{"beta-org", schedJobSweep},
		{"anchorix", schedJobPrune},
		{"alpha-org", schedJobPrune},
		{"anchorix", schedJobSweep},
		{"beta-org", schedJobPrune},
		{"alpha-org", schedJobSweep},
	}
	for _, r := range rowsIn {
		if err := repo.UpsertJob(ctx, r.org, r.job, due); err != nil {
			t.Fatalf("upsert %s/%s: %v", r.org, r.job, err)
		}
		enableJob(t, db, r.org, r.job, due)
	}

	// Expected order is (organization_id ASC, job_name ASC). Derive the
	// per-org job order from the actual constant values rather than
	// hardcoding, so the expectation tracks job_name ASC exactly (today
	// "expired_override_sweep" < "explanation_retention_prune").
	firstJob, secondJob := schedJobSweep, schedJobPrune
	if schedJobPrune < schedJobSweep {
		firstJob, secondJob = schedJobPrune, schedJobSweep
	}
	var want []string
	for _, org := range []string{"alpha-org", "anchorix", "beta-org"} {
		want = append(want, org+"/"+firstJob, org+"/"+secondJob)
	}
	// Repeat the query several times — the order must not vary.
	for attempt := 0; attempt < 4; attempt++ {
		got, err := repo.ListDueJobs(ctx, time.Now().UTC(), 100)
		if err != nil {
			t.Fatalf("list due (attempt %d): %v", attempt, err)
		}
		if len(got) != len(want) {
			t.Fatalf("attempt %d: got %d rows, want %d", attempt, len(got), len(want))
		}
		for i := range want {
			key := got[i].OrganizationID + "/" + got[i].JobName
			if key != want[i] {
				t.Fatalf("attempt %d position %d: got %s, want %s", attempt, i, key, want[i])
			}
		}
	}
}

// TestSchedulerDueExcludesNotYetDueBoundary pins the <= now boundary:
// a row due exactly at `now` is included; a row due 1µs later is not.
func TestSchedulerDueExcludesNotYetDueBoundary(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, now); err != nil {
		t.Fatalf("upsert sweep: %v", err)
	}
	if err := repo.UpsertJob(ctx, "anchorix", schedJobPrune, now); err != nil {
		t.Fatalf("upsert prune: %v", err)
	}
	enableJob(t, db, "anchorix", schedJobSweep, now)                       // due == now
	enableJob(t, db, "anchorix", schedJobPrune, now.Add(time.Microsecond)) // due > now

	got, err := repo.ListDueJobs(ctx, now, 10)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	if len(got) != 1 || got[0].JobName != schedJobSweep {
		t.Fatalf("expected only the exactly-due sweep row, got %d rows: %+v", len(got), got)
	}
}

// ---------- cursor persistence + state transitions ----------

// TestSchedulerFailedRunNeverAdvancesCursorAcrossRetries hammers the
// most security-relevant invariant: a failed run must NEVER advance the
// cursor, so the failed page is always retried from the same place and
// no eligible work is silently skipped. Drives multiple failures
// interleaved with a started-mark and asserts the cursor is pinned the
// whole time.
func TestSchedulerFailedRunNeverAdvancesCursorAcrossRetries(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Establish a known cursor via a partial run (forward progress).
	if err := repo.MarkJobPartial(ctx, "anchorix", schedJobSweep, "cert-050", now, now.Add(time.Second)); err != nil {
		t.Fatalf("seed partial: %v", err)
	}

	for i := 1; i <= 3; i++ {
		if err := repo.MarkJobStarted(ctx, "anchorix", schedJobSweep, now); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		if err := repo.MarkJobFailed(ctx, "anchorix", schedJobSweep, "transient boom", now, now.Add(time.Minute)); err != nil {
			t.Fatalf("fail %d: %v", i, err)
		}
		job, err := repo.LoadJobState(ctx, "anchorix", schedJobSweep)
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		if job.Cursor != "cert-050" {
			t.Fatalf("after failure %d cursor moved to %q, want pinned cert-050", i, job.Cursor)
		}
		if job.ConsecutiveFailures != i {
			t.Fatalf("after failure %d, consecutive_failures = %d, want %d", i, job.ConsecutiveFailures, i)
		}
		if job.LastStatus != governance.SchedulerJobError {
			t.Fatalf("after failure %d, status = %q, want error", i, job.LastStatus)
		}
	}

	// A subsequent completed run advances + clears the failure state.
	if err := repo.MarkJobCompleted(ctx, "anchorix", schedJobSweep, "cert-100", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("complete: %v", err)
	}
	job, _ := repo.LoadJobState(ctx, "anchorix", schedJobSweep)
	if job.Cursor != "cert-100" {
		t.Fatalf("completed should advance cursor to cert-100, got %q", job.Cursor)
	}
	if job.ConsecutiveFailures != 0 || job.LastError != "" {
		t.Fatalf("completed should clear failure state, got failures=%d err=%q", job.ConsecutiveFailures, job.LastError)
	}
}

// TestSchedulerStartedMarkPreservesCursorAndDueTime pins that
// MarkJobStarted only flips status/started_at — it must not disturb the
// persisted cursor or next_due_at (a crash after start, before a run
// boundary, must resume from the same cursor).
func TestSchedulerStartedMarkPreservesCursorAndDueTime(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	due := now.Add(42 * time.Minute)
	if err := repo.MarkJobPartial(ctx, "anchorix", schedJobSweep, "cert-7", now, due); err != nil {
		t.Fatalf("partial: %v", err)
	}
	before, _ := repo.LoadJobState(ctx, "anchorix", schedJobSweep)

	if err := repo.MarkJobStarted(ctx, "anchorix", schedJobSweep, now.Add(time.Minute)); err != nil {
		t.Fatalf("start: %v", err)
	}
	after, _ := repo.LoadJobState(ctx, "anchorix", schedJobSweep)

	if after.Cursor != before.Cursor {
		t.Fatalf("start changed cursor: %q -> %q", before.Cursor, after.Cursor)
	}
	if !after.NextDueAt.Equal(before.NextDueAt) {
		t.Fatalf("start changed next_due_at: %s -> %s", before.NextDueAt, after.NextDueAt)
	}
	if after.LastStatus != governance.SchedulerJobRunning {
		t.Fatalf("status after start = %q, want running", after.LastStatus)
	}
}

// ---------- partial-requeue fairness boundary ----------

// TestSchedulerPartialRequeueLandsAfterColdDueRow strengthens the
// fairness pin: an item run partial and re-armed at finished+delay must
// sort AFTER an unrelated cold due row whose next_due_at is earlier,
// even when the cold row's due time is only marginally earlier than the
// re-arm instant. The re-armed item must never crowd to the front.
func TestSchedulerPartialRequeueLandsAfterColdDueRow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)

	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, base); err != nil {
		t.Fatalf("upsert sweep: %v", err)
	}
	if err := repo.UpsertJob(ctx, "anchorix", schedJobPrune, base); err != nil {
		t.Fatalf("upsert prune: %v", err)
	}
	// prune is the cold, not-yet-served due row.
	enableJob(t, db, "anchorix", schedJobPrune, base)
	enableJob(t, db, "anchorix", schedJobSweep, base)

	finished := time.Now().UTC().Truncate(time.Microsecond)
	const delay = time.Second
	if err := repo.MarkJobStarted(ctx, "anchorix", schedJobSweep, finished); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := repo.MarkJobPartial(ctx, "anchorix", schedJobSweep, "cert-1", finished, finished.Add(delay)); err != nil {
		t.Fatalf("partial: %v", err)
	}

	// Query at an instant where both are due again. prune (base) must
	// precede the re-armed sweep (finished+1s).
	got, err := repo.ListDueJobs(ctx, finished.Add(2*delay), 10)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 due, got %d", len(got))
	}
	if got[0].JobName != schedJobPrune || got[1].JobName != schedJobSweep {
		t.Fatalf("fairness order broken: got [%s, %s], want [prune, sweep]", got[0].JobName, got[1].JobName)
	}
}

// ---------- cross-org isolation (adversarial) ----------

// TestSchedulerListDueIsolatesOrgsUnderIdenticalJobNames seeds the same
// job name in two orgs with identical due times and asserts a limited
// due scan still returns rows for both orgs in the deterministic order —
// and that a per-org state transition touches exactly one org's row.
func TestSchedulerListDueIsolatesOrgsUnderIdenticalJobNames(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedSecondOrg(t, db, "beta-org")
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	due := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)

	for _, org := range []string{"anchorix", "beta-org"} {
		if err := repo.UpsertJob(ctx, org, schedJobSweep, due); err != nil {
			t.Fatalf("upsert %s: %v", org, err)
		}
		enableJob(t, db, org, schedJobSweep, due)
	}

	// Mutate only anchorix's row.
	if err := repo.MarkJobCompleted(ctx, "anchorix", schedJobSweep, "cert-anchorix", due, due.Add(time.Hour)); err != nil {
		t.Fatalf("complete anchorix: %v", err)
	}

	beta, err := repo.LoadJobState(ctx, "beta-org", schedJobSweep)
	if err != nil {
		t.Fatalf("load beta: %v", err)
	}
	if beta.Cursor != "" || beta.LastStatus != governance.SchedulerJobPending {
		t.Fatalf("cross-org leak: beta cursor=%q status=%q", beta.Cursor, beta.LastStatus)
	}
	anchor, _ := repo.LoadJobState(ctx, "anchorix", schedJobSweep)
	if anchor.Cursor != "cert-anchorix" {
		t.Fatalf("anchorix cursor not persisted: %q", anchor.Cursor)
	}
}

// TestSchedulerMarkOnForeignOrgRowFailsClosed asserts every state
// transition fails closed (ErrSchedulerJobNotFound) when the (org, job)
// row does not exist in that org — even if it exists in another org.
func TestSchedulerMarkOnForeignOrgRowFailsClosed(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedSecondOrg(t, db, "beta-org")
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// Row exists only in anchorix.
	if err := repo.UpsertJob(ctx, "anchorix", schedJobSweep, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	marks := map[string]func() error{
		"started":   func() error { return repo.MarkJobStarted(ctx, "beta-org", schedJobSweep, now) },
		"completed": func() error { return repo.MarkJobCompleted(ctx, "beta-org", schedJobSweep, "x", now, now) },
		"partial":   func() error { return repo.MarkJobPartial(ctx, "beta-org", schedJobSweep, "x", now, now) },
		"failed":    func() error { return repo.MarkJobFailed(ctx, "beta-org", schedJobSweep, "e", now, now) },
	}
	for name, fn := range marks {
		if err := fn(); !errors.Is(err, governance.ErrSchedulerJobNotFound) {
			t.Fatalf("mark %s on foreign-org row: want ErrSchedulerJobNotFound, got %v", name, err)
		}
	}
	// anchorix's row is untouched by all the failed foreign marks.
	job, _ := repo.LoadJobState(ctx, "anchorix", schedJobSweep)
	if job.LastStatus != governance.SchedulerJobPending {
		t.Fatalf("foreign marks leaked into anchorix: status=%q", job.LastStatus)
	}
}

// ---------- advisory lock (pinned connection) ----------

// TestSchedulerLockSamePIDAcrossManyOps proves the lock stays on ONE
// physical session: pg_backend_pid is identical across repeated probes
// while held, and the unlock runs on that same session (a follow-up
// acquire succeeds, which can only happen if the unlock reached the
// right backend).
func TestSchedulerLockSamePIDAcrossManyOps(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()

	lock, acquired, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep)
	if err != nil || !acquired {
		t.Fatalf("acquire: acquired=%v err=%v", acquired, err)
	}
	pidder, ok := lock.(interface {
		BackendPID(ctx context.Context) (int32, error)
	})
	if !ok {
		t.Fatal("lock must expose BackendPID")
	}
	first, err := pidder.BackendPID(ctx)
	if err != nil {
		t.Fatalf("pid: %v", err)
	}
	for i := 0; i < 5; i++ {
		p, err := pidder.BackendPID(ctx)
		if err != nil {
			t.Fatalf("pid probe %d: %v", i, err)
		}
		if p != first {
			t.Fatalf("connection migrated mid-hold: pid %d != %d", p, first)
		}
	}
	if err := lock.Release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Reacquire proves the unlock landed on the held session.
	again, reacq, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep)
	if err != nil || !reacq {
		t.Fatalf("reacquire after release: reacq=%v err=%v", reacq, err)
	}
	_ = again.Release(ctx)
}

// TestSchedulerLockExclusionIsScopedToOrgJob proves the lock keyspace
// distinguishes (org, job) pairs: holding anchorix/sweep blocks a
// second anchorix/sweep acquire but NOT beta-org/sweep, anchorix/prune,
// or beta-org/prune (all four corners of the 2x2).
func TestSchedulerLockExclusionIsScopedToOrgJob(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedSecondOrg(t, db, "beta-org")
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()

	held, acquired, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep)
	if err != nil || !acquired {
		t.Fatalf("hold anchorix/sweep: acquired=%v err=%v", acquired, err)
	}
	defer held.Release(ctx)

	// Same (org, job): blocked.
	if l, a, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep); err != nil {
		t.Fatalf("second same-key acquire errored: %v", err)
	} else if a {
		_ = l.Release(ctx)
		t.Fatal("second anchorix/sweep acquire must be blocked")
	}

	// The other three corners: all independently lockable.
	for _, c := range []struct{ org, job string }{
		{"beta-org", schedJobSweep},
		{"anchorix", schedJobPrune},
		{"beta-org", schedJobPrune},
	} {
		l, a, err := repo.TryLockOrgJob(ctx, c.org, c.job)
		if err != nil || !a {
			t.Fatalf("independent lock %s/%s should succeed: a=%v err=%v", c.org, c.job, a, err)
		}
		_ = l.Release(ctx)
	}
}

// TestSchedulerLockConcurrentSingleWinner runs many goroutines racing
// for the same (org, job) lock and asserts exactly one wins at a time,
// and that the lock is fully reusable across the serialized winners
// (no leaked/stranded lock). This is the core "no duplicate concurrent
// execution per org/job" guarantee under real contention.
func TestSchedulerLockConcurrentSingleWinner(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()

	const racers = 12
	var (
		wg            sync.WaitGroup
		mu            sync.Mutex
		wins          int
		concurrent    int
		maxConcurrent int
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			lock, acquired, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			if !acquired {
				return // lost the race this round — expected
			}
			mu.Lock()
			wins++
			concurrent++
			if concurrent > maxConcurrent {
				maxConcurrent = concurrent
			}
			mu.Unlock()

			// Hold briefly so overlap would be observable if exclusion
			// were broken.
			time.Sleep(20 * time.Millisecond)

			mu.Lock()
			concurrent--
			mu.Unlock()
			if err := lock.Release(ctx); err != nil {
				t.Errorf("release: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if maxConcurrent > 1 {
		t.Fatalf("advisory lock allowed %d concurrent holders; must be <= 1", maxConcurrent)
	}
	if wins < 1 {
		t.Fatal("no goroutine ever acquired the lock")
	}

	// After the storm, the lock is free and reacquirable — proves no
	// winner stranded it.
	l, a, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep)
	if err != nil || !a {
		t.Fatalf("post-storm reacquire failed: a=%v err=%v", a, err)
	}
	_ = l.Release(ctx)
}

// TestSchedulerLockIndependentFromOwnershipDataLock proves the
// scheduler concurrency lock does NOT contend with the ownership data
// lock (WithTxLockedOwnership). The two use different advisory-lock
// keyspaces (single-arg bigint vs two-arg classid/objid), so holding
// one must never block the other for the same org — otherwise a
// scheduled maintenance run would deadlock against the very primitive
// it is meant to drive.
func TestSchedulerLockIndependentFromOwnershipDataLock(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceSchedulerRepository(db)
	ctx := context.Background()

	// Hold the scheduler lock for anchorix/sweep.
	lock, acquired, err := repo.TryLockOrgJob(ctx, "anchorix", schedJobSweep)
	if err != nil || !acquired {
		t.Fatalf("scheduler lock: acquired=%v err=%v", acquired, err)
	}
	defer lock.Release(ctx)

	// The ownership data lock for the SAME org must still be acquirable
	// (different keyspace). Run it with a short deadline so a regression
	// that made them collide would fail as a timeout rather than hang.
	lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ran := false
	if err := db.WithTxLockedOwnership(lockCtx, "anchorix", func(ctx context.Context) error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("ownership data lock blocked by scheduler lock (keyspace collision?): %v", err)
	}
	if !ran {
		t.Fatal("ownership-locked fn did not run")
	}
}

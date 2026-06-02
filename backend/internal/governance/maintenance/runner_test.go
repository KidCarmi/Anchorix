package maintenance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// ---- test doubles ----

// fakeClock is a controllable monotonic-ish clock. Now advances by a
// fixed step on each read so the per-run deadline check is observable
// without real sleeps, and so successive timestamps differ.
type fakeClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func newFakeClock(start time.Time, step time.Duration) *fakeClock {
	return &fakeClock{t: start, step: step}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := c.t
	c.t = c.t.Add(c.step)
	return cur
}

// recordingState is an in-memory SchedulerStateRepository that records
// every Mark* call so tests can assert the exact terminal transition,
// the persisted cursor, and the computed next-due time. It also enforces
// the PR-1 semantic that MarkJobFailed never touches the cursor.
type recordingState struct {
	mu sync.Mutex

	// the single row under test
	cursor       string
	failures     int
	lastStatus   governance.SchedulerJobStatus
	lastNextDue  time.Time
	lastError    string
	startedCalls int

	// call log for ordering assertions
	calls []string
}

func newRecordingState(initialCursor string, failures int) *recordingState {
	return &recordingState{cursor: initialCursor, failures: failures, lastStatus: governance.SchedulerJobPending}
}

func (s *recordingState) UpsertJob(ctx context.Context, org, job string, due time.Time) error {
	return nil
}
func (s *recordingState) LoadJobState(ctx context.Context, org, job string) (*governance.SchedulerJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &governance.SchedulerJob{
		OrganizationID:      org,
		JobName:             job,
		Cursor:              s.cursor,
		ConsecutiveFailures: s.failures,
		LastStatus:          s.lastStatus,
	}, nil
}
func (s *recordingState) ListDueJobs(ctx context.Context, now time.Time, limit int) ([]governance.SchedulerJob, error) {
	return nil, nil
}
func (s *recordingState) MarkJobStarted(ctx context.Context, org, job string, startedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startedCalls++
	s.lastStatus = governance.SchedulerJobRunning
	s.calls = append(s.calls, "started")
	return nil
}
func (s *recordingState) MarkJobCompleted(ctx context.Context, org, job, cursor string, finishedAt, nextDueAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursor = cursor
	s.failures = 0
	s.lastError = ""
	s.lastStatus = governance.SchedulerJobCompleted
	s.lastNextDue = nextDueAt
	s.calls = append(s.calls, "completed")
	return nil
}
func (s *recordingState) MarkJobPartial(ctx context.Context, org, job, cursor string, finishedAt, nextDueAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursor = cursor
	s.failures = 0
	s.lastError = ""
	s.lastStatus = governance.SchedulerJobPartial
	s.lastNextDue = nextDueAt
	s.calls = append(s.calls, "partial")
	return nil
}
func (s *recordingState) MarkJobFailed(ctx context.Context, org, job, redactedErr string, finishedAt, nextDueAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// PR-1 semantic: failed runs do NOT advance the cursor.
	s.failures++
	s.lastError = redactedErr
	s.lastStatus = governance.SchedulerJobError
	s.lastNextDue = nextDueAt
	s.calls = append(s.calls, "failed")
	return nil
}

// fakeLock records release calls.
type fakeLock struct {
	mu       sync.Mutex
	released int
}

func (l *fakeLock) Release(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.released++
	return nil
}
func (l *fakeLock) releaseCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.released
}

// fakeLocker hands out a lock unless `held` is set (simulating
// contention) or `err` is set (simulating infra failure). It records
// whether TryLockOrgJob ran before the job executed.
type fakeLocker struct {
	held bool
	err  error
	lock *fakeLock

	mu        sync.Mutex
	tryCalls  int
	lockedNow bool // true while a lock is outstanding
}

func (l *fakeLocker) TryLockOrgJob(ctx context.Context, org, job string) (governance.SchedulerJobLock, bool, error) {
	l.mu.Lock()
	l.tryCalls++
	l.mu.Unlock()
	if l.err != nil {
		return nil, false, l.err
	}
	if l.held {
		return nil, false, nil
	}
	if l.lock == nil {
		l.lock = &fakeLock{}
	}
	l.mu.Lock()
	l.lockedNow = true
	l.mu.Unlock()
	return l.lock, true, nil
}

// scriptedJob returns a queued sequence of page results/errors and
// records the order of RunPage vs lock acquisition via a shared probe.
type scriptedJob struct {
	name    string
	results []pageStep
	mu      sync.Mutex
	calls   int
	cursors []string // cursor seen at each RunPage call
	probe   func()   // optional: called at the start of each RunPage
}

type pageStep struct {
	res PageResult
	err error
}

func (j *scriptedJob) Name() string { return j.name }
func (j *scriptedJob) RunPage(ctx context.Context, org, cursor string, limits PageLimits) (PageResult, error) {
	if j.probe != nil {
		j.probe()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cursors = append(j.cursors, cursor)
	i := j.calls
	j.calls++
	if i >= len(j.results) {
		// Default: keep returning "more work" so a max-pages bound is hit.
		return PageResult{NextCursor: fmt.Sprintf("auto-%d", i), Done: false}, nil
	}
	return j.results[i].res, j.results[i].err
}

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	return logger.New("error", config.EnvDevelopment)
}

func testRunnerConfig() RunnerConfig {
	return RunnerConfig{
		MaxPagesPerRun:      3,
		MaxRunDuration:      time.Hour, // large; duration test overrides
		PageSize:            100,
		PartialRequeueDelay: time.Second,
		JobInterval:         time.Hour,
		RetryBase:           time.Minute,
		RetryMax:            time.Hour,
	}
}

func newTestRunner(t *testing.T, job Job, state governance.SchedulerStateRepository, locker governance.SchedulerJobLocker, clk *fakeClock, cfg RunnerConfig) *JobRunner {
	t.Helper()
	reg, err := NewJobRegistry(job)
	if err != nil {
		t.Fatalf("NewJobRegistry: %v", err)
	}
	r, err := NewJobRunner(reg, state, locker, clk, testLogger(t), cfg)
	if err != nil {
		t.Fatalf("NewJobRunner: %v", err)
	}
	return r
}

func dueState(org, job, cursor string, failures int) governance.SchedulerJob {
	return governance.SchedulerJob{OrganizationID: org, JobName: job, Cursor: cursor, ConsecutiveFailures: failures}
}

// ---- registry tests ----

func TestRegistryRejectsDuplicateNames(t *testing.T) {
	_, err := NewJobRegistry(&scriptedJob{name: "dup"}, &scriptedJob{name: "dup"})
	if err == nil {
		t.Fatal("expected duplicate-name rejection")
	}
}

func TestRegistryRejectsEmptyAndNil(t *testing.T) {
	if _, err := NewJobRegistry(&scriptedJob{name: ""}); err == nil {
		t.Fatal("expected empty-name rejection")
	}
	if _, err := NewJobRegistry(nil); err == nil {
		t.Fatal("expected nil-job rejection")
	}
}

func TestRegistryLookupUnknownFailsClosed(t *testing.T) {
	reg, err := NewJobRegistry(&scriptedJob{name: "known"})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, err := reg.Lookup("missing"); !errors.Is(err, ErrUnknownJob) {
		t.Fatalf("want ErrUnknownJob, got %v", err)
	}
	if _, err := reg.Lookup("known"); err != nil {
		t.Fatalf("known lookup failed: %v", err)
	}
}

func TestRegistryNamesDeterministic(t *testing.T) {
	reg, _ := NewJobRegistry(&scriptedJob{name: "zeta"}, &scriptedJob{name: "alpha"}, &scriptedJob{name: "mu"})
	got := reg.Names()
	want := []string{"alpha", "mu", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names not sorted: got %v want %v", got, want)
		}
	}
}

// ---- runner: lock behavior ----

// TestRunnerAcquiresLockBeforeJobExecution proves TryLockOrgJob runs and
// succeeds before any RunPage call. The probe records lock state at the
// moment the job first executes.
func TestRunnerAcquiresLockBeforeJobExecution(t *testing.T) {
	locker := &fakeLocker{}
	job := &scriptedJob{name: "j", results: []pageStep{{res: PageResult{Done: true}}}}
	lockedWhenJobRan := false
	job.probe = func() {
		locker.mu.Lock()
		lockedWhenJobRan = locker.lockedNow
		locker.mu.Unlock()
	}
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Now(), time.Millisecond), testRunnerConfig())

	rep, err := r.RunDueJob(context.Background(), dueState("anchorix", "j", "c0", 0))
	if err != nil {
		t.Fatalf("RunDueJob: %v", err)
	}
	if rep.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %s, want completed", rep.Outcome)
	}
	if locker.tryCalls != 1 {
		t.Fatalf("TryLockOrgJob calls = %d, want 1", locker.tryCalls)
	}
	if !lockedWhenJobRan {
		t.Fatal("job executed before lock was held")
	}
	if job.calls != 1 {
		t.Fatalf("RunPage calls = %d, want 1", job.calls)
	}
}

// TestRunnerSkipsWhenLockHeld proves contention skips without executing
// the job and without any state transition.
func TestRunnerSkipsWhenLockHeld(t *testing.T) {
	locker := &fakeLocker{held: true}
	job := &scriptedJob{name: "j", results: []pageStep{{res: PageResult{Done: true}}}}
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Now(), time.Millisecond), testRunnerConfig())

	rep, err := r.RunDueJob(context.Background(), dueState("anchorix", "j", "c0", 0))
	if err != nil {
		t.Fatalf("RunDueJob: %v", err)
	}
	if rep.Outcome != OutcomeSkippedLocked {
		t.Fatalf("outcome = %s, want skipped_locked", rep.Outcome)
	}
	if job.calls != 0 {
		t.Fatal("job must NOT execute when the lock is held")
	}
	if len(state.calls) != 0 {
		t.Fatalf("no state transition expected on skip, got %v", state.calls)
	}
}

func TestRunnerLockErrorFailsClosed(t *testing.T) {
	locker := &fakeLocker{err: errors.New("pool exhausted")}
	job := &scriptedJob{name: "j"}
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Now(), time.Millisecond), testRunnerConfig())

	_, err := r.RunDueJob(context.Background(), dueState("anchorix", "j", "c0", 0))
	if err == nil {
		t.Fatal("expected lock-acquisition error to surface")
	}
	if job.calls != 0 {
		t.Fatal("job must not run when lock acquisition errors")
	}
}

// TestRunnerReleasesLockOnAllPaths covers success, failure, and a panic
// in RunPage (the deferred release must still fire).
func TestRunnerReleasesLockOnAllPaths(t *testing.T) {
	clk := newFakeClock(time.Now(), time.Millisecond)

	t.Run("success", func(t *testing.T) {
		locker := &fakeLocker{}
		job := &scriptedJob{name: "j", results: []pageStep{{res: PageResult{Done: true}}}}
		state := newRecordingState("c0", 0)
		r := newTestRunner(t, job, state, locker, clk, testRunnerConfig())
		if _, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0)); err != nil {
			t.Fatalf("run: %v", err)
		}
		if locker.lock.releaseCount() != 1 {
			t.Fatalf("release count = %d, want 1", locker.lock.releaseCount())
		}
	})

	t.Run("failure", func(t *testing.T) {
		locker := &fakeLocker{}
		job := &scriptedJob{name: "j", results: []pageStep{{err: errors.New("boom")}}}
		state := newRecordingState("c0", 0)
		r := newTestRunner(t, job, state, locker, clk, testRunnerConfig())
		if _, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0)); err != nil {
			t.Fatalf("run: %v", err)
		}
		if locker.lock.releaseCount() != 1 {
			t.Fatalf("release count = %d, want 1", locker.lock.releaseCount())
		}
	})

	t.Run("panic", func(t *testing.T) {
		locker := &fakeLocker{}
		job := &panicJob{name: "j"}
		state := newRecordingState("c0", 0)
		r := newTestRunner(t, job, state, locker, clk, testRunnerConfig())
		func() {
			defer func() {
				_ = recover() // the runner does not swallow the panic; we just confirm release ran
			}()
			_, _ = r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0))
		}()
		if locker.lock.releaseCount() != 1 {
			t.Fatalf("release count after panic = %d, want 1 (deferred release must fire)", locker.lock.releaseCount())
		}
	})
}

type panicJob struct{ name string }

func (j *panicJob) Name() string { return j.name }
func (j *panicJob) RunPage(ctx context.Context, org, cursor string, limits PageLimits) (PageResult, error) {
	panic("job blew up")
}

// ---- runner: outcomes & cursor semantics ----

func TestRunnerDoneMarksCompletedAndResetsCursor(t *testing.T) {
	locker := &fakeLocker{}
	job := &scriptedJob{name: "j", results: []pageStep{{res: PageResult{NextCursor: "c-final", Done: true}}}}
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Now(), time.Millisecond), testRunnerConfig())

	rep, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %s, want completed", rep.Outcome)
	}
	// On completion the next cycle restarts from the start sentinel.
	if state.cursor != governance.SchedulerCursorStart {
		t.Fatalf("completed cursor = %q, want start sentinel", state.cursor)
	}
	if state.lastStatus != governance.SchedulerJobCompleted {
		t.Fatalf("status = %s", state.lastStatus)
	}
}

func TestRunnerNotDoneMarksPartialAndPersistsNextCursor(t *testing.T) {
	locker := &fakeLocker{}
	// One page, not done, then the page budget (1) is hit -> partial.
	cfg := testRunnerConfig()
	cfg.MaxPagesPerRun = 1
	job := &scriptedJob{name: "j", results: []pageStep{{res: PageResult{NextCursor: "c-1", Done: false}}}}
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Now(), time.Millisecond), cfg)

	rep, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Outcome != OutcomePartial {
		t.Fatalf("outcome = %s, want partial", rep.Outcome)
	}
	if state.cursor != "c-1" {
		t.Fatalf("partial cursor = %q, want c-1 (advanced past the committed page)", state.cursor)
	}
	if state.lastStatus != governance.SchedulerJobPartial {
		t.Fatalf("status = %s", state.lastStatus)
	}
}

func TestRunnerPageErrorMarksFailedAndDoesNotAdvanceCursor(t *testing.T) {
	locker := &fakeLocker{}
	job := &scriptedJob{name: "j", results: []pageStep{{err: errors.New("page boom")}}}
	state := newRecordingState("c-start", 2)
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Now(), time.Millisecond), testRunnerConfig())

	rep, err := r.RunDueJob(context.Background(), dueState("o", "j", "c-start", 2))
	if err != nil {
		t.Fatalf("run returned infra error: %v", err)
	}
	if rep.Outcome != OutcomeError {
		t.Fatalf("outcome = %s, want error", rep.Outcome)
	}
	if state.cursor != "c-start" {
		t.Fatalf("failed run advanced cursor to %q; must stay c-start", state.cursor)
	}
	if state.failures != 3 {
		t.Fatalf("consecutive_failures = %d, want 3", state.failures)
	}
	if state.lastError == "" {
		t.Fatal("failed run should record a redacted error summary")
	}
}

// TestRunnerCursorAdvancesOnlyAfterSuccessfulPage runs two good pages
// then a failing third: the persisted cursor reflects the last
// successful page, not the failing one.
func TestRunnerCursorAdvancesOnlyAfterSuccessfulPage(t *testing.T) {
	locker := &fakeLocker{}
	cfg := testRunnerConfig()
	cfg.MaxPagesPerRun = 10
	job := &scriptedJob{name: "j", results: []pageStep{
		{res: PageResult{NextCursor: "c-1", Done: false}},
		{res: PageResult{NextCursor: "c-2", Done: false}},
		{err: errors.New("boom on third")},
	}}
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Now(), time.Millisecond), cfg)

	rep, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Outcome != OutcomeError {
		t.Fatalf("outcome = %s, want error", rep.Outcome)
	}
	// MarkJobFailed does not persist a cursor; the last committed cursor
	// is whatever the prior successful boundary would have written. Since
	// this run failed before any terminal success-mark, the row's cursor
	// is unchanged from its starting value (c0) — the failing page is
	// retried from the last durable point.
	if state.cursor != "c0" {
		t.Fatalf("cursor = %q; a failed run must not persist an advanced cursor", state.cursor)
	}
	if rep.PagesRun != 2 {
		t.Fatalf("pages run = %d, want 2 successful pages before the failure", rep.PagesRun)
	}
}

// ---- runner: bounds ----

func TestRunnerMaxPagesEnforced(t *testing.T) {
	locker := &fakeLocker{}
	cfg := testRunnerConfig()
	cfg.MaxPagesPerRun = 3
	// Job never returns Done -> the page budget bounds the run.
	job := &scriptedJob{name: "j"} // default: always more work
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Now(), time.Millisecond), cfg)

	rep, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Outcome != OutcomePartial {
		t.Fatalf("outcome = %s, want partial", rep.Outcome)
	}
	if rep.PagesRun != 3 {
		t.Fatalf("pages run = %d, want exactly MaxPagesPerRun=3", rep.PagesRun)
	}
	if job.calls != 3 {
		t.Fatalf("RunPage calls = %d, want 3", job.calls)
	}
}

// TestRunnerMaxDurationEnforced uses a clock whose step exceeds the run
// budget so the deadline is crossed after the first page.
func TestRunnerMaxDurationEnforced(t *testing.T) {
	locker := &fakeLocker{}
	cfg := testRunnerConfig()
	cfg.MaxPagesPerRun = 1000 // not the binding cap here
	cfg.MaxRunDuration = 10 * time.Millisecond
	// Each Now() advances 1h, so the deadline (start+10ms) is already
	// passed by the time the loop re-checks after the first page.
	clk := newFakeClock(time.Unix(0, 0).UTC(), time.Hour)
	job := &scriptedJob{name: "j"} // always more work
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, clk, cfg)

	rep, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Outcome != OutcomePartial {
		t.Fatalf("outcome = %s, want partial (duration bound)", rep.Outcome)
	}
	if rep.PagesRun > 2 {
		t.Fatalf("duration bound not enforced promptly: pages run = %d", rep.PagesRun)
	}
}

// ---- runner: re-arm timing ----

func TestRunnerPartialRequeueDelayApplied(t *testing.T) {
	locker := &fakeLocker{}
	cfg := testRunnerConfig()
	cfg.MaxPagesPerRun = 1
	cfg.PartialRequeueDelay = 7 * time.Second
	// Fixed clock (step 0) so finishedAt is deterministic.
	start := time.Unix(1000, 0).UTC()
	clk := newFakeClock(start, 0)
	job := &scriptedJob{name: "j", results: []pageStep{{res: PageResult{NextCursor: "c-1"}}}}
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, clk, cfg)

	if _, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0)); err != nil {
		t.Fatalf("run: %v", err)
	}
	wantDue := start.Add(7 * time.Second)
	if !state.lastNextDue.Equal(wantDue) {
		t.Fatalf("partial next_due = %s, want %s (finishedAt + delay)", state.lastNextDue, wantDue)
	}
	if !state.lastNextDue.After(start) {
		t.Fatal("partial requeue delay must be strictly positive")
	}
}

func TestRunnerFailureBackoffApplied(t *testing.T) {
	locker := &fakeLocker{}
	cfg := testRunnerConfig()
	cfg.RetryBase = time.Minute
	cfg.RetryMax = time.Hour
	start := time.Unix(2000, 0).UTC()
	clk := newFakeClock(start, 0)
	job := &scriptedJob{name: "j", results: []pageStep{{err: errors.New("boom")}}}

	// priorFailures=0 -> this is failure #1 -> backoff = base * 2^0 = 1m.
	state := newRecordingState("c0", 0)
	r := newTestRunner(t, job, state, locker, clk, cfg)
	if _, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0)); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got, want := state.lastNextDue, start.Add(time.Minute); !got.Equal(want) {
		t.Fatalf("backoff #1 next_due = %s, want %s", got, want)
	}

	// priorFailures=3 -> failure #4 -> base * 2^3 = 8m.
	state2 := newRecordingState("c0", 3)
	job2 := &scriptedJob{name: "j", results: []pageStep{{err: errors.New("boom")}}}
	r2 := newTestRunner(t, job2, state2, locker, newFakeClock(start, 0), cfg)
	if _, err := r2.RunDueJob(context.Background(), dueState("o", "j", "c0", 3)); err != nil {
		t.Fatalf("run2: %v", err)
	}
	if got, want := state2.lastNextDue, start.Add(8*time.Minute); !got.Equal(want) {
		t.Fatalf("backoff #4 next_due = %s, want %s", got, want)
	}
}

func TestRunnerBackoffCapsAtRetryMax(t *testing.T) {
	r := &JobRunner{cfg: RunnerConfig{RetryBase: time.Minute, RetryMax: 10 * time.Minute}}
	// 2^large would explode; must cap at RetryMax.
	if got := r.backoffFor(50); got != 10*time.Minute {
		t.Fatalf("backoff cap = %s, want 10m", got)
	}
	if got := r.backoffFor(1); got != time.Minute {
		t.Fatalf("backoff #1 = %s, want 1m", got)
	}
}

// ---- runner: construction guards ----

func TestNewJobRunnerRejectsBadConfig(t *testing.T) {
	reg, _ := NewJobRegistry(&scriptedJob{name: "j"})
	state := newRecordingState("c0", 0)
	locker := &fakeLocker{}
	clk := newFakeClock(time.Now(), time.Millisecond)
	log := testLogger(t)

	bad := []RunnerConfig{
		{MaxPagesPerRun: 0, MaxRunDuration: time.Second, PageSize: 1, PartialRequeueDelay: time.Second, JobInterval: time.Hour, RetryBase: time.Minute, RetryMax: time.Hour},
		{MaxPagesPerRun: 1, MaxRunDuration: 0, PageSize: 1, PartialRequeueDelay: time.Second, JobInterval: time.Hour, RetryBase: time.Minute, RetryMax: time.Hour},
		{MaxPagesPerRun: 1, MaxRunDuration: time.Second, PageSize: 1, PartialRequeueDelay: 0, JobInterval: time.Hour, RetryBase: time.Minute, RetryMax: time.Hour},
		{MaxPagesPerRun: 1, MaxRunDuration: time.Second, PageSize: 1, PartialRequeueDelay: time.Second, JobInterval: time.Hour, RetryBase: time.Minute, RetryMax: time.Second},
	}
	for i, cfg := range bad {
		if _, err := NewJobRunner(reg, state, locker, clk, log, cfg); err == nil {
			t.Fatalf("bad config %d should fail closed", i)
		}
	}
}

func TestNewJobRunnerRejectsNilDeps(t *testing.T) {
	reg, _ := NewJobRegistry(&scriptedJob{name: "j"})
	state := newRecordingState("c0", 0)
	locker := &fakeLocker{}
	clk := newFakeClock(time.Now(), time.Millisecond)
	log := testLogger(t)
	cfg := testRunnerConfig()

	if _, err := NewJobRunner(nil, state, locker, clk, log, cfg); err == nil {
		t.Fatal("nil registry must fail")
	}
	if _, err := NewJobRunner(reg, nil, locker, clk, log, cfg); err == nil {
		t.Fatal("nil state must fail")
	}
	if _, err := NewJobRunner(reg, state, nil, clk, log, cfg); err == nil {
		t.Fatal("nil locker must fail")
	}
	if _, err := NewJobRunner(reg, state, locker, nil, log, cfg); err == nil {
		t.Fatal("nil clock must fail")
	}
	if _, err := NewJobRunner(reg, state, locker, clk, nil, cfg); err == nil {
		t.Fatal("nil logger must fail")
	}
}

// ---- runner: unknown job row fails closed ----

func TestRunnerUnknownJobRowFailsClosed(t *testing.T) {
	reg, _ := NewJobRegistry(&scriptedJob{name: "known"})
	state := newRecordingState("c0", 0)
	locker := &fakeLocker{}
	r, err := NewJobRunner(reg, state, locker, newFakeClock(time.Now(), time.Millisecond), testLogger(t), testRunnerConfig())
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	_, err = r.RunDueJob(context.Background(), dueState("o", "orphan", "c0", 0))
	if !errors.Is(err, ErrUnknownJob) {
		t.Fatalf("want ErrUnknownJob for orphan row, got %v", err)
	}
	// Fail-closed: no lock acquired, no job executed, no state change.
	if locker.tryCalls != 0 {
		t.Fatal("must not acquire a lock for an unknown job row")
	}
	if len(state.calls) != 0 {
		t.Fatalf("no state transition for unknown job, got %v", state.calls)
	}
}

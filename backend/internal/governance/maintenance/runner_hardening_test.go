package maintenance

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// B4 PR-2 HARDENING — adversarial, test-only regression coverage for the
// merged job registry + runner skeleton (PR #81). No production change
// accompanies this file. It fills the gaps the base runner_test.go left:
// completed/failed persistence under caller-context cancellation, lock
// release when the terminal persistence write fails, MarkJobStarted
// failure releasing the lock without executing the job, and proof that
// cancellation is honored only at a page boundary (never mid-page).
//
// Reuses same-package test doubles from runner_test.go: fakeClock,
// fakeLocker, fakeLock, scriptedJob, recordingState, ctxCheckingState,
// testLogger, testRunnerConfig, newTestRunner, dueState.

// erroringState wraps recordingState and injects an error on a chosen
// Mark* transition so tests can drive terminal-persistence failures.
type erroringState struct {
	*recordingState
	failStarted   error
	failCompleted error
	failPartial   error
	failFailed    error
}

func (s *erroringState) MarkJobStarted(ctx context.Context, org, job string, startedAt time.Time) error {
	if s.failStarted != nil {
		return s.failStarted
	}
	return s.recordingState.MarkJobStarted(ctx, org, job, startedAt)
}
func (s *erroringState) MarkJobCompleted(ctx context.Context, org, job, cursor string, finishedAt, nextDueAt time.Time) error {
	if s.failCompleted != nil {
		return s.failCompleted
	}
	return s.recordingState.MarkJobCompleted(ctx, org, job, cursor, finishedAt, nextDueAt)
}
func (s *erroringState) MarkJobPartial(ctx context.Context, org, job, cursor string, finishedAt, nextDueAt time.Time) error {
	if s.failPartial != nil {
		return s.failPartial
	}
	return s.recordingState.MarkJobPartial(ctx, org, job, cursor, finishedAt, nextDueAt)
}
func (s *erroringState) MarkJobFailed(ctx context.Context, org, job, redactedErr string, finishedAt, nextDueAt time.Time) error {
	if s.failFailed != nil {
		return s.failFailed
	}
	return s.recordingState.MarkJobFailed(ctx, org, job, redactedErr, finishedAt, nextDueAt)
}

// cancelMidPageJob cancels the run context from INSIDE RunPage and then
// returns a successful result. It models a page that is in flight when
// shutdown is signalled: the runner must let the page finish and consume
// its result, only observing the cancellation at the next boundary.
type cancelMidPageJob struct {
	name   string
	cancel context.CancelFunc
	result PageResult

	mu    sync.Mutex
	calls int
}

func (j *cancelMidPageJob) Name() string { return j.name }
func (j *cancelMidPageJob) RunPage(ctx context.Context, org, cursor string, limits PageLimits) (PageResult, error) {
	j.mu.Lock()
	j.calls++
	first := j.calls == 1
	j.mu.Unlock()
	if first {
		// Cancel mid-page, then keep working and return success. If the
		// runner aborted mid-page on cancellation this result would be
		// discarded; the test asserts it is applied.
		j.cancel()
	}
	return j.result, nil
}
func (j *cancelMidPageJob) callCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.calls
}

// ---- terminal persistence under cancellation (completed + failed) ----

// TestRunnerPersistsCompletedEvenWhenCallerContextCancelled: a run that
// reaches Done on the same page that cancellation is signalled must still
// durably record `completed` (not be stranded in `running`). The state
// fake rejects cancelled contexts, so this passes only if the terminal
// write uses the live persist context.
func TestRunnerPersistsCompletedEvenWhenCallerContextCancelled(t *testing.T) {
	locker := &fakeLocker{}
	state := &ctxCheckingState{newRecordingState("c0", 0)}
	ctx, cancel := context.WithCancel(context.Background())

	// Page 1 cancels the caller ctx, then reports Done -> completed.
	job := &cancelMidPageJob{name: "j", cancel: cancel, result: PageResult{NextCursor: "c-1", Done: true}}
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Unix(1000, 0).UTC(), 0), testRunnerConfig())

	rep, err := r.RunDueJob(ctx, dueState("o", "j", "c0", 0))
	if err != nil {
		t.Fatalf("run returned infra error despite cancellation: %v", err)
	}
	if rep.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %s, want completed", rep.Outcome)
	}
	if state.lastStatus != governance.SchedulerJobCompleted {
		t.Fatalf("row left in %s; completion must be durably recorded under cancellation", state.lastStatus)
	}
	// Completion resets to the start sentinel for the next cycle.
	if state.cursor != governance.SchedulerCursorStart {
		t.Fatalf("completed cursor = %q, want start sentinel", state.cursor)
	}
}

// TestRunnerPersistsFailedEvenWhenCallerContextCancelled: a page that
// fails on the same call that cancellation is signalled must still
// durably record `error` with the backoff next-due.
func TestRunnerPersistsFailedEvenWhenCallerContextCancelled(t *testing.T) {
	locker := &fakeLocker{}
	state := &ctxCheckingState{newRecordingState("c0", 0)}
	ctx, cancel := context.WithCancel(context.Background())

	job := &cancelThenFailJob{name: "j", cancel: cancel}
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Unix(1000, 0).UTC(), 0), testRunnerConfig())

	rep, err := r.RunDueJob(ctx, dueState("o", "j", "c0", 0))
	if err != nil {
		t.Fatalf("run returned infra error despite cancellation: %v", err)
	}
	if rep.Outcome != OutcomeError {
		t.Fatalf("outcome = %s, want error", rep.Outcome)
	}
	if state.lastStatus != governance.SchedulerJobError {
		t.Fatalf("row left in %s; failure must be durably recorded under cancellation", state.lastStatus)
	}
	if state.failures != 1 {
		t.Fatalf("consecutive_failures = %d, want 1", state.failures)
	}
	if state.cursor != "c0" {
		t.Fatalf("failed run advanced cursor to %q; must stay c0", state.cursor)
	}
}

type cancelThenFailJob struct {
	name   string
	cancel context.CancelFunc
}

func (j *cancelThenFailJob) Name() string { return j.name }
func (j *cancelThenFailJob) RunPage(ctx context.Context, org, cursor string, limits PageLimits) (PageResult, error) {
	j.cancel()
	return PageResult{}, errors.New("page boom during shutdown")
}

// ---- lock release when terminal persistence fails ----

// TestRunnerReleasesLockWhenTerminalPersistenceFails: if the terminal
// Mark* write fails (DB error), RunDueJob surfaces the error AND the
// deferred lock release still fires — the lock is never stranded.
func TestRunnerReleasesLockWhenTerminalPersistenceFails(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*erroringState)
		job   Job
		cfg   func(RunnerConfig) RunnerConfig
	}{
		{
			name:  "completed write fails",
			setup: func(s *erroringState) { s.failCompleted = errors.New("db down") },
			job:   &scriptedJob{name: "j", results: []pageStep{{res: PageResult{Done: true}}}},
		},
		{
			name:  "partial write fails",
			setup: func(s *erroringState) { s.failPartial = errors.New("db down") },
			job:   &scriptedJob{name: "j", results: []pageStep{{res: PageResult{NextCursor: "c-1", Done: false}}}},
			cfg:   func(c RunnerConfig) RunnerConfig { c.MaxPagesPerRun = 1; return c },
		},
		{
			name:  "failed write fails",
			setup: func(s *erroringState) { s.failFailed = errors.New("db down") },
			job:   &scriptedJob{name: "j", results: []pageStep{{err: errors.New("page boom")}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			locker := &fakeLocker{}
			state := &erroringState{recordingState: newRecordingState("c0", 0)}
			tc.setup(state)
			cfg := testRunnerConfig()
			if tc.cfg != nil {
				cfg = tc.cfg(cfg)
			}
			r := newTestRunner(t, tc.job, state, locker, newFakeClock(time.Now(), time.Millisecond), cfg)

			_, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0))
			if err == nil {
				t.Fatal("expected terminal-persistence error to surface")
			}
			if locker.lock.releaseCount() != 1 {
				t.Fatalf("lock release count = %d, want 1 (lock must not be stranded on a persistence failure)", locker.lock.releaseCount())
			}
		})
	}
}

// ---- MarkJobStarted failure ----

// TestRunnerMarkStartedFailureReleasesLockAndSkipsJob: if MarkJobStarted
// fails, the runner must release the already-held lock and must NOT
// execute the job (no page runs against an unrecorded start).
func TestRunnerMarkStartedFailureReleasesLockAndSkipsJob(t *testing.T) {
	locker := &fakeLocker{}
	state := &erroringState{recordingState: newRecordingState("c0", 0)}
	state.failStarted = errors.New("db down")
	job := &scriptedJob{name: "j", results: []pageStep{{res: PageResult{Done: true}}}}
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Now(), time.Millisecond), testRunnerConfig())

	_, err := r.RunDueJob(context.Background(), dueState("o", "j", "c0", 0))
	if err == nil {
		t.Fatal("expected MarkJobStarted failure to surface")
	}
	if job.calls != 0 {
		t.Fatalf("job executed despite MarkJobStarted failure (calls=%d)", job.calls)
	}
	if locker.lock.releaseCount() != 1 {
		t.Fatalf("lock release count = %d, want 1 (lock must release when start-mark fails)", locker.lock.releaseCount())
	}
	// The lock WAS acquired before the start mark (so release is meaningful).
	if locker.tryCalls != 1 {
		t.Fatalf("TryLockOrgJob calls = %d, want 1", locker.tryCalls)
	}
}

// ---- cancellation only at page boundary, never mid-page ----

// TestRunnerDoesNotInterruptInFlightPage proves the runner checks ctx
// only at a page boundary: a page that cancels the context mid-body and
// then returns a successful result has that result APPLIED (cursor
// advances), and the run stops at the NEXT boundary as partial. If the
// runner aborted mid-page, page 1's result would be discarded and the
// cursor would not advance.
func TestRunnerDoesNotInterruptInFlightPage(t *testing.T) {
	locker := &fakeLocker{}
	state := &ctxCheckingState{newRecordingState("c0", 0)}
	ctx, cancel := context.WithCancel(context.Background())

	cfg := testRunnerConfig()
	cfg.MaxPagesPerRun = 5 // not the binding cap
	job := &cancelMidPageJob{name: "j", cancel: cancel, result: PageResult{NextCursor: "c-1", Done: false}}
	r := newTestRunner(t, job, state, locker, newFakeClock(time.Unix(1000, 0).UTC(), 0), cfg)

	rep, err := r.RunDueJob(ctx, dueState("o", "j", "c0", 0))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Outcome != OutcomePartial {
		t.Fatalf("outcome = %s, want partial (stop at boundary after the in-flight page)", rep.Outcome)
	}
	// Page 1 ran exactly once, its result was applied, and page 2 never
	// started (cancellation caught at the boundary before page 2).
	if job.callCount() != 1 {
		t.Fatalf("RunPage calls = %d, want exactly 1 (no mid-page abort, no page 2)", job.callCount())
	}
	if state.cursor != "c-1" {
		t.Fatalf("in-flight page's result was not applied: cursor = %q, want c-1", state.cursor)
	}
	if rep.PagesRun != 1 {
		t.Fatalf("pages run = %d, want 1", rep.PagesRun)
	}
}

// ---- backoff monotonicity (capped) ----

// TestRunnerBackoffSequenceMonotonicAndCapped pins the full backoff
// ladder shape: strictly doubling from RetryBase until it saturates at
// RetryMax, then flat. Complements the single-point cap test in the base
// suite.
func TestRunnerBackoffSequenceMonotonicAndCapped(t *testing.T) {
	r := &JobRunner{cfg: RunnerConfig{RetryBase: time.Minute, RetryMax: 10 * time.Minute}}
	want := []time.Duration{
		1 * time.Minute,  // failure #1: base * 2^0
		2 * time.Minute,  // #2
		4 * time.Minute,  // #3
		8 * time.Minute,  // #4
		10 * time.Minute, // #5: 16m capped to 10m
		10 * time.Minute, // #6: still capped
		10 * time.Minute, // #7
	}
	prev := time.Duration(0)
	for i, w := range want {
		got := r.backoffFor(i + 1)
		if got != w {
			t.Fatalf("backoff #%d = %s, want %s", i+1, got, w)
		}
		if got < prev {
			t.Fatalf("backoff not monotonic at #%d: %s < %s", i+1, got, prev)
		}
		if got > r.cfg.RetryMax {
			t.Fatalf("backoff #%d exceeds RetryMax: %s", i+1, got)
		}
		prev = got
	}
}

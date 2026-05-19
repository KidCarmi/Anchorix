package findings

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// --- fakes ---------------------------------------------------------

// fakeOrgLister returns a fixed set of org ids. Its calls slice
// lets tests assert call count for "did the loop tick?" property
// checks.
type fakeOrgLister struct {
	mu    sync.Mutex
	orgs  []string
	err   error
	calls int32
}

func (f *fakeOrgLister) ListOrganizationIDs(_ context.Context) ([]string, error) {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	// Return a copy so the scheduler can't mutate our fixture.
	out := make([]string, len(f.orgs))
	copy(out, f.orgs)
	return out, nil
}

// fakeScheduledService records every RecomputeScheduled call.
// `fail` and `panic` let tests inject controlled misbehavior.
type fakeScheduledService struct {
	mu        sync.Mutex
	calls     []string
	failOrgs  map[string]error
	panicOrgs map[string]string
	out       *RecomputeResult
}

func newFakeScheduledService() *fakeScheduledService {
	return &fakeScheduledService{
		failOrgs:  map[string]error{},
		panicOrgs: map[string]string{},
		out:       &RecomputeResult{EvaluatedCertificates: 1, Opened: 1, RuleCount: 6},
	}
}

func (f *fakeScheduledService) RecomputeScheduled(_ context.Context, orgID string) (*RecomputeResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, orgID)
	failErr := f.failOrgs[orgID]
	panicMsg := f.panicOrgs[orgID]
	f.mu.Unlock()

	if panicMsg != "" {
		panic(panicMsg)
	}
	if failErr != nil {
		return nil, failErr
	}
	return f.out, nil
}

func (f *fakeScheduledService) callsForOrg(orgID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == orgID {
			n++
		}
	}
	return n
}

func (f *fakeScheduledService) totalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func testLogger() *logger.Logger { return logger.New("error", "development") }

type schedFixedClock struct{ t time.Time }

func (c schedFixedClock) Now() time.Time { return c.t }

// --- constructor validation ---------------------------------------

func TestNewScheduler_RejectsMissingDeps(t *testing.T) {
	clk := schedFixedClock{t: time.Now()}
	svc := newFakeScheduledService()
	orgs := &fakeOrgLister{orgs: []string{"anchorix"}}
	log := testLogger()
	good := SchedulerConfig{Enabled: true, Interval: time.Minute}

	cases := []struct {
		name string
		fn   func() error
	}{
		{"nil service", func() error {
			_, err := NewScheduler(nil, orgs, log, clk, good)
			return err
		}},
		{"nil org lister", func() error {
			_, err := NewScheduler(svc, nil, log, clk, good)
			return err
		}},
		{"nil logger", func() error {
			_, err := NewScheduler(svc, orgs, nil, clk, good)
			return err
		}},
		{"nil clock", func() error {
			_, err := NewScheduler(svc, orgs, log, nil, good)
			return err
		}},
	}
	for _, c := range cases {
		if err := c.fn(); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestNewScheduler_RejectsBadInterval(t *testing.T) {
	clk := schedFixedClock{t: time.Now()}
	svc := newFakeScheduledService()
	orgs := &fakeOrgLister{orgs: []string{"anchorix"}}
	log := testLogger()

	// Interval bounds checks only fire when Enabled=true.
	for _, c := range []struct {
		name string
		cfg  SchedulerConfig
	}{
		{"zero interval", SchedulerConfig{Enabled: true, Interval: 0}},
		{"negative interval", SchedulerConfig{Enabled: true, Interval: -time.Second}},
		{"below minimum", SchedulerConfig{Enabled: true, Interval: time.Second}},
	} {
		_, err := NewScheduler(svc, orgs, log, clk, c.cfg)
		if err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}

	// Disabled scheduler ignores interval entirely.
	if _, err := NewScheduler(svc, orgs, log, clk, SchedulerConfig{Enabled: false, Interval: 0}); err != nil {
		t.Errorf("disabled + zero interval: unexpected err %v", err)
	}
}

func TestValidateSchedulerConfig(t *testing.T) {
	if err := ValidateSchedulerConfig(SchedulerConfig{Enabled: false}); err != nil {
		t.Errorf("disabled: %v", err)
	}
	if err := ValidateSchedulerConfig(SchedulerConfig{Enabled: true, Interval: time.Hour}); err != nil {
		t.Errorf("enabled + 1h: %v", err)
	}
	if err := ValidateSchedulerConfig(SchedulerConfig{Enabled: true, Interval: 0}); err == nil {
		t.Error("zero interval: expected error")
	}
	if err := ValidateSchedulerConfig(SchedulerConfig{Enabled: true, Interval: time.Second}); err == nil {
		t.Error("below minimum: expected error")
	}
}

// --- disabled scheduler does not invoke service -------------------

func TestScheduler_Disabled_RunReturnsImmediately(t *testing.T) {
	svc := newFakeScheduledService()
	orgs := &fakeOrgLister{orgs: []string{"anchorix"}}
	sched, err := NewScheduler(svc, orgs, testLogger(), schedFixedClock{t: time.Now()},
		SchedulerConfig{Enabled: false, Interval: time.Hour})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	// Run with a context that lives much longer than the test —
	// a disabled scheduler must return WITHOUT touching the
	// service or the org lister.
	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- sched.Run(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("disabled Run returned err: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("disabled Run did not return within 500ms")
	}

	if svc.totalCalls() != 0 {
		t.Errorf("disabled scheduler called service %d times", svc.totalCalls())
	}
	if atomic.LoadInt32(&orgs.calls) != 0 {
		t.Errorf("disabled scheduler called org lister %d times", orgs.calls)
	}
}

// --- context cancellation stops the loop --------------------------

func TestScheduler_ContextCancellation_StopsLoop(t *testing.T) {
	svc := newFakeScheduledService()
	orgs := &fakeOrgLister{orgs: []string{"anchorix"}}
	sched, err := NewScheduler(svc, orgs, testLogger(), schedFixedClock{t: time.Now()},
		SchedulerConfig{Enabled: true, Interval: MinSchedulerInterval})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- sched.Run(ctx)
	}()

	// Cancel almost immediately; the loop should exit before
	// the first tick because the select-with-ctx.Done branch
	// is checked alongside ticker.C.
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("cancelled Run returned err: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled Run did not return within 1s")
	}
}

// --- one org's failure must not stop others -----------------------

func TestScheduler_RunOnce_OneOrgFailureDoesNotStopOthers(t *testing.T) {
	svc := newFakeScheduledService()
	svc.failOrgs["bad-org"] = errors.New("synthetic failure")
	orgs := &fakeOrgLister{orgs: []string{"good-a", "bad-org", "good-b"}}
	sched, err := NewScheduler(svc, orgs, testLogger(), schedFixedClock{t: time.Now()},
		SchedulerConfig{Enabled: true, Interval: MinSchedulerInterval})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	sched.runOnce(context.Background())

	if svc.callsForOrg("good-a") != 1 {
		t.Errorf("good-a recompute calls = %d, want 1", svc.callsForOrg("good-a"))
	}
	if svc.callsForOrg("bad-org") != 1 {
		t.Errorf("bad-org recompute calls = %d, want 1 (the failing call still happens)", svc.callsForOrg("bad-org"))
	}
	if svc.callsForOrg("good-b") != 1 {
		t.Errorf("good-b recompute calls = %d, want 1 (failure must not stop subsequent orgs)", svc.callsForOrg("good-b"))
	}
}

// --- panic in one org's recompute is recovered --------------------

func TestScheduler_RunOnce_PanicInOneOrgRecovered(t *testing.T) {
	svc := newFakeScheduledService()
	svc.panicOrgs["panicky-org"] = "synthetic panic"
	orgs := &fakeOrgLister{orgs: []string{"first-org", "panicky-org", "last-org"}}
	sched, err := NewScheduler(svc, orgs, testLogger(), schedFixedClock{t: time.Now()},
		SchedulerConfig{Enabled: true, Interval: MinSchedulerInterval})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	// runOnce must NOT propagate the panic.
	sched.runOnce(context.Background())

	if svc.callsForOrg("first-org") != 1 {
		t.Errorf("first-org recompute calls = %d, want 1", svc.callsForOrg("first-org"))
	}
	if svc.callsForOrg("last-org") != 1 {
		t.Errorf("last-org recompute calls = %d, want 1 (panic must not abort the sweep)", svc.callsForOrg("last-org"))
	}
}

// --- org-lister failure must not crash; just skip the sweep -------

func TestScheduler_RunOnce_OrgListerFailureLogsAndReturns(t *testing.T) {
	svc := newFakeScheduledService()
	orgs := &fakeOrgLister{err: errors.New("synthetic db error")}
	sched, err := NewScheduler(svc, orgs, testLogger(), schedFixedClock{t: time.Now()},
		SchedulerConfig{Enabled: true, Interval: MinSchedulerInterval})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	sched.runOnce(context.Background())

	if svc.totalCalls() != 0 {
		t.Errorf("service was called despite org-lister failure: %d times", svc.totalCalls())
	}
}

// --- runOnce iterates orgs in lister order ------------------------

func TestScheduler_RunOnce_VisitsAllOrgsInOrder(t *testing.T) {
	svc := newFakeScheduledService()
	orgs := &fakeOrgLister{orgs: []string{"alpha", "beta", "gamma"}}
	sched, err := NewScheduler(svc, orgs, testLogger(), schedFixedClock{t: time.Now()},
		SchedulerConfig{Enabled: true, Interval: MinSchedulerInterval})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	sched.runOnce(context.Background())

	svc.mu.Lock()
	defer svc.mu.Unlock()
	if got := strings.Join(svc.calls, ","); got != "alpha,beta,gamma" {
		t.Errorf("calls = %q, want alpha,beta,gamma", got)
	}
}

// --- shutdown during a sweep skips remaining orgs ----------------

func TestScheduler_RunOnce_ContextCancelledMidSweepSkipsRest(t *testing.T) {
	svc := newFakeScheduledService()
	orgs := &fakeOrgLister{orgs: []string{"first", "second", "third"}}
	sched, err := NewScheduler(svc, orgs, testLogger(), schedFixedClock{t: time.Now()},
		SchedulerConfig{Enabled: true, Interval: MinSchedulerInterval})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	// Pre-cancel the context. runOnce should still call the
	// org lister (which doesn't check ctx in our fake), then
	// SHORT-CIRCUIT before invoking the service.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sched.runOnce(ctx)
	if svc.totalCalls() != 0 {
		t.Errorf("expected 0 service calls under cancelled ctx, got %d", svc.totalCalls())
	}
}

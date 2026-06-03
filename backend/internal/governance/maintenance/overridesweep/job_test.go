package overridesweep

import (
	"context"
	"errors"
	"testing"

	"github.com/kidcarmi/anchorix/backend/internal/governance/maintenance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
)

// fakeSweeper records every call and returns a scripted result/error.
// It is the ONLY collaborator the adapter has, so recording calls here
// is sufficient to prove the adapter calls the primitive exactly once,
// passes its arguments through unchanged, mutates no scheduler state,
// and emits no audit (it has no state repo or audit recorder to touch).
type fakeSweeper struct {
	calls   int
	gotOrg  string
	gotCur  string
	gotSize int

	result *ownership.ExpiringOverridesSweepResult
	err    error
}

func (f *fakeSweeper) SweepExpiringOverridesPage(ctx context.Context, org, cursor string, pageSize int) (*ownership.ExpiringOverridesSweepResult, error) {
	f.calls++
	f.gotOrg = org
	f.gotCur = cursor
	f.gotSize = pageSize
	return f.result, f.err
}

func newJob(t *testing.T, s ExpiredOverrideSweeper) *Job {
	t.Helper()
	j, err := NewJob(s)
	if err != nil {
		t.Fatalf("NewJob: %v", err)
	}
	return j
}

func TestJobNameIsStable(t *testing.T) {
	if JobName != "expired_override_sweep" {
		t.Fatalf("JobName = %q, want expired_override_sweep", JobName)
	}
	j := newJob(t, &fakeSweeper{})
	if j.Name() != "expired_override_sweep" {
		t.Fatalf("Name() = %q", j.Name())
	}
}

func TestNewJobRejectsNilSweeper(t *testing.T) {
	if _, err := NewJob(nil); err == nil {
		t.Fatal("NewJob(nil) must fail closed")
	}
}

// TestNewJobRejectsTypedNilSweeper guards the typed-nil trap: a nil
// concrete pointer boxed into the ExpiredOverrideSweeper interface
// (e.g. a future composition root passing (*ownership.Service)(nil)) is
// != nil as an interface value, so the plain nil check would let it
// through and the first RunPage would panic on the nil receiver. NewJob
// must fail closed instead.
func TestNewJobRejectsTypedNilSweeper(t *testing.T) {
	var typedNil *ownership.Service // nil concrete pointer
	if _, err := NewJob(typedNil); err == nil {
		t.Fatal("NewJob((*ownership.Service)(nil)) must fail closed on a typed-nil sweeper")
	}
	// A non-nil sweeper still constructs fine.
	if _, err := NewJob(&fakeSweeper{}); err != nil {
		t.Fatalf("NewJob with a valid sweeper failed: %v", err)
	}
}

func TestRunPageCallsSweeperExactlyOnceWithPassthroughArgs(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{}}
	j := newJob(t, sw)

	_, err := j.RunPage(context.Background(), "anchorix", "cert-cursor-42", maintenance.PageLimits{PageSize: 250})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if sw.calls != 1 {
		t.Fatalf("sweeper called %d times, want exactly 1", sw.calls)
	}
	if sw.gotOrg != "anchorix" {
		t.Fatalf("org passed = %q, want anchorix (unchanged)", sw.gotOrg)
	}
	if sw.gotCur != "cert-cursor-42" {
		t.Fatalf("cursor passed = %q, want cert-cursor-42 (unchanged)", sw.gotCur)
	}
	if sw.gotSize != 250 {
		t.Fatalf("page size passed = %d, want 250 (from PageLimits.PageSize)", sw.gotSize)
	}
}

func TestRunPageMapsResultFields(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{
		OrganizationID: "anchorix",
		StartCursor:    "cert-10",
		NextCursor:     "cert-90",
		SweepID:        "sweep-abc",
		CertsScanned:   17,
		ClearedCount:   12,
		Done:           false,
	}}
	j := newJob(t, sw)

	got, err := j.RunPage(context.Background(), "anchorix", "cert-10", maintenance.PageLimits{PageSize: 100})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if got.NextCursor != "cert-90" {
		t.Fatalf("NextCursor = %q, want cert-90", got.NextCursor)
	}
	if got.Done != false {
		t.Fatalf("Done = %v, want false", got.Done)
	}
	if got.ItemsScanned != 17 {
		t.Fatalf("ItemsScanned = %d, want CertsScanned=17", got.ItemsScanned)
	}
	if got.ItemsChanged != 12 {
		t.Fatalf("ItemsChanged = %d, want ClearedCount=12", got.ItemsChanged)
	}
}

func TestRunPageMapsDoneTrue(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{
		NextCursor:   "cert-final",
		CertsScanned: 3,
		ClearedCount: 3,
		Done:         true,
	}}
	got, err := newJob(t, sw).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if !got.Done {
		t.Fatal("Done=true from primitive must map to PageResult.Done=true")
	}
	if got.NextCursor != "cert-final" {
		t.Fatalf("NextCursor = %q, want cert-final", got.NextCursor)
	}
}

func TestRunPageMapsDoneFalse(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{NextCursor: "cert-50", Done: false}}
	got, err := newJob(t, sw).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if got.Done {
		t.Fatal("Done=false from primitive must map to PageResult.Done=false")
	}
}

// TestRunPageZeroResultPageMapsCleanly: an empty terminal page (0
// scanned, 0 cleared, Done) maps to a clean PageResult with zero counts
// and no error.
func TestRunPageZeroResultPageMapsCleanly(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{
		StartCursor:  "cert-past-end",
		NextCursor:   "cert-past-end",
		CertsScanned: 0,
		ClearedCount: 0,
		Done:         true,
	}}
	got, err := newJob(t, sw).RunPage(context.Background(), "o", "cert-past-end", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if got.ItemsScanned != 0 || got.ItemsChanged != 0 {
		t.Fatalf("zero page mapped to scanned=%d changed=%d, want 0/0", got.ItemsScanned, got.ItemsChanged)
	}
	if !got.Done {
		t.Fatal("terminal empty page should be Done")
	}
}

// TestRunPageScannedNotEqualClearedMapsBoth pins that the two counters
// are mapped from DISTINCT primitive fields (a row lost to a concurrent
// operator clear is scanned but not cleared).
func TestRunPageScannedNotEqualClearedMapsBoth(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{CertsScanned: 10, ClearedCount: 7, Done: true}}
	got, _ := newJob(t, sw).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if got.ItemsScanned != 10 || got.ItemsChanged != 7 {
		t.Fatalf("scanned/changed = %d/%d, want 10/7 (distinct fields)", got.ItemsScanned, got.ItemsChanged)
	}
}

func TestRunPagePropagatesPrimitiveError(t *testing.T) {
	sentinel := errors.New("sweep failed")
	sw := &fakeSweeper{err: sentinel}
	got, err := newJob(t, sw).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err == nil {
		t.Fatal("primitive error must propagate fail-closed")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("error chain lost the primitive error: %v", err)
	}
	// On error the runner must not advance the cursor; the adapter
	// returns a zero PageResult so nothing meaningful leaks through.
	if got.NextCursor != "" || got.Done {
		t.Fatalf("error path returned non-zero result: %+v", got)
	}
	if sw.calls != 1 {
		t.Fatalf("sweeper called %d times on error path, want 1", sw.calls)
	}
}

// TestRunPageNilResultWithoutErrorFailsClosed: a primitive that returns
// (nil, nil) is a contract violation; the adapter must fail closed
// rather than report a bogus completed page.
func TestRunPageNilResultWithoutErrorFailsClosed(t *testing.T) {
	sw := &fakeSweeper{result: nil, err: nil}
	_, err := newJob(t, sw).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err == nil {
		t.Fatal("nil result without error must fail closed")
	}
}

// TestAdapterSatisfiesJobInterface is a compile-time + runtime guard that
// the adapter is usable wherever a maintenance.Job is expected (e.g. the
// registry / runner). It also documents that no other method is needed.
func TestAdapterSatisfiesJobInterface(t *testing.T) {
	var j maintenance.Job = newJob(t, &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{Done: true}})
	if j.Name() != JobName {
		t.Fatalf("Job.Name() = %q", j.Name())
	}
}

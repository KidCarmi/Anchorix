package explanationretention

import (
	"context"
	"errors"
	"testing"

	"github.com/kidcarmi/anchorix/backend/internal/governance/maintenance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
)

// fakePruner records every call and returns a scripted result/error. It
// is the adapter's ONLY collaborator, so recording calls here is
// sufficient to prove the adapter calls the primitive exactly once,
// passes its arguments through unchanged, mutates no scheduler state,
// and emits no audit (it has no state repo or audit recorder to touch).
type fakePruner struct {
	calls    int
	gotCtx   context.Context
	gotOrg   string
	gotActor string
	gotCur   string
	gotSize  int

	result *ownership.ExplanationPruneResult
	err    error
}

func (f *fakePruner) PruneExplanationsPage(ctx context.Context, org, actor, cursor string, pageSize int) (*ownership.ExplanationPruneResult, error) {
	f.calls++
	f.gotCtx = ctx
	f.gotOrg = org
	f.gotActor = actor
	f.gotCur = cursor
	f.gotSize = pageSize
	return f.result, f.err
}

func newJob(t *testing.T, p ExplanationPruner) *Job {
	t.Helper()
	j, err := NewJob(p)
	if err != nil {
		t.Fatalf("NewJob: %v", err)
	}
	return j
}

func TestJobNameIsStable(t *testing.T) {
	if JobName != "explanation_retention_prune" {
		t.Fatalf("JobName = %q, want explanation_retention_prune", JobName)
	}
	if newJob(t, &fakePruner{}).Name() != "explanation_retention_prune" {
		t.Fatal("Name() mismatch")
	}
}

func TestNewJobRejectsNilPruner(t *testing.T) {
	if _, err := NewJob(nil); err == nil {
		t.Fatal("NewJob(nil) must fail closed")
	}
}

// TestNewJobRejectsTypedNilPruner guards the typed-nil trap: a nil
// concrete pointer boxed into the ExplanationPruner interface (e.g. a
// future composition root passing (*ownership.Service)(nil)) is != nil
// as an interface value, so the plain nil check would let it through and
// the first RunPage would panic on the nil receiver. NewJob must fail
// closed instead.
func TestNewJobRejectsTypedNilPruner(t *testing.T) {
	var typedNil *ownership.Service
	if _, err := NewJob(typedNil); err == nil {
		t.Fatal("NewJob((*ownership.Service)(nil)) must fail closed on a typed-nil pruner")
	}
	if _, err := NewJob(&fakePruner{}); err != nil {
		t.Fatalf("NewJob with a valid pruner failed: %v", err)
	}
}

func TestRunPageCallsPrunerExactlyOnceWithPassthroughArgs(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{}}
	j := newJob(t, pr)

	if _, err := j.RunPage(context.Background(), "anchorix", "cert-cursor-7", maintenance.PageLimits{PageSize: 300}); err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if pr.calls != 1 {
		t.Fatalf("pruner called %d times, want exactly 1", pr.calls)
	}
	if pr.gotOrg != "anchorix" {
		t.Fatalf("org passed = %q, want anchorix (unchanged)", pr.gotOrg)
	}
	if pr.gotCur != "cert-cursor-7" {
		t.Fatalf("cursor passed = %q, want cert-cursor-7 (unchanged)", pr.gotCur)
	}
	if pr.gotSize != 300 {
		t.Fatalf("page size passed = %d, want 300 (from PageLimits.PageSize)", pr.gotSize)
	}
}

// TestRunPagePassesEmptySystemActor pins that the adapter invokes the
// prune as a system-initiated run (empty actor), which the primitive
// records as actor=system — the correct attribution for a scheduled run.
func TestRunPagePassesEmptySystemActor(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{Done: true}}
	if _, err := newJob(t, pr).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 100}); err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if pr.gotActor != "" {
		t.Fatalf("actor passed = %q, want empty (system-initiated)", pr.gotActor)
	}
}

// ctxKey is a private context key so the test can prove the EXACT caller
// context reaches the primitive.
type ctxKey struct{}

func TestRunPagePassesCallerContextThrough(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{Done: true}}
	ctx := context.WithValue(context.Background(), ctxKey{}, "sentinel-99")
	if _, err := newJob(t, pr).RunPage(ctx, "o", "c", maintenance.PageLimits{PageSize: 100}); err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if pr.gotCtx == nil || pr.gotCtx.Value(ctxKey{}) != "sentinel-99" {
		t.Fatalf("caller context not passed through unchanged: %v", pr.gotCtx)
	}
}

func TestRunPageMapsResultFields(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{
		OrganizationID: "anchorix",
		StartCursor:    "cert-10",
		NextCursor:     "cert-80",
		CertsScanned:   40,
		DeletedCount:   9,
		Done:           false,
	}}
	got, err := newJob(t, pr).RunPage(context.Background(), "anchorix", "cert-10", maintenance.PageLimits{PageSize: 100})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if got.NextCursor != "cert-80" {
		t.Fatalf("NextCursor = %q, want cert-80", got.NextCursor)
	}
	if got.Done {
		t.Fatal("Done should be false")
	}
	if got.ItemsScanned != 40 {
		t.Fatalf("ItemsScanned = %d, want CertsScanned=40", got.ItemsScanned)
	}
	if got.ItemsChanged != 9 {
		t.Fatalf("ItemsChanged = %d, want DeletedCount=9", got.ItemsChanged)
	}
}

func TestRunPageMapsDoneTrue(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{NextCursor: "cert-final", Done: true}}
	got, err := newJob(t, pr).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if !got.Done {
		t.Fatal("Done=true must map to PageResult.Done=true")
	}
	if got.NextCursor != "cert-final" {
		t.Fatalf("NextCursor = %q, want cert-final", got.NextCursor)
	}
}

func TestRunPageMapsDoneFalse(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{NextCursor: "cert-50", Done: false}}
	got, err := newJob(t, pr).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if got.Done {
		t.Fatal("Done=false must map to PageResult.Done=false")
	}
}

// TestRunPageZeroResultPageMapsCleanly: an empty terminal page (0
// scanned, 0 deleted, Done) maps to a clean PageResult with zero counts
// and no error.
func TestRunPageZeroResultPageMapsCleanly(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{
		StartCursor:  "cert-end",
		NextCursor:   "cert-end",
		CertsScanned: 0,
		DeletedCount: 0,
		Done:         true,
	}}
	got, err := newJob(t, pr).RunPage(context.Background(), "o", "cert-end", maintenance.PageLimits{PageSize: 500})
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

// TestRunPageDoesNotSwapScannedAndDeleted uses values where a swap would
// be unambiguous (scanned strictly greater than deleted) and asserts the
// exact wiring: ItemsScanned<-CertsScanned, ItemsChanged<-DeletedCount.
func TestRunPageDoesNotSwapScannedAndDeleted(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{CertsScanned: 500, DeletedCount: 3, Done: true}}
	got, err := newJob(t, pr).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if got.ItemsScanned != 500 {
		t.Fatalf("ItemsScanned = %d, want 500 (CertsScanned) — counters may be swapped", got.ItemsScanned)
	}
	if got.ItemsChanged != 3 {
		t.Fatalf("ItemsChanged = %d, want 3 (DeletedCount) — counters may be swapped", got.ItemsChanged)
	}
	if got.ItemsScanned == 3 && got.ItemsChanged == 500 {
		t.Fatal("counters are swapped: ItemsScanned<-DeletedCount, ItemsChanged<-CertsScanned")
	}
}

func TestRunPagePropagatesPrimitiveError(t *testing.T) {
	sentinel := errors.New("prune failed")
	pr := &fakePruner{err: sentinel}
	got, err := newJob(t, pr).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err == nil {
		t.Fatal("primitive error must propagate fail-closed")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("error chain lost the primitive error: %v", err)
	}
	if got.NextCursor != "" || got.Done {
		t.Fatalf("error path returned non-zero result: %+v", got)
	}
	if pr.calls != 1 {
		t.Fatalf("pruner called %d times on error path, want 1", pr.calls)
	}
}

func TestRunPageNilResultWithoutErrorFailsClosed(t *testing.T) {
	pr := &fakePruner{result: nil, err: nil}
	if _, err := newJob(t, pr).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500}); err == nil {
		t.Fatal("nil result without error must fail closed")
	}
}

func TestRunPageSingleCallAcrossAllOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		result *ownership.ExplanationPruneResult
		err    error
	}{
		{"completed", &ownership.ExplanationPruneResult{Done: true}, nil},
		{"partial", &ownership.ExplanationPruneResult{NextCursor: "c", Done: false}, nil},
		{"error", nil, errors.New("boom")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pr := &fakePruner{result: tc.result, err: tc.err}
			_, _ = newJob(t, pr).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
			if pr.calls != 1 {
				t.Fatalf("pruner called %d times for %s, want exactly 1", pr.calls, tc.name)
			}
		})
	}
}

func TestAdapterSatisfiesJobInterface(t *testing.T) {
	var j maintenance.Job = newJob(t, &fakePruner{result: &ownership.ExplanationPruneResult{Done: true}})
	if j.Name() != JobName {
		t.Fatalf("Job.Name() = %q", j.Name())
	}
}

// TestAdapterHasNoStateOrAuditCollaborator: the Job's only dependency is
// the pruner (constructor takes exactly one arg). RunPage succeeds with
// only the pruner present — no state repo, audit recorder, or locker is
// wired or needed, which is the structural proof the adapter performs no
// scheduler-state mutation and emits no audit of its own.
func TestAdapterHasNoStateOrAuditCollaborator(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{CertsScanned: 4, DeletedCount: 4, Done: true}}
	got, err := newJob(t, pr).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if pr.calls != 1 {
		t.Fatalf("pruner calls = %d, want 1 (adapter does only the prune)", pr.calls)
	}
	if got.ItemsChanged != 4 {
		t.Fatalf("result not mapped: ItemsChanged = %d", got.ItemsChanged)
	}
}

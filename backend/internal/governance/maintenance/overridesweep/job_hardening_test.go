package overridesweep

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kidcarmi/anchorix/backend/internal/governance/maintenance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
)

// B4 PR-3 HARDENING — adversarial, test-only regression coverage for the
// merged expired-override-sweep Job adapter (PR #83). No production
// change accompanies this file. It strengthens the base job_test.go with
// context passthrough, swap-detection on the two counters, single-call
// invariants across every outcome, and stronger static guards (an AST
// import check and a repo-wide "no production registry wiring" check)
// that substring scanning alone does not give.
//
// Reuses the same-package fakeSweeper / newJob helpers from job_test.go.

// ---- behavioral: passthrough + mapping under adversarial inputs ----

// ctxKey is a private context key so the test can prove the EXACT caller
// context (not a derived/replaced one) reaches the primitive.
type ctxKey struct{}

// ctxCapturingSweeper records the context it received in addition to the
// scalar args, so the adapter's context passthrough is assertable.
type ctxCapturingSweeper struct {
	gotCtx  context.Context
	calls   int
	gotOrg  string
	gotCur  string
	gotSize int
	result  *ownership.ExpiringOverridesSweepResult
}

func (s *ctxCapturingSweeper) SweepExpiringOverridesPage(ctx context.Context, org, cursor string, pageSize int) (*ownership.ExpiringOverridesSweepResult, error) {
	s.gotCtx = ctx
	s.calls++
	s.gotOrg, s.gotCur, s.gotSize = org, cursor, pageSize
	return s.result, nil
}

// TestRunPagePassesCallerContextThrough proves the adapter hands the
// caller's exact context to the primitive — it does not wrap, replace,
// or background it (the primitive owns its own tx/lock context; the
// adapter must not detach cancellation from it).
func TestRunPagePassesCallerContextThrough(t *testing.T) {
	sw := &ctxCapturingSweeper{result: &ownership.ExpiringOverridesSweepResult{Done: true}}
	j, err := NewJob(sw)
	if err != nil {
		t.Fatalf("NewJob: %v", err)
	}
	ctx := context.WithValue(context.Background(), ctxKey{}, "sentinel-42")

	if _, err := j.RunPage(ctx, "anchorix", "c", maintenance.PageLimits{PageSize: 100}); err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if sw.gotCtx == nil {
		t.Fatal("primitive received a nil context")
	}
	if got := sw.gotCtx.Value(ctxKey{}); got != "sentinel-42" {
		t.Fatalf("caller context not passed through: sentinel value = %v, want sentinel-42", got)
	}
}

// TestRunPageDoesNotSwapScannedAndChanged uses values where a swap would
// be unambiguous (scanned strictly greater than changed) and asserts the
// exact wiring: ItemsScanned<-CertsScanned, ItemsChanged<-ClearedCount.
// A regression that swapped the two assignments would flip these.
func TestRunPageDoesNotSwapScannedAndChanged(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{
		CertsScanned: 100,
		ClearedCount: 1,
		Done:         true,
	}}
	got, err := newJob(t, sw).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if got.ItemsScanned != 100 {
		t.Fatalf("ItemsScanned = %d, want 100 (from CertsScanned) — counters may be swapped", got.ItemsScanned)
	}
	if got.ItemsChanged != 1 {
		t.Fatalf("ItemsChanged = %d, want 1 (from ClearedCount) — counters may be swapped", got.ItemsChanged)
	}
	// Explicit anti-swap assertion: the swapped wiring would yield 1/100.
	if got.ItemsScanned == 1 && got.ItemsChanged == 100 {
		t.Fatal("counters are swapped: ItemsScanned<-ClearedCount, ItemsChanged<-CertsScanned")
	}
}

// TestRunPageNextCursorMappedNotCursorEchoed proves NextCursor comes from
// the primitive RESULT, not echoed from the input cursor — a regression
// that returned the input cursor would stall pagination.
func TestRunPageNextCursorMappedNotCursorEchoed(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{NextCursor: "cert-advanced", Done: false}}
	got, err := newJob(t, sw).RunPage(context.Background(), "o", "cert-input", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if got.NextCursor == "cert-input" {
		t.Fatal("NextCursor echoed the input cursor instead of the primitive result (pagination would stall)")
	}
	if got.NextCursor != "cert-advanced" {
		t.Fatalf("NextCursor = %q, want cert-advanced (from result)", got.NextCursor)
	}
}

// TestRunPageSingleCallAcrossAllOutcomes pins "exactly one primitive
// call per RunPage" for completed, partial, and error outcomes — a
// retry/loop regression inside the adapter would call more than once.
func TestRunPageSingleCallAcrossAllOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		result *ownership.ExpiringOverridesSweepResult
		err    error
	}{
		{"completed", &ownership.ExpiringOverridesSweepResult{Done: true}, nil},
		{"partial", &ownership.ExpiringOverridesSweepResult{NextCursor: "c", Done: false}, nil},
		{"error", nil, errors.New("boom")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sw := &fakeSweeper{result: tc.result, err: tc.err}
			_, _ = newJob(t, sw).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
			if sw.calls != 1 {
				t.Fatalf("primitive called %d times for %s outcome, want exactly 1", sw.calls, tc.name)
			}
		})
	}
}

// TestRunPageZeroPageSizePassedThroughUnchanged confirms the adapter does
// NOT clamp/alter page size — it forwards PageLimits.PageSize verbatim
// and lets the primitive apply its own documented default/clamp. (A
// double-clamp in the adapter would be a hidden behavior divergence.)
func TestRunPageZeroPageSizePassedThroughUnchanged(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{Done: true}}
	if _, err := newJob(t, sw).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 0}); err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if sw.gotSize != 0 {
		t.Fatalf("page size = %d, want 0 forwarded verbatim (primitive owns the clamp)", sw.gotSize)
	}
}

// ---- static: AST import guard ----

// TestAdapterImportsAreClean parses the adapter's production .go files
// and asserts the import graph excludes layers the adapter must never
// touch. This is stronger than substring scanning: it sees the actual
// import paths, including aliased or dot imports.
func TestAdapterImportsAreClean(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	forbiddenImports := []string{
		"github.com/kidcarmi/anchorix/backend/internal/storage/postgres",
		"github.com/kidcarmi/anchorix/backend/internal/httpapi",
		"github.com/kidcarmi/anchorix/backend/internal/audit",
		// the sibling retention job package must not be pulled in here
		"github.com/kidcarmi/anchorix/backend/internal/governance/maintenance/retention",
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenImports {
				if path == bad {
					t.Fatalf("%s imports forbidden package %q — the adapter must reach the primitive only through the injected ownership sweeper, never the storage/http/audit layers", e.Name(), path)
				}
			}
		}
	}
}

// ---- static: no production wiring of the job anywhere in the tree ----

// TestNoProductionRegistryWiring scans the whole backend module (minus
// this adapter package and test files) and asserts NO production file
// references the adapter — confirming the job is not auto-registered,
// constructed, or invoked in production in PR-3. When a deliberate wiring
// PR lands it will update this guard.
func TestNoProductionRegistryWiring(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	adapterDir := filepath.Dir(thisFile)
	// backend module root is three levels up from
	// internal/governance/maintenance/overridesweep.
	backendRoot := filepath.Clean(filepath.Join(adapterDir, "..", "..", "..", ".."))

	needles := []string{
		"overridesweep.NewJob",
		"overridesweep.JobName",
		"maintenance/overridesweep",
	}
	var offenders []string
	err := filepath.WalkDir(backendRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Skip the adapter package's own production source (it legitimately
		// defines these symbols).
		if filepath.Dir(path) == adapterDir {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		src := string(body)
		for _, n := range needles {
			if strings.Contains(src, n) {
				rel, _ := filepath.Rel(backendRoot, path)
				offenders = append(offenders, rel+" contains "+n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) != 0 {
		t.Fatalf("expired_override_sweep job is wired into production in PR-3 (must stay dormant):\n  %s", strings.Join(offenders, "\n  "))
	}
}

// ---- behavioral: adapter touches no state/audit collaborator ----

// sideEffectSweeper is the adapter's ONLY collaborator. If the adapter
// ever tried to mutate scheduler state or emit audit it would need a
// different collaborator than this one — there is none to inject, which
// is itself the structural proof. This test additionally asserts the
// adapter performs no work beyond the single sweep call (calls==1,
// result mapped) so a future edit that smuggled in extra collaborator
// calls would have to change the constructor signature and break here.
func TestAdapterHasNoStateOrAuditCollaborator(t *testing.T) {
	sw := &fakeSweeper{result: &ownership.ExpiringOverridesSweepResult{CertsScanned: 5, ClearedCount: 5, Done: true}}
	j, err := NewJob(sw)
	if err != nil {
		t.Fatalf("NewJob: %v", err)
	}
	// The Job struct's only dependency is the sweeper (constructor takes
	// exactly one arg). Exercising RunPage must not require any state
	// repo, audit recorder, or locker — none are wired, and the call
	// succeeds with only the sweeper present.
	got, err := j.RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
	if err != nil {
		t.Fatalf("RunPage: %v", err)
	}
	if sw.calls != 1 {
		t.Fatalf("sweeper calls = %d, want 1 (adapter does only the sweep)", sw.calls)
	}
	if got.ItemsChanged != 5 {
		t.Fatalf("result not mapped: ItemsChanged = %d", got.ItemsChanged)
	}
}

// ---- maintenance package dormancy still intact ----

// TestMaintenancePackageStillDormant re-pins that the sibling
// maintenance package did NOT acquire an ownership dependency as a side
// effect of PR-3 (the adapter lives in its own package precisely to keep
// maintenance ownership-free). A regression that moved the adapter into
// maintenance would make maintenance import governance/ownership.
func TestMaintenancePackageStillDormant(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	maintenanceDir := filepath.Clean(filepath.Join(filepath.Dir(thisFile), ".."))
	fset := token.NewFileSet()
	entries, err := os.ReadDir(maintenanceDir)
	if err != nil {
		t.Fatalf("read maintenance dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(maintenanceDir, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(path, "governance/ownership") {
				t.Fatalf("maintenance/%s imports %q — the maintenance package must stay ownership-free; the adapter belongs in its own package", e.Name(), path)
			}
		}
	}
}

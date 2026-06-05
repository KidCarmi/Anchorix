package explanationretention

import (
	"context"
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

// B4 PR-4 HARDENING — adversarial, test-only regression coverage for the
// merged explanation-retention prune Job adapter (PR #85). No production
// change accompanies this file. It fills the gaps the base job_test.go /
// dormancy_test.go left relative to the PR-3 sweep-adapter hardening:
// NextCursor-not-echoed, statelessness across calls, exhaustive
// field-mapping, a positive "calls the correct primitive" guard, and two
// extra static guards (no config creep, no migration creep) plus a few
// extra forbidden-token spellings.
//
// Reuses the same-package fakePruner / newJob helpers from job_test.go.

// ---- behavioral: NextCursor mapped from result, not echoed ----

// TestRunPageNextCursorMappedNotCursorEchoed proves NextCursor comes from
// the primitive RESULT, not echoed from the input cursor — a regression
// that returned the input cursor would stall pagination on a non-Done
// page (the runner would persist the same cursor and re-scan forever).
func TestRunPageNextCursorMappedNotCursorEchoed(t *testing.T) {
	pr := &fakePruner{result: &ownership.ExplanationPruneResult{NextCursor: "cert-advanced", Done: false}}
	got, err := newJob(t, pr).RunPage(context.Background(), "o", "cert-input", maintenance.PageLimits{PageSize: 500})
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

// ---- behavioral: adapter is stateless across calls ----

// TestAdapterIsStatelessAcrossCalls drives the SAME Job through several
// back-to-back RunPage calls with different org / cursor / page size /
// result shapes and asserts each call maps independently from its own
// inputs and the pruner's own result — no value leaks between calls. The
// adapter holds only the injected pruner; it must carry no per-call
// state (cursor, counts, org) on the struct.
func TestAdapterIsStatelessAcrossCalls(t *testing.T) {
	pr := &fakePruner{}
	j := newJob(t, pr)

	steps := []struct {
		org, cursor string
		size        int
		result      *ownership.ExplanationPruneResult
	}{
		{"anchorix", "c-a", 100, &ownership.ExplanationPruneResult{NextCursor: "c-a2", CertsScanned: 10, DeletedCount: 1, Done: false}},
		{"beta-org", "c-b", 250, &ownership.ExplanationPruneResult{NextCursor: "c-b2", CertsScanned: 7, DeletedCount: 7, Done: true}},
		{"anchorix", "", 500, &ownership.ExplanationPruneResult{NextCursor: "c-a3", CertsScanned: 0, DeletedCount: 0, Done: true}},
	}
	for i, s := range steps {
		pr.result = s.result
		pr.err = nil
		got, err := j.RunPage(context.Background(), s.org, s.cursor, maintenance.PageLimits{PageSize: s.size})
		if err != nil {
			t.Fatalf("step %d RunPage: %v", i, err)
		}
		// Inputs forwarded for THIS call (not a stale prior call's).
		if pr.gotOrg != s.org || pr.gotCur != s.cursor || pr.gotSize != s.size {
			t.Fatalf("step %d: forwarded (%q,%q,%d), want (%q,%q,%d)",
				i, pr.gotOrg, pr.gotCur, pr.gotSize, s.org, s.cursor, s.size)
		}
		// Output mapped from THIS call's result only.
		if got.NextCursor != s.result.NextCursor || got.Done != s.result.Done ||
			got.ItemsScanned != s.result.CertsScanned || got.ItemsChanged != s.result.DeletedCount {
			t.Fatalf("step %d: result not mapped independently: got %+v", i, got)
		}
	}
	if pr.calls != len(steps) {
		t.Fatalf("pruner called %d times, want %d (one per RunPage)", pr.calls, len(steps))
	}
}

// ---- behavioral: exhaustive field mapping (all four at once) ----

// TestRunPageFieldMappingTable locks all four result→PageResult field
// mappings simultaneously across several shapes, so a regression that
// dropped or crossed a single field is caught even when other fields
// happen to coincide.
func TestRunPageFieldMappingTable(t *testing.T) {
	cases := []ownership.ExplanationPruneResult{
		{NextCursor: "n1", CertsScanned: 1, DeletedCount: 0, Done: false},
		{NextCursor: "n2", CertsScanned: 999, DeletedCount: 998, Done: false},
		{NextCursor: "n3", CertsScanned: 0, DeletedCount: 0, Done: true},
		{NextCursor: "n4", CertsScanned: 64, DeletedCount: 64, Done: true},
	}
	for i, res := range cases {
		r := res // capture
		got, err := newJob(t, &fakePruner{result: &r}).RunPage(context.Background(), "o", "c", maintenance.PageLimits{PageSize: 500})
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got.NextCursor != r.NextCursor {
			t.Fatalf("case %d NextCursor = %q, want %q", i, got.NextCursor, r.NextCursor)
		}
		if got.Done != r.Done {
			t.Fatalf("case %d Done = %v, want %v", i, got.Done, r.Done)
		}
		if got.ItemsScanned != r.CertsScanned {
			t.Fatalf("case %d ItemsScanned = %d, want CertsScanned %d", i, got.ItemsScanned, r.CertsScanned)
		}
		if got.ItemsChanged != r.DeletedCount {
			t.Fatalf("case %d ItemsChanged = %d, want DeletedCount %d", i, got.ItemsChanged, r.DeletedCount)
		}
	}
}

// ---- static: calls the CORRECT primitive (positive guard) ----

// TestAdapterCallsPrunePrimitive is the positive complement to the
// dormancy guard's "no SweepExpiringOverridesPage": the adapter's
// production source MUST invoke PruneExplanationsPage. A regression that
// silently rewired this Job to a different primitive would drop this
// token.
func TestAdapterCallsPrunePrimitive(t *testing.T) {
	src := readAdapterSource(t)
	if !strings.Contains(src, "PruneExplanationsPage") {
		t.Fatal("adapter source no longer references PruneExplanationsPage — the retention job must call exactly that primitive")
	}
	if strings.Contains(src, "SweepExpiringOverridesPage") {
		t.Fatal("adapter source references SweepExpiringOverridesPage — the retention job must not touch the override-sweep primitive")
	}
}

// ---- static: extra forbidden-token spellings ----

// TestRetentionAdapterNoExtraLoopSurfaces adds token spellings the
// merged dormancy guard does not check explicitly (time.NewTimer,
// time.Tick(), the bare "go func " spacing form).
func TestRetentionAdapterNoExtraLoopSurfaces(t *testing.T) {
	src := readAdapterSource(t)
	for _, needle := range []string{"time.NewTimer", "time.Tick(", "func (s *Scheduler) Run"} {
		if strings.Contains(src, needle) {
			t.Fatalf("forbidden surface %q present in adapter source — must stay dormant", needle)
		}
	}
}

// ---- static: no config creep ----

// TestAdapterDoesNotImportConfig pins that the adapter pulls in no
// configuration dependency (B4 PR-4 must add no config). An adapter
// reading config would be hidden behavior + a scope expansion.
func TestAdapterDoesNotImportConfig(t *testing.T) {
	for file, imports := range adapterImports(t) {
		for _, path := range imports {
			if path == "github.com/kidcarmi/anchorix/backend/internal/config" {
				t.Fatalf("%s imports internal/config — the retention adapter must not read config (no config creep)", file)
			}
		}
	}
}

// ---- static: no migration creep ----

// TestNoMigrationReferencesRetentionJob asserts no SQL migration wires
// the retention job (e.g. by name). PR-4 adds no migration; the
// scheduler-state row is seeded at runtime, never in DDL. A migration
// mentioning the job name would be an out-of-band activation surface.
func TestNoMigrationReferencesRetentionJob(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	backendRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".."))
	migrationsDir := filepath.Join(backendRoot, "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(migrationsDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if strings.Contains(string(body), JobName) {
			t.Fatalf("migration %s references the retention job key %q — PR-4 adds no migration and must not wire the job in DDL", e.Name(), JobName)
		}
	}
}

// ---- helpers ----

// readAdapterSource returns the concatenated production (non-test,
// non-doc) source of the adapter package.
func readAdapterSource(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") || e.Name() == "doc.go" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		b.Write(body)
		b.WriteByte('\n')
	}
	return b.String()
}

// adapterImports returns a map of production-file-name -> import paths.
func adapterImports(t *testing.T) map[string][]string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	out := map[string][]string{}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, imp := range f.Imports {
			out[e.Name()] = append(out[e.Name()], strings.Trim(imp.Path.Value, `"`))
		}
	}
	return out
}

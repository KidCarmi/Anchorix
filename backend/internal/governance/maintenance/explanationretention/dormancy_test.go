package explanationretention

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRetentionAdapterIsDormant is the B4 PR-4 dormant-contract guard:
// this package is a thin Job ADAPTER only. Its production source must not
// contain a background-execution surface (Scheduler.Run loop, goroutine,
// ticker), an HTTP surface, a scheduler-state mutation, or a production
// registry/serve.go wiring. The adapter calls exactly one primitive
// (PruneExplanationsPage) and maps the result — nothing more. The sibling
// override-sweep job must not appear here (each job is independent).
func TestRetentionAdapterIsDormant(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	forbidden := []string{
		// Background-execution surfaces.
		"go func(",
		"go func ",
		"time.Ticker",
		"time.NewTicker",
		"time.NewTimer",
		"time.Tick(",
		"Scheduler.Run",
		"func (s *Scheduler) Run",
		// HTTP surfaces.
		"HandleFunc",
		"http.Handle",
		"http.HandlerFunc",
		"/api/v1",
		// Storage / audit layering: the adapter must not reach the DB
		// directly or emit its own audit (the primitive owns both).
		"storage/postgres",
		"audit.Record",
		// Scheduler-state mutation must not happen inside the adapter.
		"MarkJobStarted",
		"MarkJobCompleted",
		"MarkJobPartial",
		"MarkJobFailed",
		"UpsertJob",
		// The sibling override-sweep job must not leak into this package.
		"overridesweep",
		"SweepExpiringOverridesPage",
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		if e.Name() == "doc.go" {
			continue // pure boundary documentation; it names forbidden tokens to declare the rule
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		src := string(body)
		for _, needle := range forbidden {
			if strings.Contains(src, needle) {
				t.Fatalf("forbidden surface %q in %s — B4 PR-4 retention adapter must stay a thin dormant adapter; add it in a deliberate later PR, not here", needle, e.Name())
			}
		}
	}
}

// TestAdapterImportsAreClean parses the adapter's production .go files
// and asserts the import graph excludes layers the adapter must never
// touch (stronger than substring scanning: it sees aliased/dot imports).
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
		"github.com/kidcarmi/anchorix/backend/internal/governance/maintenance/overridesweep",
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
					t.Fatalf("%s imports forbidden package %q — the adapter must reach the primitive only through the injected ownership pruner, never the storage/http/audit layers or the sibling sweep job", e.Name(), path)
				}
			}
		}
	}
}

// TestNoProductionRegistryWiring scans the whole backend module (minus
// this adapter package and test files) and asserts NO production file
// references the adapter — confirming the job is not auto-registered,
// constructed, or invoked in production in PR-4.
func TestNoProductionRegistryWiring(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	adapterDir := filepath.Dir(thisFile)
	backendRoot := filepath.Clean(filepath.Join(adapterDir, "..", "..", "..", ".."))

	needles := []string{
		"explanationretention.NewJob",
		"explanationretention.JobName",
		"maintenance/explanationretention",
	}
	var offenders []string
	err := filepath.WalkDir(backendRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Dir(path) == adapterDir {
			return nil // the adapter's own source legitimately defines these
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
		t.Fatalf("explanation_retention_prune job is wired into production in PR-4 (must stay dormant):\n  %s", strings.Join(offenders, "\n  "))
	}
}

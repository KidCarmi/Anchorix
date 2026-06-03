package overridesweep

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestOverrideSweepAdapterIsDormant is the B4 PR-3 dormant-contract
// guard: this package is a thin Job ADAPTER only. Its production source
// must not contain a background-execution surface (Scheduler.Run loop,
// goroutine, ticker), an HTTP surface, a scheduler-state mutation, or a
// production registry/serve.go wiring. The adapter calls exactly one
// primitive (SweepExpiringOverridesPage) and maps the result — nothing
// more. The explanation-retention job is a SEPARATE PR-4 package and
// must not appear here.
//
// It also pins the package boundary: the adapter must NOT import
// storage/postgres (it goes through the injected ownership sweeper) and
// must not duplicate the audit layer.
func TestOverrideSweepAdapterIsDormant(t *testing.T) {
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
		// The sibling retention job must not leak into this package.
		"PruneExplanationsPage",
		"explanation_retention",
		// Scheduler-state mutation must not happen inside the adapter.
		"MarkJobStarted",
		"MarkJobCompleted",
		"MarkJobPartial",
		"MarkJobFailed",
		"UpsertJob",
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
				t.Fatalf("forbidden surface %q in %s — B4 PR-3 override-sweep adapter must stay a thin dormant adapter; add it in a deliberate later PR, not here", needle, e.Name())
			}
		}
	}
}

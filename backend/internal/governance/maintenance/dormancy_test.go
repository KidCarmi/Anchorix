package maintenance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMaintenancePackageIsDormant is the B4 PR-2 dormant-contract guard:
// the maintenance package ships the Job/registry/runner skeleton ONLY.
// Its production source must NOT contain a background-execution surface
// (Scheduler.Run tick loop, goroutine, ticker/timer) nor a call into the
// dormant H-027/H-029 maintenance primitives. The PR-3+ tick loop and the
// real job adapters are deliberate, separately-reviewed scope expansions.
//
// Substring-level on purpose: an author who needs one of these tokens
// must acknowledge they are crossing the dormant boundary.
func TestMaintenancePackageIsDormant(t *testing.T) {
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
		// Background-execution surfaces (the tick loop is PR-3+).
		"go func(",
		"time.Ticker",
		"time.NewTicker",
		"time.NewTimer",
		"func (s *Scheduler) Run",
		// HTTP surfaces.
		"HandleFunc",
		"http.Handle",
		"/api/v1",
		// Maintenance-primitive invocation (real adapters land PR-3/PR-4).
		"SweepExpiringOverridesPage",
		"PruneExplanationsPage",
		// The dormant primitives live in the ownership package; PR-2 must
		// not import it.
		"governance/ownership",
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		// doc.go is pure package documentation: it intentionally NAMES
		// the forbidden surfaces (Scheduler.Run, time.Ticker, the
		// primitives, the ownership import) to declare the boundary.
		// Scanning it would flag the very prose that defines the rule.
		// The executable files (job.go, registry.go, runner.go) carry
		// the real guard.
		if e.Name() == "doc.go" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		src := string(body)
		for _, needle := range forbidden {
			if strings.Contains(src, needle) {
				t.Fatalf("forbidden surface %q in %s — B4 PR-2 maintenance package must stay dormant (skeleton only); add it in a deliberate PR-3+ change", needle, e.Name())
			}
		}
	}
}

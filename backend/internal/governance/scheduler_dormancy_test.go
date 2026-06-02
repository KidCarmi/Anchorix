package governance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSchedulerDomainFileIsDormant is the B4 PR-1 dormant-contract guard
// for the domain-side scheduler types/interfaces. governance/scheduler.go
// must declare types + consumer-owned interfaces ONLY — no scheduler
// loop, goroutine, ticker, HTTP surface, or maintenance-primitive call.
// Scheduler.Run / JobRegistry / JobRunner land in B4 PR-2+ in a separate
// package; if any of these tokens appears here it is an undeclared scope
// expansion, caught in CI's unit phase long before integration.
func TestSchedulerDomainFileIsDormant(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate source file")
	}
	sourcePath := filepath.Join(filepath.Dir(thisFile), "scheduler.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	src := string(source)
	forbidden := []string{
		// Concurrency / loop surfaces
		"go func(",
		"time.Ticker",
		"time.NewTicker",
		"time.NewTimer",
		// HTTP surfaces
		"HandleFunc",
		"http.Handle",
		"/api/v1",
		// Maintenance-primitive invocation
		"SweepExpiringOverridesPage",
		"PruneExplanationsPage",
	}
	for _, needle := range forbidden {
		if strings.Contains(src, needle) {
			t.Fatalf("forbidden surface %q present in governance/scheduler.go — B4 PR-1 domain file must stay types+interfaces only; add behavior in a deliberate B4 PR-2+ scope expansion, not here", needle)
		}
	}
}

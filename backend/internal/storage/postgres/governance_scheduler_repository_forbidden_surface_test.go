package postgres

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSchedulerRepositoryHasNoForbiddenSurfaces is the B4 PR-1 dormant
// contract guard: the scheduler state repository must NOT grow a
// scheduler loop, background goroutine, ticker, or HTTP/router surface
// in this file. PR-1 ships persistence + a non-blocking lock helper
// ONLY; Scheduler.Run / JobRegistry / JobRunner / the tick loop land in
// B4 PR-2+ in the governance/maintenance package, not here. If a future
// PR genuinely needs one of these tokens, that is a deliberate scope
// expansion — not a quiet edit to this storage file.
//
// Substring-level on purpose (would flag a comment mention too): an
// author who needs these tokens should at least acknowledge they are
// breaking the dormant contract.
func TestSchedulerRepositoryHasNoForbiddenSurfaces(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate source file")
	}
	sourcePath := filepath.Join(filepath.Dir(thisFile), "governance_scheduler_repository.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	src := string(source)
	forbidden := []string{
		// Concurrency / scheduler loop surfaces
		"go func(",
		"time.Ticker",
		"time.NewTicker",
		"time.NewTimer",
		// HTTP routing / handlers
		"HandleFunc",
		"http.Handle",
		"mux.Handle",
		"http.HandlerFunc",
		"/api/v1",
		// Maintenance-primitive invocation (must not be called from the
		// dormant state layer)
		"SweepExpiringOverridesPage",
		"PruneExplanationsPage",
	}
	for _, needle := range forbidden {
		if strings.Contains(src, needle) {
			t.Fatalf("forbidden surface %q present in governance_scheduler_repository.go — B4 PR-1 must stay dormant (no loop/goroutine/ticker/HTTP/primitive-call); add it in a deliberate B4 PR-2+ scope expansion, not here", needle)
		}
	}
}

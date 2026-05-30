package ownership

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSweepPrimitiveHasNoForbiddenSurfaces is a regression guard for
// the H-029 PR-2 dormant contract: the sweep primitive must NOT grow
// router / HTTP-handler / background-goroutine / scheduler surfaces in
// this file. If a future PR genuinely intends to add such a surface,
// the primitive is no longer "dormant" and that change should be a
// deliberate scope expansion (e.g. an H-029 PR-3 manual trigger or the
// B4 scheduler) — not a quiet edit to this file.
//
// The check is intentionally substring-level (it would flag a comment
// containing "HandleFunc" too). That's the right strictness: an
// author who needs to mention these tokens in a comment should at
// least acknowledge they are breaking the dormant contract, even if
// the comment is benign in isolation.
func TestSweepPrimitiveHasNoForbiddenSurfaces(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate source file")
	}
	sourcePath := filepath.Join(filepath.Dir(thisFile), "expiring_overrides_sweep.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	src := string(source)
	forbidden := []string{
		// HTTP routing / handlers
		"HandleFunc",
		"http.Handle",
		"mux.Handle",
		"http.HandlerFunc",
		// Concurrency surfaces
		"go func(",
		"time.Ticker",
		"time.NewTicker",
		// API path strings
		"/api/v1",
	}
	for _, needle := range forbidden {
		if strings.Contains(src, needle) {
			t.Fatalf("forbidden surface %q present in expiring_overrides_sweep.go — H-029 PR-2 sweep primitive must stay dormant; reintroduce in a deliberate H-029 PR-3 / B4 scope expansion, not here", needle)
		}
	}
}

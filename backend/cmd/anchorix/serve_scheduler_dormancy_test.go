package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestServeDoesNotWireGovernanceScheduler is the B4 PR-1 composition-root
// dormancy guard: cmd/anchorix must NOT construct or start the governance
// scheduler in this phase. serve.go wires the dormant scheduler state
// repository to NOTHING — there is no Scheduler.Run, no go-routine
// spawning it, and no scheduler-repository construction. PR-2 wires the
// loop in a deliberate, reviewed change; until then any of these tokens
// appearing in the composition root is an undeclared activation.
//
// Scanned tokens are scheduler-specific so this never collides with the
// existing findings.Scheduler wiring (a different type) the binary
// already starts.
func TestServeDoesNotWireGovernanceScheduler(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate source file")
	}
	dir := filepath.Dir(thisFile)
	forbidden := []string{
		"NewGovernanceSchedulerRepository",
		"SchedulerStateRepository",
		"SchedulerJobLocker",
		"TryLockOrgJob",
		"GovernanceScheduler{", // a future maintenance.Scheduler struct literal
		"maintenance.NewScheduler",
	}
	// Scan every composition-root source file (serve.go, main.go, ...).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		src := string(body)
		for _, needle := range forbidden {
			if strings.Contains(src, needle) {
				t.Fatalf("composition root %s references %q — B4 PR-1 must NOT wire the governance scheduler; activation belongs in a deliberate PR-2 change", e.Name(), needle)
			}
		}
	}
}

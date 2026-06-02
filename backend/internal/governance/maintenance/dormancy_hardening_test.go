package maintenance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMaintenanceDormancyHardening is an additive forbidden-surface
// guard for B4 PR-2 hardening. It complements the merged
// TestMaintenancePackageIsDormant with a few extra token forms the base
// guard does not check explicitly, so a future edit that introduces a
// background loop or a primitive call in any spelling is caught in CI's
// unit phase. Like the base guard it scans executable source only
// (doc.go is pure boundary documentation and intentionally names these
// tokens).
func TestMaintenanceDormancyHardening(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	// Extra spellings beyond the base guard's list.
	forbidden := []string{
		// Any reference to a Scheduler.Run tick loop, in declaration or
		// call form (base guard only checks the exact method-decl string).
		"Scheduler.Run",
		// HandlerFunc value form.
		"http.HandlerFunc",
		// time.Tick (the package-level convenience leaker).
		"time.Tick(",
		// Bare goroutine spawn without the "(" the base guard requires.
		"go func ",
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
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
				t.Fatalf("forbidden surface %q in %s — B4 PR-2 maintenance package must stay dormant; add it in a deliberate PR-3+ change", needle, e.Name())
			}
		}
	}
}

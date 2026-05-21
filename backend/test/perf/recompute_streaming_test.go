//go:build perf

package perf

import (
	"context"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/inventory/fixtures"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// TestPerfStreamingRecomputeSmallv01Baseline measures one
// streaming recompute against the Smallv01 fixture pre-seeded
// with steady-state findings. Logs the duration and counters
// so a follow-up PR (or operator running this manually) has
// a baseline number to compare against.
//
// Substantive wall-clock budget assertions are deferred to
// H-024C per H024_PERFORMANCE_PLAN.md §4.5 — landing them
// now would mean baking a number into the test without
// measured grounding. Today the test fails ONLY on hard
// errors (recompute returns err, or post-conditions miss).
func TestPerfStreamingRecomputeSmallv01Baseline(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	fleet, err := fixtures.NewFleetBuilder(2026, fixtures.Smallv01(), now).Build()
	if err != nil {
		t.Fatalf("fixtures.Build: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := fleet.WriteTo(ctx, db); err != nil {
		t.Fatalf("fleet.WriteTo: %v", err)
	}

	// Pre-seed findings so the recompute under test exercises
	// the steady-state diff (mostly Updates, a few Opens /
	// Resolves) rather than the cold-start path (all
	// Inserts). The H-024B byte-identical test covers
	// cold-start equivalence; this baseline exercises the
	// hot path.
	rules := findings.DefaultRules()
	inserted, _, _, err := fleet.PreSeedFindings(ctx, db, rules)
	if err != nil {
		t.Fatalf("PreSeedFindings: %v", err)
	}
	if inserted == 0 {
		t.Fatal("pre-seed inserted 0 findings; Smallv01 should produce some")
	}

	auditRec := postgres.NewAuditRecorder(db, clock.System{})
	certRepo := postgres.NewCertificateInventoryRepository(db)
	findingsRepo := postgres.NewFindingsRepository(db)
	svc, err := findings.NewService(findingsRepo, certRepo, db, auditRec, perfClock{now: now}, rules)
	if err != nil {
		t.Fatalf("findings.NewService: %v", err)
	}

	start := time.Now()
	result, err := svc.Recompute(ctx, findings.RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "perf-baseline",
	})
	duration := time.Since(start)
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}

	// Post-conditions that any healthy recompute must hit.
	// Failing here means the H-024B algorithm regressed in a
	// structural way the integration tier should already have
	// caught; the redundancy is cheap.
	if result.EvaluatedCertificates == 0 {
		t.Error("EvaluatedCertificates = 0; recompute did not visit any cert")
	}
	if result.LoadedCertificates == 0 {
		t.Error("LoadedCertificates = 0; H-024B audit metadata not populated")
	}
	// LoadedFindings can be 0 in this fixture if pre-seed
	// inserted only into open-status rows; the streaming page
	// loop still walks them. We assert > 0 against the
	// pre-seeded baseline.
	if result.LoadedFindings != inserted {
		t.Errorf("LoadedFindings = %d, want %d (pre-seeded)", result.LoadedFindings, inserted)
	}

	t.Logf("Smallv01 streaming recompute baseline: duration=%s evaluated=%d loaded_certs=%d loaded_findings=%d opened=%d updated=%d resolved=%d unchanged=%d",
		duration,
		result.EvaluatedCertificates, result.LoadedCertificates, result.LoadedFindings,
		result.Opened, result.Updated, result.Resolved, result.Unchanged)
}

// perfClock is the perf-tier clock fake. Kept local to this
// file; if a third test arrives, it can be hoisted into a
// shared helper.
type perfClock struct{ now time.Time }

func (c perfClock) Now() time.Time { return c.now }

//go:build stress

package stress

import (
	"context"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/inventory/fixtures"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// TestStressStreamingRecomputePilotBaseline measures one
// streaming recompute against the Pilot fleet
// (1K agents, 5K certs, ~120K observations) pre-seeded with
// steady-state findings. Logs the duration and counters as a
// baseline.
//
// On-demand only (`//go:build stress`). The substantive
// pilot-budget wall-clock assertions land in H-024C once an
// operator-confirmed baseline exists; today the test fails
// only on hard errors.
func TestStressStreamingRecomputePilotBaseline(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)

	startBuild := time.Now()
	fleet, err := fixtures.NewFleetBuilder(2026, fixtures.Pilot(), now).Build()
	if err != nil {
		t.Fatalf("fixtures.Build: %v", err)
	}
	t.Logf("Pilot build: agents=%d certs=%d observations=%d duration=%s",
		len(fleet.Agents), len(fleet.Certificates), len(fleet.Observations),
		time.Since(startBuild))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	startWrite := time.Now()
	if err := fleet.WriteTo(ctx, db); err != nil {
		t.Fatalf("fleet.WriteTo: %v", err)
	}
	t.Logf("Pilot write: duration=%s", time.Since(startWrite))

	rules := findings.DefaultRules()

	startSeed := time.Now()
	inserted, _, _, err := fleet.PreSeedFindings(ctx, db, rules)
	if err != nil {
		t.Fatalf("PreSeedFindings: %v", err)
	}
	t.Logf("Pilot pre-seed: inserted=%d duration=%s", inserted, time.Since(startSeed))

	auditRec := postgres.NewAuditRecorder(db, clock.System{})
	certRepo := postgres.NewCertificateInventoryRepository(db)
	findingsRepo := postgres.NewFindingsRepository(db)
	svc, err := findings.NewService(findingsRepo, certRepo, db, auditRec, stressClock{now: now}, rules)
	if err != nil {
		t.Fatalf("findings.NewService: %v", err)
	}

	startRecompute := time.Now()
	result, err := svc.Recompute(ctx, findings.RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "stress-baseline",
	})
	recomputeDuration := time.Since(startRecompute)
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}

	if result.EvaluatedCertificates == 0 {
		t.Error("EvaluatedCertificates = 0 at pilot scale; recompute did not visit any cert")
	}

	t.Logf("Pilot streaming recompute baseline: duration=%s evaluated=%d loaded_certs=%d loaded_findings=%d opened=%d updated=%d resolved=%d unchanged=%d",
		recomputeDuration,
		result.EvaluatedCertificates, result.LoadedCertificates, result.LoadedFindings,
		result.Opened, result.Updated, result.Resolved, result.Unchanged)
}

type stressClock struct{ now time.Time }

func (c stressClock) Now() time.Time { return c.now }

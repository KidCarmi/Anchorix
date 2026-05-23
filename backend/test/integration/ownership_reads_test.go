//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// seedOwnershipRow writes one explanation + one certificate_ownership
// row for certID with the supplied last_evaluated_at. The cert and
// service must already exist.
func seedOwnershipRow(
	t *testing.T,
	repo *postgres.OwnershipRepository,
	ctx context.Context,
	certID, svcID string,
	lastEval time.Time,
) {
	t.Helper()
	exp := &governance.OwnershipMatchExplanation{
		ID:               "exp-" + certID,
		OrganizationID:   "anchorix",
		CertificateID:    certID,
		DecidedAt:        lastEval,
		DecidedDecision:  governance.DecisionMatched,
		DecidedServiceID: &svcID,
		LosingRules:      json.RawMessage(`[]`),
		SignalsSeen:      json.RawMessage(`{}`),
		EngineVersion:    1,
	}
	if err := repo.CreateOwnershipExplanation(ctx, exp); err != nil {
		t.Fatalf("seed explanation %s: %v", certID, err)
	}
	co := &governance.CertificateOwnership{
		OrganizationID:  "anchorix",
		CertificateID:   certID,
		ServiceID:       &svcID,
		Decision:        governance.DecisionMatched,
		ExplanationID:   exp.ID,
		Confidence:      governance.ConfidenceLow,
		FirstAssignedAt: lastEval,
		LastEvaluatedAt: lastEval,
		LastChangedAt:   lastEval,
	}
	if err := repo.UpsertCertificateOwnership(ctx, co); err != nil {
		t.Fatalf("seed ownership %s: %v", certID, err)
	}
}

// TestListOwnershipRulesForEngineOrdering pins the deterministic
// engine walk order (ladder ordinal → priority → created_at → id)
// and that disabled rules are excluded — the ordering is the §4.2
// ladder, NOT the lexical text order of the tier enum.
func TestListOwnershipRulesForEngineOrdering(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t0 := time.Now().UTC()

	seedService(t, db, ctx, "svc-eng-1")
	mk := func(id string, tier governance.PrecedenceTier, kind governance.MatchKind, prio int, created time.Time, enabled bool) {
		r := &governance.OwnershipRule{
			ID:             id,
			OrganizationID: "anchorix",
			Name:           id,
			ServiceID:      "svc-eng-1",
			PrecedenceTier: tier,
			Priority:       prio,
			MatchKind:      kind,
			MatchValue:     "x",
			Enabled:        enabled,
			CreatedAt:      created,
			UpdatedAt:      created,
			CreatedBy:      "tester",
		}
		if err := repo.CreateOwnershipRule(ctx, r); err != nil {
			t.Fatalf("create rule %s: %v", id, err)
		}
		if !enabled {
			if err := repo.DisableOwnershipRule(ctx, "anchorix", id); err != nil {
				t.Fatalf("disable rule %s: %v", id, err)
			}
		}
	}

	// Intentionally insert out of ladder order. 'fallback' sorts
	// BEFORE 'explicit' lexically — if the read used text order it
	// would be wrong.
	mk("r-fallback", governance.PrecedenceFallback, governance.MatchFallback, 1, t0, true)
	mk("r-explicit", governance.PrecedenceExplicit, governance.MatchTag, 100, t0, true)
	mk("r-agent", governance.PrecedenceAgentGroup, governance.MatchAgentGroup, 100, t0, true)
	mk("r-san-late", governance.PrecedenceSANPattern, governance.MatchSANGlob, 100, t0.Add(time.Minute), true)
	mk("r-san-early", governance.PrecedenceSANPattern, governance.MatchSANGlob, 100, t0, true)
	mk("r-san-lowprio", governance.PrecedenceSANPattern, governance.MatchSANGlob, 200, t0, true)
	mk("r-disabled", governance.PrecedenceSANPattern, governance.MatchSANGlob, 1, t0, false)

	rules, err := repo.ListOwnershipRulesForEngine(ctx, "anchorix")
	if err != nil {
		t.Fatalf("ListOwnershipRulesForEngine: %v", err)
	}
	gotIDs := make([]string, len(rules))
	for i, r := range rules {
		gotIDs[i] = r.ID
	}
	want := []string{
		"r-explicit",    // tier 1
		"r-agent",       // tier 3
		"r-san-early",   // tier 4, prio 100, earliest created_at
		"r-san-late",    // tier 4, prio 100, later created_at
		"r-san-lowprio", // tier 4, prio 200
		"r-fallback",    // tier 8
	}
	if len(gotIDs) != len(want) {
		t.Fatalf("engine rules = %v; want %v (disabled excluded)", gotIDs, want)
	}
	for i := range want {
		if gotIDs[i] != want[i] {
			t.Fatalf("engine order = %v; want %v", gotIDs, want)
		}
	}
}

// TestListCertificateOwnershipPaged walks the derived-ownership read
// in small pages and asserts ordered, disjoint, complete coverage.
func TestListCertificateOwnershipPaged(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-co-paged")
	const n = 5
	for i := 0; i < n; i++ {
		id := "cert-co-pg-" + string(rune('a'+i))
		seedCertificate(t, db, ctx, id)
		seedOwnershipRow(t, repo, ctx, id, "svc-co-paged", now)
	}

	seen := map[string]bool{}
	cursor := ""
	var last string
	for {
		page, err := repo.ListCertificateOwnershipPaged(ctx, "anchorix", cursor, 2)
		if err != nil {
			t.Fatalf("page: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, o := range page {
			if seen[o.CertificateID] {
				t.Fatalf("duplicate across pages: %s", o.CertificateID)
			}
			seen[o.CertificateID] = true
			if last != "" && o.CertificateID <= last {
				t.Fatalf("not ascending: %s after %s", o.CertificateID, last)
			}
			last = o.CertificateID
		}
		cursor = page[len(page)-1].CertificateID
		if len(page) < 2 {
			break
		}
	}
	if len(seen) != n {
		t.Fatalf("covered %d rows; want %d", len(seen), n)
	}
}

// TestListCertificateOwnershipStale returns only rows last evaluated
// before the threshold, paged and ordered.
func TestListCertificateOwnershipStale(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-stale")
	// Two stale (evaluated 10 days ago), one fresh (now).
	seedCertificate(t, db, ctx, "cert-stale-a")
	seedCertificate(t, db, ctx, "cert-stale-b")
	seedCertificate(t, db, ctx, "cert-fresh")
	staleAt := now.Add(-10 * 24 * time.Hour)
	seedOwnershipRow(t, repo, ctx, "cert-stale-a", "svc-stale", staleAt)
	seedOwnershipRow(t, repo, ctx, "cert-stale-b", "svc-stale", staleAt)
	seedOwnershipRow(t, repo, ctx, "cert-fresh", "svc-stale", now)

	threshold := now.Add(-7 * 24 * time.Hour)
	stale, err := repo.ListCertificateOwnershipStale(ctx, "anchorix", threshold, "", 100)
	if err != nil {
		t.Fatalf("ListCertificateOwnershipStale: %v", err)
	}
	if len(stale) != 2 {
		t.Fatalf("stale = %d rows; want 2 (%+v)", len(stale), stale)
	}
	for _, o := range stale {
		if o.CertificateID == "cert-fresh" {
			t.Fatalf("fresh row returned as stale")
		}
	}

	// Paging: first page of one, then the rest.
	page1, err := repo.ListCertificateOwnershipStale(ctx, "anchorix", threshold, "", 1)
	if err != nil {
		t.Fatalf("stale page1: %v", err)
	}
	if len(page1) != 1 || page1[0].CertificateID != "cert-stale-a" {
		t.Fatalf("stale page1 = %+v; want [cert-stale-a]", page1)
	}
	page2, err := repo.ListCertificateOwnershipStale(ctx, "anchorix", threshold, page1[0].CertificateID, 100)
	if err != nil {
		t.Fatalf("stale page2: %v", err)
	}
	if len(page2) != 1 || page2[0].CertificateID != "cert-stale-b" {
		t.Fatalf("stale page2 = %+v; want [cert-stale-b]", page2)
	}
}

// TestListActiveOwnershipOverridesPaged returns only active overrides
// (cleared excluded), keyed by certificate id, paged and ordered.
func TestListActiveOwnershipOverridesPaged(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-ovr-pg")
	for _, c := range []string{"cert-ovr-a", "cert-ovr-b", "cert-ovr-c"} {
		seedCertificate(t, db, ctx, c)
	}
	mkOverride := func(id, certID string) {
		if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
			ID:             id,
			OrganizationID: "anchorix",
			CertificateID:  certID,
			ServiceID:      "svc-ovr-pg",
			Reason:         "pin",
			SetBy:          "tester",
			SetAt:          now,
		}); err != nil {
			t.Fatalf("create override %s: %v", id, err)
		}
	}
	mkOverride("ovr-a", "cert-ovr-a")
	mkOverride("ovr-b", "cert-ovr-b")
	mkOverride("ovr-c", "cert-ovr-c")
	// Clear the one on cert-ovr-b — it must drop out of the active set.
	if err := repo.ClearOwnershipOverride(ctx, "anchorix", "ovr-b", "tester", "rotated", now.Add(time.Hour)); err != nil {
		t.Fatalf("clear override: %v", err)
	}

	active, err := repo.ListActiveOwnershipOverridesPaged(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("ListActiveOwnershipOverridesPaged: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("active = %d; want 2 (%+v)", len(active), active)
	}
	if active[0].CertificateID != "cert-ovr-a" || active[1].CertificateID != "cert-ovr-c" {
		t.Fatalf("active order = %s,%s; want cert-ovr-a,cert-ovr-c", active[0].CertificateID, active[1].CertificateID)
	}

	// Paging by certificate id.
	page1, err := repo.ListActiveOwnershipOverridesPaged(ctx, "anchorix", "", 1)
	if err != nil {
		t.Fatalf("active page1: %v", err)
	}
	if len(page1) != 1 || page1[0].CertificateID != "cert-ovr-a" {
		t.Fatalf("active page1 = %+v", page1)
	}
	page2, err := repo.ListActiveOwnershipOverridesPaged(ctx, "anchorix", page1[0].CertificateID, 100)
	if err != nil {
		t.Fatalf("active page2: %v", err)
	}
	if len(page2) != 1 || page2[0].CertificateID != "cert-ovr-c" {
		t.Fatalf("active page2 = %+v", page2)
	}
}

// TestListOverridesExpiringBy returns only active overrides whose
// expiry has passed — future, no-expiry, and cleared rows excluded.
func TestListOverridesExpiringBy(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-exp")
	for _, c := range []string{"cert-exp-a", "cert-exp-b", "cert-exp-c", "cert-exp-d"} {
		seedCertificate(t, db, ctx, c)
	}
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	mk := func(id, certID string, expires *time.Time) {
		if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
			ID:             id,
			OrganizationID: "anchorix",
			CertificateID:  certID,
			ServiceID:      "svc-exp",
			Reason:         "pin",
			SetBy:          "tester",
			SetAt:          now.Add(-2 * time.Hour),
			ExpiresAt:      expires,
		}); err != nil {
			t.Fatalf("create override %s: %v", id, err)
		}
	}
	mk("exp-past", "cert-exp-a", &past)     // expired + active → returned
	mk("exp-future", "cert-exp-b", &future) // future → excluded
	mk("exp-none", "cert-exp-c", nil)       // no expiry → excluded
	mk("exp-cleared", "cert-exp-d", &past)  // expired but cleared → excluded
	if err := repo.ClearOwnershipOverride(ctx, "anchorix", "exp-cleared", "tester", "done", now); err != nil {
		t.Fatalf("clear: %v", err)
	}

	expiring, err := repo.ListOverridesExpiringBy(ctx, "anchorix", now)
	if err != nil {
		t.Fatalf("ListOverridesExpiringBy: %v", err)
	}
	if len(expiring) != 1 || expiring[0].ID != "exp-past" {
		t.Fatalf("expiring = %+v; want only exp-past", expiring)
	}
}

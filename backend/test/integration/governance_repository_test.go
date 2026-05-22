//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// TestOwnershipRuleRoundTrip exercises ownership_rules create /
// get / list / disable / enable / update / per-service list.
func TestOwnershipRuleRoundTrip(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	identityRepo := postgres.NewIdentityRepository(db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	svc := &identity.Service{
		ID:             "svc-rule-1",
		OrganizationID: "anchorix",
		Slug:           "svc-rule-1",
		DisplayName:    "Rule Target",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := identityRepo.CreateService(ctx, svc); err != nil {
		t.Fatalf("seed service: %v", err)
	}

	rule := &governance.OwnershipRule{
		ID:             "rule-rt-1",
		OrganizationID: "anchorix",
		Name:           "billing-san",
		ServiceID:      svc.ID,
		PrecedenceTier: governance.PrecedenceSANPattern,
		Priority:       100,
		MatchKind:      governance.MatchSANGlob,
		MatchValue:     "*.billing.corp.example",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      "tester",
	}
	if err := repo.CreateOwnershipRule(ctx, rule); err != nil {
		t.Fatalf("CreateOwnershipRule: %v", err)
	}

	got, err := repo.GetOwnershipRule(ctx, "anchorix", rule.ID)
	if err != nil {
		t.Fatalf("GetOwnershipRule: %v", err)
	}
	if got.PrecedenceTier != governance.PrecedenceSANPattern ||
		got.MatchKind != governance.MatchSANGlob ||
		got.MatchValue != "*.billing.corp.example" {
		t.Fatalf("rule mismatch: %+v", got)
	}

	// Update mutable fields.
	if err := repo.UpdateOwnershipRuleMutable(
		ctx, "anchorix", rule.ID, 50,
		"*.billing-prod.corp.example", "tighter match",
	); err != nil {
		t.Fatalf("UpdateOwnershipRuleMutable: %v", err)
	}
	got, err = repo.GetOwnershipRule(ctx, "anchorix", rule.ID)
	if err != nil {
		t.Fatalf("GetOwnershipRule after update: %v", err)
	}
	if got.Priority != 50 || got.MatchValue != "*.billing-prod.corp.example" {
		t.Fatalf("update did not stick: %+v", got)
	}

	// Disable + verify enabled-only list excludes the rule.
	if err := repo.DisableOwnershipRule(ctx, "anchorix", rule.ID); err != nil {
		t.Fatalf("DisableOwnershipRule: %v", err)
	}
	got, err = repo.GetOwnershipRule(ctx, "anchorix", rule.ID)
	if err != nil {
		t.Fatalf("GetOwnershipRule after disable: %v", err)
	}
	if got.Enabled {
		t.Fatalf("rule still enabled after DisableOwnershipRule")
	}
	if got.DisabledAt == nil {
		t.Fatalf("disabled_at not stamped")
	}
	enabled, err := repo.ListOwnershipRules(ctx, "anchorix", true)
	if err != nil {
		t.Fatalf("ListOwnershipRules enabledOnly: %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("ListOwnershipRules enabledOnly = %d; want 0", len(enabled))
	}
	all, err := repo.ListOwnershipRules(ctx, "anchorix", false)
	if err != nil {
		t.Fatalf("ListOwnershipRules all: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("ListOwnershipRules all = %d; want 1", len(all))
	}

	// Re-enable.
	if err := repo.EnableOwnershipRule(ctx, "anchorix", rule.ID); err != nil {
		t.Fatalf("EnableOwnershipRule: %v", err)
	}
	got, err = repo.GetOwnershipRule(ctx, "anchorix", rule.ID)
	if err != nil {
		t.Fatalf("GetOwnershipRule after enable: %v", err)
	}
	if !got.Enabled || got.DisabledAt != nil {
		t.Fatalf("enable did not clear flags: %+v", got)
	}

	// Per-service list.
	byService, err := repo.ListOwnershipRulesByService(ctx, "anchorix", svc.ID)
	if err != nil {
		t.Fatalf("ListOwnershipRulesByService: %v", err)
	}
	if len(byService) != 1 || byService[0].ID != rule.ID {
		t.Fatalf("ListOwnershipRulesByService = %+v", byService)
	}

	// Cross-org get is not-found.
	if _, err := repo.GetOwnershipRule(ctx, "other", rule.ID); !errors.Is(err, governance.ErrOwnershipRuleNotFound) {
		t.Fatalf("cross-org GetOwnershipRule = %v; want ErrOwnershipRuleNotFound", err)
	}
}

// TestCertificateOwnershipUpsertAndQueries exercises the
// derived-state UPSERT plus the by-service / by-decision list
// methods used by the H-026B engine and operator triage views.
func TestCertificateOwnershipUpsertAndQueries(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	// Seed two certs, one service, one fallback rule, one
	// explanation per cert.
	for _, id := range []string{"cert-co-1", "cert-co-2"} {
		seedCertificate(t, db, ctx, id)
	}
	svcID := "svc-co-1"
	seedService(t, db, ctx, svcID)

	rule := &governance.OwnershipRule{
		ID:             "rule-co-1",
		OrganizationID: "anchorix",
		Name:           "fallback-co",
		ServiceID:      svcID,
		PrecedenceTier: governance.PrecedenceFallback,
		Priority:       1000,
		MatchKind:      governance.MatchFallback,
		MatchValue:     "",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      "tester",
	}
	if err := repo.CreateOwnershipRule(ctx, rule); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	// One explanation per cert.
	for i, certID := range []string{"cert-co-1", "cert-co-2"} {
		exp := &governance.OwnershipMatchExplanation{
			ID:               "exp-co-" + certID,
			OrganizationID:   "anchorix",
			CertificateID:    certID,
			DecidedAt:        now.Add(time.Duration(i) * time.Second),
			DecidedDecision:  governance.DecisionMatched,
			DecidedServiceID: &svcID,
			WinningRuleID:    &rule.ID,
			LosingRules:      json.RawMessage(`[]`),
			SignalsSeen:      json.RawMessage(`{}`),
			EngineVersion:    1,
		}
		if err := repo.CreateOwnershipExplanation(ctx, exp); err != nil {
			t.Fatalf("CreateOwnershipExplanation %s: %v", certID, err)
		}
		co := &governance.CertificateOwnership{
			OrganizationID:  "anchorix",
			CertificateID:   certID,
			ServiceID:       &svcID,
			Decision:        governance.DecisionMatched,
			WinningRuleID:   &rule.ID,
			ExplanationID:   exp.ID,
			Confidence:      governance.ConfidenceLow,
			FirstAssignedAt: now,
			LastEvaluatedAt: now,
			LastChangedAt:   now,
		}
		if err := repo.UpsertCertificateOwnership(ctx, co); err != nil {
			t.Fatalf("UpsertCertificateOwnership %s: %v", certID, err)
		}
	}

	// By-service list returns both certs.
	byService, err := repo.ListCertificateOwnershipByService(ctx, "anchorix", svcID)
	if err != nil {
		t.Fatalf("ListCertificateOwnershipByService: %v", err)
	}
	if len(byService) != 2 {
		t.Fatalf("ListCertificateOwnershipByService = %d; want 2", len(byService))
	}

	// Move one cert to unowned (UPSERT replaces the row).
	expUnowned := &governance.OwnershipMatchExplanation{
		ID:              "exp-co-unowned",
		OrganizationID:  "anchorix",
		CertificateID:   "cert-co-1",
		DecidedAt:       now.Add(time.Minute),
		DecidedDecision: governance.DecisionUnowned,
		LosingRules:     json.RawMessage(`[]`),
		SignalsSeen:     json.RawMessage(`{}`),
		EngineVersion:   1,
	}
	if err := repo.CreateOwnershipExplanation(ctx, expUnowned); err != nil {
		t.Fatalf("CreateOwnershipExplanation unowned: %v", err)
	}
	if err := repo.UpsertCertificateOwnership(ctx, &governance.CertificateOwnership{
		OrganizationID:  "anchorix",
		CertificateID:   "cert-co-1",
		Decision:        governance.DecisionUnowned,
		ExplanationID:   expUnowned.ID,
		Confidence:      governance.ConfidenceLow,
		FirstAssignedAt: now,
		LastEvaluatedAt: now.Add(time.Minute),
		LastChangedAt:   now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("UpsertCertificateOwnership unowned: %v", err)
	}

	unowned, err := repo.ListCertificateOwnershipByDecision(ctx, "anchorix", governance.DecisionUnowned)
	if err != nil {
		t.Fatalf("ListCertificateOwnershipByDecision: %v", err)
	}
	if len(unowned) != 1 || unowned[0].CertificateID != "cert-co-1" {
		t.Fatalf("unowned list = %+v", unowned)
	}

	byService, err = repo.ListCertificateOwnershipByService(ctx, "anchorix", svcID)
	if err != nil {
		t.Fatalf("ListCertificateOwnershipByService after move: %v", err)
	}
	if len(byService) != 1 || byService[0].CertificateID != "cert-co-2" {
		t.Fatalf("byService after move = %+v", byService)
	}

	// Cross-org returns empty (not-found semantics for lists).
	got, err := repo.ListCertificateOwnershipByService(ctx, "other", svcID)
	if err != nil {
		t.Fatalf("cross-org list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("cross-org list = %d rows; want 0", len(got))
	}
}

// TestOwnershipOverrideLifecycle exercises the override
// create / get-active / clear sequence and the
// historical-cleared-then-fresh-active behavior the partial
// unique index enables.
func TestOwnershipOverrideLifecycle(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedCertificate(t, db, ctx, "cert-ovr-1")
	seedService(t, db, ctx, "svc-ovr-1")

	o1 := &governance.CertificateOwnershipOverride{
		ID:             "ovr-life-1",
		OrganizationID: "anchorix",
		CertificateID:  "cert-ovr-1",
		ServiceID:      "svc-ovr-1",
		Reason:         "operator pin",
		SetBy:          "tester",
		SetAt:          now,
	}
	if err := repo.CreateOwnershipOverride(ctx, o1); err != nil {
		t.Fatalf("CreateOwnershipOverride: %v", err)
	}

	active, err := repo.GetActiveOwnershipOverride(ctx, "anchorix", "cert-ovr-1")
	if err != nil {
		t.Fatalf("GetActiveOwnershipOverride: %v", err)
	}
	if active == nil || active.ID != o1.ID {
		t.Fatalf("GetActiveOwnershipOverride = %+v", active)
	}

	// Clear and verify nil result.
	if err := repo.ClearOwnershipOverride(
		ctx, "anchorix", o1.ID, "tester", "rotated", now.Add(time.Hour),
	); err != nil {
		t.Fatalf("ClearOwnershipOverride: %v", err)
	}
	active, err = repo.GetActiveOwnershipOverride(ctx, "anchorix", "cert-ovr-1")
	if err != nil {
		t.Fatalf("GetActiveOwnershipOverride after clear: %v", err)
	}
	if active != nil {
		t.Fatalf("GetActiveOwnershipOverride returned non-nil after clear: %+v", active)
	}

	// The cleared row is still retrievable by id.
	got, err := repo.GetOwnershipOverride(ctx, "anchorix", o1.ID)
	if err != nil {
		t.Fatalf("GetOwnershipOverride after clear: %v", err)
	}
	if got.ClearedAt == nil || got.ClearedBy == nil || *got.ClearedBy != "tester" {
		t.Fatalf("cleared metadata not populated: %+v", got)
	}

	// Second clear of the same row is a no-op (no active row).
	err = repo.ClearOwnershipOverride(
		ctx, "anchorix", o1.ID, "tester", "again", now.Add(2*time.Hour),
	)
	if !errors.Is(err, governance.ErrOwnershipOverrideNotFound) {
		t.Fatalf("second clear = %v; want ErrOwnershipOverrideNotFound", err)
	}

	// Fresh override after the clear succeeds.
	o2 := &governance.CertificateOwnershipOverride{
		ID:             "ovr-life-2",
		OrganizationID: "anchorix",
		CertificateID:  "cert-ovr-1",
		ServiceID:      "svc-ovr-1",
		Reason:         "second pin",
		SetBy:          "tester",
		SetAt:          now.Add(2 * time.Hour),
	}
	if err := repo.CreateOwnershipOverride(ctx, o2); err != nil {
		t.Fatalf("CreateOwnershipOverride second: %v", err)
	}
}

// TestOwnershipExplanationTimeline exercises the per-cert
// explanation timeline read.
func TestOwnershipExplanationTimeline(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedCertificate(t, db, ctx, "cert-exp-1")

	// Three explanations across an hour.
	for i := 0; i < 3; i++ {
		exp := &governance.OwnershipMatchExplanation{
			ID:              "exp-tl-" + string(rune('A'+i)),
			OrganizationID:  "anchorix",
			CertificateID:   "cert-exp-1",
			DecidedAt:       now.Add(time.Duration(i) * time.Minute),
			DecidedDecision: governance.DecisionUnowned,
			LosingRules:     json.RawMessage(`[]`),
			SignalsSeen:     json.RawMessage(`{}`),
			EngineVersion:   1,
		}
		if err := repo.CreateOwnershipExplanation(ctx, exp); err != nil {
			t.Fatalf("CreateOwnershipExplanation %d: %v", i, err)
		}
	}

	all, err := repo.ListOwnershipExplanationsForCertificate(ctx, "anchorix", "cert-exp-1", 0)
	if err != nil {
		t.Fatalf("ListOwnershipExplanationsForCertificate: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("timeline = %d rows; want 3", len(all))
	}
	// Ordering is decided_at DESC — the newest row is first.
	if !all[0].DecidedAt.After(all[1].DecidedAt) {
		t.Fatalf("ordering not DESC: %+v", all)
	}

	// limit caps the response.
	limited, err := repo.ListOwnershipExplanationsForCertificate(ctx, "anchorix", "cert-exp-1", 2)
	if err != nil {
		t.Fatalf("limited timeline: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("limit not honored: got %d rows", len(limited))
	}
}

// TestPolicyDefinitionsLatestPerSlug exercises the
// versioned-definitions table and the "latest per slug" lookup.
func TestPolicyDefinitionsLatestPerSlug(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewPolicyRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	// Two versions of the same slug.
	for i, version := range []int{1, 2} {
		d := &governance.PolicyDefinition{
			ID:             "pol-ver-v" + string(rune('0'+i+1)),
			OrganizationID: "anchorix",
			Slug:           "pci-baseline",
			DisplayName:    "PCI Baseline",
			Rules:          json.RawMessage(`[]`),
			SchemaVersion:  1,
			Version:        version,
			CreatedAt:      now.Add(time.Duration(i) * time.Hour),
			UpdatedAt:      now.Add(time.Duration(i) * time.Hour),
			CreatedBy:      "tester",
		}
		if err := repo.CreatePolicyDefinition(ctx, d); err != nil {
			t.Fatalf("CreatePolicyDefinition v%d: %v", version, err)
		}
	}

	latest, err := repo.GetLatestPolicyDefinitionBySlug(ctx, "anchorix", "pci-baseline")
	if err != nil {
		t.Fatalf("GetLatestPolicyDefinitionBySlug: %v", err)
	}
	if latest.Version != 2 {
		t.Fatalf("latest version = %d; want 2", latest.Version)
	}

	// All versions list returns both.
	all, err := repo.ListPolicyDefinitions(ctx, "anchorix", true)
	if err != nil {
		t.Fatalf("ListPolicyDefinitions: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("list = %d; want 2", len(all))
	}

	// Unknown slug surfaces as ErrPolicyDefinitionNotFound.
	_, err = repo.GetLatestPolicyDefinitionBySlug(ctx, "anchorix", "missing")
	if !errors.Is(err, governance.ErrPolicyDefinitionNotFound) {
		t.Fatalf("unknown slug = %v; want ErrPolicyDefinitionNotFound", err)
	}
}

// TestPolicyAssignmentLifecycle exercises create / list /
// clear and the historical-cleared-then-fresh-active behavior.
func TestPolicyAssignmentLifecycle(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewPolicyRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedPolicyDefinition(t, db, ctx, "pol-pa-1", "pol-pa-1", 1)
	seedService(t, db, ctx, "svc-pa-1")

	a1 := &governance.PolicyAssignment{
		ID:                 "pa-life-1",
		OrganizationID:     "anchorix",
		PolicyDefinitionID: "pol-pa-1",
		ScopeKind:          governance.PolicyScopeService,
		ScopeID:            "svc-pa-1",
		AssignedBy:         "tester",
		AssignedAt:         now,
	}
	if err := repo.CreatePolicyAssignment(ctx, a1); err != nil {
		t.Fatalf("CreatePolicyAssignment: %v", err)
	}

	active, err := repo.ListActivePolicyAssignmentsForScope(
		ctx, "anchorix", governance.PolicyScopeService, "svc-pa-1",
	)
	if err != nil {
		t.Fatalf("ListActivePolicyAssignmentsForScope: %v", err)
	}
	if len(active) != 1 || active[0].ID != a1.ID {
		t.Fatalf("active list = %+v", active)
	}

	// Clear and verify list is empty.
	if err := repo.ClearPolicyAssignment(ctx, "anchorix", a1.ID, "tester", now.Add(time.Hour)); err != nil {
		t.Fatalf("ClearPolicyAssignment: %v", err)
	}
	active, err = repo.ListActivePolicyAssignmentsForScope(
		ctx, "anchorix", governance.PolicyScopeService, "svc-pa-1",
	)
	if err != nil {
		t.Fatalf("list after clear: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("list after clear = %d; want 0", len(active))
	}

	// Second clear is no-op.
	err = repo.ClearPolicyAssignment(ctx, "anchorix", a1.ID, "tester", now.Add(2*time.Hour))
	if !errors.Is(err, governance.ErrPolicyAssignmentNotFound) {
		t.Fatalf("second clear = %v; want ErrPolicyAssignmentNotFound", err)
	}

	// Fresh assignment after clear succeeds.
	a2 := &governance.PolicyAssignment{
		ID:                 "pa-life-2",
		OrganizationID:     "anchorix",
		PolicyDefinitionID: "pol-pa-1",
		ScopeKind:          governance.PolicyScopeService,
		ScopeID:            "svc-pa-1",
		AssignedBy:         "tester",
		AssignedAt:         now.Add(2 * time.Hour),
	}
	if err := repo.CreatePolicyAssignment(ctx, a2); err != nil {
		t.Fatalf("CreatePolicyAssignment second: %v", err)
	}

	// "For definition" view returns the still-active row only.
	forDef, err := repo.ListActivePolicyAssignmentsForDefinition(ctx, "anchorix", "pol-pa-1")
	if err != nil {
		t.Fatalf("ListActivePolicyAssignmentsForDefinition: %v", err)
	}
	if len(forDef) != 1 || forDef[0].ID != a2.ID {
		t.Fatalf("forDef = %+v", forDef)
	}
}

// TestPolicyWaiverLifecycle exercises waiver create / list /
// clear and the historical-cleared-then-fresh-active behavior.
func TestPolicyWaiverLifecycle(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewPolicyRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedPolicyDefinition(t, db, ctx, "pol-pw-1", "pol-pw-1", 1)
	seedService(t, db, ctx, "svc-pw-1")

	w1 := &governance.PolicyWaiver{
		ID:                 "pw-life-1",
		OrganizationID:     "anchorix",
		PolicyDefinitionID: "pol-pw-1",
		PolicyRuleLocalID:  "rule-min-rsa",
		ScopeKind:          governance.PolicyScopeService,
		ScopeID:            "svc-pw-1",
		Reason:             "vendor migration",
		GrantedBy:          "tester",
		GrantedAt:          now,
		ExpiresAt:          now.Add(30 * 24 * time.Hour),
	}
	if err := repo.CreatePolicyWaiver(ctx, w1); err != nil {
		t.Fatalf("CreatePolicyWaiver: %v", err)
	}

	active, err := repo.ListActivePolicyWaiversForScope(
		ctx, "anchorix", governance.PolicyScopeService, "svc-pw-1",
	)
	if err != nil {
		t.Fatalf("ListActivePolicyWaiversForScope: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("active waivers = %d; want 1", len(active))
	}

	if err := repo.ClearPolicyWaiver(ctx, "anchorix", w1.ID, "tester", now.Add(time.Hour)); err != nil {
		t.Fatalf("ClearPolicyWaiver: %v", err)
	}
	active, err = repo.ListActivePolicyWaiversForScope(
		ctx, "anchorix", governance.PolicyScopeService, "svc-pw-1",
	)
	if err != nil {
		t.Fatalf("list after clear: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("list after clear = %d; want 0", len(active))
	}

	err = repo.ClearPolicyWaiver(ctx, "anchorix", w1.ID, "tester", now.Add(2*time.Hour))
	if !errors.Is(err, governance.ErrPolicyWaiverNotFound) {
		t.Fatalf("second clear = %v; want ErrPolicyWaiverNotFound", err)
	}
}

// TestGovernanceRecomputeRunsLifecycle exercises the per-pass
// operational record: StartRecomputeRun → FinishRecomputeRun →
// ListRecentRecomputeRuns.
func TestGovernanceRecomputeRunsLifecycle(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewGovernanceRecomputeRunsRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	r := &governance.GovernanceRecomputeRun{
		ID:             "run-life-1",
		OrganizationID: "anchorix",
		Kind:           governance.RecomputeKindOwnership,
		StartedAt:      now,
		Actor:          "tester",
		ActorKind:      governance.RecomputeActorUser,
		EngineVersion:  1,
	}
	if err := repo.StartRecomputeRun(ctx, r); err != nil {
		t.Fatalf("StartRecomputeRun: %v", err)
	}

	got, err := repo.GetRecomputeRun(ctx, "anchorix", r.ID)
	if err != nil {
		t.Fatalf("GetRecomputeRun: %v", err)
	}
	if got.Succeeded != nil {
		t.Fatalf("Succeeded should be NULL pre-finish; got %v", got.Succeeded)
	}

	// Finish with counters + success flag.
	finished := now.Add(2 * time.Second)
	succeeded := true
	r.FinishedAt = &finished
	r.Succeeded = &succeeded
	r.EvaluatedCount = 42
	r.ChangedCount = 7
	r.UnchangedCount = 35
	r.BecameOwnedCount = 4
	r.BecameUnownedCount = 1
	r.FlippedOwnerCount = 2
	if err := repo.FinishRecomputeRun(ctx, r); err != nil {
		t.Fatalf("FinishRecomputeRun: %v", err)
	}

	got, err = repo.GetRecomputeRun(ctx, "anchorix", r.ID)
	if err != nil {
		t.Fatalf("GetRecomputeRun after finish: %v", err)
	}
	if got.Succeeded == nil || !*got.Succeeded {
		t.Fatalf("Succeeded not populated: %+v", got.Succeeded)
	}
	if got.EvaluatedCount != 42 || got.ChangedCount != 7 {
		t.Fatalf("counters not populated: %+v", got)
	}

	// Recent list returns the row in DESC order.
	recent, err := repo.ListRecentRecomputeRuns(ctx, "anchorix", governance.RecomputeKindOwnership, 10)
	if err != nil {
		t.Fatalf("ListRecentRecomputeRuns: %v", err)
	}
	if len(recent) != 1 || recent[0].ID != r.ID {
		t.Fatalf("recent list = %+v", recent)
	}

	// Different kind returns empty.
	other, err := repo.ListRecentRecomputeRuns(ctx, "anchorix", governance.RecomputeKindPolicy, 10)
	if err != nil {
		t.Fatalf("ListRecentRecomputeRuns policy: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("policy list = %d rows; want 0", len(other))
	}
}

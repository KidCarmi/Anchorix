//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// TestOwnershipExplanationJSONBDefaults pins the
// CreateOwnershipExplanation behavior when the caller supplies
// zero-valued LosingRules / SignalsSeen: the storage layer must
// substitute '[]'::jsonb for losing_rules (a JSONB array column
// with that default) and '{}'::jsonb for signals_seen (a JSONB
// object column with that default).
//
// The shape is enforced by the jsonValueOr helper. A regression
// that drops the second argument (or shares findings.jsonValue,
// which always returns '{}') would break the losing_rules
// default — silently turning an empty array into an empty
// object. Tests that read losing_rules as a JSON array would
// fail with a type mismatch; this test catches the storage-layer
// regression before any downstream code does.
func TestOwnershipExplanationJSONBDefaults(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedCertificate(t, db, ctx, "cert-jdef-1")

	// Caller passes zero-value json.RawMessage for both JSONB
	// columns. The storage layer must substitute defaults.
	exp := &governance.OwnershipMatchExplanation{
		ID:              "exp-jdef-1",
		OrganizationID:  "anchorix",
		CertificateID:   "cert-jdef-1",
		DecidedAt:       now,
		DecidedDecision: governance.DecisionUnowned,
		// LosingRules and SignalsSeen left as zero-value
		// (nil / empty) deliberately to exercise the defaults.
		EngineVersion: 1,
	}
	if err := repo.CreateOwnershipExplanation(ctx, exp); err != nil {
		t.Fatalf("CreateOwnershipExplanation: %v", err)
	}

	got, err := repo.GetOwnershipExplanation(ctx, "anchorix", exp.ID)
	if err != nil {
		t.Fatalf("GetOwnershipExplanation: %v", err)
	}

	// losing_rules must round-trip as a JSON array, NOT an
	// object. Parsing as []any pins the wire shape.
	var losing []any
	if err := json.Unmarshal(got.LosingRules, &losing); err != nil {
		t.Fatalf("LosingRules is not a JSON array: %v (raw=%s)", err, string(got.LosingRules))
	}
	if len(losing) != 0 {
		t.Fatalf("LosingRules expected empty array; got %v", losing)
	}

	// signals_seen must round-trip as a JSON object.
	var signals map[string]any
	if err := json.Unmarshal(got.SignalsSeen, &signals); err != nil {
		t.Fatalf("SignalsSeen is not a JSON object: %v (raw=%s)", err, string(got.SignalsSeen))
	}
	if len(signals) != 0 {
		t.Fatalf("SignalsSeen expected empty object; got %v", signals)
	}
}

// TestCrossOrgListIsolation verifies that every list method
// scopes by organization_id — a foreign org sees an empty list
// even when rows exist in another org. The schema CHECK
// constraints + composite FKs already enforce write-side
// isolation; this test pins the read side.
func TestCrossOrgListIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	identityRepo := postgres.NewIdentityRepository(db)
	ownershipRepo := postgres.NewOwnershipRepository(db)
	policyRepo := postgres.NewPolicyRepository(db)
	runsRepo := postgres.NewGovernanceRecomputeRunsRepository(db)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()

	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO organizations (id, name) VALUES ('other', 'Other')`, nil,
	}); err != nil {
		t.Fatalf("seed other org: %v", err)
	}

	// Populate 'anchorix' with one of every kind so each list
	// method has rows to NOT return for 'other'.
	if err := identityRepo.CreateTag(ctx, &identity.Tag{
		ID: "tag-x", OrganizationID: "anchorix", Key: "k", Value: "v",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	svcID := "svc-x"
	if err := identityRepo.CreateService(ctx, &identity.Service{
		ID: svcID, OrganizationID: "anchorix", Slug: "svc-x", DisplayName: "X",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	if err := identityRepo.CreateServiceGroup(ctx, &identity.ServiceGroup{
		ID: "sg-x", OrganizationID: "anchorix", Slug: "sg-x", DisplayName: "X",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed service_group: %v", err)
	}
	if err := identityRepo.CreateAgentGroup(ctx, &identity.AgentGroup{
		ID: "ag-x", OrganizationID: "anchorix", Slug: "ag-x", DisplayName: "X",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed agent_group: %v", err)
	}
	if err := ownershipRepo.CreateOwnershipRule(ctx, &governance.OwnershipRule{
		ID: "rule-x", OrganizationID: "anchorix", Name: "rule-x", ServiceID: svcID,
		PrecedenceTier: governance.PrecedenceFallback, Priority: 1000,
		MatchKind: governance.MatchFallback, MatchValue: "", Enabled: true,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "tester",
	}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	seedPolicyDefinition(t, db, ctx, "pol-x", "pol-x", 1)
	if err := policyRepo.CreatePolicyAssignment(ctx, &governance.PolicyAssignment{
		ID: "pa-x", OrganizationID: "anchorix", PolicyDefinitionID: "pol-x",
		ScopeKind: governance.PolicyScopeService, ScopeID: svcID,
		AssignedBy: "tester", AssignedAt: now,
	}); err != nil {
		t.Fatalf("seed policy_assignment: %v", err)
	}
	if err := policyRepo.CreatePolicyWaiver(ctx, &governance.PolicyWaiver{
		ID: "pw-x", OrganizationID: "anchorix", PolicyDefinitionID: "pol-x",
		PolicyRuleLocalID: "r1", ScopeKind: governance.PolicyScopeService, ScopeID: svcID,
		Reason: "tester", GrantedBy: "tester", GrantedAt: now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("seed policy_waiver: %v", err)
	}
	if err := runsRepo.StartRecomputeRun(ctx, &governance.GovernanceRecomputeRun{
		ID: "run-x", OrganizationID: "anchorix", Kind: governance.RecomputeKindOwnership,
		StartedAt: now, Actor: "tester", ActorKind: governance.RecomputeActorUser,
		EngineVersion: 1,
	}); err != nil {
		t.Fatalf("seed recompute_run: %v", err)
	}

	// Every list method must return empty for 'other'.
	checks := []struct {
		name string
		fn   func() (int, error)
	}{
		{"ListTags", func() (int, error) {
			out, err := identityRepo.ListTags(ctx, "other", false)
			return len(out), err
		}},
		{"ListServices", func() (int, error) {
			out, err := identityRepo.ListServices(ctx, "other", false)
			return len(out), err
		}},
		{"ListServiceGroups", func() (int, error) {
			out, err := identityRepo.ListServiceGroups(ctx, "other", false)
			return len(out), err
		}},
		{"ListAgentGroups", func() (int, error) {
			out, err := identityRepo.ListAgentGroups(ctx, "other", false)
			return len(out), err
		}},
		{"ListOwnershipRules", func() (int, error) {
			out, err := ownershipRepo.ListOwnershipRules(ctx, "other", false)
			return len(out), err
		}},
		{"ListOwnershipRulesByService", func() (int, error) {
			out, err := ownershipRepo.ListOwnershipRulesByService(ctx, "other", svcID)
			return len(out), err
		}},
		{"ListPolicyDefinitions", func() (int, error) {
			out, err := policyRepo.ListPolicyDefinitions(ctx, "other", false)
			return len(out), err
		}},
		{"ListActivePolicyAssignmentsForScope", func() (int, error) {
			out, err := policyRepo.ListActivePolicyAssignmentsForScope(
				ctx, "other", governance.PolicyScopeService, svcID)
			return len(out), err
		}},
		{"ListActivePolicyAssignmentsForDefinition", func() (int, error) {
			out, err := policyRepo.ListActivePolicyAssignmentsForDefinition(ctx, "other", "pol-x")
			return len(out), err
		}},
		{"ListActivePolicyWaiversForScope", func() (int, error) {
			out, err := policyRepo.ListActivePolicyWaiversForScope(
				ctx, "other", governance.PolicyScopeService, svcID)
			return len(out), err
		}},
		{"ListActivePolicyWaiversForDefinition", func() (int, error) {
			out, err := policyRepo.ListActivePolicyWaiversForDefinition(ctx, "other", "pol-x")
			return len(out), err
		}},
		{"ListRecentRecomputeRuns", func() (int, error) {
			out, err := runsRepo.ListRecentRecomputeRuns(
				ctx, "other", governance.RecomputeKindOwnership, 50)
			return len(out), err
		}},
	}

	for _, c := range checks {
		count, err := c.fn()
		if err != nil {
			t.Fatalf("%s for foreign org: %v", c.name, err)
		}
		if count != 0 {
			t.Fatalf("%s for foreign org returned %d rows; want 0 (org isolation leak)", c.name, count)
		}
	}

	// Same calls on the 'anchorix' org must return non-zero —
	// confirms the rows really exist and the empty results
	// above are isolation, not absence of data.
	tags, err := identityRepo.ListTags(ctx, "anchorix", false)
	if err != nil || len(tags) == 0 {
		t.Fatalf("anchorix ListTags = %d, err=%v; expected non-empty", len(tags), err)
	}
}

// TestServiceGroupMembershipCascadeAndRestrict pins the
// asymmetric FK policies on service_group_memberships:
// service_id ON DELETE CASCADE (deleting a service auto-removes
// memberships) and service_group_id ON DELETE RESTRICT
// (cannot delete a group while a service is membered in it).
// Both directions matter for the H-026A2 service-disable
// preflight check.
func TestServiceGroupMembershipCascadeAndRestrict(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	identityRepo := postgres.NewIdentityRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	if err := identityRepo.CreateService(ctx, &identity.Service{
		ID: "svc-mem-1", OrganizationID: "anchorix", Slug: "svc-mem-1",
		DisplayName: "Mem 1", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	if err := identityRepo.CreateServiceGroup(ctx, &identity.ServiceGroup{
		ID: "sg-mem-1", OrganizationID: "anchorix", Slug: "sg-mem-1",
		DisplayName: "Mem Group 1", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateServiceGroup: %v", err)
	}
	if err := identityRepo.SetServiceGroupMembership(ctx, &identity.ServiceGroupMembership{
		OrganizationID: "anchorix", ServiceID: "svc-mem-1",
		ServiceGroupID: "sg-mem-1", AssignedAt: now,
	}); err != nil {
		t.Fatalf("SetServiceGroupMembership: %v", err)
	}

	// RESTRICT direction: deleting the group while a
	// membership references it must fail.
	err := execRawSQL(ctx, db, rawStmt{
		`DELETE FROM service_groups WHERE id = 'sg-mem-1'`, nil,
	})
	if err == nil {
		t.Fatalf("service_group delete with active membership succeeded; RESTRICT should reject")
	}

	// CASCADE direction: deleting the service auto-removes
	// its memberships, freeing the group for delete.
	if err := execRawSQL(ctx, db, rawStmt{
		`DELETE FROM services WHERE id = 'svc-mem-1'`, nil,
	}); err != nil {
		t.Fatalf("service delete (cascading membership): %v", err)
	}
	// Confirm membership is gone.
	mems, err := identityRepo.ListServicesInGroup(ctx, "anchorix", "sg-mem-1")
	if err != nil {
		t.Fatalf("ListServicesInGroup after cascade: %v", err)
	}
	if len(mems) != 0 {
		t.Fatalf("membership not cascaded: %+v", mems)
	}
	// Now the group can be deleted.
	if err := execRawSQL(ctx, db, rawStmt{
		`DELETE FROM service_groups WHERE id = 'sg-mem-1'`, nil,
	}); err != nil {
		t.Fatalf("service_group delete after cascade: %v", err)
	}
}

// TestServiceGroupCleanupHandlesSelfFK exercises the
// freshDatabase ordering fix: after a parent-child
// service_groups setup, a subsequent freshDatabase call must
// successfully clear the table even though parent_id ON DELETE
// RESTRICT applies. The test deliberately establishes the
// parent-then-child setup and asserts the cleanup completes
// without error.
func TestServiceGroupCleanupHandlesSelfFK(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	identityRepo := postgres.NewIdentityRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	// Establish parent + child.
	if err := identityRepo.CreateServiceGroup(ctx, &identity.ServiceGroup{
		ID: "sg-fk-root", OrganizationID: "anchorix", Slug: "sg-fk-root",
		DisplayName: "Root", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateServiceGroup root: %v", err)
	}
	rootID := "sg-fk-root"
	if err := identityRepo.CreateServiceGroup(ctx, &identity.ServiceGroup{
		ID: "sg-fk-child", OrganizationID: "anchorix", Slug: "sg-fk-child",
		DisplayName: "Child", ParentID: &rootID,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateServiceGroup child: %v", err)
	}

	// Sanity: both rows exist.
	groups, err := identityRepo.ListServiceGroups(ctx, "anchorix", false)
	if err != nil {
		t.Fatalf("ListServiceGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 service_groups; got %d", len(groups))
	}

	// freshDatabase must succeed even with parent+child
	// referencing each other.
	freshDatabase(t, db)

	groups, err = identityRepo.ListServiceGroups(ctx, "anchorix", false)
	if err != nil {
		t.Fatalf("ListServiceGroups after fresh: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("service_groups not cleared by freshDatabase: %d rows remain", len(groups))
	}
}

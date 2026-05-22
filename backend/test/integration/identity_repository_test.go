//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/identity"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// TestIdentityTagsRoundTrip exercises the tag CRUD methods on
// identity.Repository.
func TestIdentityTagsRoundTrip(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewIdentityRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	t1 := &identity.Tag{
		ID:             "tag-rt-1",
		OrganizationID: "anchorix",
		Key:            "env",
		Value:          "prod",
		Description:    "production",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateTag(ctx, t1); err != nil {
		t.Fatalf("CreateTag: %v", err)
	}

	got, err := repo.GetTag(ctx, "anchorix", t1.ID)
	if err != nil {
		t.Fatalf("GetTag: %v", err)
	}
	if got.Key != "env" || got.Value != "prod" || got.Description != "production" {
		t.Fatalf("GetTag returned %+v", got)
	}

	// GetTagByKey resolves the same row.
	gotByKey, err := repo.GetTagByKey(ctx, "anchorix", "env", "prod")
	if err != nil {
		t.Fatalf("GetTagByKey: %v", err)
	}
	if gotByKey.ID != t1.ID {
		t.Fatalf("GetTagByKey id mismatch: %q", gotByKey.ID)
	}

	// ListTags includes the row.
	tags, err := repo.ListTags(ctx, "anchorix", true)
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 1 || tags[0].ID != t1.ID {
		t.Fatalf("ListTags = %+v", tags)
	}

	// Update description.
	if err := repo.UpdateTagDescription(ctx, "anchorix", t1.ID, "PROD environment"); err != nil {
		t.Fatalf("UpdateTagDescription: %v", err)
	}
	got, err = repo.GetTag(ctx, "anchorix", t1.ID)
	if err != nil {
		t.Fatalf("GetTag after update: %v", err)
	}
	if got.Description != "PROD environment" {
		t.Fatalf("description not updated: %q", got.Description)
	}

	// Disable + re-enable.
	if err := repo.DisableTag(ctx, "anchorix", t1.ID); err != nil {
		t.Fatalf("DisableTag: %v", err)
	}
	// activeOnly excludes disabled.
	activeTags, err := repo.ListTags(ctx, "anchorix", true)
	if err != nil {
		t.Fatalf("ListTags activeOnly: %v", err)
	}
	if len(activeTags) != 0 {
		t.Fatalf("ListTags activeOnly = %d rows; want 0", len(activeTags))
	}
	// includeAll surfaces it.
	allTags, err := repo.ListTags(ctx, "anchorix", false)
	if err != nil {
		t.Fatalf("ListTags all: %v", err)
	}
	if len(allTags) != 1 {
		t.Fatalf("ListTags all = %d rows; want 1", len(allTags))
	}
	if err := repo.EnableTag(ctx, "anchorix", t1.ID); err != nil {
		t.Fatalf("EnableTag: %v", err)
	}
	got, err = repo.GetTag(ctx, "anchorix", t1.ID)
	if err != nil {
		t.Fatalf("GetTag after enable: %v", err)
	}
	if got.DisabledAt != nil {
		t.Fatalf("disabled_at not cleared after EnableTag")
	}

	// Cross-org id collapses to not-found.
	if _, err := repo.GetTag(ctx, "other-org", t1.ID); !errors.Is(err, identity.ErrTagNotFound) {
		t.Fatalf("cross-org GetTag = %v; want ErrTagNotFound", err)
	}
}

// TestIdentityServicesRoundTrip exercises the services CRUD
// methods plus the disable-enable cycle.
func TestIdentityServicesRoundTrip(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewIdentityRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	svc := &identity.ServiceRecord{
		ID:             "svc-rt-1",
		OrganizationID: "anchorix",
		Slug:           "billing",
		DisplayName:    "Billing",
		OwnerTeam:      "payments",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateService(ctx, svc); err != nil {
		t.Fatalf("CreateService: %v", err)
	}

	got, err := repo.GetServiceBySlug(ctx, "anchorix", "billing")
	if err != nil {
		t.Fatalf("GetServiceBySlug: %v", err)
	}
	if got.ID != svc.ID {
		t.Fatalf("GetServiceBySlug id mismatch: %q", got.ID)
	}

	if err := repo.UpdateServiceMetadata(
		ctx, "anchorix", svc.ID,
		"Billing Service", "core billing", "billing@example.com", "payments-platform", "Finance",
	); err != nil {
		t.Fatalf("UpdateServiceMetadata: %v", err)
	}
	got, err = repo.GetService(ctx, "anchorix", svc.ID)
	if err != nil {
		t.Fatalf("GetService after update: %v", err)
	}
	if got.DisplayName != "Billing Service" || got.OwnerEmail != "billing@example.com" {
		t.Fatalf("metadata not updated: %+v", got)
	}

	if err := repo.DisableService(ctx, "anchorix", svc.ID); err != nil {
		t.Fatalf("DisableService: %v", err)
	}
	if err := repo.EnableService(ctx, "anchorix", svc.ID); err != nil {
		t.Fatalf("EnableService: %v", err)
	}
}

// TestIdentityServiceGroupsHierarchy exercises the
// service_groups parent-child shape and the membership
// upsert + clear flow.
func TestIdentityServiceGroupsHierarchy(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewIdentityRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	root := &identity.ServiceGroup{
		ID:             "sg-payments",
		OrganizationID: "anchorix",
		Slug:           "payments",
		DisplayName:    "Payments",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateServiceGroup(ctx, root); err != nil {
		t.Fatalf("CreateServiceGroup root: %v", err)
	}
	billingID := "sg-billing"
	billing := &identity.ServiceGroup{
		ID:             billingID,
		OrganizationID: "anchorix",
		Slug:           "billing-group",
		DisplayName:    "Billing",
		ParentID:       &root.ID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateServiceGroup(ctx, billing); err != nil {
		t.Fatalf("CreateServiceGroup billing: %v", err)
	}

	gotBilling, err := repo.GetServiceGroup(ctx, "anchorix", billingID)
	if err != nil {
		t.Fatalf("GetServiceGroup billing: %v", err)
	}
	if gotBilling.ParentID == nil || *gotBilling.ParentID != root.ID {
		t.Fatalf("parent id not persisted: %+v", gotBilling.ParentID)
	}

	// Set parent to NULL.
	if err := repo.UpdateServiceGroupParent(ctx, "anchorix", billingID, nil); err != nil {
		t.Fatalf("UpdateServiceGroupParent NULL: %v", err)
	}
	gotBilling, err = repo.GetServiceGroup(ctx, "anchorix", billingID)
	if err != nil {
		t.Fatalf("GetServiceGroup after re-parent: %v", err)
	}
	if gotBilling.ParentID != nil {
		t.Fatalf("parent not cleared")
	}

	// Service + membership.
	svc := &identity.ServiceRecord{
		ID:             "svc-checkout",
		OrganizationID: "anchorix",
		Slug:           "checkout",
		DisplayName:    "Checkout",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateService(ctx, svc); err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	if err := repo.SetServiceGroupMembership(ctx, &identity.ServiceGroupMembership{
		OrganizationID: "anchorix",
		ServiceID:      svc.ID,
		ServiceGroupID: root.ID,
		AssignedAt:     now,
	}); err != nil {
		t.Fatalf("SetServiceGroupMembership: %v", err)
	}
	mem, err := repo.GetServiceGroupMembership(ctx, "anchorix", svc.ID)
	if err != nil {
		t.Fatalf("GetServiceGroupMembership: %v", err)
	}
	if mem.ServiceGroupID != root.ID {
		t.Fatalf("membership group mismatch: %q", mem.ServiceGroupID)
	}

	// Re-set to a different group — UPSERT replaces.
	if err := repo.SetServiceGroupMembership(ctx, &identity.ServiceGroupMembership{
		OrganizationID: "anchorix",
		ServiceID:      svc.ID,
		ServiceGroupID: billingID,
		AssignedAt:     now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("SetServiceGroupMembership replace: %v", err)
	}
	mem, err = repo.GetServiceGroupMembership(ctx, "anchorix", svc.ID)
	if err != nil {
		t.Fatalf("GetServiceGroupMembership after replace: %v", err)
	}
	if mem.ServiceGroupID != billingID {
		t.Fatalf("UPSERT did not replace group: %q", mem.ServiceGroupID)
	}

	// Clear.
	if err := repo.ClearServiceGroupMembership(ctx, "anchorix", svc.ID); err != nil {
		t.Fatalf("ClearServiceGroupMembership: %v", err)
	}
	if _, err := repo.GetServiceGroupMembership(ctx, "anchorix", svc.ID); !errors.Is(err, identity.ErrServiceGroupMembershipNotFound) {
		t.Fatalf("GetServiceGroupMembership after clear = %v; want NotFound", err)
	}
}

// TestIdentityAgentGroupsMembership exercises agent_group
// creation and many-to-many memberships.
func TestIdentityAgentGroupsMembership(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewIdentityRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	// Seed an agent so we can attach memberships to a real row.
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO agents (id, organization_id, hostname, status, public_key_fingerprint)
		 VALUES ('agent-am-1', 'anchorix', 'host-1', 'active', 'fp-am-1')`,
		nil,
	}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	// agents needs the (organization_id, id) UNIQUE for the
	// composite FK from agent_group_memberships — this was added
	// in migration 0004, so it already exists.

	g1 := &identity.AgentGroup{
		ID:             "ag-dc",
		OrganizationID: "anchorix",
		Slug:           "domain-controllers",
		DisplayName:    "Domain Controllers",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	g2 := &identity.AgentGroup{
		ID:             "ag-pci",
		OrganizationID: "anchorix",
		Slug:           "pci-tier",
		DisplayName:    "PCI Tier",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	for _, g := range []*identity.AgentGroup{g1, g2} {
		if err := repo.CreateAgentGroup(ctx, g); err != nil {
			t.Fatalf("CreateAgentGroup %s: %v", g.ID, err)
		}
	}

	for _, gID := range []string{g1.ID, g2.ID} {
		if err := repo.AddAgentToGroup(ctx, &identity.AgentGroupMembership{
			OrganizationID: "anchorix",
			AgentID:        "agent-am-1",
			AgentGroupID:   gID,
			AssignedBy:     "tester",
			AssignedAt:     now,
		}); err != nil {
			t.Fatalf("AddAgentToGroup %s: %v", gID, err)
		}
	}

	groups, err := repo.ListGroupsForAgent(ctx, "anchorix", "agent-am-1")
	if err != nil {
		t.Fatalf("ListGroupsForAgent: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("ListGroupsForAgent = %d rows; want 2", len(groups))
	}

	agents, err := repo.ListAgentsInGroup(ctx, "anchorix", g1.ID)
	if err != nil {
		t.Fatalf("ListAgentsInGroup: %v", err)
	}
	if len(agents) != 1 || agents[0].AgentID != "agent-am-1" {
		t.Fatalf("ListAgentsInGroup = %+v", agents)
	}

	// Removing the membership leaves the other in place.
	if err := repo.RemoveAgentFromGroup(ctx, "anchorix", "agent-am-1", g1.ID); err != nil {
		t.Fatalf("RemoveAgentFromGroup: %v", err)
	}
	groups, err = repo.ListGroupsForAgent(ctx, "anchorix", "agent-am-1")
	if err != nil {
		t.Fatalf("ListGroupsForAgent after remove: %v", err)
	}
	if len(groups) != 1 || groups[0].AgentGroupID != g2.ID {
		t.Fatalf("remaining membership wrong: %+v", groups)
	}

	// Second remove is a not-found.
	if err := repo.RemoveAgentFromGroup(ctx, "anchorix", "agent-am-1", g1.ID); !errors.Is(err, identity.ErrAgentGroupMembershipNotFound) {
		t.Fatalf("second RemoveAgentFromGroup = %v; want NotFound", err)
	}
}

// TestIdentityTagAssignmentsByTarget verifies the assignment
// list-by-target query honors the polymorphic target tuple and
// stays org-scoped.
func TestIdentityTagAssignmentsByTarget(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewIdentityRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()

	// Two tags + one assignment each on the same target.
	for i, key := range []string{"env", "tier"} {
		tag := &identity.Tag{
			ID:             "tag-by-tgt-" + key,
			OrganizationID: "anchorix",
			Key:            key,
			Value:          "prod",
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := repo.CreateTag(ctx, tag); err != nil {
			t.Fatalf("CreateTag %d: %v", i, err)
		}
		if err := repo.CreateTagAssignment(ctx, &identity.TagAssignment{
			ID:             "ta-by-tgt-" + key,
			OrganizationID: "anchorix",
			TagID:          tag.ID,
			TargetType:     identity.TagTargetService,
			TargetID:       "svc-billing",
			AssignedBy:     "tester",
			AssignedAt:     now.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("CreateTagAssignment %d: %v", i, err)
		}
	}

	got, err := repo.ListTagAssignmentsForTarget(ctx, "anchorix", identity.TagTargetService, "svc-billing")
	if err != nil {
		t.Fatalf("ListTagAssignmentsForTarget: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListTagAssignmentsForTarget returned %d rows; want 2", len(got))
	}

	// Different target type, same id — must return empty (we
	// stored the assignments under target_type=service).
	got, err = repo.ListTagAssignmentsForTarget(ctx, "anchorix", identity.TagTargetCertificate, "svc-billing")
	if err != nil {
		t.Fatalf("ListTagAssignmentsForTarget cert: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListTagAssignmentsForTarget cert = %d; want 0", len(got))
	}

	// Cross-org returns empty regardless.
	got, err = repo.ListTagAssignmentsForTarget(ctx, "other", identity.TagTargetService, "svc-billing")
	if err != nil {
		t.Fatalf("ListTagAssignmentsForTarget cross-org: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListTagAssignmentsForTarget cross-org = %d; want 0", len(got))
	}

	// Delete one, list returns one.
	if err := repo.DeleteTagAssignmentByTarget(
		ctx, "anchorix", "tag-by-tgt-env",
		identity.TagTargetService, "svc-billing",
	); err != nil {
		t.Fatalf("DeleteTagAssignmentByTarget: %v", err)
	}
	got, err = repo.ListTagAssignmentsForTarget(ctx, "anchorix", identity.TagTargetService, "svc-billing")
	if err != nil {
		t.Fatalf("ListTagAssignmentsForTarget after delete: %v", err)
	}
	if len(got) != 1 || got[0].TagID != "tag-by-tgt-tier" {
		t.Fatalf("remaining assignment wrong: %+v", got)
	}
}

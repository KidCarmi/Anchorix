package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
)

// fixedClock returns the same instant on every Now() call.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

var _ clock.Clock = fixedClock{}

// ----- in-memory repository fake -----
//
// Captures the minimum surface the service touches. Real
// integration tests in test/integration exercise the postgres
// implementation; this file is for the service-layer rules.
type fakeRepo struct {
	tags         map[string]*Tag
	tagAsgmts    []TagAssignment
	services     map[string]*ServiceRecord
	serviceGrps  map[string]*ServiceGroup
	srvGrpMems   map[string]*ServiceGroupMembership // keyed by service_id
	agentGroups  map[string]*AgentGroup
	agentGrpMems []AgentGroupMembership

	// failOnUpdateTag: when true, UpdateTagDescription returns
	// a forced error so we can exercise audit-rollback paths.
	failOnUpdateTag bool

	// counters for audit-rollback assertions
	createTagCalls    int
	updateTagCalls    int
	tagAssignCalls    int
	createServiceHits int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		tags:        map[string]*Tag{},
		services:    map[string]*ServiceRecord{},
		serviceGrps: map[string]*ServiceGroup{},
		srvGrpMems:  map[string]*ServiceGroupMembership{},
		agentGroups: map[string]*AgentGroup{},
	}
}

func (r *fakeRepo) CreateTag(_ context.Context, t *Tag) error {
	r.createTagCalls++
	r.tags[t.ID] = t
	return nil
}
func (r *fakeRepo) GetTag(_ context.Context, _, id string) (*Tag, error) {
	if t, ok := r.tags[id]; ok {
		return t, nil
	}
	return nil, ErrTagNotFound
}
func (r *fakeRepo) GetTagByKey(_ context.Context, _, _, _ string) (*Tag, error) {
	return nil, ErrTagNotFound
}
func (r *fakeRepo) ListTags(_ context.Context, _ string, _ bool) ([]Tag, error) {
	out := make([]Tag, 0, len(r.tags))
	for _, t := range r.tags {
		out = append(out, *t)
	}
	return out, nil
}
func (r *fakeRepo) UpdateTagDescription(_ context.Context, _, id, desc string) error {
	r.updateTagCalls++
	if r.failOnUpdateTag {
		return errors.New("forced update failure")
	}
	t, ok := r.tags[id]
	if !ok {
		return ErrTagNotFound
	}
	t.Description = desc
	return nil
}
func (r *fakeRepo) DisableTag(_ context.Context, _, id string) error {
	t, ok := r.tags[id]
	if !ok {
		return ErrTagNotFound
	}
	if t.DisabledAt == nil {
		now := time.Now()
		t.DisabledAt = &now
	}
	return nil
}
func (r *fakeRepo) EnableTag(_ context.Context, _, id string) error {
	t, ok := r.tags[id]
	if !ok {
		return ErrTagNotFound
	}
	t.DisabledAt = nil
	return nil
}

func (r *fakeRepo) CreateTagAssignment(_ context.Context, a *TagAssignment) error {
	r.tagAssignCalls++
	r.tagAsgmts = append(r.tagAsgmts, *a)
	return nil
}
func (r *fakeRepo) DeleteTagAssignmentByTarget(_ context.Context, _, tagID string, tt TagTargetType, tid string) error {
	for i := range r.tagAsgmts {
		a := r.tagAsgmts[i]
		if a.TagID == tagID && a.TargetType == tt && a.TargetID == tid {
			r.tagAsgmts = append(r.tagAsgmts[:i], r.tagAsgmts[i+1:]...)
			return nil
		}
	}
	return ErrTagAssignmentNotFound
}
func (r *fakeRepo) ListTagAssignmentsForTarget(_ context.Context, _ string, tt TagTargetType, tid string) ([]TagAssignment, error) {
	var out []TagAssignment
	for _, a := range r.tagAsgmts {
		if a.TargetType == tt && a.TargetID == tid {
			out = append(out, a)
		}
	}
	return out, nil
}
func (r *fakeRepo) ListTagAssignmentsForTag(_ context.Context, _, tagID string) ([]TagAssignment, error) {
	var out []TagAssignment
	for _, a := range r.tagAsgmts {
		if a.TagID == tagID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *fakeRepo) CreateService(_ context.Context, s *ServiceRecord) error {
	r.createServiceHits++
	r.services[s.ID] = s
	return nil
}
func (r *fakeRepo) GetService(_ context.Context, _, id string) (*ServiceRecord, error) {
	if s, ok := r.services[id]; ok {
		return s, nil
	}
	return nil, ErrServiceNotFound
}
func (r *fakeRepo) GetServiceBySlug(_ context.Context, _, _ string) (*ServiceRecord, error) {
	return nil, ErrServiceNotFound
}
func (r *fakeRepo) ListServices(_ context.Context, _ string, _ bool) ([]ServiceRecord, error) {
	out := make([]ServiceRecord, 0, len(r.services))
	for _, s := range r.services {
		out = append(out, *s)
	}
	return out, nil
}
func (r *fakeRepo) UpdateServiceMetadata(_ context.Context, _, _ string, _, _, _, _, _ string) error {
	return nil
}
func (r *fakeRepo) DisableService(_ context.Context, _, _ string) error { return nil }
func (r *fakeRepo) EnableService(_ context.Context, _, _ string) error  { return nil }

func (r *fakeRepo) CreateServiceGroup(_ context.Context, g *ServiceGroup) error {
	r.serviceGrps[g.ID] = g
	return nil
}
func (r *fakeRepo) GetServiceGroup(_ context.Context, _, id string) (*ServiceGroup, error) {
	if g, ok := r.serviceGrps[id]; ok {
		return g, nil
	}
	return nil, ErrServiceGroupNotFound
}
func (r *fakeRepo) GetServiceGroupBySlug(_ context.Context, _, _ string) (*ServiceGroup, error) {
	return nil, ErrServiceGroupNotFound
}
func (r *fakeRepo) ListServiceGroups(_ context.Context, _ string, _ bool) ([]ServiceGroup, error) {
	out := make([]ServiceGroup, 0, len(r.serviceGrps))
	for _, g := range r.serviceGrps {
		out = append(out, *g)
	}
	return out, nil
}
func (r *fakeRepo) UpdateServiceGroupParent(_ context.Context, _, id string, parentID *string) error {
	g, ok := r.serviceGrps[id]
	if !ok {
		return ErrServiceGroupNotFound
	}
	g.ParentID = parentID
	return nil
}
func (r *fakeRepo) DisableServiceGroup(_ context.Context, _, _ string) error { return nil }

func (r *fakeRepo) SetServiceGroupMembership(_ context.Context, m *ServiceGroupMembership) error {
	cp := *m
	r.srvGrpMems[m.ServiceID] = &cp
	return nil
}
func (r *fakeRepo) ClearServiceGroupMembership(_ context.Context, _, serviceID string) error {
	if _, ok := r.srvGrpMems[serviceID]; !ok {
		return ErrServiceGroupMembershipNotFound
	}
	delete(r.srvGrpMems, serviceID)
	return nil
}
func (r *fakeRepo) GetServiceGroupMembership(_ context.Context, _, serviceID string) (*ServiceGroupMembership, error) {
	if m, ok := r.srvGrpMems[serviceID]; ok {
		return m, nil
	}
	return nil, ErrServiceGroupMembershipNotFound
}
func (r *fakeRepo) ListServicesInGroup(_ context.Context, _, _ string) ([]ServiceGroupMembership, error) {
	return nil, nil
}

func (r *fakeRepo) CreateAgentGroup(_ context.Context, g *AgentGroup) error {
	r.agentGroups[g.ID] = g
	return nil
}
func (r *fakeRepo) GetAgentGroup(_ context.Context, _, id string) (*AgentGroup, error) {
	if g, ok := r.agentGroups[id]; ok {
		return g, nil
	}
	return nil, ErrAgentGroupNotFound
}
func (r *fakeRepo) GetAgentGroupBySlug(_ context.Context, _, _ string) (*AgentGroup, error) {
	return nil, ErrAgentGroupNotFound
}
func (r *fakeRepo) ListAgentGroups(_ context.Context, _ string, _ bool) ([]AgentGroup, error) {
	out := make([]AgentGroup, 0, len(r.agentGroups))
	for _, g := range r.agentGroups {
		out = append(out, *g)
	}
	return out, nil
}
func (r *fakeRepo) DisableAgentGroup(_ context.Context, _, _ string) error { return nil }

func (r *fakeRepo) AddAgentToGroup(_ context.Context, m *AgentGroupMembership) error {
	r.agentGrpMems = append(r.agentGrpMems, *m)
	return nil
}
func (r *fakeRepo) RemoveAgentFromGroup(_ context.Context, _, agentID, groupID string) error {
	for i := range r.agentGrpMems {
		m := r.agentGrpMems[i]
		if m.AgentID == agentID && m.AgentGroupID == groupID {
			r.agentGrpMems = append(r.agentGrpMems[:i], r.agentGrpMems[i+1:]...)
			return nil
		}
	}
	return ErrAgentGroupMembershipNotFound
}
func (r *fakeRepo) ListGroupsForAgent(_ context.Context, _, _ string) ([]AgentGroupMembership, error) {
	return r.agentGrpMems, nil
}
func (r *fakeRepo) ListAgentsInGroup(_ context.Context, _, _ string) ([]AgentGroupMembership, error) {
	return r.agentGrpMems, nil
}

// fakeTx runs fn directly. To simulate audit-rollback the tx
// would need real cross-call rollback semantics; for service-
// layer tests we override CreateTag etc. to "succeed", record
// an audit failure, and assert the higher-level method
// surfaces the audit error.
type fakeTx struct{}

func (fakeTx) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type fakeResolver struct{ certs, agents map[string]bool }

func (f *fakeResolver) CertificateExists(_ context.Context, _, id string) (bool, error) {
	return f.certs[id], nil
}
func (f *fakeResolver) AgentExists(_ context.Context, _, id string) (bool, error) {
	return f.agents[id], nil
}

type fakeAudit struct {
	events []audit.Event
	// failNext: when > 0, the next failNext calls to Record
	// return a forced error; decremented each call.
	failNext int
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	if f.failNext > 0 {
		f.failNext--
		return errors.New("forced audit failure")
	}
	f.events = append(f.events, e)
	return nil
}
func (f *fakeAudit) List(_ context.Context, _ audit.ListQuery) ([]audit.Event, error) {
	return f.events, nil
}

// ----- helpers -----

func newSvc(t *testing.T) (*Service, *fakeRepo, *fakeAudit, *fakeResolver) {
	t.Helper()
	repo := newFakeRepo()
	a := &fakeAudit{}
	res := &fakeResolver{certs: map[string]bool{}, agents: map[string]bool{}}
	svc, err := NewService(repo, fakeTx{}, a, res, fixedClock{t: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, repo, a, res
}

// ----- slug validation -----

func TestValidateSlug(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"billing", false},
		{"billing-prod", false},
		{"a", false},
		{"a1", false},
		{"42-the-answer", false},
		// boundary at maxSlugLen
		{strings.Repeat("a", maxSlugLen), false},
		{strings.Repeat("a", maxSlugLen+1), true},

		// rejects
		{"", true},
		{"-leading", true},
		{"trailing-", true},
		{"double--hyphen", true},
		{"UPPER", true},
		{"under_score", true},
		{"space here", true},
		{"slash/x", true},
	}
	for _, tc := range cases {
		err := validateSlug("field", tc.in)
		if tc.wantErr && err == nil {
			t.Errorf("validateSlug(%q) = nil; want error", tc.in)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validateSlug(%q) = %v; want nil", tc.in, err)
		}
	}
}

// ----- Tag identity immutability -----

func TestUpdateTagDescription_OnlyUpdatesDescription(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t)

	tag, err := svc.CreateTag(ctx, CreateTagInput{
		OrganizationID: "anchorix", Key: "env", Value: "prod",
		Description: "production", ActorUserID: "u1",
	})
	if err != nil {
		t.Fatalf("CreateTag: %v", err)
	}
	if err := svc.UpdateTagDescription(ctx, UpdateTagDescriptionInput{
		OrganizationID: "anchorix", TagID: tag.ID,
		Description: "PROD", ActorUserID: "u1",
	}); err != nil {
		t.Fatalf("UpdateTagDescription: %v", err)
	}
	got, _ := svc.GetTag(ctx, "anchorix", tag.ID)
	if got.Description != "PROD" {
		t.Fatalf("description not updated: %q", got.Description)
	}
	if got.Key != "env" || got.Value != "prod" {
		t.Fatalf("identity mutated: key=%q value=%q", got.Key, got.Value)
	}
}

// ----- Service-group cycle detection -----

func TestUpdateServiceGroupParent_DetectsSelfCycle(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t)
	g, err := svc.CreateServiceGroup(ctx, CreateServiceGroupInput{
		OrganizationID: "anchorix", Slug: "root", DisplayName: "Root",
		ActorUserID: "u1",
	})
	if err != nil {
		t.Fatalf("CreateServiceGroup: %v", err)
	}
	// parent = self → cycle.
	err = svc.UpdateServiceGroupParent(ctx, UpdateServiceGroupParentInput{
		OrganizationID: "anchorix", GroupID: g.ID, ParentID: &g.ID, ActorUserID: "u1",
	})
	if !errors.Is(err, ErrServiceGroupCycle) {
		t.Fatalf("self-parent = %v; want ErrServiceGroupCycle", err)
	}
}

func TestUpdateServiceGroupParent_DetectsTransitiveCycle(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t)
	root, _ := svc.CreateServiceGroup(ctx, CreateServiceGroupInput{
		OrganizationID: "anchorix", Slug: "root", DisplayName: "Root", ActorUserID: "u1",
	})
	mid, _ := svc.CreateServiceGroup(ctx, CreateServiceGroupInput{
		OrganizationID: "anchorix", Slug: "mid", DisplayName: "Mid",
		ParentID: &root.ID, ActorUserID: "u1",
	})
	leaf, _ := svc.CreateServiceGroup(ctx, CreateServiceGroupInput{
		OrganizationID: "anchorix", Slug: "leaf", DisplayName: "Leaf",
		ParentID: &mid.ID, ActorUserID: "u1",
	})
	// Attempt to re-parent root under leaf — cycle:
	// root → leaf → mid → root.
	err := svc.UpdateServiceGroupParent(ctx, UpdateServiceGroupParentInput{
		OrganizationID: "anchorix", GroupID: root.ID, ParentID: &leaf.ID, ActorUserID: "u1",
	})
	if !errors.Is(err, ErrServiceGroupCycle) {
		t.Fatalf("transitive cycle = %v; want ErrServiceGroupCycle", err)
	}
}

// ----- Polymorphic tag-assignment target validation -----

func TestAssignTag_RejectsNonExistentTarget(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t)
	tag, _ := svc.CreateTag(ctx, CreateTagInput{
		OrganizationID: "anchorix", Key: "env", Value: "prod", ActorUserID: "u1",
	})
	_, err := svc.AssignTag(ctx, AssignTagInput{
		OrganizationID: "anchorix", TagID: tag.ID,
		TargetType: TagTargetService, TargetID: "svc-does-not-exist",
		ActorUserID: "u1",
	})
	if !errors.Is(err, ErrTagAssignmentTargetInvalid) {
		t.Fatalf("non-existent service target = %v; want ErrTagAssignmentTargetInvalid", err)
	}
}

func TestAssignTag_AcceptsCertificateTargetWhenResolverConfirms(t *testing.T) {
	ctx := context.Background()
	svc, _, _, res := newSvc(t)
	res.certs["cert-x"] = true
	tag, _ := svc.CreateTag(ctx, CreateTagInput{
		OrganizationID: "anchorix", Key: "env", Value: "prod", ActorUserID: "u1",
	})
	a, err := svc.AssignTag(ctx, AssignTagInput{
		OrganizationID: "anchorix", TagID: tag.ID,
		TargetType: TagTargetCertificate, TargetID: "cert-x", ActorUserID: "u1",
	})
	if err != nil {
		t.Fatalf("AssignTag: %v", err)
	}
	if a.TargetID != "cert-x" || a.TargetType != TagTargetCertificate {
		t.Fatalf("assignment shape: %+v", a)
	}
}

// ----- Disable preflight: tag_in_use -----

func TestDisableTag_RejectsWhenAssignmentsExist(t *testing.T) {
	ctx := context.Background()
	svc, _, _, res := newSvc(t)
	res.certs["cert-1"] = true
	tag, _ := svc.CreateTag(ctx, CreateTagInput{
		OrganizationID: "anchorix", Key: "env", Value: "prod", ActorUserID: "u1",
	})
	_, _ = svc.AssignTag(ctx, AssignTagInput{
		OrganizationID: "anchorix", TagID: tag.ID,
		TargetType: TagTargetCertificate, TargetID: "cert-1", ActorUserID: "u1",
	})
	err := svc.DisableTag(ctx, DisableTagInput{
		OrganizationID: "anchorix", TagID: tag.ID,
		Reason: "rotating", ActorUserID: "u1",
	})
	if !errors.Is(err, ErrTagInUse) {
		t.Fatalf("disable in-use = %v; want ErrTagInUse", err)
	}
}

// ----- Disable preflight: service_group_has_children -----

func TestDisableServiceGroup_RejectsWhenChildrenExist(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t)
	root, _ := svc.CreateServiceGroup(ctx, CreateServiceGroupInput{
		OrganizationID: "anchorix", Slug: "root", DisplayName: "Root", ActorUserID: "u1",
	})
	_, _ = svc.CreateServiceGroup(ctx, CreateServiceGroupInput{
		OrganizationID: "anchorix", Slug: "child", DisplayName: "Child",
		ParentID: &root.ID, ActorUserID: "u1",
	})
	err := svc.DisableServiceGroup(ctx, DisableServiceGroupInput{
		OrganizationID: "anchorix", GroupID: root.ID, Reason: "x", ActorUserID: "u1",
	})
	if !errors.Is(err, ErrServiceGroupHasChildren) {
		t.Fatalf("disable parent with children = %v; want ErrServiceGroupHasChildren", err)
	}
}

// ----- Audit-rollback: audit failure surfaces as ErrInternalAudit -----

func TestCreateTag_AuditFailureSurfacesError(t *testing.T) {
	ctx := context.Background()
	svc, _, a, _ := newSvc(t)
	a.failNext = 1
	_, err := svc.CreateTag(ctx, CreateTagInput{
		OrganizationID: "anchorix", Key: "env", Value: "prod", ActorUserID: "u1",
	})
	if !errors.Is(err, ErrInternalAudit) {
		t.Fatalf("audit failure = %v; want ErrInternalAudit", err)
	}
}

// ----- Audit metadata carries severity=security -----

func TestCreateTag_AuditMetadataIncludesSecuritySeverity(t *testing.T) {
	ctx := context.Background()
	svc, _, a, _ := newSvc(t)
	if _, err := svc.CreateTag(ctx, CreateTagInput{
		OrganizationID: "anchorix", Key: "env", Value: "prod", ActorUserID: "u1",
	}); err != nil {
		t.Fatalf("CreateTag: %v", err)
	}
	if len(a.events) != 1 {
		t.Fatalf("audit events = %d; want 1", len(a.events))
	}
	var meta map[string]any
	if err := json.Unmarshal(a.events[0].Metadata, &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta["severity"] != "security" {
		t.Fatalf("severity = %v; want security", meta["severity"])
	}
}

// ----- Cross-org/missing input surfaces as InvalidInput -----

func TestInputValidation(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t)

	// Missing org id.
	_, err := svc.CreateTag(ctx, CreateTagInput{
		OrganizationID: "", Key: "k", Value: "", ActorUserID: "u1",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing org = %v; want ErrInvalidInput", err)
	}

	// Missing actor.
	_, err = svc.CreateTag(ctx, CreateTagInput{
		OrganizationID: "anchorix", Key: "k", Value: "", ActorUserID: "",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing actor = %v; want ErrInvalidInput", err)
	}

	// Invalid slug for service.
	_, err = svc.CreateService(ctx, CreateServiceInput{
		OrganizationID: "anchorix", Slug: "UPPER-CASE",
		DisplayName: "X", ActorUserID: "u1",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid slug = %v; want ErrInvalidInput", err)
	}
}

// ----- Membership target validation -----

func TestAddAgentToGroup_RejectsUnknownAgent(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t)
	g, _ := svc.CreateAgentGroup(ctx, CreateAgentGroupInput{
		OrganizationID: "anchorix", Slug: "dc", DisplayName: "DC", ActorUserID: "u1",
	})
	err := svc.AddAgentToGroup(ctx, AddAgentToGroupInput{
		OrganizationID: "anchorix", AgentID: "unknown", GroupID: g.ID, ActorUserID: "u1",
	})
	if !errors.Is(err, ErrMembershipTargetInvalid) {
		t.Fatalf("unknown agent = %v; want ErrMembershipTargetInvalid", err)
	}
}

func TestSetServiceGroupMembership_RejectsUnknownGroup(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t)
	sr, _ := svc.CreateService(ctx, CreateServiceInput{
		OrganizationID: "anchorix", Slug: "billing", DisplayName: "Billing", ActorUserID: "u1",
	})
	err := svc.SetServiceGroupMembership(ctx, SetServiceGroupMembershipInput{
		OrganizationID: "anchorix", ServiceID: sr.ID, ServiceGroupID: "no-such-group", ActorUserID: "u1",
	})
	if !errors.Is(err, ErrMembershipTargetInvalid) {
		t.Fatalf("unknown group = %v; want ErrMembershipTargetInvalid", err)
	}
}

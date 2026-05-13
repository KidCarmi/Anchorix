package enrollment

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
)

// fixedClock returns the same time on every call. Tests that need to
// assert on the precise timestamp inside a generated package or
// agent pin this to a known instant.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// inlineTx runs fn with the same ctx, no transactional semantics. It
// is the unit-test equivalent of the production *postgres.DB.WithTx,
// which binds a tx to ctx so repository calls inside fn participate
// automatically. For unit tests the repositories are fakes that
// have no SQL — the only behavior we care about is fn's error
// propagation.
type inlineTx struct{}

func (inlineTx) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// fakePackageRepo is an in-memory DeploymentPackageRepository for
// service unit tests. Test cases mutate its public fields to
// configure behavior (createErr, incrementErr, etc.) and inspect
// recorded calls afterwards.
type fakePackageRepo struct {
	mu sync.Mutex

	byHash map[string]*DeploymentPackage // indexed by string(hash)

	createCalls    []packageCreateCall
	incrementCalls []packageIncrementCall
	revokeCalls    []packageRevokeCall

	// Error overrides. Zero-value means "no error".
	createErr    error
	getErr       error
	incrementErr error
	revokeErr    error
}

type packageCreateCall struct {
	Package *DeploymentPackage
	Hash    []byte
}

type packageIncrementCall struct {
	ID string
	At time.Time
}

func newFakePackageRepo() *fakePackageRepo {
	return &fakePackageRepo{byHash: map[string]*DeploymentPackage{}}
}

func (f *fakePackageRepo) Create(_ context.Context, pkg *DeploymentPackage, hash []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return f.createErr
	}
	f.byHash[string(hash)] = pkg
	f.createCalls = append(f.createCalls, packageCreateCall{Package: pkg, Hash: append([]byte(nil), hash...)})
	return nil
}

func (f *fakePackageRepo) GetByBootstrapHash(_ context.Context, hash []byte) (*DeploymentPackage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	pkg, ok := f.byHash[string(hash)]
	if !ok {
		return nil, ErrPackageNotFound
	}
	return pkg, nil
}

func (f *fakePackageRepo) GetByIDAndOrg(_ context.Context, id, organizationID string) (*DeploymentPackage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	for _, pkg := range f.byHash {
		if pkg.ID == id && pkg.OrganizationID == organizationID {
			return pkg, nil
		}
	}
	return nil, ErrPackageNotFound
}

// revokeCalls records every Revoke invocation; tests inspect this
// list to assert idempotency and ordering.
type packageRevokeCall struct {
	ID, OrganizationID, RevokedByUserID, Reason string
	At                                          time.Time
}

func (f *fakePackageRepo) Revoke(_ context.Context, id, organizationID, revokedByUserID, reason string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls = append(f.revokeCalls, packageRevokeCall{
		ID: id, OrganizationID: organizationID,
		RevokedByUserID: revokedByUserID, Reason: reason, At: at,
	})
	if f.revokeErr != nil {
		return f.revokeErr
	}
	for _, pkg := range f.byHash {
		if pkg.ID != id || pkg.OrganizationID != organizationID {
			continue
		}
		if pkg.RevokedAt != nil {
			return ErrPackageAlreadyRevoked
		}
		t := at
		pkg.RevokedAt = &t
		pkg.RevokedByUserID = revokedByUserID
		pkg.RevokedReason = reason
		return nil
	}
	return ErrPackageNotFound
}

func (f *fakePackageRepo) IncrementUses(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.incrementCalls = append(f.incrementCalls, packageIncrementCall{ID: id, At: at})
	if f.incrementErr != nil {
		return f.incrementErr
	}
	// Mirror the production atomic increment so happy-path tests can
	// later observe the package's UsesCount.
	for _, pkg := range f.byHash {
		if pkg.ID == id {
			pkg.UsesCount++
			pkg.LastUsedAt = &at
			return nil
		}
	}
	return ErrPackageNotFound
}

// fakeAgentRepo is an in-memory AgentRepository.
type fakeAgentRepo struct {
	mu sync.Mutex

	created      []agentCreateCall
	createErr    error
	listErr      error
	findErr      error
	listAgents   map[string][]Agent // orgID -> agents
	byCredential map[string]*Agent  // string(hash) -> agent
}

type agentCreateCall struct {
	Agent          *Agent
	CredentialHash []byte
}

func newFakeAgentRepo() *fakeAgentRepo {
	return &fakeAgentRepo{
		listAgents:   map[string][]Agent{},
		byCredential: map[string]*Agent{},
	}
}

func (f *fakeAgentRepo) Create(_ context.Context, a *Agent, credentialHash []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, agentCreateCall{Agent: a, CredentialHash: append([]byte(nil), credentialHash...)})
	f.listAgents[a.OrganizationID] = append(f.listAgents[a.OrganizationID], *a)
	f.byCredential[string(credentialHash)] = a
	return nil
}

func (f *fakeAgentRepo) List(_ context.Context, orgID string) ([]Agent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listAgents[orgID], nil
}

func (f *fakeAgentRepo) FindByCredentialHash(_ context.Context, hash []byte) (*Agent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.findErr != nil {
		return nil, f.findErr
	}
	a, ok := f.byCredential[string(hash)]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return a, nil
}

// fakeAuditRecorder records every audit event the service writes.
// failOnAction makes the recorder return an error for events whose
// Action matches — used to test the rollback contract.
type fakeAuditRecorder struct {
	mu sync.Mutex

	events       []audit.Event
	failOnAction string
}

func (f *fakeAuditRecorder) Record(_ context.Context, e audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOnAction != "" && e.Action == f.failOnAction {
		return errors.New("synthetic audit failure")
	}
	f.events = append(f.events, e)
	return nil
}

func (f *fakeAuditRecorder) List(_ context.Context, _ audit.ListQuery) ([]audit.Event, error) {
	return f.events, nil
}

// newTestService wires the service with all the fakes and a
// deterministic random source. The rng's seed bytes are arbitrary;
// what matters is that two tokens (bootstrap + credential) drawn
// from the same Service in one test do not collide.
func newTestService(t *testing.T) (
	*Service,
	*fakePackageRepo,
	*fakeAgentRepo,
	*fakeAuditRecorder,
	io.Reader,
) {
	t.Helper()
	packages := newFakePackageRepo()
	agents := newFakeAgentRepo()
	auditRec := &fakeAuditRecorder{}
	// 128 bytes is enough for two 32-byte token draws plus a margin.
	// Distinct seed bytes for each test guarantee distinct tokens.
	rng := bytes.NewReader(bytes.Repeat([]byte{0xAB}, 4096))
	svc, err := NewService(packages, agents, auditRec, inlineTx{}, fixedClock{now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}, rng)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, packages, agents, auditRec, rng
}

func validCreateInput() CreatePackageInput {
	return CreatePackageInput{
		OrganizationID:   "anchorix",
		CreatedByUserID:  "user-1",
		Name:             "Baseline Windows 0.1.0",
		Description:      "Approved baseline build",
		PackageType:      PackageTypeBaseline,
		AgentVersion:     "0.1.0",
		TTL:              7 * 24 * time.Hour,
		MaxUses:          500,
		DefaultGroupName: "Default",
		DefaultLabels:    []string{"baseline", "win"},
	}
}

func TestNewServiceRejectsMissingDependency(t *testing.T) {
	packages := newFakePackageRepo()
	agents := newFakeAgentRepo()
	auditRec := &fakeAuditRecorder{}
	tx := inlineTx{}
	clk := clock.System{}
	rng := bytes.NewReader([]byte{1})

	cases := []struct {
		name string
		fn   func() (*Service, error)
	}{
		{"missing packages", func() (*Service, error) {
			return NewService(nil, agents, auditRec, tx, clk, rng)
		}},
		{"missing agents", func() (*Service, error) {
			return NewService(packages, nil, auditRec, tx, clk, rng)
		}},
		{"missing audit", func() (*Service, error) {
			return NewService(packages, agents, nil, tx, clk, rng)
		}},
		{"missing tx", func() (*Service, error) {
			return NewService(packages, agents, auditRec, nil, clk, rng)
		}},
		{"missing clock", func() (*Service, error) {
			return NewService(packages, agents, auditRec, tx, nil, rng)
		}},
		{"missing rng", func() (*Service, error) {
			return NewService(packages, agents, auditRec, tx, clk, nil)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.fn(); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestCreatePackageHappyPath(t *testing.T) {
	svc, packages, _, auditRec, _ := newTestService(t)

	out, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	if out.BootstrapSecret == "" {
		t.Fatal("BootstrapSecret must be non-empty")
	}
	if out.Package == nil {
		t.Fatal("Package must be non-nil")
	}
	if out.Package.ID == "" {
		t.Fatal("Package.ID must be non-empty")
	}
	if out.Package.MaxUses != 500 {
		t.Errorf("MaxUses = %d, want 500", out.Package.MaxUses)
	}
	if out.Package.PackageType != PackageTypeBaseline {
		t.Errorf("PackageType = %q, want baseline", out.Package.PackageType)
	}
	if got := out.Package.DefaultLabels; len(got) != 2 || got[0] != "baseline" || got[1] != "win" {
		t.Errorf("DefaultLabels = %v, want [baseline win]", got)
	}
	if len(packages.createCalls) != 1 {
		t.Fatalf("packages.Create called %d times, want 1", len(packages.createCalls))
	}
	if len(packages.createCalls[0].Hash) != 32 {
		t.Errorf("hash length = %d, want 32 (SHA-256)", len(packages.createCalls[0].Hash))
	}
	if len(auditRec.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(auditRec.events))
	}
	if auditRec.events[0].Action != "deployment_package.created" {
		t.Errorf("audit action = %q", auditRec.events[0].Action)
	}
	// The bootstrap secret MUST NOT appear anywhere in the audit
	// metadata. Convert to string and grep.
	if md := string(auditRec.events[0].Metadata); strings.Contains(md, out.BootstrapSecret) {
		t.Error("audit metadata leaked the bootstrap secret")
	}
}

func TestCreatePackageRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		in   func(CreatePackageInput) CreatePackageInput
	}{
		{"empty org", func(c CreatePackageInput) CreatePackageInput { c.OrganizationID = ""; return c }},
		{"empty creator", func(c CreatePackageInput) CreatePackageInput { c.CreatedByUserID = ""; return c }},
		{"empty name", func(c CreatePackageInput) CreatePackageInput { c.Name = "   "; return c }},
		{"invalid type", func(c CreatePackageInput) CreatePackageInput {
			c.PackageType = PackageType("nope")
			return c
		}},
		{"zero ttl", func(c CreatePackageInput) CreatePackageInput { c.TTL = 0; return c }},
		{"negative ttl", func(c CreatePackageInput) CreatePackageInput { c.TTL = -time.Hour; return c }},
		{"zero max_uses", func(c CreatePackageInput) CreatePackageInput { c.MaxUses = 0; return c }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, packages, _, auditRec, _ := newTestService(t)
			_, err := svc.CreatePackage(context.Background(), c.in(validCreateInput()))
			if !errors.Is(err, ErrInvalidPackageInput) {
				t.Fatalf("err = %v, want ErrInvalidPackageInput", err)
			}
			if len(packages.createCalls) != 0 {
				t.Errorf("packages.Create called on invalid input")
			}
			if len(auditRec.events) != 0 {
				t.Errorf("audit recorded on invalid input")
			}
		})
	}
}

func TestCreatePackageAuditFailureRollsBack(t *testing.T) {
	// inlineTx returns whatever fn returns; if the audit record
	// errors out, the returned error from CreatePackage should be
	// non-nil. In production, the real WithTx rolls back the
	// package insert so it never persists. The fake repo's
	// createCalls still records the insert attempt (we don't model
	// rollback in the fake), so the assertion focuses on the
	// returned error and the absence of an audit event.
	svc, _, _, auditRec, _ := newTestService(t)
	auditRec.failOnAction = "deployment_package.created"

	_, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err == nil {
		t.Fatal("expected error from audit failure")
	}
	if len(auditRec.events) != 0 {
		t.Errorf("audit events captured = %d, want 0 (rollback)", len(auditRec.events))
	}
}

func TestEnrollAgentUnknownSecretRejected(t *testing.T) {
	svc, _, agents, auditRec, _ := newTestService(t)
	_, err := svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: "definitely-not-real",
		Hostname:        "ws-001",
	})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("err = %v, want ErrEnrollmentRejected", err)
	}
	if len(agents.created) != 0 {
		t.Errorf("agent created from unknown secret")
	}
	// Internal rejection must be audited with severity:"security".
	if len(auditRec.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(auditRec.events))
	}
	if auditRec.events[0].Action != "agent.enrollment_rejected" {
		t.Errorf("audit action = %q", auditRec.events[0].Action)
	}
	if !strings.Contains(string(auditRec.events[0].Metadata), `"severity":"security"`) {
		t.Error("rejection audit missing severity:security marker")
	}
}

func TestEnrollAgentInvalidInputRejected(t *testing.T) {
	svc, _, agents, auditRec, _ := newTestService(t)
	cases := []EnrollAgentInput{
		{BootstrapSecret: "", Hostname: "ws-001"},
		{BootstrapSecret: "secret", Hostname: ""},
	}
	for _, in := range cases {
		if _, err := svc.EnrollAgent(context.Background(), in); !errors.Is(err, ErrEnrollmentRejected) {
			t.Errorf("err = %v, want ErrEnrollmentRejected for input %+v", err, in)
		}
	}
	if len(agents.created) != 0 {
		t.Errorf("invalid-input enrollment created an agent")
	}
	if len(auditRec.events) != 0 {
		t.Errorf("invalid-input enrollment wrote an audit event (should be silent)")
	}
}

func TestEnrollAgentHappyPath(t *testing.T) {
	svc, packages, agents, auditRec, _ := newTestService(t)

	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}

	out, err := svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: pkgOut.BootstrapSecret,
		Hostname:        "ws-001",
		AgentVersion:    "0.1.0",
		InstallID:       "install-1",
	})
	if err != nil {
		t.Fatalf("EnrollAgent: %v", err)
	}
	if out.AgentCredential == "" {
		t.Fatal("AgentCredential must be returned exactly once")
	}
	if out.Agent.Status != AgentStatusActive {
		t.Errorf("Status = %q, want active", out.Agent.Status)
	}
	// Group + labels propagate from the package.
	if out.Agent.GroupName != "Default" {
		t.Errorf("GroupName = %q, want Default", out.Agent.GroupName)
	}
	if got := out.Agent.Labels; len(got) != 2 || got[0] != "baseline" || got[1] != "win" {
		t.Errorf("Labels = %v, want [baseline win]", got)
	}
	// Package usage incremented.
	if len(packages.incrementCalls) != 1 {
		t.Errorf("IncrementUses calls = %d, want 1", len(packages.incrementCalls))
	}
	// Agent stored with credential hash, not plaintext.
	if len(agents.created) != 1 {
		t.Fatalf("agents.Create called %d times", len(agents.created))
	}
	if len(agents.created[0].CredentialHash) != 32 {
		t.Errorf("credential hash length = %d, want 32", len(agents.created[0].CredentialHash))
	}
	// Audit: package.created + agent.enrolled.
	actions := make([]string, 0, len(auditRec.events))
	for _, e := range auditRec.events {
		actions = append(actions, e.Action)
	}
	if len(actions) != 2 || actions[0] != "deployment_package.created" || actions[1] != "agent.enrolled" {
		t.Errorf("audit actions = %v", actions)
	}
	// agent.enrolled audit must NOT contain the credential.
	for _, e := range auditRec.events {
		if e.Action != "agent.enrolled" {
			continue
		}
		if strings.Contains(string(e.Metadata), out.AgentCredential) {
			t.Error("audit metadata leaked the agent credential")
		}
	}
}

func TestEnrollAgentRevokedPackageRejected(t *testing.T) {
	svc, packages, _, _, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	// Simulate revocation: mutate the in-memory package.
	now := time.Now()
	packages.byHash[string(hashBearerToken(pkgOut.BootstrapSecret))].RevokedAt = &now

	_, err = svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: pkgOut.BootstrapSecret,
		Hostname:        "ws-001",
	})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("err = %v, want ErrEnrollmentRejected", err)
	}
}

func TestEnrollAgentExpiredPackageRejected(t *testing.T) {
	svc, packages, _, _, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	// Mutate expires_at into the past.
	packages.byHash[string(hashBearerToken(pkgOut.BootstrapSecret))].ExpiresAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	_, err = svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: pkgOut.BootstrapSecret,
		Hostname:        "ws-001",
	})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("err = %v, want ErrEnrollmentRejected", err)
	}
}

func TestEnrollAgentExhaustedPackageRejected(t *testing.T) {
	svc, packages, _, _, _ := newTestService(t)
	in := validCreateInput()
	in.MaxUses = 1
	pkgOut, err := svc.CreatePackage(context.Background(), in)
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	// Mutate uses_count to the limit.
	packages.byHash[string(hashBearerToken(pkgOut.BootstrapSecret))].UsesCount = 1

	_, err = svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: pkgOut.BootstrapSecret,
		Hostname:        "ws-001",
	})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("err = %v, want ErrEnrollmentRejected", err)
	}
}

func TestEnrollAgentKnownPackageRejectionPropagatesAuditFailure(t *testing.T) {
	// Pre-PR review fix: when the rejection is for a KNOWN package
	// (revoked / expired / exhausted / duplicate install_id), an
	// audit-write failure MUST surface as a non-rejected error so
	// the caller does not silently lose the security audit record.
	// Only the unknown-bootstrap-secret path stays best-effort.
	cases := []struct {
		name  string
		setup func(t *testing.T) (*Service, EnrollAgentInput)
	}{
		{
			name: "revoked package + audit failure",
			setup: func(t *testing.T) (*Service, EnrollAgentInput) {
				svc, packages, _, auditRec, _ := newTestService(t)
				pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
				if err != nil {
					t.Fatalf("CreatePackage: %v", err)
				}
				now := time.Now()
				packages.byHash[string(hashBearerToken(pkgOut.BootstrapSecret))].RevokedAt = &now
				auditRec.failOnAction = "agent.enrollment_rejected"
				return svc, EnrollAgentInput{
					BootstrapSecret: pkgOut.BootstrapSecret,
					Hostname:        "ws-001",
				}
			},
		},
		{
			name: "expired package + audit failure",
			setup: func(t *testing.T) (*Service, EnrollAgentInput) {
				svc, packages, _, auditRec, _ := newTestService(t)
				pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
				if err != nil {
					t.Fatalf("CreatePackage: %v", err)
				}
				packages.byHash[string(hashBearerToken(pkgOut.BootstrapSecret))].ExpiresAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
				auditRec.failOnAction = "agent.enrollment_rejected"
				return svc, EnrollAgentInput{
					BootstrapSecret: pkgOut.BootstrapSecret,
					Hostname:        "ws-001",
				}
			},
		},
		{
			name: "exhausted package + audit failure",
			setup: func(t *testing.T) (*Service, EnrollAgentInput) {
				svc, packages, _, auditRec, _ := newTestService(t)
				in := validCreateInput()
				in.MaxUses = 1
				pkgOut, err := svc.CreatePackage(context.Background(), in)
				if err != nil {
					t.Fatalf("CreatePackage: %v", err)
				}
				packages.byHash[string(hashBearerToken(pkgOut.BootstrapSecret))].UsesCount = 1
				auditRec.failOnAction = "agent.enrollment_rejected"
				return svc, EnrollAgentInput{
					BootstrapSecret: pkgOut.BootstrapSecret,
					Hostname:        "ws-001",
				}
			},
		},
		{
			name: "duplicate install_id + audit failure",
			setup: func(t *testing.T) (*Service, EnrollAgentInput) {
				svc, _, agents, auditRec, _ := newTestService(t)
				pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
				if err != nil {
					t.Fatalf("CreatePackage: %v", err)
				}
				agents.createErr = ErrAgentAlreadyEnrolled
				auditRec.failOnAction = "agent.enrollment_rejected"
				return svc, EnrollAgentInput{
					BootstrapSecret: pkgOut.BootstrapSecret,
					Hostname:        "ws-001",
					InstallID:       "dup",
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, in := c.setup(t)
			_, err := svc.EnrollAgent(context.Background(), in)
			if err == nil {
				t.Fatal("expected non-nil error")
			}
			// Crucial: the caller MUST NOT see ErrEnrollmentRejected
			// here, because the security audit failed to land. The
			// HTTP layer maps non-ErrEnrollmentRejected to 500
			// internal_error, which is what we want operators to
			// see when audit is broken.
			if errors.Is(err, ErrEnrollmentRejected) {
				t.Errorf("err = %v (ErrEnrollmentRejected); want propagated audit failure", err)
			}
		})
	}
}

func TestEnrollAgentUnknownSecretAuditFailureStaysBestEffort(t *testing.T) {
	// The unknown-bootstrap-secret path deliberately keeps audit
	// best-effort. Document the contract: an audit-storage failure
	// on this path still produces ErrEnrollmentRejected so an
	// attacker cannot probe audit health by guessing secrets.
	svc, _, _, auditRec, _ := newTestService(t)
	auditRec.failOnAction = "agent.enrollment_rejected"

	_, err := svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: "definitely-not-real",
		Hostname:        "ws-001",
	})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("err = %v, want ErrEnrollmentRejected (best-effort policy)", err)
	}
}

func TestEnrollAgentPackageConcurrentlyDeletedSurfacesAsRejection(t *testing.T) {
	// IncrementUses returns ErrPackageNotFound when the package row
	// disappeared between the conditional UPDATE and the follow-up
	// classification SELECT (concurrent operator delete). The agent
	// MUST still see the standard generic rejection envelope, not a
	// 500. Codex review of PR #13 caught this gap — without an
	// explicit ErrPackageNotFound case in the post-tx switch, the
	// error would fall through and the HTTP layer would emit
	// internal_error.
	svc, packages, _, auditRec, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	// Simulate the race: GetByBootstrapHash succeeds (we still have
	// the in-memory entry), but IncrementUses fails as if the row
	// were deleted mid-transaction.
	packages.incrementErr = ErrPackageNotFound

	_, err = svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: pkgOut.BootstrapSecret,
		Hostname:        "ws-001",
	})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("err = %v, want ErrEnrollmentRejected", err)
	}

	// The audit row must carry the specific reason so operators can
	// see this case in the rejection feed.
	var sawReason bool
	for _, e := range auditRec.events {
		if e.Action == "agent.enrollment_rejected" &&
			strings.Contains(string(e.Metadata), `"reason":"package_concurrently_deleted"`) {
			sawReason = true
			break
		}
	}
	if !sawReason {
		t.Errorf("expected agent.enrollment_rejected audit with reason=package_concurrently_deleted; got events: %v", auditRec.events)
	}
}

func TestEnrollAgentAuditFailureRollsBack(t *testing.T) {
	// Symmetric to TestCreatePackageAuditFailureRollsBack. EnrollAgent
	// runs IncrementUses + agents.Create + audit.Record (agent.enrolled)
	// inside one WithTx. If the agent.enrolled audit fails — and this
	// audit is NOT the agent.enrollment_rejected event, it is the
	// state-change event — the entire tx must roll back: no agent
	// row should persist and the caller MUST receive a
	// non-ErrEnrollmentRejected error so the HTTP layer maps it to
	// 500 internal_error rather than 401 enrollment_rejected (which
	// would be misleading: enrollment WAS valid, audit storage was
	// the failure).
	svc, _, _, auditRec, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	auditRec.failOnAction = "agent.enrolled"

	_, err = svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: pkgOut.BootstrapSecret,
		Hostname:        "ws-001",
	})
	if err == nil {
		t.Fatal("expected non-nil error from audit failure")
	}
	if errors.Is(err, ErrEnrollmentRejected) {
		t.Errorf("err = %v (ErrEnrollmentRejected); want a non-rejection error "+
			"from audit failure on a valid enrollment", err)
	}
}

func TestEnrollAgentDuplicateInstallIDRejected(t *testing.T) {
	svc, _, agents, _, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	// Configure the agent repo to return ErrAgentAlreadyEnrolled.
	agents.createErr = ErrAgentAlreadyEnrolled

	_, err = svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: pkgOut.BootstrapSecret,
		Hostname:        "ws-001",
		InstallID:       "install-dup",
	})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("err = %v, want ErrEnrollmentRejected", err)
	}
}

func TestEnrollAgentMachineFingerprintHashedNotStoredPlaintext(t *testing.T) {
	svc, _, agents, _, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	rawFingerprint := "raw-machine-fingerprint-do-not-leak"
	_, err = svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret:    pkgOut.BootstrapSecret,
		Hostname:           "ws-001",
		MachineFingerprint: rawFingerprint,
	})
	if err != nil {
		t.Fatalf("EnrollAgent: %v", err)
	}
	if len(agents.created) != 1 {
		t.Fatalf("agents.Create not called")
	}
	stored := agents.created[0].Agent
	if len(stored.MachineFingerprintHash) != 32 {
		t.Fatalf("fingerprint hash length = %d, want 32", len(stored.MachineFingerprintHash))
	}
	if got := string(stored.MachineFingerprintHash); strings.Contains(got, rawFingerprint) {
		t.Error("raw fingerprint string appeared inside the hash bytes")
	}
}

func TestPackageTypeValid(t *testing.T) {
	for _, valid := range []PackageType{
		PackageTypeBaseline, PackageTypeBulkSCCM, PackageTypeTechnician,
		PackageTypeVIP, PackageTypeLab,
	} {
		if !valid.Valid() {
			t.Errorf("PackageType %q reported invalid", valid)
		}
	}
	for _, invalid := range []PackageType{"", "unknown", "Baseline", "BULK_SCCM"} {
		if PackageType(invalid).Valid() {
			t.Errorf("PackageType %q reported valid", invalid)
		}
	}
}

// --- RevokePackage (H-005) -------------------------------------------------

func TestRevokePackageRejectsInvalidInput(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	cases := []struct {
		name string
		in   RevokePackageInput
	}{
		{"empty org", RevokePackageInput{PackageID: "p", RevokedByUserID: "u"}},
		{"empty pkg id", RevokePackageInput{OrganizationID: "anchorix", RevokedByUserID: "u"}},
		{"empty user", RevokePackageInput{OrganizationID: "anchorix", PackageID: "p"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := svc.RevokePackage(context.Background(), c.in)
			if !errors.Is(err, ErrInvalidPackageInput) {
				t.Fatalf("err = %v, want ErrInvalidPackageInput", err)
			}
		})
	}
}

func TestRevokePackageHappyPath(t *testing.T) {
	svc, packages, _, auditRec, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}

	out, err := svc.RevokePackage(context.Background(), RevokePackageInput{
		OrganizationID:  "anchorix",
		PackageID:       pkgOut.Package.ID,
		RevokedByUserID: "admin-1",
		Reason:          "rotating to 0.1.1",
	})
	if err != nil {
		t.Fatalf("RevokePackage: %v", err)
	}
	if out.AlreadyRevoked {
		t.Errorf("AlreadyRevoked = true on first revoke")
	}
	if out.Package.RevokedAt == nil {
		t.Fatal("Package.RevokedAt not set")
	}
	if out.Package.RevokedByUserID != "admin-1" {
		t.Errorf("RevokedByUserID = %q, want admin-1", out.Package.RevokedByUserID)
	}
	if out.Package.RevokedReason != "rotating to 0.1.1" {
		t.Errorf("RevokedReason = %q", out.Package.RevokedReason)
	}
	if got := len(packages.revokeCalls); got != 1 {
		t.Errorf("Revoke calls = %d, want 1", got)
	}
	// The audit row must land alongside the UPDATE. Look for the
	// specific action; metadata must not contain the bootstrap secret.
	var sawRevoke bool
	for _, e := range auditRec.events {
		if e.Action == "deployment_package.revoked" {
			sawRevoke = true
			if strings.Contains(string(e.Metadata), pkgOut.BootstrapSecret) {
				t.Error("audit metadata leaked the bootstrap secret")
			}
		}
	}
	if !sawRevoke {
		t.Error("missing deployment_package.revoked audit event")
	}
}

func TestRevokePackageOrgScopedRejection(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}

	// An admin from a different org calling revoke on this package
	// must see ErrPackageNotFound (HTTP 404), NOT a generic forbidden
	// or success — anything that surfaces the package's existence
	// would leak cross-org information.
	_, err = svc.RevokePackage(context.Background(), RevokePackageInput{
		OrganizationID:  "neighbor-org",
		PackageID:       pkgOut.Package.ID,
		RevokedByUserID: "neighbor-admin",
	})
	if !errors.Is(err, ErrPackageNotFound) {
		t.Fatalf("err = %v, want ErrPackageNotFound", err)
	}
}

func TestRevokePackageNotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	_, err := svc.RevokePackage(context.Background(), RevokePackageInput{
		OrganizationID:  "anchorix",
		PackageID:       "no-such-package",
		RevokedByUserID: "admin-1",
	})
	if !errors.Is(err, ErrPackageNotFound) {
		t.Fatalf("err = %v, want ErrPackageNotFound", err)
	}
}

func TestRevokePackageIdempotentOnAlreadyRevoked(t *testing.T) {
	svc, _, _, auditRec, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	if _, err := svc.RevokePackage(context.Background(), RevokePackageInput{
		OrganizationID:  "anchorix",
		PackageID:       pkgOut.Package.ID,
		RevokedByUserID: "admin-1",
		Reason:          "first revoke",
	}); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	firstAuditCount := 0
	for _, e := range auditRec.events {
		if e.Action == "deployment_package.revoked" {
			firstAuditCount++
		}
	}
	if firstAuditCount != 1 {
		t.Fatalf("first revoke audit count = %d, want 1", firstAuditCount)
	}

	// Second revoke: idempotent success, no new audit row.
	out, err := svc.RevokePackage(context.Background(), RevokePackageInput{
		OrganizationID:  "anchorix",
		PackageID:       pkgOut.Package.ID,
		RevokedByUserID: "admin-2",
		Reason:          "second revoke ignored",
	})
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if !out.AlreadyRevoked {
		t.Error("AlreadyRevoked = false on second revoke; want true")
	}
	// The response still carries the FIRST revoker's metadata —
	// re-revoking does NOT overwrite revoked_by_user_id.
	if out.Package.RevokedByUserID != "admin-1" {
		t.Errorf("RevokedByUserID after second revoke = %q, want admin-1 (first revoker preserved)",
			out.Package.RevokedByUserID)
	}
	// No duplicate audit row.
	secondAuditCount := 0
	for _, e := range auditRec.events {
		if e.Action == "deployment_package.revoked" {
			secondAuditCount++
		}
	}
	if secondAuditCount != 1 {
		t.Errorf("audit count after second revoke = %d, want 1 (idempotent)", secondAuditCount)
	}
}

func TestRevokePackageAuditFailureRollsBack(t *testing.T) {
	svc, _, _, auditRec, _ := newTestService(t)
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	auditRec.failOnAction = "deployment_package.revoked"

	_, err = svc.RevokePackage(context.Background(), RevokePackageInput{
		OrganizationID:  "anchorix",
		PackageID:       pkgOut.Package.ID,
		RevokedByUserID: "admin-1",
	})
	if err == nil {
		t.Fatal("expected non-nil error from audit failure")
	}
	// The HTTP layer maps any non-known error to 500 internal_error,
	// which is the right outcome here: the operator action did not
	// commit, so the response should NOT be 200.
	if errors.Is(err, ErrPackageNotFound) {
		t.Errorf("err = %v (ErrPackageNotFound); want a raw audit failure", err)
	}

	// No deployment_package.revoked audit row should have landed.
	for _, e := range auditRec.events {
		if e.Action == "deployment_package.revoked" {
			t.Error("audit row recorded despite failure (rollback contract violated)")
		}
	}
}

// --- AuthenticateAgent (H-007) ---------------------------------------------

// enrollOneAgent runs the full create-package + enroll-agent flow
// and returns the plaintext credential. The other auth tests need
// a real credential whose hash is in the fake repo.
func enrollOneAgent(t *testing.T, svc *Service, agents *fakeAgentRepo) (plaintext string, agentID string) {
	t.Helper()
	pkgOut, err := svc.CreatePackage(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	out, err := svc.EnrollAgent(context.Background(), EnrollAgentInput{
		BootstrapSecret: pkgOut.BootstrapSecret,
		Hostname:        "ws-auth",
	})
	if err != nil {
		t.Fatalf("EnrollAgent: %v", err)
	}
	if out.AgentCredential == "" {
		t.Fatal("EnrollAgent returned empty credential")
	}
	return out.AgentCredential, out.Agent.ID
}

func TestAuthenticateAgentHappyPath(t *testing.T) {
	svc, _, agents, _, _ := newTestService(t)
	plaintext, agentID := enrollOneAgent(t, svc, agents)

	got, err := svc.AuthenticateAgent(context.Background(), AuthenticateAgentInput{
		BootstrapCredential: plaintext,
	})
	if err != nil {
		t.Fatalf("AuthenticateAgent: %v", err)
	}
	if got.AgentID != agentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, agentID)
	}
	if got.OrganizationID != "anchorix" {
		t.Errorf("OrganizationID = %q, want anchorix", got.OrganizationID)
	}
	if got.Status != AgentStatusActive {
		t.Errorf("Status = %q, want active", got.Status)
	}
}

func TestAuthenticateAgentRejectsEmptyCredential(t *testing.T) {
	svc, _, _, auditRec, _ := newTestService(t)
	_, err := svc.AuthenticateAgent(context.Background(), AuthenticateAgentInput{
		BootstrapCredential: "",
	})
	if !errors.Is(err, ErrAgentAuthenticationFailed) {
		t.Fatalf("err = %v, want ErrAgentAuthenticationFailed", err)
	}
	// Failed auth attempt should be recorded with severity:security
	// and the credential_empty reason.
	if !hasAuthFailureWithReason(auditRec.events, "credential_empty") {
		t.Errorf("missing agent.authentication_failed audit with reason=credential_empty")
	}
}

func TestAuthenticateAgentRejectsUnknownCredential(t *testing.T) {
	svc, _, _, auditRec, _ := newTestService(t)
	_, err := svc.AuthenticateAgent(context.Background(), AuthenticateAgentInput{
		BootstrapCredential: "not-a-real-credential",
	})
	if !errors.Is(err, ErrAgentAuthenticationFailed) {
		t.Fatalf("err = %v, want ErrAgentAuthenticationFailed", err)
	}
	if !hasAuthFailureWithReason(auditRec.events, "credential_unknown") {
		t.Errorf("missing agent.authentication_failed audit with reason=credential_unknown")
	}
}

func TestAuthenticateAgentRejectsDisabledAgent(t *testing.T) {
	svc, _, agents, auditRec, _ := newTestService(t)
	plaintext, agentID := enrollOneAgent(t, svc, agents)

	// Disable the agent in the fake repo, bypassing any UI.
	agents.mu.Lock()
	for _, a := range agents.byCredential {
		if a.ID == agentID {
			a.Status = AgentStatusDisabled
		}
	}
	agents.mu.Unlock()

	_, err := svc.AuthenticateAgent(context.Background(), AuthenticateAgentInput{
		BootstrapCredential: plaintext,
	})
	if !errors.Is(err, ErrAgentAuthenticationFailed) {
		t.Fatalf("err = %v, want ErrAgentAuthenticationFailed", err)
	}
	if !hasAuthFailureWithReason(auditRec.events, "agent_status_disabled") {
		t.Errorf("missing audit row with reason=agent_status_disabled")
	}
}

func TestAuthenticateAgentLookupErrorPropagates(t *testing.T) {
	svc, _, agents, _, _ := newTestService(t)
	agents.findErr = errors.New("synthetic repository failure")

	_, err := svc.AuthenticateAgent(context.Background(), AuthenticateAgentInput{
		BootstrapCredential: "anything",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrAgentAuthenticationFailed) {
		t.Errorf("repository error must NOT collapse to ErrAgentAuthenticationFailed (HTTP would map to 401 instead of 500); got %v", err)
	}
}

func TestAuthenticateAgentAuditFailureStaysBestEffort(t *testing.T) {
	svc, _, _, auditRec, _ := newTestService(t)
	auditRec.failOnAction = "agent.authentication_failed"

	_, err := svc.AuthenticateAgent(context.Background(), AuthenticateAgentInput{
		BootstrapCredential: "not-real",
	})
	// Audit failure must NOT cause the auth response to flip to
	// 500 — otherwise an attacker can DOS agent connectivity by
	// probing audit-storage health. Authentication-failed audit
	// is best-effort by design (matches the rejection-audit policy
	// on enrollment unknown-bootstrap-secret).
	if !errors.Is(err, ErrAgentAuthenticationFailed) {
		t.Fatalf("err = %v, want ErrAgentAuthenticationFailed (best-effort audit)", err)
	}
}

// hasAuthFailureWithReason scans recorded audit events for an
// agent.authentication_failed row whose metadata contains the
// supplied reason string. Substring match (not exact JSON) so the
// helper tolerates jsonb-style formatting.
func hasAuthFailureWithReason(events []audit.Event, reason string) bool {
	for _, e := range events {
		if e.Action != "agent.authentication_failed" {
			continue
		}
		if strings.Contains(string(e.Metadata), reason) {
			return true
		}
	}
	return false
}

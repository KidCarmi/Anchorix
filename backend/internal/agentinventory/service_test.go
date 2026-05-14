package agentinventory

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixedClock returns the same time on every call. Service tests that
// assert on ReceivedAt / UpdatedAt pin this to a known instant.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// fakeRepo is an in-memory SnapshotRepository for unit tests. It
// keys exactly the way the real postgres repo does:
// (organization_id, agent_id).
type fakeRepo struct {
	mu sync.Mutex

	rows map[string]*Snapshot // key: orgID + "|" + agentID

	upsertCalls int
	getCalls    int

	upsertErr error
	getErr    error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{rows: map[string]*Snapshot{}}
}

func (f *fakeRepo) Upsert(_ context.Context, s *Snapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upsertCalls++
	if f.upsertErr != nil {
		return f.upsertErr
	}
	cp := *s
	cp.LocalIPs = append([]string(nil), s.LocalIPs...)
	f.rows[s.OrganizationID+"|"+s.AgentID] = &cp
	return nil
}

func (f *fakeRepo) GetByAgentAndOrg(_ context.Context, agentID, organizationID string) (*Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	row, ok := f.rows[organizationID+"|"+agentID]
	if !ok {
		return nil, ErrSnapshotNotFound
	}
	cp := *row
	cp.LocalIPs = append([]string(nil), row.LocalIPs...)
	return &cp, nil
}

const (
	testOrg     = "anchorix"
	testAgentID = "agent-abc"
)

func newServiceForTest(t *testing.T) (*Service, *fakeRepo, time.Time) {
	t.Helper()
	repo := newFakeRepo()
	clk := fixedClock{now: time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)}
	svc, err := NewService(repo, clk)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, repo, clk.now
}

func TestNewServiceRejectsMissingDeps(t *testing.T) {
	if _, err := NewService(nil, fixedClock{}); err == nil {
		t.Fatal("NewService(nil repo) = nil err; want error")
	}
	if _, err := NewService(newFakeRepo(), nil); err == nil {
		t.Fatal("NewService(nil clock) = nil err; want error")
	}
}

func TestSubmitHappyPathRecordsTrimmedFields(t *testing.T) {
	svc, repo, now := newServiceForTest(t)

	installed := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	got, err := svc.Submit(context.Background(), SubmitInput{
		OrganizationID: testOrg,
		AgentID:        testAgentID,
		Hostname:       "  ws-001.corp.example  ",
		OSName:         " Windows 11 ",
		OSVersion:      "10.0.22631 ",
		AgentVersion:   " 0.1.0",
		MachineArch:    "amd64",
		LocalIPs:       []string{"10.0.0.5", "  fe80::1%eth0  "},
		InstalledAt:    &installed,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if got.Hostname != "ws-001.corp.example" {
		t.Errorf("Hostname = %q, want trimmed", got.Hostname)
	}
	if got.OSName != "Windows 11" {
		t.Errorf("OSName = %q, want trimmed", got.OSName)
	}
	if got.AgentVersion != "0.1.0" {
		t.Errorf("AgentVersion = %q, want trimmed", got.AgentVersion)
	}
	if len(got.LocalIPs) != 2 || got.LocalIPs[0] != "10.0.0.5" || got.LocalIPs[1] != "fe80::1%eth0" {
		t.Errorf("LocalIPs = %#v, want trimmed entries", got.LocalIPs)
	}
	if !got.ReceivedAt.Equal(now) {
		t.Errorf("ReceivedAt = %v, want %v", got.ReceivedAt, now)
	}
	if !got.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
	}
	if got.InstalledAt == nil || !got.InstalledAt.Equal(installed) {
		t.Errorf("InstalledAt = %v, want %v", got.InstalledAt, installed)
	}
	if repo.upsertCalls != 1 {
		t.Errorf("upsertCalls = %d, want 1", repo.upsertCalls)
	}
}

func TestSubmitSecondCallReplacesSnapshot(t *testing.T) {
	svc, repo, _ := newServiceForTest(t)
	ctx := context.Background()
	if _, err := svc.Submit(ctx, baseValidInput()); err != nil {
		t.Fatalf("submit 1: %v", err)
	}
	in2 := baseValidInput()
	in2.AgentVersion = "0.1.1"
	in2.Hostname = "renamed"
	if _, err := svc.Submit(ctx, in2); err != nil {
		t.Fatalf("submit 2: %v", err)
	}
	if len(repo.rows) != 1 {
		t.Errorf("row count = %d, want 1", len(repo.rows))
	}
	row := repo.rows[testOrg+"|"+testAgentID]
	if row.AgentVersion != "0.1.1" {
		t.Errorf("AgentVersion = %q, want 0.1.1", row.AgentVersion)
	}
	if row.Hostname != "renamed" {
		t.Errorf("Hostname = %q, want renamed", row.Hostname)
	}
	if repo.upsertCalls != 2 {
		t.Errorf("upsertCalls = %d, want 2", repo.upsertCalls)
	}
}

func TestSubmitEmptyLocalIPsValid(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	in := baseValidInput()
	in.LocalIPs = nil
	got, err := svc.Submit(context.Background(), in)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if got.LocalIPs == nil {
		t.Error("LocalIPs = nil, want empty slice")
	}
	if len(got.LocalIPs) != 0 {
		t.Errorf("LocalIPs len = %d, want 0", len(got.LocalIPs))
	}
}

func TestSubmitRejectsMissingAgentID(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	in := baseValidInput()
	in.AgentID = ""
	_, err := svc.Submit(context.Background(), in)
	if !errors.Is(err, ErrInvalidSnapshotInput) {
		t.Errorf("err = %v, want ErrInvalidSnapshotInput", err)
	}
}

func TestSubmitRejectsMissingOrgID(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	in := baseValidInput()
	in.OrganizationID = ""
	_, err := svc.Submit(context.Background(), in)
	if !errors.Is(err, ErrInvalidSnapshotInput) {
		t.Errorf("err = %v, want ErrInvalidSnapshotInput", err)
	}
}

func TestSubmitRejectsOversizeFields(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*SubmitInput)
	}{
		{"hostname", func(in *SubmitInput) { in.Hostname = strings.Repeat("h", MaxHostnameLength+1) }},
		{"os_name", func(in *SubmitInput) { in.OSName = strings.Repeat("o", MaxOSNameLength+1) }},
		{"os_version", func(in *SubmitInput) { in.OSVersion = strings.Repeat("v", MaxOSVersionLength+1) }},
		{"agent_version", func(in *SubmitInput) { in.AgentVersion = strings.Repeat("a", MaxAgentVersionLength+1) }},
		{"machine_arch", func(in *SubmitInput) { in.MachineArch = strings.Repeat("m", MaxMachineArchLength+1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _ := newServiceForTest(t)
			in := baseValidInput()
			tc.mut(&in)
			_, err := svc.Submit(context.Background(), in)
			if !errors.Is(err, ErrInvalidSnapshotInput) {
				t.Errorf("err = %v, want ErrInvalidSnapshotInput", err)
			}
		})
	}
}

func TestSubmitRejectsTooManyLocalIPs(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	in := baseValidInput()
	in.LocalIPs = make([]string, MaxLocalIPs+1)
	for i := range in.LocalIPs {
		in.LocalIPs[i] = "10.0.0.1"
	}
	_, err := svc.Submit(context.Background(), in)
	if !errors.Is(err, ErrInvalidSnapshotInput) {
		t.Errorf("err = %v, want ErrInvalidSnapshotInput", err)
	}
}

func TestSubmitRejectsOversizeLocalIP(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	in := baseValidInput()
	in.LocalIPs = []string{strings.Repeat("a", MaxLocalIPLength+1)}
	_, err := svc.Submit(context.Background(), in)
	if !errors.Is(err, ErrInvalidSnapshotInput) {
		t.Errorf("err = %v, want ErrInvalidSnapshotInput", err)
	}
}

func TestSubmitRejectsEmptyLocalIPEntry(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	in := baseValidInput()
	in.LocalIPs = []string{"10.0.0.5", "   "}
	_, err := svc.Submit(context.Background(), in)
	if !errors.Is(err, ErrInvalidSnapshotInput) {
		t.Errorf("err = %v, want ErrInvalidSnapshotInput for whitespace-only entry", err)
	}
}

func TestGetForAgentMissingReturnsNotFound(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	_, err := svc.GetForAgent(context.Background(), testAgentID, testOrg)
	if !errors.Is(err, ErrSnapshotNotFound) {
		t.Errorf("err = %v, want ErrSnapshotNotFound", err)
	}
}

func TestGetForAgentReturnsStoredSnapshot(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	ctx := context.Background()
	if _, err := svc.Submit(ctx, baseValidInput()); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	got, err := svc.GetForAgent(ctx, testAgentID, testOrg)
	if err != nil {
		t.Fatalf("GetForAgent: %v", err)
	}
	if got.AgentID != testAgentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, testAgentID)
	}
	if got.Hostname != "ws-001" {
		t.Errorf("Hostname = %q, want ws-001", got.Hostname)
	}
}

func TestGetForAgentCrossOrgReturnsNotFound(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	ctx := context.Background()
	if _, err := svc.Submit(ctx, baseValidInput()); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	_, err := svc.GetForAgent(ctx, testAgentID, "other-org")
	if !errors.Is(err, ErrSnapshotNotFound) {
		t.Errorf("err = %v, want ErrSnapshotNotFound for cross-org lookup", err)
	}
}

func TestGetForAgentRejectsEmptyArgs(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	if _, err := svc.GetForAgent(context.Background(), "", testOrg); !errors.Is(err, ErrInvalidSnapshotInput) {
		t.Errorf("empty agent id err = %v, want ErrInvalidSnapshotInput", err)
	}
	if _, err := svc.GetForAgent(context.Background(), testAgentID, ""); !errors.Is(err, ErrInvalidSnapshotInput) {
		t.Errorf("empty org id err = %v, want ErrInvalidSnapshotInput", err)
	}
}

func baseValidInput() SubmitInput {
	return SubmitInput{
		OrganizationID: testOrg,
		AgentID:        testAgentID,
		Hostname:       "ws-001",
		OSName:         "Windows 11",
		OSVersion:      "10.0.22631",
		AgentVersion:   "0.1.0",
		MachineArch:    "amd64",
		LocalIPs:       []string{"10.0.0.5"},
	}
}

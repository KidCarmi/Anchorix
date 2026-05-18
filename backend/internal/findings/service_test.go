package findings

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// --- fakes ---------------------------------------------------------

// fakeFindingsRepo is an in-memory Repository used to exercise
// Service.Recompute's lifecycle logic without a real database.
// All mutations go through this struct so tests can inspect the
// final state and the call history.
type fakeFindingsRepo struct {
	mu      sync.Mutex
	rows    map[string]*Finding // keyed by ID
	inserts []Finding
	updates []Finding
}

func newFakeFindingsRepo() *fakeFindingsRepo {
	return &fakeFindingsRepo{rows: map[string]*Finding{}}
}

func (f *fakeFindingsRepo) InsertFinding(_ context.Context, finding *Finding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	clone := *finding
	f.rows[finding.ID] = &clone
	f.inserts = append(f.inserts, clone)
	return nil
}

func (f *fakeFindingsRepo) UpdateFinding(_ context.Context, finding *Finding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[finding.ID]; !ok {
		return ErrFindingNotFound
	}
	clone := *finding
	f.rows[finding.ID] = &clone
	f.updates = append(f.updates, clone)
	return nil
}

func (f *fakeFindingsRepo) GetFinding(_ context.Context, orgID, id string) (*Finding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.rows[id]
	if !ok || row.OrganizationID != orgID {
		return nil, ErrFindingNotFound
	}
	c := *row
	return &c, nil
}

func (f *fakeFindingsRepo) ListAllForOrg(_ context.Context, orgID string) ([]Finding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Finding, 0)
	for _, r := range f.rows {
		if r.OrganizationID == orgID {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (f *fakeFindingsRepo) ListFindings(_ context.Context, _ ListQuery) ([]Finding, error) {
	// Not used by Recompute. Empty stub keeps the interface
	// satisfied for any future test that wants it.
	return nil, nil
}

// fakeCertificateLister returns a fixed set of cert summaries.
type fakeCertificateLister struct {
	certs []inventory.CertificateSummary
}

func (f fakeCertificateLister) ListAllCertificateSummariesForOrg(_ context.Context, _ string) ([]inventory.CertificateSummary, error) {
	return f.certs, nil
}

// fakeAudit records every audit Event and optionally fails on
// the next Record call. Used to exercise the audit-rollback
// path in Recompute.
type fakeAudit struct {
	mu    sync.Mutex
	calls []audit.Event
	fail  error
}

func (a *fakeAudit) Record(_ context.Context, e audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return a.fail
	}
	a.calls = append(a.calls, e)
	return nil
}

func (a *fakeAudit) List(_ context.Context, _ audit.ListQuery) ([]audit.Event, error) {
	return nil, nil
}

// fakeTransactor.WithTxLockedFindings invokes fn and, on any
// error fn returns, runs the registered rollback callbacks to
// mimic the transactional rollback the real implementation
// provides. Each repo mutation registers a rollback that
// reverses it; this lets the audit-failure test prove that
// finding state changes get undone.
//
// The fake does NOT model the per-org advisory lock that the
// real implementation acquires — the lock's serialization
// behavior is exercised by the integration concurrency test
// against real Postgres, where the lock has observable effect.
// Unit tests here only exercise the rollback property.
type fakeTransactor struct {
	rollbacks []func()
}

func (t *fakeTransactor) WithTxLockedFindings(_ context.Context, _ string, fn func(ctx context.Context) error) error {
	t.rollbacks = nil
	err := fn(context.Background())
	if err != nil {
		for i := len(t.rollbacks) - 1; i >= 0; i-- {
			t.rollbacks[i]()
		}
	}
	return err
}

// rollbackAwareRepo wraps fakeFindingsRepo so each Insert/Update
// also registers a rollback on the transactor. Letting the
// service exercise the real "audit failure -> rollback finding
// state" property without the test reaching inside the service.
type rollbackAwareRepo struct {
	inner *fakeFindingsRepo
	tx    *fakeTransactor
}

func (r *rollbackAwareRepo) InsertFinding(ctx context.Context, f *Finding) error {
	if err := r.inner.InsertFinding(ctx, f); err != nil {
		return err
	}
	id := f.ID
	r.tx.rollbacks = append(r.tx.rollbacks, func() {
		r.inner.mu.Lock()
		defer r.inner.mu.Unlock()
		delete(r.inner.rows, id)
	})
	return nil
}

func (r *rollbackAwareRepo) UpdateFinding(ctx context.Context, f *Finding) error {
	r.inner.mu.Lock()
	prior, ok := r.inner.rows[f.ID]
	if !ok {
		r.inner.mu.Unlock()
		return ErrFindingNotFound
	}
	saved := *prior
	r.inner.mu.Unlock()

	if err := r.inner.UpdateFinding(ctx, f); err != nil {
		return err
	}
	r.tx.rollbacks = append(r.tx.rollbacks, func() {
		r.inner.mu.Lock()
		defer r.inner.mu.Unlock()
		r.inner.rows[saved.ID] = &saved
	})
	return nil
}

func (r *rollbackAwareRepo) GetFinding(ctx context.Context, orgID, id string) (*Finding, error) {
	return r.inner.GetFinding(ctx, orgID, id)
}

func (r *rollbackAwareRepo) ListAllForOrg(ctx context.Context, orgID string) ([]Finding, error) {
	return r.inner.ListAllForOrg(ctx, orgID)
}

func (r *rollbackAwareRepo) ListFindings(ctx context.Context, q ListQuery) ([]Finding, error) {
	return r.inner.ListFindings(ctx, q)
}

// fixedClock satisfies clock.Clock with a stable Now().
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// --- tests ---------------------------------------------------------

// TestServiceRecompute_AuditFailureRollsBackFindings is the unit
// pin for the H-021 invariant "If audit fails: recompute state
// changes must roll back". Difficult to exercise through the
// public HTTP API (no failure-injection in the real
// audit.Recorder), so the service is wired with a fake audit
// recorder that fails, a fake transactor that runs rollbacks,
// and a rollback-aware repository that registers undo callbacks
// per mutation.
//
// Property: after a recompute call whose audit Record returns
// an error, the findings repository must contain NO rows the
// recompute would have inserted/updated.
func TestServiceRecompute_AuditFailureRollsBackFindings(t *testing.T) {
	repo := newFakeFindingsRepo()
	tx := &fakeTransactor{}
	rollbackRepo := &rollbackAwareRepo{inner: repo, tx: tx}
	aud := &fakeAudit{fail: errors.New("synthetic audit failure")}
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}

	// One weak-RSA cert: would normally open 1 finding.
	certs := []inventory.CertificateSummary{
		{
			ID:            "cert-rollback-target",
			Subject:       "CN=rollback.example",
			SignatureAlg:  "SHA256-RSA",
			PublicKeyAlg:  "RSA",
			PublicKeyBits: 1024,
			NotBefore:     clk.t.Add(-30 * 24 * time.Hour),
			NotAfter:      clk.t.Add(180 * 24 * time.Hour),
		},
	}
	certs2 := fakeCertificateLister{certs: certs}

	svc, err := NewService(rollbackRepo, certs2, tx, aud, clk, DefaultRules())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = svc.Recompute(context.Background(), RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "test-user-id",
	})
	if err == nil {
		t.Fatal("expected error from Recompute when audit fails")
	}
	if !errors.Is(err, ErrInternalAudit) {
		t.Errorf("err = %v, want wrapping ErrInternalAudit", err)
	}

	// The synthetic insert should have been rolled back. The
	// repo must contain zero rows for the org.
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.rows) != 0 {
		t.Errorf("repo rows = %d after audit failure, want 0 (rollback failed)", len(repo.rows))
	}
}

// TestServiceRecompute_SuccessWritesAuditAndFinding is the
// negative-space counterpart: with a working audit recorder, the
// happy path produces both the finding and the audit row in one
// transaction.
func TestServiceRecompute_SuccessWritesAuditAndFinding(t *testing.T) {
	repo := newFakeFindingsRepo()
	tx := &fakeTransactor{}
	rollbackRepo := &rollbackAwareRepo{inner: repo, tx: tx}
	aud := &fakeAudit{}
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}

	certs := []inventory.CertificateSummary{
		{
			ID:            "happy-cert",
			Subject:       "CN=happy.example",
			SignatureAlg:  "SHA256-RSA",
			PublicKeyAlg:  "RSA",
			PublicKeyBits: 1024,
			NotBefore:     clk.t.Add(-30 * 24 * time.Hour),
			NotAfter:      clk.t.Add(180 * 24 * time.Hour),
		},
	}
	svc, err := NewService(rollbackRepo, fakeCertificateLister{certs: certs}, tx, aud, clk, DefaultRules())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	out, err := svc.Recompute(context.Background(), RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "test-user-id",
	})
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if out.Opened != 1 {
		t.Errorf("opened = %d, want 1", out.Opened)
	}
	if len(repo.rows) != 1 {
		t.Errorf("repo rows = %d, want 1", len(repo.rows))
	}
	if len(aud.calls) != 1 {
		t.Errorf("audit calls = %d, want 1", len(aud.calls))
	}
	if aud.calls[0].Action != "findings.recomputed" {
		t.Errorf("audit action = %q, want findings.recomputed", aud.calls[0].Action)
	}
	// Codex P2: the audit row must carry the real user ID, not
	// a hardcoded "operator" placeholder. ActorType must mirror.
	if aud.calls[0].Actor != "test-user-id" {
		t.Errorf("audit actor = %q, want test-user-id", aud.calls[0].Actor)
	}
	if aud.calls[0].ActorType != "user" {
		t.Errorf("audit actor_type = %q, want user", aud.calls[0].ActorType)
	}
}

// TestServiceRecompute_InvalidInput pins the empty-org rejection.
func TestServiceRecompute_InvalidInput(t *testing.T) {
	repo := newFakeFindingsRepo()
	tx := &fakeTransactor{}
	rollbackRepo := &rollbackAwareRepo{inner: repo, tx: tx}
	svc, err := NewService(
		rollbackRepo, fakeCertificateLister{}, tx, &fakeAudit{},
		fixedClock{t: time.Now()}, DefaultRules(),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, err = svc.Recompute(context.Background(), RecomputeInput{OrganizationID: "   "})
	if !errors.Is(err, ErrInvalidRecomputeInput) {
		t.Errorf("err = %v, want ErrInvalidRecomputeInput", err)
	}
}

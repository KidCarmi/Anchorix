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

// --- H-023 override + recompute transitions ---------------------
//
// The five tests below replace the H-021 hardening pass's
// TestServiceRecompute_UnsupportedStatusFailsLoudly_* pair —
// those were placeholders pinning the defensive
// `ErrUnsupportedFindingStatus` arm BEFORE H-023 shipped the
// real handling. With H-023 in place, the override statuses
// now have positive behavior contracts, and the tests below
// pin them.

func seedFindingWithStatus(t *testing.T, repo *fakeFindingsRepo, clk fixedClock, status Status, suppressExpiresAt *time.Time) string {
	t.Helper()
	id := "pre-" + string(status) + "-finding"
	f := &Finding{
		ID:                id,
		OrganizationID:    "anchorix",
		CertificateID:     "target-cert",
		RuleID:            RuleWeakRSAKey,
		RuleVersion:       1,
		Severity:          SeverityHigh,
		Status:            status,
		Title:             "RSA key below 2048 bits",
		FirstSeenAt:       clk.t.Add(-24 * time.Hour),
		LastSeenAt:        clk.t.Add(-12 * time.Hour),
		UpdatedAt:         clk.t.Add(-12 * time.Hour),
		StatusReason:      "ticket CSCM-001",
		StatusActor:       "alice@example.com",
		SuppressExpiresAt: suppressExpiresAt,
	}
	changed := clk.t.Add(-12 * time.Hour)
	f.StatusChangedAt = &changed
	if err := repo.InsertFinding(context.Background(), f); err != nil {
		t.Fatalf("pre-seed: %v", err)
	}
	return id
}

func matchingWeakRSACerts(clk fixedClock) []inventory.CertificateSummary {
	return []inventory.CertificateSummary{{
		ID:            "target-cert",
		Subject:       "CN=target.example",
		SignatureAlg:  "SHA256-RSA",
		PublicKeyAlg:  "RSA",
		PublicKeyBits: 1024,
		NotBefore:     clk.t.Add(-30 * 24 * time.Hour),
		NotAfter:      clk.t.Add(180 * 24 * time.Hour),
	}}
}

func healthyCerts(clk fixedClock) []inventory.CertificateSummary {
	c := matchingWeakRSACerts(clk)[0]
	c.PublicKeyBits = 2048 // no longer weak
	return []inventory.CertificateSummary{c}
}

func newServiceForOverride(t *testing.T, clk fixedClock, certs []inventory.CertificateSummary) (*Service, *fakeFindingsRepo) {
	t.Helper()
	repo := newFakeFindingsRepo()
	tx := &fakeTransactor{}
	rollbackRepo := &rollbackAwareRepo{inner: repo, tx: tx}
	svc, err := NewService(rollbackRepo, fakeCertificateLister{certs: certs},
		tx, &fakeAudit{}, clk, DefaultRules())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	// Repo wrapper isn't visible to tests that want to inspect
	// the raw rows; return the inner repo so assertions can
	// read state directly.
	return svc, repo
}

// TestServiceRecompute_AcknowledgedStaysAcknowledged pins:
// rule still matches on an acknowledged finding → stays
// acknowledged, last_seen_at bumped, override metadata
// PRESERVED.
func TestServiceRecompute_AcknowledgedStaysAcknowledged(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	svc, repo := newServiceForOverride(t, clk, matchingWeakRSACerts(clk))
	id := seedFindingWithStatus(t, repo, clk, StatusAcknowledged, nil)

	out, err := svc.Recompute(context.Background(), RecomputeInput{
		OrganizationID: "anchorix", ActorUserID: "test-user",
	})
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if out.Updated != 1 || out.Opened != 0 || out.Resolved != 0 {
		t.Errorf("counters = (opened=%d updated=%d resolved=%d), want (0,1,0)",
			out.Opened, out.Updated, out.Resolved)
	}

	got, _ := repo.GetFinding(context.Background(), "anchorix", id)
	if got.Status != StatusAcknowledged {
		t.Errorf("status = %q, want acknowledged", got.Status)
	}
	if got.StatusReason != "ticket CSCM-001" {
		t.Errorf("status_reason = %q, want preserved value", got.StatusReason)
	}
	if !got.LastSeenAt.Equal(clk.t) {
		t.Errorf("last_seen_at = %s, want bumped to clk.t", got.LastSeenAt)
	}
}

// TestServiceRecompute_AcknowledgedNoLongerMatchingResolves
// pins: rule stops matching on an acknowledged finding →
// resolves and CLEARS the override metadata.
func TestServiceRecompute_AcknowledgedNoLongerMatchingResolves(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	svc, repo := newServiceForOverride(t, clk, healthyCerts(clk))
	id := seedFindingWithStatus(t, repo, clk, StatusAcknowledged, nil)

	out, err := svc.Recompute(context.Background(), RecomputeInput{
		OrganizationID: "anchorix", ActorUserID: "test-user",
	})
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if out.Resolved != 1 {
		t.Errorf("resolved counter = %d, want 1", out.Resolved)
	}

	got, _ := repo.GetFinding(context.Background(), "anchorix", id)
	if got.Status != StatusResolved {
		t.Errorf("status = %q, want resolved", got.Status)
	}
	if got.StatusReason != "" || got.StatusActor != "" || got.StatusChangedAt != nil {
		t.Errorf("override metadata not cleared: reason=%q actor=%q changed=%v",
			got.StatusReason, got.StatusActor, got.StatusChangedAt)
	}
}

// TestServiceRecompute_SuppressedNotExpiredStays pins:
// suppressed + not expired + rule matches → stays suppressed.
func TestServiceRecompute_SuppressedNotExpiredStays(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	future := clk.t.Add(7 * 24 * time.Hour)
	svc, repo := newServiceForOverride(t, clk, matchingWeakRSACerts(clk))
	id := seedFindingWithStatus(t, repo, clk, StatusSuppressed, &future)

	out, err := svc.Recompute(context.Background(), RecomputeInput{
		OrganizationID: "anchorix", ActorUserID: "test-user",
	})
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if out.Updated != 1 || out.Opened != 0 {
		t.Errorf("counters = (opened=%d updated=%d), want (0,1)", out.Opened, out.Updated)
	}

	got, _ := repo.GetFinding(context.Background(), "anchorix", id)
	if got.Status != StatusSuppressed {
		t.Errorf("status = %q, want suppressed", got.Status)
	}
	if got.SuppressExpiresAt == nil || !got.SuppressExpiresAt.Equal(future) {
		t.Errorf("suppress_expires_at not preserved: %v", got.SuppressExpiresAt)
	}
}

// TestServiceRecompute_SuppressedNoExpiryStaysIndefinitely pins
// the nil-expiry permanent-suppression path: the matches loop's
// expiry-check is `SuppressExpiresAt != nil && ...`, so a nil
// pointer must skip the reopen branch entirely no matter how
// far in the future `now` is. Without this test, a regression
// to e.g. `SuppressExpiresAt == nil || ...` would silently
// reopen every nil-expiry suppression.
//
// The clock is advanced by 60 days (NOT 100 years) so the
// seeded cert stays valid — a 100-year jump would cross the
// cert's not_after and trigger the `certificate_expired` rule
// against the SAME cert, adding a second finding and muddying
// the counter assertion. 60 days is well past any plausible
// suppression-expiry window operators set in practice but
// safely within the seeded cert's 180-day validity.
func TestServiceRecompute_SuppressedNoExpiryStaysIndefinitely(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	svc, repo := newServiceForOverride(t, clk, matchingWeakRSACerts(clk))
	// nil expiry — no SuppressExpiresAt argument.
	id := seedFindingWithStatus(t, repo, clk, StatusSuppressed, nil)

	// First recompute at clk.t — should stay suppressed.
	out, err := svc.Recompute(context.Background(), RecomputeInput{
		OrganizationID: "anchorix", ActorUserID: "test-user",
	})
	if err != nil {
		t.Fatalf("Recompute at clk.t: %v", err)
	}
	if out.Opened != 0 || out.Updated != 1 {
		t.Errorf("counters at clk.t = (opened=%d updated=%d), want (0,1)", out.Opened, out.Updated)
	}

	got, _ := repo.GetFinding(context.Background(), "anchorix", id)
	if got.Status != StatusSuppressed {
		t.Fatalf("status at clk.t = %q, want suppressed", got.Status)
	}
	if got.SuppressExpiresAt != nil {
		t.Errorf("expected nil expiry preserved, got %v", got.SuppressExpiresAt)
	}

	// Advance the clock 60 days. The seeded cert's not_after is
	// clk.t + 180 days so it stays valid; the only matching
	// rule remains weak_rsa_key, and the suppression of the
	// pre-existing finding must NOT reopen. Without the `!= nil`
	// guard, this would fire the expired branch.
	svc.clock = fixedClock{t: clk.t.AddDate(0, 0, 60)}

	out, err = svc.Recompute(context.Background(), RecomputeInput{
		OrganizationID: "anchorix", ActorUserID: "test-user",
	})
	if err != nil {
		t.Fatalf("Recompute at +60d: %v", err)
	}
	if out.Opened != 0 || out.Updated != 1 {
		t.Errorf("counters at +60d = (opened=%d updated=%d), want (0,1) — nil expiry must NEVER reopen",
			out.Opened, out.Updated)
	}

	got, _ = repo.GetFinding(context.Background(), "anchorix", id)
	if got.Status != StatusSuppressed {
		t.Errorf("status at +60d = %q, want suppressed (nil expiry must not auto-reopen)", got.Status)
	}
	if got.SuppressExpiresAt != nil {
		t.Errorf("suppress_expires_at = %v, want nil (permanent suppression must stay permanent)",
			got.SuppressExpiresAt)
	}
}

// TestServiceRecompute_SuppressedExpiredReopens pins: suppressed
// + expiry passed + rule still matches → reopens to `open`
// AND clears override metadata.
func TestServiceRecompute_SuppressedExpiredReopens(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	past := clk.t.Add(-1 * time.Hour) // expired
	svc, repo := newServiceForOverride(t, clk, matchingWeakRSACerts(clk))
	id := seedFindingWithStatus(t, repo, clk, StatusSuppressed, &past)

	out, err := svc.Recompute(context.Background(), RecomputeInput{
		OrganizationID: "anchorix", ActorUserID: "test-user",
	})
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if out.Opened != 1 {
		t.Errorf("opened counter = %d, want 1", out.Opened)
	}

	got, _ := repo.GetFinding(context.Background(), "anchorix", id)
	if got.Status != StatusOpen {
		t.Errorf("status = %q, want open (reopened from expired suppression)", got.Status)
	}
	if got.SuppressExpiresAt != nil {
		t.Errorf("suppress_expires_at = %v, want nil after reopen", got.SuppressExpiresAt)
	}
	if got.StatusReason != "" {
		t.Errorf("status_reason = %q, want cleared after reopen", got.StatusReason)
	}
}

// TestServiceRecompute_SuppressedNoLongerMatchingResolves pins:
// suppressed + rule no longer matches → resolves + clears.
func TestServiceRecompute_SuppressedNoLongerMatchingResolves(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	future := clk.t.Add(7 * 24 * time.Hour)
	svc, repo := newServiceForOverride(t, clk, healthyCerts(clk))
	id := seedFindingWithStatus(t, repo, clk, StatusSuppressed, &future)

	if _, err := svc.Recompute(context.Background(), RecomputeInput{
		OrganizationID: "anchorix", ActorUserID: "test-user",
	}); err != nil {
		t.Fatalf("Recompute: %v", err)
	}

	got, _ := repo.GetFinding(context.Background(), "anchorix", id)
	if got.Status != StatusResolved {
		t.Errorf("status = %q, want resolved", got.Status)
	}
	if got.SuppressExpiresAt != nil || got.StatusReason != "" {
		t.Errorf("override metadata not cleared after resolve")
	}
}

// --- H-023 override input validation ----------------------------

func TestServiceAcknowledge_RequiresReason(t *testing.T) {
	clk := fixedClock{t: time.Now()}
	svc, _ := newServiceForOverride(t, clk, nil)
	for _, reason := range []string{"", "   ", "\t\n"} {
		_, err := svc.AcknowledgeFinding(context.Background(), AcknowledgeInput{
			OrganizationID: "anchorix", FindingID: "x", ActorUserID: "u", Reason: reason,
		})
		if !errors.Is(err, ErrInvalidOverrideInput) {
			t.Errorf("reason %q: err = %v, want ErrInvalidOverrideInput", reason, err)
		}
	}
}

func TestServiceSuppress_RequiresReason(t *testing.T) {
	clk := fixedClock{t: time.Now()}
	svc, _ := newServiceForOverride(t, clk, nil)
	_, err := svc.SuppressFinding(context.Background(), SuppressInput{
		OrganizationID: "anchorix", FindingID: "x", ActorUserID: "u", Reason: "",
	})
	if !errors.Is(err, ErrInvalidOverrideInput) {
		t.Errorf("err = %v, want ErrInvalidOverrideInput", err)
	}
}

func TestServiceSuppress_RejectsPastExpiry(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	svc, _ := newServiceForOverride(t, clk, nil)
	past := clk.t.Add(-1 * time.Second)
	_, err := svc.SuppressFinding(context.Background(), SuppressInput{
		OrganizationID: "anchorix", FindingID: "x", ActorUserID: "u",
		Reason: "ok", ExpiresAt: &past,
	})
	if !errors.Is(err, ErrInvalidOverrideInput) {
		t.Errorf("past expiry: err = %v, want ErrInvalidOverrideInput", err)
	}
	// Exactly-now is also rejected (strictly-future).
	now := clk.t
	_, err = svc.SuppressFinding(context.Background(), SuppressInput{
		OrganizationID: "anchorix", FindingID: "x", ActorUserID: "u",
		Reason: "ok", ExpiresAt: &now,
	})
	if !errors.Is(err, ErrInvalidOverrideInput) {
		t.Errorf("exact-now expiry: err = %v, want ErrInvalidOverrideInput", err)
	}
}

// TestServiceAcknowledge_AuditFailureRollsBack mirrors the H-021
// audit-rollback test for the new override path.
func TestServiceAcknowledge_AuditFailureRollsBack(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	repo := newFakeFindingsRepo()
	tx := &fakeTransactor{}
	rollbackRepo := &rollbackAwareRepo{inner: repo, tx: tx}
	aud := &fakeAudit{fail: errors.New("synthetic audit failure")}

	// Pre-seed an open finding.
	if err := repo.InsertFinding(context.Background(), &Finding{
		ID: "open-finding", OrganizationID: "anchorix",
		CertificateID: "c", RuleID: RuleWeakRSAKey,
		Status: StatusOpen, Title: "T", Severity: SeverityHigh,
		FirstSeenAt: clk.t, LastSeenAt: clk.t, UpdatedAt: clk.t,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	svc, err := NewService(rollbackRepo, fakeCertificateLister{}, tx, aud, clk, DefaultRules())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, err = svc.AcknowledgeFinding(context.Background(), AcknowledgeInput{
		OrganizationID: "anchorix", FindingID: "open-finding",
		ActorUserID: "u", Reason: "test",
	})
	if !errors.Is(err, ErrInternalAudit) {
		t.Fatalf("err = %v, want ErrInternalAudit", err)
	}
	// The finding's status MUST still be `open` — rollback worked.
	got, _ := repo.GetFinding(context.Background(), "anchorix", "open-finding")
	if got.Status != StatusOpen {
		t.Errorf("status = %q, want open (rollback failed)", got.Status)
	}
}

// TestServiceAcknowledge_ClearsResolvedAt pins the Codex P2 fix
// on PR #34: overriding a resolved finding (acknowledge or
// suppress) MUST clear `resolved_at` so the documented invariant
// "resolved_at is non-null iff status == 'resolved'" holds.
// An earlier draft left ResolvedAt populated on the override
// path, which would have surfaced rows with
// status="acknowledged" AND a non-null resolved_at — a wire-
// contract bug.
func TestServiceAcknowledge_ClearsResolvedAt(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	repo := newFakeFindingsRepo()
	tx := &fakeTransactor{}
	rollbackRepo := &rollbackAwareRepo{inner: repo, tx: tx}

	// Pre-seed a resolved finding (an unusual but legitimate
	// state — the rule used to match, recompute resolved it,
	// then an operator wants to "I see this, don't reopen if
	// the rule matches again" via acknowledge).
	resolvedAt := clk.t.Add(-1 * time.Hour)
	if err := repo.InsertFinding(context.Background(), &Finding{
		ID: "resolved-finding", OrganizationID: "anchorix",
		CertificateID: "c", RuleID: RuleWeakRSAKey,
		Status: StatusResolved, Title: "T", Severity: SeverityHigh,
		FirstSeenAt: clk.t.Add(-2 * time.Hour),
		LastSeenAt:  clk.t.Add(-1 * time.Hour),
		ResolvedAt:  &resolvedAt,
		UpdatedAt:   clk.t.Add(-1 * time.Hour),
	}); err != nil {
		t.Fatalf("pre-seed: %v", err)
	}

	svc, err := NewService(rollbackRepo, fakeCertificateLister{},
		tx, &fakeAudit{}, clk, DefaultRules())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	updated, err := svc.AcknowledgeFinding(context.Background(), AcknowledgeInput{
		OrganizationID: "anchorix", FindingID: "resolved-finding",
		ActorUserID: "u", Reason: "ack the resolved one",
	})
	if err != nil {
		t.Fatalf("AcknowledgeFinding: %v", err)
	}
	if updated.Status != StatusAcknowledged {
		t.Errorf("status = %q, want acknowledged", updated.Status)
	}
	if updated.ResolvedAt != nil {
		t.Errorf("resolved_at = %v, want nil (invariant: non-null iff status=resolved)",
			updated.ResolvedAt)
	}

	// Double-check by re-reading via the repo.
	got, _ := repo.GetFinding(context.Background(), "anchorix", "resolved-finding")
	if got.ResolvedAt != nil {
		t.Errorf("repo ResolvedAt = %v, want nil after override", got.ResolvedAt)
	}
}

// TestServiceSuppress_ClearsResolvedAt is the suppress-path
// counterpart for completeness — both override paths must
// honor the invariant.
func TestServiceSuppress_ClearsResolvedAt(t *testing.T) {
	clk := fixedClock{t: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	repo := newFakeFindingsRepo()
	tx := &fakeTransactor{}
	rollbackRepo := &rollbackAwareRepo{inner: repo, tx: tx}

	resolvedAt := clk.t.Add(-1 * time.Hour)
	if err := repo.InsertFinding(context.Background(), &Finding{
		ID: "resolved-finding-2", OrganizationID: "anchorix",
		CertificateID: "c", RuleID: RuleWeakRSAKey,
		Status: StatusResolved, Title: "T", Severity: SeverityHigh,
		FirstSeenAt: clk.t.Add(-2 * time.Hour),
		LastSeenAt:  clk.t.Add(-1 * time.Hour),
		ResolvedAt:  &resolvedAt,
		UpdatedAt:   clk.t.Add(-1 * time.Hour),
	}); err != nil {
		t.Fatalf("pre-seed: %v", err)
	}

	svc, _ := NewService(rollbackRepo, fakeCertificateLister{},
		tx, &fakeAudit{}, clk, DefaultRules())

	future := clk.t.Add(7 * 24 * time.Hour)
	updated, err := svc.SuppressFinding(context.Background(), SuppressInput{
		OrganizationID: "anchorix", FindingID: "resolved-finding-2",
		ActorUserID: "u", Reason: "suppress the resolved one",
		ExpiresAt: &future,
	})
	if err != nil {
		t.Fatalf("SuppressFinding: %v", err)
	}
	if updated.ResolvedAt != nil {
		t.Errorf("suppress resolved_at = %v, want nil", updated.ResolvedAt)
	}
}

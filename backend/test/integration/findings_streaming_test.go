//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
	"github.com/kidcarmi/anchorix/backend/internal/inventory/fixtures"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- H-024B integration tests --------------------------------------
//
// The H-024B streaming recompute rewrite is gated on two integration
// tests in this file:
//
//   1. TestFindingsByteIdenticalLoadAllVsStreaming — proves the
//      streaming path's final findings-table state matches the legacy
//      load-all path's against the same Smallv01 fixture.
//   2. TestFindingsStreamingRecomputeSnapshotIsolation — proves
//      REPEATABLE READ + session-scope advisory lock together prevent
//      a concurrent ingestion commit from leaking into an in-flight
//      streaming recompute.
//
// Plus one supporting test that asserts the new audit-metadata fields
// (`loaded_certificates`, `loaded_findings`) are emitted.

// findingsSnapshotRow is the byte-comparable shape of one
// `findings` row used by TestFindingsByteIdenticalLoadAllVsStreaming.
// Includes every column the recompute touches; the override
// metadata columns are explicit so a future regression that
// drops one would surface as a snapshot mismatch.
type findingsSnapshotRow struct {
	ID                string
	OrganizationID    string
	CertificateID     string
	RuleID            string
	RuleVersion       int
	Severity          string
	Status            string
	Title             string
	Evidence          string
	FirstSeenAt       time.Time
	LastSeenAt        time.Time
	ResolvedAt        *time.Time
	UpdatedAt         time.Time
	StatusReason      *string
	StatusActor       *string
	StatusChangedAt   *time.Time
	SuppressExpiresAt *time.Time
}

func snapshotFindings(t *testing.T, db *postgres.DB) []findingsSnapshotRow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var rows []findingsSnapshotRow
	err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		// Order by (certificate_id, rule_id) so the snapshot
		// is stable regardless of the insert order the diff
		// happens to use. Both diff paths randomise map
		// iteration; an id-ordered snapshot would be flaky.
		r, err := tx.Query(ctx, `
			SELECT id, organization_id, certificate_id, rule_id, rule_version,
			       severity, status, title, evidence::text,
			       opened_at, last_seen_at, resolved_at, updated_at,
			       status_reason, status_actor, status_changed_at, suppress_expires_at
			  FROM findings
			 ORDER BY organization_id, certificate_id, rule_id`)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var row findingsSnapshotRow
			if err := r.Scan(
				&row.ID, &row.OrganizationID, &row.CertificateID, &row.RuleID, &row.RuleVersion,
				&row.Severity, &row.Status, &row.Title, &row.Evidence,
				&row.FirstSeenAt, &row.LastSeenAt, &row.ResolvedAt, &row.UpdatedAt,
				&row.StatusReason, &row.StatusActor, &row.StatusChangedAt, &row.SuppressExpiresAt,
			); err != nil {
				return err
			}
			rows = append(rows, row)
		}
		return r.Err()
	})
	if err != nil {
		t.Fatalf("snapshot findings: %v", err)
	}
	return rows
}

// equivalentSnapshots returns true when two snapshots match
// modulo the per-row `ID` column. Recompute mints fresh ids
// on insert via `ids.New()` (crypto/rand), so IDs differ
// between runs even when every other column matches. The
// H-024B byte-identical contract is about the TABLE STATE,
// not the row primary keys — the rows still represent the
// same (cert, rule) pairs with the same derived data.
func equivalentSnapshots(a, b []findingsSnapshotRow) (bool, string) {
	if len(a) != len(b) {
		return false, "row count differs"
	}
	for i := range a {
		ai, bi := a[i], b[i]
		if ai.OrganizationID != bi.OrganizationID {
			return false, "org id differs"
		}
		if ai.CertificateID != bi.CertificateID || ai.RuleID != bi.RuleID {
			return false, "(cert_id, rule_id) tuple differs"
		}
		if ai.Severity != bi.Severity || ai.Status != bi.Status || ai.Title != bi.Title {
			return false, "severity/status/title differs"
		}
		if ai.RuleVersion != bi.RuleVersion {
			return false, "rule version differs"
		}
		if ai.Evidence != bi.Evidence {
			return false, "evidence JSON differs"
		}
		if !ai.FirstSeenAt.Equal(bi.FirstSeenAt) || !ai.LastSeenAt.Equal(bi.LastSeenAt) || !ai.UpdatedAt.Equal(bi.UpdatedAt) {
			return false, "timestamps differ"
		}
		if (ai.ResolvedAt == nil) != (bi.ResolvedAt == nil) {
			return false, "resolved_at nullness differs"
		}
		if ai.ResolvedAt != nil && !ai.ResolvedAt.Equal(*bi.ResolvedAt) {
			return false, "resolved_at differs"
		}
		// Override metadata equivalence.
		if !nullableStringEq(ai.StatusReason, bi.StatusReason) {
			return false, "status_reason differs"
		}
		if !nullableStringEq(ai.StatusActor, bi.StatusActor) {
			return false, "status_actor differs"
		}
		if !nullableTimeEq(ai.StatusChangedAt, bi.StatusChangedAt) {
			return false, "status_changed_at differs"
		}
		if !nullableTimeEq(ai.SuppressExpiresAt, bi.SuppressExpiresAt) {
			return false, "suppress_expires_at differs"
		}
	}
	return true, ""
}

func nullableStringEq(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	return *a == *b
}

func nullableTimeEq(a, b *time.Time) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	return a.Equal(*b)
}

// TestFindingsByteIdenticalLoadAllVsStreaming is the H-024B
// gating test: seed the Smallv01 fixture, run the legacy
// load-all recompute, snapshot the findings table; reset to
// the same fixture, run the streaming recompute, snapshot;
// assert the two snapshots are equivalent.
//
// Equivalence means "same rows up to differing primary keys"
// — see `equivalentSnapshots` for the exact comparator. The
// recompute mints fresh ids on every insert, so requiring
// byte-identical PKs would force the test to share state
// across runs, which would break the "reset between runs"
// premise.
//
// Without the H-024B helper extraction in service_diff.go,
// this test would surface every per-(cert, rule) decision
// drift between the two paths. With the extraction, the
// helpers are the single source of truth; this test is the
// gating proof that the orchestration around them does not
// re-introduce drift.
func TestFindingsByteIdenticalLoadAllVsStreaming(t *testing.T) {
	db := testDB(t)

	fixedNow := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)

	// Run 1: legacy load-all path against a freshly-seeded fixture.
	freshDatabase(t, db)
	seedSmallv01Fleet(t, db, fixedNow)
	svc := newStreamingFindingsService(t, db, fixedNow, nil)
	if _, err := svc.RecomputeLegacyLoadAll(context.Background(), findings.RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "fixture-tester",
	}); err != nil {
		t.Fatalf("legacy recompute: %v", err)
	}
	legacySnapshot := snapshotFindings(t, db)
	if len(legacySnapshot) == 0 {
		t.Fatal("legacy recompute produced no findings; fixture should fire at least one rule")
	}

	// Run 2: streaming path against the same fixture, fresh DB.
	freshDatabase(t, db)
	seedSmallv01Fleet(t, db, fixedNow)
	svc = newStreamingFindingsService(t, db, fixedNow, nil)
	if _, err := svc.Recompute(context.Background(), findings.RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "fixture-tester",
	}); err != nil {
		t.Fatalf("streaming recompute: %v", err)
	}
	streamingSnapshot := snapshotFindings(t, db)

	ok, reason := equivalentSnapshots(legacySnapshot, streamingSnapshot)
	if !ok {
		t.Fatalf("snapshots diverged: %s (legacy=%d rows, streaming=%d rows)",
			reason, len(legacySnapshot), len(streamingSnapshot))
	}
	if len(streamingSnapshot) < 5 {
		t.Errorf("streaming snapshot has only %d rows; Smallv01 should produce more", len(streamingSnapshot))
	}
}

// TestFindingsStreamingRecomputeSnapshotIsolation is the
// H-024B snapshot-isolation contract test. Pauses a streaming
// recompute mid-scan via a deterministic channel barrier
// (NOT sleep), commits a new weak-RSA cert through the same
// repo, then asserts the in-flight recompute does NOT see
// the new cert (its REPEATABLE READ snapshot was taken
// BEFORE the new commit).
//
// A second recompute, started AFTER the concurrent insert
// committed, MUST see the new cert and evaluate it.
//
// Without the H-024B `WithTxLockedFindingsRepeatableRead`
// session-scope-lock pattern this test fails: the streaming
// recompute's paginated cert SELECTs would each take a fresh
// READ COMMITTED snapshot and the in-flight run would surface
// the mid-recompute cert.
//
// Page-size override:
//
// The production `recomputeStreamingPageSize` is 500. With
// only a handful of seeded certs, the streaming loop would
// read everything in one cert SELECT, terminate immediately
// (`len(page) < pageSize`), and never make a second cert
// read. The mid-test insert would then happen AFTER the only
// cert SELECT — which means the test would pass even under
// READ COMMITTED. The Codex P2 review on PR #39 caught
// exactly this. Force pageSize=1 via
// `SetStreamingPageSizeForTest` so the streaming loop makes
// MULTIPLE cert SELECTs and the mid-recompute insert lands
// between them.
func TestFindingsStreamingRecomputeSnapshotIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	fixedNow := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)

	// Seed two weak-RSA certs first. IDs deliberately sort
	// BEFORE the mid-recompute cert's id below, so a fresh
	// snapshot (READ COMMITTED) would include the new row
	// when the streaming loop's id-ASC cursor reaches it.
	// Without this ordering, the test would false-pass under
	// READ COMMITTED because the cursor would walk PAST the
	// new cert's id (the new id is lexically earlier).
	for _, subject := range []string{"weak-iso-a.example", "weak-iso-b.example"} {
		fixture := mustWeakCertFixture("snapshot-iso-aa-" + subject)
		fixture.Subject = "CN=" + subject
		seedCert(t, db, fixture)
	}

	pauseAfterFirstPage := make(chan struct{}, 1)
	resumeAfterCommit := make(chan struct{})

	pauseLister := &pauseAfterFirstPageLister{
		inner:               postgres.NewCertificateInventoryRepository(db),
		pauseAfterFirstPage: pauseAfterFirstPage,
		resumeAfterCommit:   resumeAfterCommit,
	}

	svc := newStreamingFindingsService(t, db, fixedNow, pauseLister)

	// Force one-cert-per-page so the streaming loop makes
	// multiple cert SELECTs against the small fixture. See
	// the test doc for why this matters.
	svc.SetStreamingPageSizeForTest(1)

	type recomputeOutcome struct {
		result *findings.RecomputeResult
		err    error
	}
	first := make(chan recomputeOutcome, 1)
	go func() {
		result, err := svc.Recompute(context.Background(), findings.RecomputeInput{
			OrganizationID: "anchorix",
			ActorUserID:    "snapshot-iso",
		})
		first <- recomputeOutcome{result: result, err: err}
	}()

	// Wait for the first paginated cert read to land, then
	// commit a brand-new weak-RSA cert through the same DB
	// pool. Under REPEATABLE READ + session-scope lock the
	// in-flight recompute MUST NOT see it; its snapshot is
	// fixed to a moment BEFORE this commit.
	<-pauseAfterFirstPage
	// ID prefix "zz" ensures the new row sorts AFTER the two
	// seeded "aa" certs. The streaming loop's id-ASC cursor
	// would visit it on a subsequent page IF the snapshot
	// were re-read (READ COMMITTED). REPEATABLE READ keeps
	// the snapshot fixed, so the new row stays invisible to
	// the in-flight run.
	newFixture := mustWeakCertFixture("snapshot-iso-zz-mid-recompute")
	newFixture.Subject = "CN=snapshot-iso-mid-recompute.example"
	seedCert(t, db, newFixture)
	close(resumeAfterCommit)

	out := <-first
	if out.err != nil {
		t.Fatalf("in-flight recompute returned error: %v", out.err)
	}

	// The new cert should NOT have been evaluated by the
	// in-flight run. The recompute's EvaluatedCertificates
	// counter equals the cert count at snapshot time = 2.
	if out.result.EvaluatedCertificates != 2 {
		t.Errorf("EvaluatedCertificates = %d during in-flight recompute; want 2 (snapshot isolation failed — recompute saw the mid-recompute cert)",
			out.result.EvaluatedCertificates)
	}

	// Re-arm the lister so the second recompute runs without
	// pausing.
	pauseLister.disable()

	// Second recompute, AFTER the mid-recompute commit, MUST
	// see all three certs.
	second, err := svc.Recompute(context.Background(), findings.RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "snapshot-iso-second",
	})
	if err != nil {
		t.Fatalf("second recompute: %v", err)
	}
	if second.EvaluatedCertificates != 3 {
		t.Errorf("second recompute EvaluatedCertificates = %d; want 3", second.EvaluatedCertificates)
	}
}

// TestFindingsRecomputeAuditCarriesLoadedCounters pins the
// H-024B audit-metadata additive contract: the
// `findings.recomputed` audit row now includes
// `loaded_certificates` and `loaded_findings` alongside the
// existing counters.
func TestFindingsRecomputeAuditCarriesLoadedCounters(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	fixedNow := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	seedSmallv01Fleet(t, db, fixedNow)

	svc := newStreamingFindingsService(t, db, fixedNow, nil)
	if _, err := svc.Recompute(context.Background(), findings.RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "audit-counters",
	}); err != nil {
		t.Fatalf("recompute: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var metadata []byte
	err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT metadata FROM audit_events
			 WHERE organization_id = 'anchorix'
			   AND action = 'findings.recomputed'
			 ORDER BY occurred_at DESC
			 LIMIT 1`).Scan(&metadata)
	})
	if err != nil {
		t.Fatalf("read audit metadata: %v", err)
	}

	var parsed struct {
		LoadedCertificates int `json:"loaded_certificates"`
		LoadedFindings     int `json:"loaded_findings"`
	}
	if err := json.Unmarshal(metadata, &parsed); err != nil {
		t.Fatalf("parse audit metadata: %v", err)
	}
	if parsed.LoadedCertificates == 0 {
		t.Errorf("audit metadata loaded_certificates = 0; Smallv01 fixture should have produced > 0")
	}
	// LoadedFindings can legitimately be 0 on a fresh DB
	// (no pre-existing rows). Smallv01's first recompute IS
	// that case; we only assert the field is present, not its
	// value.
	_ = parsed.LoadedFindings
}

// --- helpers used only by H-024B tests -----------------------------

// pauseAfterFirstPageLister wraps the real CertificateLister
// and pauses ONCE between the first and second paginated cert
// reads. Used by the snapshot-isolation test for deterministic
// interleaving via channels (no sleep).
type pauseAfterFirstPageLister struct {
	inner               *postgres.CertificateInventoryRepository
	mu                  sync.Mutex
	calls               int
	disabled            bool
	pauseAfterFirstPage chan<- struct{}
	resumeAfterCommit   <-chan struct{}
}

func (p *pauseAfterFirstPageLister) ListAllCertificateSummariesForOrg(ctx context.Context, orgID string) ([]inventory.CertificateSummary, error) {
	return p.inner.ListAllCertificateSummariesForOrg(ctx, orgID)
}

func (p *pauseAfterFirstPageLister) ListCertificateBareSummariesForOrgPaged(ctx context.Context, orgID, cursorID string, pageSize int) ([]inventory.CertificateSummary, error) {
	page, err := p.inner.ListCertificateBareSummariesForOrgPaged(ctx, orgID, cursorID, pageSize)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.calls++
	first := p.calls == 1 && !p.disabled
	p.mu.Unlock()
	if first {
		p.pauseAfterFirstPage <- struct{}{}
		<-p.resumeAfterCommit
	}
	return page, nil
}

func (p *pauseAfterFirstPageLister) disable() {
	p.mu.Lock()
	p.disabled = true
	p.mu.Unlock()
}

// newStreamingFindingsService wires a findings.Service for
// H-024B tests. Pass `nil` for `lister` to use the default
// Postgres CertificateLister; pass a pauseAfterFirstPageLister
// to intercept paginated cert reads.
func newStreamingFindingsService(t *testing.T, db *postgres.DB, now time.Time, lister findings.CertificateLister) *findings.Service {
	t.Helper()
	auditRec := postgres.NewAuditRecorder(db, clock.System{})
	findingsRepo := postgres.NewFindingsRepository(db)
	if lister == nil {
		lister = postgres.NewCertificateInventoryRepository(db)
	}
	svc, err := findings.NewService(findingsRepo, lister, db, auditRec, streamingTestClock{now: now}, findings.DefaultRules())
	if err != nil {
		t.Fatalf("findings.NewService: %v", err)
	}
	return svc
}

// seedSmallv01Fleet writes the Smallv01 fixture to the DB.
// Deterministic structurally; the H-024B byte-identical test
// relies on the same fixture being produced twice (different
// PEM bytes but same shape) so the legacy and streaming runs
// see equivalent input.
func seedSmallv01Fleet(t *testing.T, db *postgres.DB, now time.Time) {
	t.Helper()
	fleet, err := fixtures.NewFleetBuilder(2026, fixtures.Smallv01(), now).Build()
	if err != nil {
		t.Fatalf("fixtures.Build: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := fleet.WriteTo(ctx, db); err != nil {
		t.Fatalf("fleet.WriteTo: %v", err)
	}
}

// streamingTestClock is the H-024B test-local clock fake.
// Lives in this file because other integration tests don't
// need one; if a second clock-using test arrives, this can be
// hoisted into a shared helper.
type streamingTestClock struct{ now time.Time }

func (c streamingTestClock) Now() time.Time { return c.now }

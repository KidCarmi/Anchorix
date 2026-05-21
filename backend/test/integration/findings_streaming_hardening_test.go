//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- post-H-024B hardening tests -----------------------------------
//
// These tests close known regression risks the H-024B merge left
// uncovered. None of them validate H-024B's CORE contract (that's
// what findings_streaming_test.go does); they validate edge cases
// and failure modes the byte-equivalence / snapshot-isolation
// tests don't reach.

// TestFindingsStreamingRecomputeReleasesLockOnCtxCancel proves the
// post-H-024B-soak invariant that a cancelled recompute does NOT
// leak the per-org session advisory lock. The harness:
//
//  1. Wraps the real CertificateLister with a hangLister that
//     blocks the SECOND paginated cert SELECT until a signal
//     channel closes.
//  2. Kicks off a recompute in a goroutine, with `pageSize=1`
//     forcing multiple cert SELECTs against the small seeded
//     fixture.
//  3. Waits for the hang to fire (= recompute is inside the tx,
//     holding the lock, blocked on the second SELECT).
//  4. Cancels the recompute's ctx. The recompute MUST return
//     promptly with an error.
//  5. Releases the hang channel (so any lingering pgx send
//     completes and the goroutine fully exits).
//  6. Starts a SECOND recompute from a fresh ctx. If the
//     session lock leaked, this second recompute would block
//     forever on `pg_advisory_lock`. The test bounds it with a
//     short context deadline and asserts success.
//
// Without the post-H-024B unlock-failure fix (`Hijack()`+`Close()`
// on failed unlock), AND in the specific failure mode where the
// unlock SQL times out on a non-broken connection, the second
// recompute would block on the inherited lock. This test does
// not trigger the unlock-failure code path directly (that
// requires a flaky network or PG hiccup we cannot simulate
// portably); it instead exercises the OTHER cancellation route —
// pgx's Release() detecting a tx-in-progress connection and
// dropping it — which closes the TCP connection and releases
// session locks at the kernel level.
//
// Either way, the cancelled recompute MUST NOT leak the lock.
// This test catches a regression in either cleanup path.
func TestFindingsStreamingRecomputeReleasesLockOnCtxCancel(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	fixedNow := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	// Seed two weak-RSA certs so the streaming loop must make
	// MORE than one paginated cert SELECT (with the page-size
	// override below). IDs sort "aa-…" so they come before
	// the hang signal's bookkeeping (no other rows interfere).
	for _, subject := range []string{"cancel-aa-a.example", "cancel-aa-b.example"} {
		fixture := mustWeakCertFixture("cancel-iso-" + subject)
		fixture.Subject = "CN=" + subject
		seedCert(t, db, fixture)
	}

	hangAtSecondPage := make(chan struct{}, 1)
	releaseHang := make(chan struct{})
	hangLister := &hangAtSecondPageLister{
		inner:            postgres.NewCertificateInventoryRepository(db),
		hangAtSecondPage: hangAtSecondPage,
		releaseHang:      releaseHang,
	}

	svc := newStreamingFindingsService(t, db, fixedNow, hangLister)
	svc.SetStreamingPageSizeForTest(1)

	cancellableCtx, cancelRecompute := context.WithCancel(context.Background())
	type outcome struct {
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		_, err := svc.Recompute(cancellableCtx, findings.RecomputeInput{
			OrganizationID: "anchorix",
			ActorUserID:    "cancel-test",
		})
		done <- outcome{err: err}
	}()

	// Wait for the recompute to enter the second cert SELECT,
	// then cancel.
	select {
	case <-hangAtSecondPage:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for second cert SELECT to begin; the recompute likely never reached the hang point")
	}

	cancelRecompute()
	close(releaseHang)

	select {
	case out := <-done:
		if out.err == nil {
			t.Error("cancelled recompute returned nil error; want a cancellation error")
		}
		// We don't assert on the specific error value — pgx
		// can surface ctx.Cancelled or a wrapped network error
		// depending on which statement was in flight when the
		// cancel hit. Either way, the recompute returned.
	case <-time.After(30 * time.Second):
		t.Fatal("cancelled recompute did not return within 30s")
	}

	// Critical: a fresh recompute must proceed. If the session
	// lock leaked, pg_advisory_lock on this orgID would block
	// indefinitely. The 10s ctx forces a fast failure if so.
	hangLister.disable()
	cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cleanCancel()
	if _, err := svc.Recompute(cleanCtx, findings.RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "post-cancel",
	}); err != nil {
		t.Fatalf("post-cancel recompute failed (session lock likely leaked): %v", err)
	}
}

// TestFindingsStreamingRecomputeEmptyOrgIsNoOp pins the
// degenerate case the H-024B byte-equivalence and snapshot-iso
// tests don't reach: an org with NO certificates and NO
// pre-existing findings. The streaming algorithm's three
// phases must all degenerate cleanly to zero work; counters
// must be all zero; the audit row must still be emitted.
//
// A regression here (e.g., nil-deref on an empty cert page,
// or skipping the audit on zero counters) would silently
// break every fresh-install or new-org bootstrap flow.
func TestFindingsStreamingRecomputeEmptyOrgIsNoOp(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	fixedNow := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	svc := newStreamingFindingsService(t, db, fixedNow, nil)

	result, err := svc.Recompute(context.Background(), findings.RecomputeInput{
		OrganizationID: "anchorix",
		ActorUserID:    "empty-org",
	})
	if err != nil {
		t.Fatalf("empty-org recompute returned err: %v", err)
	}
	if result.EvaluatedCertificates != 0 || result.LoadedCertificates != 0 || result.LoadedFindings != 0 {
		t.Errorf("expected all loads to be zero; got evaluated=%d loaded_certs=%d loaded_findings=%d",
			result.EvaluatedCertificates, result.LoadedCertificates, result.LoadedFindings)
	}
	if result.Opened != 0 || result.Updated != 0 || result.Resolved != 0 || result.Unchanged != 0 {
		t.Errorf("expected all counters zero; got opened=%d updated=%d resolved=%d unchanged=%d",
			result.Opened, result.Updated, result.Resolved, result.Unchanged)
	}
	if result.RuleCount == 0 {
		t.Error("RuleCount should reflect the registered rule set even on an empty-org recompute")
	}

	// Audit row must still be written.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var count int
	err = db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT COUNT(*) FROM audit_events
			 WHERE organization_id = 'anchorix'
			   AND action = 'findings.recomputed'`).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 findings.recomputed audit row on empty-org recompute; got %d", count)
	}

	// No findings rows materialized.
	err = db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM findings WHERE organization_id = 'anchorix'`).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if count != 0 {
		t.Errorf("empty-org recompute produced %d findings; want 0", count)
	}
}

// --- helpers used only by the post-H-024B hardening tests ---------

// hangAtSecondPageLister wraps the real CertificateLister and
// blocks the SECOND paginated cert SELECT until a signal
// closes. Used by the cancellation test to give the test
// deterministic control over WHEN to cancel the recompute.
type hangAtSecondPageLister struct {
	inner            *postgres.CertificateInventoryRepository
	mu               sync.Mutex
	calls            int
	disabled         bool
	hangAtSecondPage chan<- struct{}
	releaseHang      <-chan struct{}
}

func (h *hangAtSecondPageLister) ListAllCertificateSummariesForOrg(ctx context.Context, orgID string) ([]inventory.CertificateSummary, error) {
	return h.inner.ListAllCertificateSummariesForOrg(ctx, orgID)
}

func (h *hangAtSecondPageLister) ListCertificateBareSummariesForOrgPaged(ctx context.Context, orgID, cursorID string, pageSize int) ([]inventory.CertificateSummary, error) {
	page, err := h.inner.ListCertificateBareSummariesForOrgPaged(ctx, orgID, cursorID, pageSize)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.calls++
	hang := h.calls == 2 && !h.disabled
	h.mu.Unlock()
	if hang {
		// Signal the test that we're inside the second
		// paginated SELECT, then block until the test
		// releases us.
		h.hangAtSecondPage <- struct{}{}
		select {
		case <-h.releaseHang:
		case <-ctx.Done():
			// ctx cancelled while we're blocked — return
			// the ctx error so pgx propagates the
			// cancellation up through the recompute call.
			return nil, ctx.Err()
		}
	}
	return page, nil
}

func (h *hangAtSecondPageLister) disable() {
	h.mu.Lock()
	h.disabled = true
	h.mu.Unlock()
}

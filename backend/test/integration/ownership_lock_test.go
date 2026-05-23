//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// TestWithTxLockedOwnershipSerializesSameOrg proves the per-org
// advisory lock serializes concurrent ownership writes for the SAME
// org: the two critical sections never overlap.
func TestWithTxLockedOwnershipSerializesSameOrg(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var mu sync.Mutex
	inside := 0
	maxObserved := 0

	fn := func(context.Context) error {
		mu.Lock()
		inside++
		if inside > maxObserved {
			maxObserved = inside
		}
		mu.Unlock()
		time.Sleep(150 * time.Millisecond)
		mu.Lock()
		inside--
		mu.Unlock()
		return nil
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = db.WithTxLockedOwnership(ctx, "anchorix", fn)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("WithTxLockedOwnership: %v", err)
		}
	}
	if maxObserved != 1 {
		t.Fatalf("max concurrent critical sections = %d; want 1 (lock did not serialize)", maxObserved)
	}
}

// TestWithTxLockedOwnershipDifferentOrgsDoNotBlock proves the lock is
// keyed by org: a held lock on one org must not block a lock on a
// different org.
func TestWithTxLockedOwnershipDifferentOrgsDoNotBlock(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inA := make(chan struct{})
	releaseA := make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		aDone <- db.WithTxLockedOwnership(ctx, "org-A", func(context.Context) error {
			close(inA)
			<-releaseA
			return nil
		})
	}()
	<-inA // org-A lock is held.

	bDone := make(chan error, 1)
	go func() {
		bDone <- db.WithTxLockedOwnership(ctx, "org-B", func(context.Context) error { return nil })
	}()

	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("org-B lock: %v", err)
		}
	case <-time.After(3 * time.Second):
		close(releaseA)
		t.Fatalf("org-B blocked behind org-A lock — lock is not org-keyed")
	}

	close(releaseA)
	if err := <-aDone; err != nil {
		t.Fatalf("org-A lock: %v", err)
	}
}

// TestWithTxLockedOwnershipRepeatableReadSnapshot proves the RR
// helper gives fn one consistent input snapshot: a cert inserted by a
// concurrent committed transaction mid-fn is invisible to the
// in-flight read.
func TestWithTxLockedOwnershipRepeatableReadSnapshot(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Seed a gap (1,2,4,5) so a mid-walk insert of "3" would land in
	// a NOT-YET-READ page under READ COMMITTED. The RR snapshot must
	// hide it ACROSS the page boundary — this is the real guarantee
	// the streaming recompute relies on, not a single-read illusion.
	for _, n := range []string{"1", "2", "4", "5"} {
		seedCertMeta(t, db, ctx, "anchorix", "cert-snap-"+n, "CN="+n, "CN=ca", nil)
	}

	seen := map[string]bool{}
	err := db.WithTxLockedOwnershipRepeatableRead(ctx, "anchorix", func(txCtx context.Context) error {
		// Page 1 (size 2): cert-snap-1, cert-snap-2.
		page1, err := repo.ListCertificateSignalsPaged(txCtx, "anchorix", "", 2)
		if err != nil {
			return err
		}
		if len(page1) != 2 || page1[0].CertificateID != "cert-snap-1" || page1[1].CertificateID != "cert-snap-2" {
			t.Fatalf("page1 = %v; want [cert-snap-1 cert-snap-2]", certIDs(page1))
		}
		for _, s := range page1 {
			seen[s.CertificateID] = true
		}

		// Commit a NEW cert mid-walk that sorts BETWEEN page 1 and the
		// next page (cert-snap-3 < cert-snap-4). On a separate pool
		// connection so it truly commits.
		seedCertMeta(t, db, ctx, "anchorix", "cert-snap-3", "CN=3", "CN=ca", nil)

		// Page 2 (cursor = cert-snap-2): under RR the snapshot was
		// fixed before cert-snap-3 existed, so page 2 MUST be
		// [cert-snap-4 cert-snap-5], skipping the mid-walk insert.
		page2, err := repo.ListCertificateSignalsPaged(txCtx, "anchorix", "cert-snap-2", 2)
		if err != nil {
			return err
		}
		for _, s := range page2 {
			if s.CertificateID == "cert-snap-3" {
				t.Fatalf("page-boundary snapshot leak: walk saw mid-walk insert cert-snap-3 (READ COMMITTED behavior, not REPEATABLE READ)")
			}
			seen[s.CertificateID] = true
		}
		if len(page2) != 2 || page2[0].CertificateID != "cert-snap-4" || page2[1].CertificateID != "cert-snap-5" {
			t.Fatalf("page2 = %v; want [cert-snap-4 cert-snap-5]", certIDs(page2))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTxLockedOwnershipRepeatableRead: %v", err)
	}
	if len(seen) != 4 || seen["cert-snap-3"] {
		t.Fatalf("walk saw %v; want exactly the 4 snapshot-time certs (no cert-snap-3)", seen)
	}

	// Outside the snapshot, the mid-walk insert is now visible.
	after, err := repo.ListCertificateSignalsPaged(ctx, "anchorix", "", 1000)
	if err != nil {
		t.Fatalf("post-tx read: %v", err)
	}
	if len(after) != 5 {
		t.Fatalf("post-tx read = %d certs; want 5 (cert-snap-3 now visible)", len(after))
	}
}

func certIDs(sigs []governance.CertificateSignals) []string {
	out := make([]string, len(sigs))
	for i, s := range sigs {
		out[i] = s.CertificateID
	}
	return out
}

// TestWithTxLockedOwnershipRepeatableReadReleasesLock proves the RR
// helper releases its session-scope advisory lock when fn returns: a
// subsequent lock acquisition on the same org must not block. This
// exercises the deferred unlock / connection-cleanup path.
func TestWithTxLockedOwnershipRepeatableReadReleasesLock(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := db.WithTxLockedOwnershipRepeatableRead(ctx, "org-rel", func(context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("RR helper: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- db.WithTxLockedOwnership(ctx, "org-rel", func(context.Context) error { return nil })
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("subsequent lock: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("subsequent lock blocked — RR helper did not release its session lock")
	}
}

//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"
	"time"

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

	seedCertMeta(t, db, ctx, "anchorix", "cert-snap-1", "CN=1", "CN=ca", nil)
	seedCertMeta(t, db, ctx, "anchorix", "cert-snap-2", "CN=2", "CN=ca", nil)

	err := db.WithTxLockedOwnershipRepeatableRead(ctx, "anchorix", func(txCtx context.Context) error {
		first, err := repo.ListCertificateSignalsPaged(txCtx, "anchorix", "", 1000)
		if err != nil {
			return err
		}
		if len(first) != 2 {
			t.Fatalf("first read = %d certs; want 2", len(first))
		}

		// Commit a NEW cert on a separate pool connection mid-pass.
		seedCertMeta(t, db, ctx, "anchorix", "cert-snap-3", "CN=3", "CN=ca", nil)

		second, err := repo.ListCertificateSignalsPaged(txCtx, "anchorix", "", 1000)
		if err != nil {
			return err
		}
		if len(second) != 2 {
			t.Fatalf("second read = %d certs; want 2 (REPEATABLE READ snapshot broken — saw the mid-pass insert)", len(second))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTxLockedOwnershipRepeatableRead: %v", err)
	}

	// Outside the snapshot, the new cert is visible.
	after, err := repo.ListCertificateSignalsPaged(ctx, "anchorix", "", 1000)
	if err != nil {
		t.Fatalf("post-tx read: %v", err)
	}
	if len(after) != 3 {
		t.Fatalf("post-tx read = %d certs; want 3", len(after))
	}
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

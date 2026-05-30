//go:build integration

package integration

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- helpers ----------------------------------------------------------

// tableSnapshot captures the row id set + total row count for one
// table in one organization. The id set is what catches a sneaky
// INSERT/DELETE (counts alone would miss a balanced insert+delete).
type tableSnapshot struct {
	count int
	ids   map[string]struct{}
}

func snapshotTable(t *testing.T, db *postgres.DB, ctx context.Context, query string, args ...any) tableSnapshot {
	t.Helper()
	ids := map[string]struct{}{}
	var count int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids[id] = struct{}{}
			count++
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("snapshot %q: %v", query, err)
	}
	return tableSnapshot{count: count, ids: ids}
}

func assertSnapshotsEqual(t *testing.T, label string, before, after tableSnapshot) {
	t.Helper()
	if before.count != after.count {
		t.Fatalf("%s row count: before=%d after=%d", label, before.count, after.count)
	}
	if !reflect.DeepEqual(before.ids, after.ids) {
		t.Fatalf("%s row id set diverged across the read call (read-only invariant violated)", label)
	}
}

// --- read-only guarantee ----------------------------------------------

// TestListExpiringOverridesPagedIsReadOnly proves the paged read has
// ZERO side effects: row id sets and counts on every table the read
// touches OR could plausibly mutate stay byte-identical across the
// call. A regression that turned the read into a clear-on-read (or
// any sneaky side-effecting variant) would fail this assertion.
func TestListExpiringOverridesPagedIsReadOnly(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-ro")
	for i := 0; i < 5; i++ {
		certID := fmt.Sprintf("cert-ro-%02d", i)
		seedCertificate(t, db, ctx, certID)
		seedExpiringOverride(t, db, ctx, "anchorix", fmt.Sprintf("ovr-ro-%02d", i), certID, "svc-ro", pastTime(now, 1))
	}

	tables := map[string]string{
		"overrides":             `SELECT id FROM certificate_ownership_overrides WHERE organization_id='anchorix'`,
		"certificates":          `SELECT id FROM certificates WHERE organization_id='anchorix'`,
		"certificate_ownership": `SELECT certificate_id FROM certificate_ownership WHERE organization_id='anchorix'`,
		"audit_events":          `SELECT id FROM audit_events WHERE organization_id='anchorix'`,
		"explanations":          `SELECT id FROM ownership_match_explanations WHERE organization_id='anchorix'`,
		"services":              `SELECT id FROM services WHERE organization_id='anchorix'`,
		"ownership_rules":       `SELECT id FROM ownership_rules WHERE organization_id='anchorix'`,
	}
	before := map[string]tableSnapshot{}
	for label, q := range tables {
		before[label] = snapshotTable(t, db, ctx, q)
	}

	repo := postgres.NewOwnershipRepository(db)
	// Several reads with varied parameters — page-size clamp, empty
	// cursor, mid-walk cursor — none can mutate anything.
	for _, args := range []struct {
		cursor   string
		pageSize int
	}{
		{"", 0},              // default
		{"", 100_000},        // clamp
		{"cert-ro-02", 100},  // mid-walk resume
		{"cert-ro-zzz", 100}, // past-last cursor
	} {
		if _, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, args.cursor, args.pageSize); err != nil {
			t.Fatalf("read (cursor=%q size=%d): %v", args.cursor, args.pageSize, err)
		}
	}

	for label, q := range tables {
		after := snapshotTable(t, db, ctx, q)
		assertSnapshotsEqual(t, label, before[label], after)
	}
}

// --- cursor semantics --------------------------------------------------

// TestListExpiringOverridesPagedCursorResumeBoundary isolates the
// page-boundary hand-off: page 1 returns the first N rows; resuming
// from NextCursor returns exactly the next N rows (no overlap, no gap).
func TestListExpiringOverridesPagedCursorResumeBoundary(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-bd")
	const fleet = 6
	for i := 1; i <= fleet; i++ {
		certID := fmt.Sprintf("cert-bd-%02d", i)
		seedCertificate(t, db, ctx, certID)
		seedExpiringOverride(t, db, ctx, "anchorix", fmt.Sprintf("ovr-bd-%02d", i), certID, "svc-bd", pastTime(now, 1))
	}

	repo := postgres.NewOwnershipRepository(db)
	first, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "", 3)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("page 1 len = %d; want 3", len(first))
	}
	wantFirst := []string{"cert-bd-01", "cert-bd-02", "cert-bd-03"}
	for i, ovr := range first {
		if ovr.CertificateID != wantFirst[i] {
			t.Fatalf("page 1[%d] = %s; want %s", i, ovr.CertificateID, wantFirst[i])
		}
	}

	nextCursor := first[len(first)-1].CertificateID
	second, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, nextCursor, 3)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	wantSecond := []string{"cert-bd-04", "cert-bd-05", "cert-bd-06"}
	if len(second) != len(wantSecond) {
		t.Fatalf("page 2 len = %d; want %d", len(second), len(wantSecond))
	}
	for i, ovr := range second {
		if ovr.CertificateID != wantSecond[i] {
			t.Fatalf("page 2[%d] = %s; want %s", i, ovr.CertificateID, wantSecond[i])
		}
		if ovr.CertificateID == nextCursor {
			t.Fatalf("page 2 contains cursor cert %s (cursor must be exclusive at boundary)", nextCursor)
		}
	}
}

// TestListExpiringOverridesPagedEmptyCursorReturnsSmallest proves the
// empty cursor sentinel starts the walk at the lexicographically
// smallest certificate_id, not at some arbitrary or NULL-mishandled
// position.
func TestListExpiringOverridesPagedEmptyCursorReturnsSmallest(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-em")
	// Seed in non-lexicographic insertion order so a buggy "insertion
	// order" implementation wouldn't pass.
	for _, c := range []string{"cert-em-zz", "cert-em-aa", "cert-em-mm"} {
		seedCertificate(t, db, ctx, c)
		seedExpiringOverride(t, db, ctx, "anchorix", "ovr-"+c, c, "svc-em", pastTime(now, 1))
	}

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "", 1)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(got) != 1 || got[0].CertificateID != "cert-em-aa" {
		t.Fatalf("first page = %+v; want exactly [cert-em-aa] (lexicographically smallest)", got)
	}
}

// TestListExpiringOverridesPagedCursorPastLastReturnsEmpty proves a
// cursor lexicographically greater than every cert id returns an
// empty slice without error — the terminal-page behavior the future
// sweeper relies on to know it's done.
func TestListExpiringOverridesPagedCursorPastLastReturnsEmpty(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-pl")
	for _, c := range []string{"cert-pl-a", "cert-pl-b"} {
		seedCertificate(t, db, ctx, c)
		seedExpiringOverride(t, db, ctx, "anchorix", "ovr-"+c, c, "svc-pl", pastTime(now, 1))
	}

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "cert-zzz", 100)
	if err != nil {
		t.Fatalf("past-last cursor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("past-last got %+v; want empty", got)
	}
}

// TestListExpiringOverridesPagedEqualExpiresAtOrderedByCertID proves
// equal `expires_at` values do NOT perturb the cert_id ASC order. The
// ORDER BY is on certificate_id only, so a same-timestamp tie must
// resolve deterministically by cert_id ASC, not by some opaque heap-
// scan order.
func TestListExpiringOverridesPagedEqualExpiresAtOrderedByCertID(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-tie")
	// All four overrides expire at the same instant (single Go
	// time.Time → identical TIMESTAMPTZ to microsecond precision).
	shared := now.Add(-time.Hour)
	insertOrder := []string{"cert-tie-d", "cert-tie-b", "cert-tie-a", "cert-tie-c"}
	for _, c := range insertOrder {
		seedCertificate(t, db, ctx, c)
		seedExpiringOverride(t, db, ctx, "anchorix", "ovr-"+c, c, "svc-tie", &shared)
	}

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "", 100)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := []string{"cert-tie-a", "cert-tie-b", "cert-tie-c", "cert-tie-d"}
	if len(got) != len(want) {
		t.Fatalf("got %d rows; want %d", len(got), len(want))
	}
	for i, ovr := range got {
		if ovr.CertificateID != want[i] {
			t.Fatalf("equal-expires tie[%d] = %s; want %s (cert_id ASC must dominate)", i, ovr.CertificateID, want[i])
		}
	}
}

// TestListExpiringOverridesPagedClearedRowDoesNotReappearOnResume
// proves the cursor-walk invariant a future sweeper relies on: once a
// row is cleared, the active partial index drops it, so a resume from
// a cursor BEFORE that cert never re-surfaces it. The walk must remain
// exclusive of (a) the cursor cert and (b) every already-cleared cert.
//
// This is the closest analog to "concurrent operator clear between
// pages" we can test at the read-only PR-1 layer — the sweep service
// (PR-2) will run this same shape under WithTxLockedOwnership.
func TestListExpiringOverridesPagedClearedRowDoesNotReappearOnResume(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-cr")
	const fleet = 5
	for i := 1; i <= fleet; i++ {
		certID := fmt.Sprintf("cert-cr-%02d", i)
		seedCertificate(t, db, ctx, certID)
		seedExpiringOverride(t, db, ctx, "anchorix", fmt.Sprintf("ovr-cr-%02d", i), certID, "svc-cr", pastTime(now, 1))
	}

	repo := postgres.NewOwnershipRepository(db)
	first, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "", 2)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(first) != 2 || first[0].CertificateID != "cert-cr-01" || first[1].CertificateID != "cert-cr-02" {
		t.Fatalf("page 1 = %+v; want cert-cr-01,02", first)
	}

	// Simulate a mid-walk concurrent operator clear: clear ovr-cr-03
	// (a row the SWEEPER would otherwise process next). Resume from
	// the cursor of page 1 — the cleared row must NOT reappear.
	if err := repo.ClearOwnershipOverride(ctx, "anchorix", "ovr-cr-03", "operator", "mid-walk", now); err != nil {
		t.Fatalf("clear ovr-cr-03: %v", err)
	}

	second, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, first[len(first)-1].CertificateID, 100)
	if err != nil {
		t.Fatalf("page 2 (post-clear): %v", err)
	}
	for _, ovr := range second {
		if ovr.ID == "ovr-cr-03" || ovr.CertificateID == "cert-cr-03" {
			t.Fatalf("page 2 returned cleared row: %+v", ovr)
		}
	}
	// The remaining expected expired-active rows are cert-cr-04 and
	// cert-cr-05 (cert-cr-01,02 are before the cursor; cert-cr-03 is
	// cleared).
	if len(second) != 2 || second[0].CertificateID != "cert-cr-04" || second[1].CertificateID != "cert-cr-05" {
		t.Fatalf("page 2 = %+v; want cert-cr-04, cert-cr-05 only", second)
	}
}

// --- EXPLAIN re-pin ----------------------------------------------------

// TestListExpiringOverridesPagedExplainBoundaryShapes re-pins the
// query plan shape under a few representative bound configurations:
// the boundedness contract (Limit present, no fleet-wide Group Key)
// holds whether the page is small, at the default, or at the max.
// Belt-and-suspenders with the existing TestListExpiringOverridesPagedExplainBounded
// (PR-1) which covers the default-shape case.
func TestListExpiringOverridesPagedExplainBoundaryShapes(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-ex")
	for i := 0; i < 20; i++ {
		certID := fmt.Sprintf("cert-ex-%02d", i)
		seedCertificate(t, db, ctx, certID)
		seedExpiringOverride(t, db, ctx, "anchorix", fmt.Sprintf("ovr-ex-%02d", i), certID, "svc-ex", pastTime(now, 1))
	}

	for _, pageSize := range []int{1, postgres.DefaultExpiringOverridesPageSize, postgres.MaxExpiringOverridesPageSize} {
		plan := explainPlan(t, db, ctx, postgres.ListExpiringOverridesPagedQuery, "anchorix", now, "", pageSize)
		if !strings.Contains(plan, "Limit") {
			t.Fatalf("pageSize=%d plan must contain Limit, got:\n%s", pageSize, plan)
		}
		if strings.Contains(plan, "Group Key") {
			t.Fatalf("pageSize=%d plan must not fleet-aggregate (Group Key), got:\n%s", pageSize, plan)
		}
	}
}

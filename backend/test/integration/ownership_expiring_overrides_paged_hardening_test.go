//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- helpers ----------------------------------------------------------

// tableSnapshot captures, per row in one organization's slice of a
// table, both the primary key and a content hash (md5 of the row's
// to_jsonb serialization). The content hash is what catches an
// in-place UPDATE — a row whose mutable columns (e.g. cleared_at,
// cleared_by, cleared_reason on certificate_ownership_overrides) shift
// stays in the id set but its hash diverges. An INSERT adds a new
// key; a DELETE removes one.
type tableSnapshot struct {
	count int
	// rows[primary_key] = md5(to_jsonb(row)::text).
	rows map[string]string
}

// snapshotTable runs a query that MUST return exactly two text columns:
// the org-scoped row key (single-column pk or any unique identifier
// within the org) and a content hash digest of the row. The caller
// supplies a query like:
//
//	SELECT id::text, md5(to_jsonb(t.*)::text)
//	  FROM <table> t WHERE organization_id = $1
func snapshotTable(t *testing.T, db *postgres.DB, ctx context.Context, query string, args ...any) tableSnapshot {
	t.Helper()
	rows := map[string]string{}
	var count int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		queryRows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer queryRows.Close()
		for queryRows.Next() {
			var key, hash string
			if err := queryRows.Scan(&key, &hash); err != nil {
				return err
			}
			rows[key] = hash
			count++
		}
		return queryRows.Err()
	}); err != nil {
		t.Fatalf("snapshot %q: %v", query, err)
	}
	return tableSnapshot{count: count, rows: rows}
}

// assertSnapshotsEqual fails if the row count, primary-key set, or any
// row's content hash diverges between before and after. Diff is
// surfaced per-row so a regression message points at the exact rows
// that changed.
func assertSnapshotsEqual(t *testing.T, label string, before, after tableSnapshot) {
	t.Helper()
	if before.count != after.count {
		t.Fatalf("%s row count: before=%d after=%d", label, before.count, after.count)
	}
	for key, beforeHash := range before.rows {
		afterHash, ok := after.rows[key]
		if !ok {
			t.Fatalf("%s row %q vanished across the read call", label, key)
		}
		if beforeHash != afterHash {
			t.Fatalf("%s row %q content hash diverged across the read call: %s -> %s (in-place UPDATE detected — read is not side-effect-free)", label, key, beforeHash, afterHash)
		}
	}
	for key := range after.rows {
		if _, ok := before.rows[key]; !ok {
			t.Fatalf("%s row %q appeared across the read call (INSERT side effect)", label, key)
		}
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

	// Each query returns (org-scoped pk, md5 of the row's to_jsonb
	// serialization) so the snapshot catches in-place UPDATE — not
	// just INSERT/DELETE — across every table the read might plausibly
	// mutate.
	tables := map[string]string{
		"overrides":             `SELECT id::text, md5(to_jsonb(t.*)::text) FROM certificate_ownership_overrides t WHERE organization_id='anchorix'`,
		"certificates":          `SELECT id::text, md5(to_jsonb(t.*)::text) FROM certificates t WHERE organization_id='anchorix'`,
		"certificate_ownership": `SELECT certificate_id::text, md5(to_jsonb(t.*)::text) FROM certificate_ownership t WHERE organization_id='anchorix'`,
		"audit_events":          `SELECT id::text, md5(to_jsonb(t.*)::text) FROM audit_events t WHERE organization_id='anchorix'`,
		"explanations":          `SELECT id::text, md5(to_jsonb(t.*)::text) FROM ownership_match_explanations t WHERE organization_id='anchorix'`,
		"services":              `SELECT id::text, md5(to_jsonb(t.*)::text) FROM services t WHERE organization_id='anchorix'`,
		"ownership_rules":       `SELECT id::text, md5(to_jsonb(t.*)::text) FROM ownership_rules t WHERE organization_id='anchorix'`,
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

// TestReadOnlyGuardCatchesInPlaceUpdate is the positive control for
// TestListExpiringOverridesPagedIsReadOnly: it proves the snapshot
// mechanism is sensitive to the exact regression the read-only test
// claims to catch — an in-place UPDATE that mutates cleared_at /
// cleared_by / cleared_reason on an override row without
// changing the row's id or the table's row count. Snapshot, perform a
// real UPDATE via the existing ClearOwnershipOverride API, snapshot
// again — assertSnapshotsEqual MUST fail.
//
// Without this guard, a regression that silently weakened the snapshot
// query (e.g. dropping the content hash) would let the read-only
// invariant test pass vacuously.
func TestReadOnlyGuardCatchesInPlaceUpdate(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-pc")
	seedCertificate(t, db, ctx, "cert-pc")
	seedExpiringOverride(t, db, ctx, "anchorix", "ovr-pc", "cert-pc", "svc-pc", pastTime(now, 1))

	query := `SELECT id::text, md5(to_jsonb(t.*)::text) FROM certificate_ownership_overrides t WHERE organization_id='anchorix'`
	before := snapshotTable(t, db, ctx, query)

	// Real UPDATE via the production API — sets cleared_at / cleared_by /
	// cleared_reason on the existing row. Row id and table count are
	// unchanged.
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.ClearOwnershipOverride(ctx, "anchorix", "ovr-pc", "tester", "positive-control", now); err != nil {
		t.Fatalf("clear: %v", err)
	}

	after := snapshotTable(t, db, ctx, query)
	// Sanity: row count and id set are deliberately unchanged.
	if before.count != after.count {
		t.Fatalf("positive-control: row count changed (%d -> %d); the mechanism is testing the wrong thing", before.count, after.count)
	}
	if _, ok := after.rows["ovr-pc"]; !ok {
		t.Fatalf("positive-control: id 'ovr-pc' vanished from the after snapshot; the mechanism is testing the wrong thing")
	}
	// THE assertion: the upgraded snapshot mechanism MUST catch the
	// in-place update — the content hash MUST diverge.
	if before.rows["ovr-pc"] == after.rows["ovr-pc"] {
		t.Fatalf("positive-control: content hash did not change across an UPDATE — read-only guard would have missed an in-place mutation regression")
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

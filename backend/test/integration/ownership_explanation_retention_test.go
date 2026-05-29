//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- helpers -----------------------------------------------------------

// ownershipServiceWithRetention wires the engine with an explicit H-027
// retention policy and the real audit recorder.
func ownershipServiceWithRetention(t *testing.T, db *postgres.DB, policy ownership.RetentionPolicy) *ownership.Service {
	t.Helper()
	return ownershipServiceWithRecorder(t, db, postgres.NewAuditRecorder(db, clock.System{}), policy)
}

func ownershipServiceWithRecorder(t *testing.T, db *postgres.DB, rec audit.Recorder, policy ownership.RetentionPolicy) *ownership.Service {
	t.Helper()
	repo := &governance.Repo{
		Ownership:     postgres.NewOwnershipRepository(db),
		Policy:        postgres.NewPolicyRepository(db),
		RecomputeRuns: postgres.NewGovernanceRecomputeRunsRepository(db),
	}
	svc, err := ownership.NewService(repo, db, rec, clock.System{},
		postgres.NewOwnershipRuleTargetResolver(db),
		ownership.ServiceConfig{Retention: policy})
	if err != nil {
		t.Fatalf("ownership.NewService: %v", err)
	}
	return svc
}

// seedExplanationAged inserts an explanation row with decided_at set
// ageDays in the past, so retention age math is deterministic.
func seedExplanationAged(t *testing.T, db *postgres.DB, ctx context.Context, org, certID, explID string, ageDays int) {
	t.Helper()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO ownership_match_explanations
				(id, organization_id, certificate_id, decided_at, decided_decision, engine_version)
			VALUES ($1, $2, $3, now() - ($4 * interval '1 day'), 'unowned', 1)`,
			explID, org, certID, ageDays)
		return err
	}); err != nil {
		t.Fatalf("seed explanation %s: %v", explID, err)
	}
}

// pinCurrentExplanation upserts the certificate_ownership row so its
// FK-pinned current explanation is explID.
func pinCurrentExplanation(t *testing.T, db *postgres.DB, ctx context.Context, org, certID, explID string) {
	t.Helper()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO certificate_ownership
				(organization_id, certificate_id, decision, explanation_id, confidence)
			VALUES ($1, $2, 'unowned', $3, 'low')
			ON CONFLICT (organization_id, certificate_id)
			DO UPDATE SET explanation_id = EXCLUDED.explanation_id`,
			org, certID, explID)
		return err
	}); err != nil {
		t.Fatalf("pin current explanation for %s: %v", certID, err)
	}
}

func explanationIDsFor(t *testing.T, db *postgres.DB, ctx context.Context, org, certID string) []string {
	t.Helper()
	var ids []string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id FROM ownership_match_explanations
			 WHERE organization_id = $1 AND certificate_id = $2
			 ORDER BY decided_at DESC, id ASC`, org, certID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("explanation ids for %s: %v", certID, err)
	}
	return ids
}

func explanationCountForCert(t *testing.T, db *postgres.DB, ctx context.Context, org, certID string) int {
	t.Helper()
	return scalarInt(t, db, ctx,
		`SELECT count(*) FROM ownership_match_explanations WHERE organization_id=$1 AND certificate_id=$2`,
		org, certID)
}

func explanationRowExists(t *testing.T, db *postgres.DB, ctx context.Context, org, explID string) bool {
	t.Helper()
	return scalarInt(t, db, ctx,
		`SELECT count(*) FROM ownership_match_explanations WHERE organization_id=$1 AND id=$2`,
		org, explID) == 1
}

// seedAgedCert seeds a cert plus a descending-age explanation timeline.
// ages[i] is the age in days of explanation cert/"e{i}"; the row pinned
// as current is named by currentIdx. Returns the explanation ids.
func seedAgedCert(t *testing.T, db *postgres.DB, ctx context.Context, org, certID string, ages []int, currentIdx int) []string {
	t.Helper()
	seedCertMeta(t, db, ctx, org, certID, "CN="+certID, "CN=ca", nil)
	ids := make([]string, len(ages))
	for i, age := range ages {
		explID := fmt.Sprintf("%s-e%d", certID, i)
		seedExplanationAged(t, db, ctx, org, certID, explID, age)
		ids[i] = explID
	}
	pinCurrentExplanation(t, db, ctx, org, certID, ids[currentIdx])
	return ids
}

// --- tests -------------------------------------------------------------

// Aggressive policy (KeepN=1, MaxAge=24h) with the OLDEST explanation
// pinned as current: the current row must survive (selector exclusion +
// NOT EXISTS guard + FK RESTRICT), and the ownership row stays intact.
func TestPruneExplanationsCurrentNeverDeletedAggressivePolicy(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// e0 oldest (400d) and pinned current; e4 newest (1d).
	ids := seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{400, 300, 200, 100, 1}, 0)
	currentID := ids[0]

	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 24 * time.Hour})
	res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err != nil {
		t.Fatalf("PruneExplanationsPage: %v", err)
	}

	// latest-1 = e4 (kept); current = e0 (kept). e1,e2,e3 beyond-1, old,
	// not current → deleted (3).
	if res.DeletedCount != 3 {
		t.Fatalf("deleted = %d; want 3", res.DeletedCount)
	}
	if !explanationRowExists(t, db, ctx, "anchorix", currentID) {
		t.Fatalf("current explanation %s was deleted", currentID)
	}
	if got := explanationIDsFor(t, db, ctx, "anchorix", "cert-01"); len(got) != 2 {
		t.Fatalf("remaining explanations = %v; want 2 (current + latest-1)", got)
	}
	// certificate_ownership pin intact.
	pin := scalarInt(t, db, ctx,
		`SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix' AND certificate_id='cert-01' AND explanation_id=$1`,
		currentID)
	if pin != 1 {
		t.Fatalf("certificate_ownership pin lost: count=%d", pin)
	}
}

func TestPruneExplanationsLatestNKept(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 5 old rows; current = newest (index 0 = 100d). KeepN=3.
	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{100, 101, 102, 103, 104}, 0)
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 3, MaxAge: 24 * time.Hour})
	res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err != nil {
		t.Fatalf("PruneExplanationsPage: %v", err)
	}
	if res.DeletedCount != 2 {
		t.Fatalf("deleted = %d; want 2 (keep latest 3)", res.DeletedCount)
	}
	if n := explanationCountForCert(t, db, ctx, "anchorix", "cert-01"); n != 3 {
		t.Fatalf("remaining = %d; want 3", n)
	}
}

func TestPruneExplanationsNewerThanMaxAgeKeptBeyondN(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 6 rows all within 5 days; KeepN=2 but MaxAge=90d protects all.
	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{0, 1, 2, 3, 4, 5}, 0)
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 2, MaxAge: 90 * 24 * time.Hour})
	res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err != nil {
		t.Fatalf("PruneExplanationsPage: %v", err)
	}
	if res.DeletedCount != 0 {
		t.Fatalf("deleted = %d; want 0 (all newer than MaxAge)", res.DeletedCount)
	}
	if n := explanationCountForCert(t, db, ctx, "anchorix", "cert-01"); n != 6 {
		t.Fatalf("remaining = %d; want 6", n)
	}
}

func TestPruneExplanationsOldBeyondNDeleted(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 2 recent (1d,2d) + 2 ancient (100d,120d); KeepN=2, MaxAge=90d;
	// current = newest. The 2 ancient beyond-N rows are deleted.
	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 2, 100, 120}, 0)
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 2, MaxAge: 90 * 24 * time.Hour})
	res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err != nil {
		t.Fatalf("PruneExplanationsPage: %v", err)
	}
	if res.DeletedCount != 2 {
		t.Fatalf("deleted = %d; want 2", res.DeletedCount)
	}
	if n := explanationCountForCert(t, db, ctx, "anchorix", "cert-01"); n != 2 {
		t.Fatalf("remaining = %d; want 2", n)
	}
}

func TestPruneExplanationsIdempotentSecondRunZero(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 2, 100, 120}, 0)
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 2, MaxAge: 90 * 24 * time.Hour})

	first, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err != nil {
		t.Fatalf("first prune: %v", err)
	}
	if first.DeletedCount != 2 {
		t.Fatalf("first deleted = %d; want 2", first.DeletedCount)
	}
	second, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if second.DeletedCount != 0 {
		t.Fatalf("second deleted = %d; want 0 (idempotent)", second.DeletedCount)
	}
	// Exactly one rollup audit row: the first pass deleted, the second
	// changed nothing and so emits no audit.
	if n := auditCount(t, db, ctx, "anchorix", "governance.explanation_pruned"); n != 1 {
		t.Fatalf("explanation_pruned audit = %d; want 1", n)
	}
}

func TestPruneExplanationsCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedOrganization(t, db, "other-org", "Other Org")
	// Identical prunable history in both orgs (cert id is a global PK,
	// so the two orgs use distinct cert ids).
	seedAgedCert(t, db, ctx, "anchorix", "cert-a1", []int{1, 100, 120}, 0)
	seedAgedCert(t, db, ctx, "other-org", "cert-o1", []int{1, 100, 120}, 0)

	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	if _, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100); err != nil {
		t.Fatalf("prune anchorix: %v", err)
	}

	if n := explanationCountForCert(t, db, ctx, "anchorix", "cert-a1"); n != 1 {
		t.Fatalf("anchorix remaining = %d; want 1", n)
	}
	if n := explanationCountForCert(t, db, ctx, "other-org", "cert-o1"); n != 3 {
		t.Fatalf("other-org remaining = %d; want 3 (untouched)", n)
	}
	if n := auditCount(t, db, ctx, "other-org", "governance.explanation_pruned"); n != 0 {
		t.Fatalf("other-org prune audit = %d; want 0", n)
	}
}

func TestPruneExplanationsCursorPaginationWalk(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const certCount = 5
	for i := 1; i <= certCount; i++ {
		certID := fmt.Sprintf("cert-%02d", i)
		seedAgedCert(t, db, ctx, "anchorix", certID, []int{1, 100, 120}, 0) // KeepN=1 → 2 prunable each
	}
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})

	cursor := ""
	totalScanned, totalDeleted, pages := 0, 0, 0
	var lastCursor string
	for {
		res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", cursor, 2)
		if err != nil {
			t.Fatalf("prune page (cursor=%q): %v", cursor, err)
		}
		pages++
		totalScanned += res.CertsScanned
		totalDeleted += res.DeletedCount
		// Cursor must advance strictly (certificate_id ASC).
		if res.NextCursor <= lastCursor && res.CertsScanned > 0 {
			t.Fatalf("cursor did not advance: last=%q next=%q", lastCursor, res.NextCursor)
		}
		lastCursor = res.NextCursor
		if res.Done {
			break
		}
		cursor = res.NextCursor
		if pages > 10 {
			t.Fatal("walk did not terminate")
		}
	}
	if totalScanned != certCount {
		t.Fatalf("total scanned = %d; want %d (each cert once)", totalScanned, certCount)
	}
	if totalDeleted != certCount*2 {
		t.Fatalf("total deleted = %d; want %d", totalDeleted, certCount*2)
	}
	// Every cert retains exactly its current row.
	for i := 1; i <= certCount; i++ {
		certID := fmt.Sprintf("cert-%02d", i)
		if n := explanationCountForCert(t, db, ctx, "anchorix", certID); n != 1 {
			t.Fatalf("%s remaining = %d; want 1", certID, n)
		}
	}
}

func TestPruneExplanationsBoundedPageOnlyDeletesPage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 1; i <= 5; i++ {
		seedAgedCert(t, db, ctx, "anchorix", fmt.Sprintf("cert-%02d", i), []int{1, 100, 120}, 0)
	}
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})

	res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 2)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.CertsScanned != 2 || res.DeletedCount != 4 || res.Done {
		t.Fatalf("page = %+v; want scanned=2 deleted=4 done=false", res)
	}
	if res.NextCursor != "cert-02" {
		t.Fatalf("next cursor = %q; want cert-02 (deterministic)", res.NextCursor)
	}
	// cert-01, cert-02 pruned to 1 row each; cert-03..05 untouched (3 each).
	for i := 1; i <= 2; i++ {
		if n := explanationCountForCert(t, db, ctx, "anchorix", fmt.Sprintf("cert-%02d", i)); n != 1 {
			t.Fatalf("cert-%02d remaining = %d; want 1", i, n)
		}
	}
	for i := 3; i <= 5; i++ {
		if n := explanationCountForCert(t, db, ctx, "anchorix", fmt.Sprintf("cert-%02d", i)); n != 3 {
			t.Fatalf("cert-%02d remaining = %d; want 3 (off-page, untouched)", i, n)
		}
	}
}

func TestPruneExplanationsAuditRollupExactlyOnce(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Two certs, each contributes deletions; one page covers both.
	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 120}, 0)
	seedAgedCert(t, db, ctx, "anchorix", "cert-02", []int{1, 100}, 0)
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})

	res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.DeletedCount != 3 {
		t.Fatalf("deleted = %d; want 3 (2 + 1)", res.DeletedCount)
	}
	if n := auditCount(t, db, ctx, "anchorix", "governance.explanation_pruned"); n != 1 {
		t.Fatalf("explanation_pruned audit = %d; want exactly 1 rollup", n)
	}

	// Verify rollup metadata fields.
	var raw []byte
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT metadata FROM audit_events WHERE organization_id='anchorix' AND action='governance.explanation_pruned' ORDER BY occurred_at DESC, id DESC LIMIT 1`,
		).Scan(&raw)
	}); err != nil {
		t.Fatalf("read prune audit metadata: %v", err)
	}
	var md struct {
		Severity     string `json:"severity"`
		DeletedCount int    `json:"deleted_count"`
		CertsScanned int    `json:"certs_scanned"`
		KeepN        int    `json:"keep_n"`
		MaxAge       string `json:"max_age"`
	}
	if err := json.Unmarshal(raw, &md); err != nil {
		t.Fatalf("unmarshal prune metadata: %v", err)
	}
	if md.Severity != "security" || md.DeletedCount != 3 || md.CertsScanned != 2 || md.KeepN != 1 || md.MaxAge == "" {
		t.Fatalf("rollup metadata = %+v; want severity=security deleted=3 scanned=2 keep_n=1 max_age set", md)
	}
}

func TestPruneExplanationsAuditRollbackOnFailure(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 120}, 0)
	failing := &failingRecorder{
		inner:         postgres.NewAuditRecorder(db, clock.System{}),
		failOnAction:  "governance.explanation_pruned",
		failOnceArmed: true,
	}
	svc := ownershipServiceWithRecorder(t, db, failing, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})

	_, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err == nil {
		t.Fatal("PruneExplanationsPage: want error from audit failure")
	}
	// Deletes rolled back: all 3 rows survive.
	if n := explanationCountForCert(t, db, ctx, "anchorix", "cert-01"); n != 3 {
		t.Fatalf("remaining = %d; want 3 (deletes rolled back)", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "governance.explanation_pruned"); n != 0 {
		t.Fatalf("explanation_pruned audit = %d; want 0 (rolled back)", n)
	}
}

func TestPruneExplanationsDoesNotTouchOtherTables(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 120}, 0)
	ownBefore := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix'`)
	auditBefore := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix'`)

	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	if _, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100); err != nil {
		t.Fatalf("prune: %v", err)
	}

	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix'`); n != ownBefore {
		t.Fatalf("certificate_ownership count = %d; want %d (untouched)", n, ownBefore)
	}
	// audit_events only grows (the one rollup row), never shrinks.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix'`); n != auditBefore+1 {
		t.Fatalf("audit_events count = %d; want %d (only +1 rollup)", n, auditBefore+1)
	}
}

// TestExplanationRestrictBlocksCurrentDelete proves the DB-level
// fail-closed guarantee independent of the prune query: a direct DELETE
// of the FK-pinned current explanation is refused by ON DELETE RESTRICT.
func TestExplanationRestrictBlocksCurrentDelete(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ids := seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1}, 0)
	currentID := ids[0]

	err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM ownership_match_explanations WHERE organization_id='anchorix' AND id=$1`, currentID)
		return e
	})
	if err == nil {
		t.Fatal("expected ON DELETE RESTRICT to block deleting the pinned current explanation")
	}
	if !explanationRowExists(t, db, ctx, "anchorix", currentID) {
		t.Fatal("current explanation was deleted despite RESTRICT")
	}
}

func TestPruneExplanationsEmptyOrgFailsClosed(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	if _, err := svc.PruneExplanationsPage(ctx, "  ", "op-1", "", 100); err == nil {
		t.Fatal("PruneExplanationsPage: want error for empty organization id")
	}
}

// TestPruneExplanationsBoundedPerCertBatch proves the per-certificate
// work is bounded: with the per-cert candidate cap forced to 2, a cert
// with 5 prunable rows deletes at most 2 per page and drains across
// passes, never an unbounded read/delete inside one transaction.
func TestPruneExplanationsBoundedPerCertBatch(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1 recent (current, 1d) + 5 ancient (100..104d); KeepN=1, MaxAge=90d
	// → 5 prunable rows.
	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 101, 102, 103, 104}, 0)
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	svc.SetPrunePerCertLimitForTest(2)

	first, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if first.DeletedCount != 2 {
		t.Fatalf("first page deleted = %d; want 2 (per-cert cap)", first.DeletedCount)
	}

	total := first.DeletedCount
	for i := 0; i < 10; i++ {
		res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
		if err != nil {
			t.Fatalf("drain page: %v", err)
		}
		if res.DeletedCount > 2 {
			t.Fatalf("page deleted = %d; want <= 2 (per-cert cap)", res.DeletedCount)
		}
		total += res.DeletedCount
		if res.DeletedCount == 0 {
			break
		}
	}
	if total != 5 {
		t.Fatalf("total drained = %d; want 5", total)
	}
	if n := explanationCountForCert(t, db, ctx, "anchorix", "cert-01"); n != 1 {
		t.Fatalf("remaining = %d; want 1 (current only)", n)
	}
}

// TestPrunableExplanationIDsQueryBounded pins the per-cert candidate
// selection plan: bounded (a Limit node) and not a fleet-wide GROUP BY.
// Boundedness of the actual per-page work is proven concretely by
// TestPruneExplanationsBoundedPerCertBatch; this guards the query shape.
// (Index vs Seq Scan is left to the planner — on tiny test tables a
// filtered Seq Scan under the Limit is expected and harmless.)
func TestPrunableExplanationIDsQueryBounded(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 1; i <= 20; i++ {
		seedAgedCert(t, db, ctx, "anchorix", fmt.Sprintf("cert-%02d", i), []int{1, 100, 101}, 0)
	}
	cutoff := time.Now().Add(-90 * 24 * time.Hour)
	plan := explainPlan(t, db, ctx, postgres.PrunableExplanationIDsQuery, "anchorix", "cert-01", cutoff, 1, 256)
	if !strings.Contains(plan, "Limit") {
		t.Fatalf("candidate query must be bounded (Limit), got:\n%s", plan)
	}
	if strings.Contains(plan, "Group Key") {
		t.Fatalf("candidate query must not fleet-aggregate (Group Key), got:\n%s", plan)
	}
}

// TestPruneExplanationsOuterWalkBounded pins the outer cert-id walk's
// query plan as bounded by a Limit (cursor pagination), so the prune
// never enumerates the whole org's certificate set in one statement.
func TestPruneExplanationsOuterWalkBounded(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 1; i <= 20; i++ {
		seedAgedCert(t, db, ctx, "anchorix", fmt.Sprintf("cert-%02d", i), []int{1, 100}, 0)
	}
	plan := explainPlan(t, db, ctx, postgres.ListCertificateIDsWithExplanationsPagedQuery, "anchorix", "", 5)
	if !strings.Contains(plan, "Limit") {
		t.Fatalf("outer walk must be bounded (Limit), got:\n%s", plan)
	}
}

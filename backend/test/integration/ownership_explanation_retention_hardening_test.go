//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// auditActorAndKind returns the (actor, actor_type) of the single
// governance.explanation_pruned audit row, or fails the test if there
// is not exactly one.
func auditActorAndKind(t *testing.T, db *postgres.DB, ctx context.Context, org string) (string, string) {
	t.Helper()
	var actor, actorType string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT actor, actor_type FROM audit_events
			  WHERE organization_id=$1 AND action='governance.explanation_pruned'
			  ORDER BY occurred_at DESC, id DESC LIMIT 1`,
			org).Scan(&actor, &actorType)
	}); err != nil {
		t.Fatalf("read prune audit actor: %v", err)
	}
	return actor, actorType
}

// --- Repository-level adversarial guards ------------------------------

// TestDeleteOwnershipExplanationsRejectsCrossCertIDs proves the DELETE
// is org+cert scoped: passing explanation ids that belong to a
// DIFFERENT certificate in the SAME organization must not delete those
// rows, no matter what a buggy caller hands in.
func TestDeleteOwnershipExplanationsRejectsCrossCertIDs(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a := seedAgedCert(t, db, ctx, "anchorix", "cert-a", []int{1, 100, 120}, 0)
	b := seedAgedCert(t, db, ctx, "anchorix", "cert-b", []int{1, 100, 120}, 0)

	repo := postgres.NewOwnershipRepository(db)
	// Try to delete cert-b's non-current ids while scoping to cert-a.
	deleted, err := repo.DeleteOwnershipExplanationsForCertificate(ctx, "anchorix", "cert-a", []string{b[1], b[2]})
	if err != nil {
		t.Fatalf("DeleteOwnershipExplanationsForCertificate: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("deleted = %d; want 0 (cert-scope must reject cross-cert ids)", deleted)
	}
	// Both cert-b's non-current and cert-a's full timeline survive.
	if !explanationRowExists(t, db, ctx, "anchorix", b[1]) || !explanationRowExists(t, db, ctx, "anchorix", b[2]) {
		t.Fatal("cert-b rows were touched despite cert-a scope")
	}
	if n := explanationCountForCert(t, db, ctx, "anchorix", "cert-a"); n != 3 {
		t.Fatalf("cert-a timeline = %d; want 3 (untouched)", n)
	}
	_ = a
}

// TestDeleteOwnershipExplanationsRejectsCurrentInSlice proves the
// current-explanation guard works even when a buggy caller includes the
// pinned current id in the delete batch. The NOT EXISTS clause must
// exclude it; the FK ON DELETE RESTRICT is the second line of defense.
func TestDeleteOwnershipExplanationsRejectsCurrentInSlice(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ids := seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 120}, 0)
	currentID := ids[0]

	repo := postgres.NewOwnershipRepository(db)
	// All three ids passed in; the current one MUST be excluded by the
	// NOT EXISTS guard, but the other two are still eligible for delete.
	deleted, err := repo.DeleteOwnershipExplanationsForCertificate(ctx, "anchorix", "cert-01", ids)
	if err != nil {
		t.Fatalf("DeleteOwnershipExplanationsForCertificate: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d; want 2 (current must be excluded, non-current deleted)", deleted)
	}
	if !explanationRowExists(t, db, ctx, "anchorix", currentID) {
		t.Fatalf("current explanation %s was deleted via the NOT EXISTS guard's failure", currentID)
	}
}

// TestDeleteOwnershipExplanationsEmptySliceNoOp proves the no-op
// short-circuit is safe: an empty id slice does not error, does not
// touch any row, and does not produce a spurious DB round trip's
// observable side effects.
func TestDeleteOwnershipExplanationsEmptySliceNoOp(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100}, 0)
	before := explanationCountForCert(t, db, ctx, "anchorix", "cert-01")

	repo := postgres.NewOwnershipRepository(db)
	deleted, err := repo.DeleteOwnershipExplanationsForCertificate(ctx, "anchorix", "cert-01", nil)
	if err != nil {
		t.Fatalf("nil slice: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("nil slice deleted = %d; want 0", deleted)
	}
	deleted, err = repo.DeleteOwnershipExplanationsForCertificate(ctx, "anchorix", "cert-01", []string{})
	if err != nil {
		t.Fatalf("empty slice: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("empty slice deleted = %d; want 0", deleted)
	}
	if got := explanationCountForCert(t, db, ctx, "anchorix", "cert-01"); got != before {
		t.Fatalf("timeline changed: before=%d after=%d", before, got)
	}
}

// TestListPrunableExplanationIDsNeverReturnsCurrent proves the
// candidate-selection SQL excludes the FK-pinned current explanation
// even when the current row is also the oldest (would otherwise be the
// prime candidate). The NOT EXISTS clause must apply before the
// LIMIT/ORDER BY.
func TestListPrunableExplanationIDsNeverReturnsCurrent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// e0 is the oldest AND pinned current — without the guard it would
	// be the first row the oldest-first query returns.
	ids := seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{400, 300, 200, 100, 1}, 0)
	currentID := ids[0]

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.ListPrunableExplanationIDs(ctx, "anchorix", "cert-01",
		time.Now().Add(-24*time.Hour), 1, 100)
	if err != nil {
		t.Fatalf("ListPrunableExplanationIDs: %v", err)
	}
	for _, id := range got {
		if id == currentID {
			t.Fatalf("candidate list returned the current explanation %s: %v", currentID, got)
		}
	}
}

// --- Boundary semantics -----------------------------------------------

// TestListPrunableExplanationIDsCutoffStrictlyLess proves the
// "older than cutoff" boundary uses strict inequality (decided_at < cutoff):
// a row whose decided_at is EXACTLY equal to the cutoff is kept, not pruned.
// The check is done at the SQL primitive level so the cutoff value is
// derived from the seeded decided_at directly — no wall-clock drift
// between seed and prune can affect the comparison.
func TestListPrunableExplanationIDsCutoffStrictlyLess(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 200}, 0)

	// Read back the decided_at of the middle row (100 days old) and use
	// it as the cutoff. The 200d row is strictly older; the 100d row is
	// exactly equal to the cutoff; the 1d (current) is newer.
	var midDecidedAt time.Time
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT decided_at FROM ownership_match_explanations WHERE id='cert-01-e1'`,
		).Scan(&midDecidedAt)
	}); err != nil {
		t.Fatalf("read midDecidedAt: %v", err)
	}

	repo := postgres.NewOwnershipRepository(db)
	// KeepN=1 means only the latest (current) is in the keep set; the
	// other two are eligibility-decided by the cutoff. With cutoff =
	// midDecidedAt and strict <, only the 200d row should be returned.
	got, err := repo.ListPrunableExplanationIDs(ctx, "anchorix", "cert-01", midDecidedAt, 1, 100)
	if err != nil {
		t.Fatalf("ListPrunableExplanationIDs: %v", err)
	}
	if len(got) != 1 || got[0] != "cert-01-e2" {
		t.Fatalf("candidates = %v; want [cert-01-e2] (strict <: at-cutoff kept, strictly-older selected)", got)
	}
}

// TestPruneExplanationsPageSizeClampedAboveMax proves a caller cannot
// request an unbounded transaction: pageSize above maxExplanationPrune-
// PageSize (1000) is clamped down. We seed maxExplanationPrunePageSize+10
// certs and a huge requested pageSize, then assert at most
// maxExplanationPrunePageSize certs were scanned in one call.
func TestPruneExplanationsPageSizeClampedAboveMax(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const overMax = 1010
	for i := 0; i < overMax; i++ {
		seedAgedCert(t, db, ctx, "anchorix", fmt.Sprintf("cert-%04d", i), []int{1}, 0)
	}
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100000)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	// 1000 is maxExplanationPrunePageSize (private; cross-checked here).
	if res.CertsScanned > 1000 {
		t.Fatalf("CertsScanned = %d; want <= 1000 (oversized pageSize must be clamped)", res.CertsScanned)
	}
	if res.Done {
		t.Fatalf("Done=true with %d > 1000 certs remaining; pageSize was not clamped", overMax)
	}
}

// TestPruneExplanationsPageSizeZeroUsesDefault proves pageSize <= 0
// falls back to DefaultExplanationPrunePageSize rather than scanning
// zero certs. We seed a small fleet and assert the walk completes,
// matching the documented default-fallback contract.
func TestPruneExplanationsPageSizeZeroUsesDefault(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const fleet = 5
	for i := 0; i < fleet; i++ {
		seedAgedCert(t, db, ctx, "anchorix", fmt.Sprintf("cert-%02d", i), []int{1, 100, 120}, 0)
	}
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 0)
	if err != nil {
		t.Fatalf("prune with pageSize=0: %v", err)
	}
	// Default (500) >> fleet → whole fleet scanned, walk Done.
	if res.CertsScanned != fleet {
		t.Fatalf("CertsScanned = %d; want %d (default pageSize covers small fleet)", res.CertsScanned, fleet)
	}
	if !res.Done {
		t.Fatal("Done = false; default pageSize > fleet should complete the walk")
	}
	if res.DeletedCount != fleet*2 {
		t.Fatalf("DeletedCount = %d; want %d", res.DeletedCount, fleet*2)
	}
}

// TestPruneExplanationsActorAttributionSystem proves an empty actor
// produces system/system audit attribution (not a blank or
// user-mistaken row).
func TestPruneExplanationsActorAttributionSystem(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 120}, 0)
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	if _, err := svc.PruneExplanationsPage(ctx, "anchorix", "   ", "", 100); err != nil {
		t.Fatalf("prune: %v", err)
	}
	actor, kind := auditActorAndKind(t, db, ctx, "anchorix")
	if actor != "system" || kind != "system" {
		t.Fatalf("audit attribution = (%s,%s); want (system,system)", actor, kind)
	}
}

// TestPruneExplanationsActorAttributionUser proves a non-empty actor
// produces user attribution and the actor string is preserved verbatim
// (after trimming whitespace).
func TestPruneExplanationsActorAttributionUser(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 120}, 0)
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	if _, err := svc.PruneExplanationsPage(ctx, "anchorix", "operator-7", "", 100); err != nil {
		t.Fatalf("prune: %v", err)
	}
	actor, kind := auditActorAndKind(t, db, ctx, "anchorix")
	if actor != "operator-7" || kind != "user" {
		t.Fatalf("audit attribution = (%s,%s); want (operator-7,user)", actor, kind)
	}
}

// --- Multi-cert atomicity / cursor / empty-candidate -----------------

// TestPruneExplanationsAuditRollbackAcrossMultipleCerts proves the
// audit-rollback atomicity extends across the whole page, not just one
// cert: when the rollup audit fails, deletes from EVERY cert touched in
// the page are rolled back.
func TestPruneExplanationsAuditRollbackAcrossMultipleCerts(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 120}, 0)
	seedAgedCert(t, db, ctx, "anchorix", "cert-02", []int{1, 100, 120}, 0)
	seedAgedCert(t, db, ctx, "anchorix", "cert-03", []int{1, 100, 120}, 0)
	beforeCounts := []int{
		explanationCountForCert(t, db, ctx, "anchorix", "cert-01"),
		explanationCountForCert(t, db, ctx, "anchorix", "cert-02"),
		explanationCountForCert(t, db, ctx, "anchorix", "cert-03"),
	}

	failing := &failingRecorder{
		inner:         postgres.NewAuditRecorder(db, clock.System{}),
		failOnAction:  "governance.explanation_pruned",
		failOnceArmed: true,
	}
	svc := ownershipServiceWithRecorder(t, db, failing, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	if _, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100); err == nil {
		t.Fatal("PruneExplanationsPage: want error from audit failure")
	}
	for i, certID := range []string{"cert-01", "cert-02", "cert-03"} {
		if got := explanationCountForCert(t, db, ctx, "anchorix", certID); got != beforeCounts[i] {
			t.Fatalf("%s remaining = %d; want %d (rolled back across page)", certID, got, beforeCounts[i])
		}
	}
	if n := auditCount(t, db, ctx, "anchorix", "governance.explanation_pruned"); n != 0 {
		t.Fatalf("explanation_pruned audit = %d; want 0", n)
	}
}

// TestPruneExplanationsCursorResumeIsDeterministic proves the cursor
// produces deterministic forward progress: after a partial page, the
// resumed walk hits exactly the next cert range and never revisits
// already-scanned certs. The current explanation surviving every prune
// keeps the cursor space stable across passes.
func TestPruneExplanationsCursorResumeIsDeterministic(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const fleet = 6
	for i := 1; i <= fleet; i++ {
		seedAgedCert(t, db, ctx, "anchorix", fmt.Sprintf("cert-%02d", i), []int{1, 100, 120}, 0)
	}
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})

	first, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 2)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if first.NextCursor != "cert-02" || first.CertsScanned != 2 || first.DeletedCount != 4 || first.Done {
		t.Fatalf("first = %+v; want NextCursor=cert-02 scanned=2 deleted=4 done=false", first)
	}
	second, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", first.NextCursor, 2)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if second.StartCursor != "cert-02" || second.NextCursor != "cert-04" || second.CertsScanned != 2 || second.DeletedCount != 4 || second.Done {
		t.Fatalf("second = %+v; want Start=cert-02 NextCursor=cert-04 scanned=2 deleted=4 done=false", second)
	}
	// cert-01 and cert-02 are NOT re-scanned (they only retain their
	// current row — but the outer walk's cursor is exclusive of the
	// previous NextCursor, so they must not appear in second's range).
	for _, alreadyPruned := range []string{"cert-01", "cert-02"} {
		if n := explanationCountForCert(t, db, ctx, "anchorix", alreadyPruned); n != 1 {
			t.Fatalf("%s remaining = %d; want 1 (untouched by second page)", alreadyPruned, n)
		}
	}
}

// TestPruneExplanationsEmptyCandidatePathNoAudit proves the rollup
// audit is emitted ONLY when rows were actually deleted: a cert whose
// timeline is entirely within KeepN produces zero candidates → zero
// deletes → zero audit row, even though CertsScanned > 0.
func TestPruneExplanationsEmptyCandidatePathNoAudit(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 3 rows; KeepN=3 → none are beyond latest-N → candidate list empty.
	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{100, 101, 102}, 0)
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 3, MaxAge: 24 * time.Hour})

	res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.CertsScanned != 1 || res.DeletedCount != 0 {
		t.Fatalf("res = %+v; want CertsScanned=1 DeletedCount=0", res)
	}
	if n := auditCount(t, db, ctx, "anchorix", "governance.explanation_pruned"); n != 0 {
		t.Fatalf("explanation_pruned audit = %d; want 0 (no-op page emits no audit)", n)
	}
	if n := explanationCountForCert(t, db, ctx, "anchorix", "cert-01"); n != 3 {
		t.Fatalf("remaining = %d; want 3", n)
	}
}

// TestPruneExplanationsDeepHistoryStaysBounded proves the "no unbounded
// per-cert load regression" requirement concretely: with 100 prunable
// rows on ONE certificate and a per-cert candidate cap of 10, exactly
// 10 are deleted per page (oldest-first), draining across 10 passes.
func TestPruneExplanationsDeepHistoryStaysBounded(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1 current (1d) + 100 ancient (100..199d). KeepN=1, MaxAge=90d.
	ages := []int{1}
	for i := 0; i < 100; i++ {
		ages = append(ages, 100+i)
	}
	seedAgedCert(t, db, ctx, "anchorix", "cert-deep", ages, 0)

	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	svc.SetPrunePerCertLimitForTest(10)

	const wantPages = 10
	total, passes := 0, 0
	for passes < wantPages+2 {
		res, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100)
		if err != nil {
			t.Fatalf("pass %d: %v", passes, err)
		}
		if res.DeletedCount > 10 {
			t.Fatalf("pass %d deleted %d; want <= 10 (per-cert cap)", passes, res.DeletedCount)
		}
		total += res.DeletedCount
		passes++
		if res.DeletedCount == 0 {
			break
		}
	}
	if total != 100 {
		t.Fatalf("total drained = %d; want 100", total)
	}
	if n := explanationCountForCert(t, db, ctx, "anchorix", "cert-deep"); n != 1 {
		t.Fatalf("remaining = %d; want 1 (current only)", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "governance.explanation_pruned"); n != wantPages {
		t.Fatalf("audit rows = %d; want %d (one per non-empty page)", n, wantPages)
	}
}

// --- Broader other-tables coverage ------------------------------------

// TestPruneExplanationsLeavesGovernanceTablesUntouched extends the
// "other tables" guarantee from cert_ownership + audit_events (already
// covered) to the operator-curated vocabulary the engine reads:
// ownership_rules, services, certificate_ownership_overrides, tags,
// agent_groups. None of them are touched by the prune.
func TestPruneExplanationsLeavesGovernanceTablesUntouched(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Seed prunable history.
	seedAgedCert(t, db, ctx, "anchorix", "cert-01", []int{1, 100, 120}, 0)

	// Seed unrelated governance + identity rows that must not be touched.
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		stmts := []string{
			`INSERT INTO services (id, organization_id, slug, display_name) VALUES ('svc-1','anchorix','svc-one','Svc One')`,
			`INSERT INTO ownership_rules
				(id, organization_id, name, service_id, precedence_tier, priority,
				 match_kind, match_value, enabled, created_at, updated_at, created_by)
			 VALUES ('rule-1','anchorix','rule-1','svc-1','subject_pattern',100,
				 'subject_cn_glob','cn-test*',true, now(), now(), 'tester')`,
			`INSERT INTO tags (id, organization_id, key, value) VALUES ('tag-1','anchorix','env','prod')`,
			`INSERT INTO agent_groups (id, organization_id, slug, display_name) VALUES ('grp-1','anchorix','grp-one','Group One')`,
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed governance/identity: %v", err)
	}

	type counts struct{ rules, services, overrides, tags, groups int }
	read := func() counts {
		return counts{
			rules:     scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_rules WHERE organization_id='anchorix'`),
			services:  scalarInt(t, db, ctx, `SELECT count(*) FROM services WHERE organization_id='anchorix'`),
			overrides: scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE organization_id='anchorix'`),
			tags:      scalarInt(t, db, ctx, `SELECT count(*) FROM tags WHERE organization_id='anchorix'`),
			groups:    scalarInt(t, db, ctx, `SELECT count(*) FROM agent_groups WHERE organization_id='anchorix'`),
		}
	}
	before := read()
	svc := ownershipServiceWithRetention(t, db, ownership.RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour})
	if _, err := svc.PruneExplanationsPage(ctx, "anchorix", "op-1", "", 100); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if got := read(); got != before {
		t.Fatalf("governance/identity counts changed: before=%+v after=%+v", before, got)
	}
}

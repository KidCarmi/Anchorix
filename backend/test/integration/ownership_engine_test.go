//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// ownershipService wires the engine against the real postgres repos +
// DB transactor with the given bulk-audit threshold (0 = default).
func ownershipService(t *testing.T, db *postgres.DB, bulkThreshold int) *ownership.Service {
	t.Helper()
	repo := &governance.Repo{
		Ownership:     postgres.NewOwnershipRepository(db),
		Policy:        postgres.NewPolicyRepository(db),
		RecomputeRuns: postgres.NewGovernanceRecomputeRunsRepository(db),
	}
	svc, err := ownership.NewService(repo, db, postgres.NewAuditRecorder(db, clock.System{}), clock.System{},
		ownership.ServiceConfig{BulkAuditThreshold: bulkThreshold})
	if err != nil {
		t.Fatalf("ownership.NewService: %v", err)
	}
	return svc
}

func seedOwnershipRule(t *testing.T, db *postgres.DB, ctx context.Context, id, svcID string, tier governance.PrecedenceTier, kind governance.MatchKind, val string, prio int) {
	t.Helper()
	repo := postgres.NewOwnershipRepository(db)
	now := time.Now().UTC()
	if err := repo.CreateOwnershipRule(ctx, &governance.OwnershipRule{
		ID: id, OrganizationID: "anchorix", Name: id, ServiceID: svcID,
		PrecedenceTier: tier, Priority: prio, MatchKind: kind, MatchValue: val,
		Enabled: true, CreatedAt: now, UpdatedAt: now, CreatedBy: "tester",
	}); err != nil {
		t.Fatalf("seed rule %s: %v", id, err)
	}
}

func auditCount(t *testing.T, db *postgres.DB, ctx context.Context, org, action string) int {
	t.Helper()
	var n int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action=$2`, org, action).Scan(&n)
	}); err != nil {
		t.Fatalf("auditCount(%s): %v", action, err)
	}
	return n
}

func scalarInt(t *testing.T, db *postgres.DB, ctx context.Context, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("scalar: %v", err)
	}
	return n
}

type recomputedMeta struct {
	FirstRun              bool `json:"first_run"`
	CreatedUnownedRows    int  `json:"created_unowned_rows"`
	EvaluatedCertificates int  `json:"evaluated_certificates"`
	ChangedCertificates   int  `json:"changed_certificates"`
	EngineVersion         int  `json:"engine_version"`
}

func latestRecomputedMeta(t *testing.T, db *postgres.DB, ctx context.Context, org string) recomputedMeta {
	t.Helper()
	var raw []byte
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT metadata FROM audit_events WHERE organization_id=$1 AND action='governance.recomputed' ORDER BY occurred_at DESC, id DESC LIMIT 1`,
			org).Scan(&raw)
	}); err != nil {
		t.Fatalf("latest recomputed meta: %v", err)
	}
	var m recomputedMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal recomputed meta: %v", err)
	}
	return m
}

func TestOwnershipRecomputeFirstRunUnownedIsQuiet(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, id := range []string{"cert-fr-1", "cert-fr-2", "cert-fr-3"} {
		seedCertMeta(t, db, ctx, "anchorix", id, "CN="+id, "CN=ca", nil)
	}
	svc := ownershipService(t, db, 0)

	res, err := svc.Recompute(ctx, "anchorix", "op-1")
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if !res.FirstRun || res.CreatedUnownedRows != 3 || res.EvaluatedCertificates != 3 || res.ChangedCertificates != 0 {
		t.Fatalf("first run result = %+v; want firstRun, created=3, evaluated=3, changed=0", res)
	}
	// No per-cert ownership transition audit rows on a quiet first run.
	if n := auditCount(t, db, ctx, "anchorix", "ownership.assigned"); n != 0 {
		t.Fatalf("ownership.assigned = %d; want 0 on quiet first run", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "governance.recomputed"); n != 1 {
		t.Fatalf("governance.recomputed = %d; want 1", n)
	}
	// Explanation written for every cert (explainability), 3 unowned rows.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_match_explanations WHERE organization_id='anchorix'`); n != 3 {
		t.Fatalf("explanations = %d; want 3", n)
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix' AND decision='unowned'`); n != 3 {
		t.Fatalf("unowned rows = %d; want 3", n)
	}
	meta := latestRecomputedMeta(t, db, ctx, "anchorix")
	if !meta.FirstRun || meta.CreatedUnownedRows != 3 || meta.EngineVersion != 1 {
		t.Fatalf("recomputed meta = %+v; want first_run, created_unowned=3, engine_version=1", meta)
	}

	// Second pass: not first run, nothing created, all unchanged.
	res2, err := svc.Recompute(ctx, "anchorix", "op-1")
	if err != nil {
		t.Fatalf("Recompute 2: %v", err)
	}
	if res2.FirstRun || res2.CreatedUnownedRows != 0 || res2.UnchangedCertificates != 3 || res2.ChangedCertificates != 0 {
		t.Fatalf("second run = %+v; want !firstRun, created=0, unchanged=3, changed=0", res2)
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_match_explanations WHERE organization_id='anchorix'`); n != 3 {
		t.Fatalf("explanations after idempotent re-run = %d; want still 3", n)
	}
}

func TestOwnershipRecomputeIdempotentWithRules(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-idem")
	seedCertMeta(t, db, ctx, "anchorix", "cert-idem-1", "CN=a.example", "CN=ca", []string{"a.example"})
	seedOwnershipRule(t, db, ctx, "rule-idem", "svc-idem", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)
	svc := ownershipService(t, db, 0)

	r1, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("run1: %v", err)
	}
	if r1.BecameOwned != 1 || r1.ChangedCertificates != 1 {
		t.Fatalf("run1 = %+v; want becameOwned=1 changed=1", r1)
	}
	expCount := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_match_explanations WHERE organization_id='anchorix'`)

	r2, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("run2: %v", err)
	}
	if r2.ChangedCertificates != 0 || r2.UnchangedCertificates != 1 {
		t.Fatalf("run2 = %+v; want changed=0 unchanged=1 (idempotent)", r2)
	}
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_match_explanations WHERE organization_id='anchorix'`); got != expCount {
		t.Fatalf("explanations grew on idempotent re-run: %d → %d", expCount, got)
	}
}

func TestOwnershipRecomputeDeterministicEquivalence(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-eq-a")
	seedService(t, db, ctx, "svc-eq-fb")
	seedCertMeta(t, db, ctx, "anchorix", "cert-eq-1", "CN=a.example", "CN=ca", []string{"a.example"})
	seedCertMeta(t, db, ctx, "anchorix", "cert-eq-2", "CN=z.other", "CN=ca", []string{"z.other"})
	seedOwnershipRule(t, db, ctx, "rule-eq-san", "svc-eq-a", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)
	seedOwnershipRule(t, db, ctx, "rule-eq-fb", "svc-eq-fb", governance.PrecedenceFallback, governance.MatchFallback, "", 1000)
	svc := ownershipService(t, db, 0)

	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("run1: %v", err)
	}
	snap1 := ownershipSnapshot(t, db, ctx)

	// Wipe derived state (keep certs + rules), re-run, compare.
	if err := execRawSQL(ctx, db, rawStmt{`DELETE FROM certificate_ownership WHERE organization_id='anchorix'`, nil}); err != nil {
		t.Fatalf("wipe ownership: %v", err)
	}
	if err := execRawSQL(ctx, db, rawStmt{`DELETE FROM ownership_match_explanations WHERE organization_id='anchorix'`, nil}); err != nil {
		t.Fatalf("wipe explanations: %v", err)
	}
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("run2: %v", err)
	}
	snap2 := ownershipSnapshot(t, db, ctx)

	if len(snap1) != len(snap2) || len(snap1) != 2 {
		t.Fatalf("snapshot sizes = %d / %d; want 2", len(snap1), len(snap2))
	}
	for k, v := range snap1 {
		if snap2[k] != v {
			t.Fatalf("non-deterministic for %s:\n run1=%s\n run2=%s", k, v, snap2[k])
		}
	}
	// Sanity: the san cert is owned by svc-eq-a, the other by fallback.
	if !containsSub(snap1["cert-eq-1"], "matched|svc-eq-a|rule-eq-san") {
		t.Fatalf("cert-eq-1 snapshot = %s", snap1["cert-eq-1"])
	}
	if !containsSub(snap1["cert-eq-2"], "matched|svc-eq-fb|rule-eq-fb") {
		t.Fatalf("cert-eq-2 snapshot = %s", snap1["cert-eq-2"])
	}
}

func ownershipSnapshot(t *testing.T, db *postgres.DB, ctx context.Context) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT co.certificate_id, co.decision, COALESCE(co.service_id,''), COALESCE(co.winning_rule_id,''),
			       e.losing_rules::text, e.signals_seen::text
			  FROM certificate_ownership co
			  JOIN ownership_match_explanations e ON e.organization_id = co.organization_id AND e.id = co.explanation_id
			 WHERE co.organization_id='anchorix' ORDER BY co.certificate_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var cert, dec, svc, wr, losing, signals string
			if err := rows.Scan(&cert, &dec, &svc, &wr, &losing, &signals); err != nil {
				return err
			}
			out[cert] = dec + "|" + svc + "|" + wr + "|" + losing + "|" + signals
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return out
}

func containsSub(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestOwnershipAmbiguityDetected(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-amb-a")
	seedService(t, db, ctx, "svc-amb-b")
	seedCertMeta(t, db, ctx, "anchorix", "cert-amb", "CN=a.example", "CN=ca", []string{"a.example"})
	// Two san rules, same tier + priority; created_at equal enough?
	// CreateOwnershipRule stamps created_at from the struct — seed both
	// with the SAME created_at to force the (priority, created_at) tie.
	now := time.Now().UTC()
	repo := postgres.NewOwnershipRepository(db)
	for _, id := range []string{"rule-amb-2", "rule-amb-1"} {
		if err := repo.CreateOwnershipRule(ctx, &governance.OwnershipRule{
			ID: id, OrganizationID: "anchorix", Name: id, ServiceID: "svc-amb-a",
			PrecedenceTier: governance.PrecedenceSANPattern, Priority: 100,
			MatchKind: governance.MatchSANGlob, MatchValue: "*.example",
			Enabled: true, CreatedAt: now, UpdatedAt: now, CreatedBy: "tester",
		}); err != nil {
			t.Fatalf("seed rule %s: %v", id, err)
		}
	}
	svc := ownershipService(t, db, 0)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	co, err := repo.GetCertificateOwnership(ctx, "anchorix", "cert-amb")
	if err != nil {
		t.Fatalf("GetCertificateOwnership: %v", err)
	}
	if co.Decision != governance.DecisionAmbiguous {
		t.Fatalf("decision = %s; want ambiguous", co.Decision)
	}
	if co.WinningRuleID == nil || *co.WinningRuleID != "rule-amb-1" {
		t.Fatalf("winner = %v; want rule-amb-1 (lowest id)", co.WinningRuleID)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.ambiguous_match"); n != 1 {
		t.Fatalf("ambiguous_match audit = %d; want 1", n)
	}
}

func TestOwnershipOverridePrecedence(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-ovr-rule")
	seedService(t, db, ctx, "svc-ovr-pin")
	seedCertMeta(t, db, ctx, "anchorix", "cert-ovr", "CN=a.example", "CN=ca", []string{"a.example"})
	seedOwnershipRule(t, db, ctx, "rule-ovr", "svc-ovr-rule", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-1", OrganizationID: "anchorix", CertificateID: "cert-ovr", ServiceID: "svc-ovr-pin",
		Reason: "pin", SetBy: "op", SetAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create override: %v", err)
	}
	svc := ownershipService(t, db, 0)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	co, err := repo.GetCertificateOwnership(ctx, "anchorix", "cert-ovr")
	if err != nil {
		t.Fatalf("get ownership: %v", err)
	}
	if co.Decision != governance.DecisionOverridden || co.ServiceID == nil || *co.ServiceID != "svc-ovr-pin" {
		t.Fatalf("override must win: %+v", co)
	}
	if co.OverrideID == nil || *co.OverrideID != "ovr-1" || co.WinningRuleID != nil {
		t.Fatalf("override metadata wrong: %+v", co)
	}
}

func TestOwnershipRegexCompileFailureIsAuditedNotFatal(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-rx")
	seedService(t, db, ctx, "svc-rx-fb")
	seedCertMeta(t, db, ctx, "anchorix", "cert-rx", "CN=a.example", "CN=ca", []string{"a.example"})
	seedOwnershipRule(t, db, ctx, "rule-rx-bad", "svc-rx", governance.PrecedenceSANPattern, governance.MatchSANRegex, "[", 100)
	seedOwnershipRule(t, db, ctx, "rule-rx-fb", "svc-rx-fb", governance.PrecedenceFallback, governance.MatchFallback, "", 1000)
	svc := ownershipService(t, db, 0)
	res, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("recompute must not abort on bad regex: %v", err)
	}
	if res.RuleCompileFailures != 1 {
		t.Fatalf("compile failures = %d; want 1", res.RuleCompileFailures)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_compile_failed"); n != 1 {
		t.Fatalf("rule_compile_failed audit = %d; want 1", n)
	}
	// The inert bad rule must not own the cert; the fallback does.
	co, err := postgres.NewOwnershipRepository(db).GetCertificateOwnership(ctx, "anchorix", "cert-rx")
	if err != nil {
		t.Fatalf("get ownership: %v", err)
	}
	if co.ServiceID == nil || *co.ServiceID != "svc-rx-fb" {
		t.Fatalf("cert should be owned by fallback, not the inert bad-regex rule: %+v", co)
	}
}

func TestOwnershipUnknownTierLoudRejection(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-drift")
	seedCertMeta(t, db, ctx, "anchorix", "cert-drift", "CN=a.example", "CN=ca", []string{"a.example"})

	dropCheck := `DO $$
		DECLARE cname text;
		BEGIN
		  SELECT conname INTO cname FROM pg_constraint
		   WHERE conrelid='ownership_rules'::regclass AND contype='c'
		     AND pg_get_constraintdef(oid) LIKE '%precedence_tier%';
		  IF cname IS NOT NULL THEN
		    EXECUTE 'ALTER TABLE ownership_rules DROP CONSTRAINT ' || quote_ident(cname);
		  END IF;
		END $$;`
	if err := execRawSQL(ctx, db, rawStmt{dropCheck, nil}); err != nil {
		t.Fatalf("drop check: %v", err)
	}
	t.Cleanup(func() {
		cctx, cc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cc()
		_ = execRawSQL(cctx, db, rawStmt{`DELETE FROM certificate_ownership`, nil})
		_ = execRawSQL(cctx, db, rawStmt{`DELETE FROM ownership_match_explanations`, nil})
		_ = execRawSQL(cctx, db, rawStmt{`DELETE FROM ownership_rules`, nil})
		_ = execRawSQL(cctx, db, rawStmt{`ALTER TABLE ownership_rules ADD CONSTRAINT ownership_rules_precedence_tier_check
			CHECK (precedence_tier IN ('explicit','service_member','agent_group','san_pattern','subject_pattern','tag','issuer_store','fallback'))`, nil})
	})
	seedOwnershipRule(t, db, ctx, "rule-bogus", "svc-drift", governance.PrecedenceTier("bogus_tier"), governance.MatchFallback, "", 1)

	svc := ownershipService(t, db, 0)
	_, err := svc.Recompute(ctx, "anchorix", "op")
	if !errors.Is(err, ownership.ErrUnknownPrecedenceTier) {
		t.Fatalf("recompute err = %v; want ErrUnknownPrecedenceTier (loud abort)", err)
	}
	// The pass rolled back: no run row committed.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM governance_recompute_runs WHERE organization_id='anchorix'`); n != 0 {
		t.Fatalf("recompute_runs = %d; want 0 (aborted pass rolls back)", n)
	}
}

func TestOwnershipBulkAuditRollup(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-bulk")
	const n = 12
	for i := 0; i < n; i++ {
		id := "cert-bulk-" + string(rune('a'+i))
		seedCertMeta(t, db, ctx, "anchorix", id, "CN="+id, "CN=ca", nil)
	}
	seedOwnershipRule(t, db, ctx, "rule-bulk-fb", "svc-bulk", governance.PrecedenceFallback, governance.MatchFallback, "", 1)
	svc := ownershipService(t, db, 5) // threshold 5 < 12

	res, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if res.BecameOwned != n {
		t.Fatalf("becameOwned = %d; want %d", res.BecameOwned, n)
	}
	if got := auditCount(t, db, ctx, "anchorix", "ownership.assigned"); got != 0 {
		t.Fatalf("per-cert ownership.assigned = %d; want 0 (rolled up)", got)
	}
	if got := auditCount(t, db, ctx, "anchorix", "ownership.bulk_assigned"); got != 1 {
		t.Fatalf("ownership.bulk_assigned = %d; want 1", got)
	}
}

func TestOwnershipBelowThresholdEmitsPerCert(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-small")
	for i := 0; i < 3; i++ {
		id := "cert-small-" + string(rune('a'+i))
		seedCertMeta(t, db, ctx, "anchorix", id, "CN="+id, "CN=ca", nil)
	}
	seedOwnershipRule(t, db, ctx, "rule-small-fb", "svc-small", governance.PrecedenceFallback, governance.MatchFallback, "", 1)
	svc := ownershipService(t, db, 500)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if got := auditCount(t, db, ctx, "anchorix", "ownership.assigned"); got != 3 {
		t.Fatalf("per-cert ownership.assigned = %d; want 3 (under threshold)", got)
	}
	if got := auditCount(t, db, ctx, "anchorix", "ownership.bulk_assigned"); got != 0 {
		t.Fatalf("bulk_assigned = %d; want 0", got)
	}
}

func TestOwnershipPageBoundaryCompleteness(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-pg")
	const n = 7
	for i := 0; i < n; i++ {
		seedCertMeta(t, db, ctx, "anchorix", "cert-pgwalk-"+string(rune('a'+i)), "CN=x", "CN=ca", nil)
	}
	seedOwnershipRule(t, db, ctx, "rule-pg-fb", "svc-pg", governance.PrecedenceFallback, governance.MatchFallback, "", 1)
	svc := ownershipService(t, db, 0)
	svc.SetPageSizeForTest(2) // force multi-page walk across boundaries

	res, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if res.EvaluatedCertificates != n {
		t.Fatalf("evaluated = %d; want %d (multi-page walk must cover every cert exactly once)", res.EvaluatedCertificates, n)
	}
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix'`); got != n {
		t.Fatalf("ownership rows = %d; want %d", got, n)
	}
}

func TestOwnershipStaleLastEvaluatedBumped(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-stale")
	seedCertMeta(t, db, ctx, "anchorix", "cert-stale", "CN=a.example", "CN=ca", []string{"a.example"})
	seedOwnershipRule(t, db, ctx, "rule-stale", "svc-stale", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)
	svc := ownershipService(t, db, 0)
	repo := postgres.NewOwnershipRepository(db)

	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("run1: %v", err)
	}
	co1, _ := repo.GetCertificateOwnership(ctx, "anchorix", "cert-stale")
	time.Sleep(5 * time.Millisecond)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("run2: %v", err)
	}
	co2, _ := repo.GetCertificateOwnership(ctx, "anchorix", "cert-stale")
	if !co2.LastEvaluatedAt.After(co1.LastEvaluatedAt) {
		t.Fatalf("last_evaluated_at not bumped: %s → %s", co1.LastEvaluatedAt, co2.LastEvaluatedAt)
	}
	if !co2.LastChangedAt.Equal(co1.LastChangedAt) {
		t.Fatalf("last_changed_at moved on an unchanged recompute: %s → %s", co1.LastChangedAt, co2.LastChangedAt)
	}
}

func TestOwnershipCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedOrganization(t, db, "other", "Other")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-iso")
	seedCertMeta(t, db, ctx, "anchorix", "cert-iso-a", "CN=a.example", "CN=ca", []string{"a.example"})
	seedCertMeta(t, db, ctx, "other", "cert-iso-b", "CN=b.example", "CN=ca", []string{"b.example"})
	seedOwnershipRule(t, db, ctx, "rule-iso", "svc-iso", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)
	svc := ownershipService(t, db, 0)

	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("Recompute anchorix: %v", err)
	}
	// anchorix cert owned; other-org cert untouched (no ownership row).
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='other'`); got != 0 {
		t.Fatalf("other-org ownership rows = %d; want 0 (isolation)", got)
	}
	co, err := postgres.NewOwnershipRepository(db).GetCertificateOwnership(ctx, "anchorix", "cert-iso-a")
	if err != nil || co.ServiceID == nil || *co.ServiceID != "svc-iso" {
		t.Fatalf("anchorix cert not owned as expected: %+v err=%v", co, err)
	}
}

func TestOwnershipLargeFixtureRecompute(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-large")
	const n = 1000
	bulkSeedCerts(t, db, ctx, "anchorix", "cert-lg-", n)
	seedOwnershipRule(t, db, ctx, "rule-lg-fb", "svc-large", governance.PrecedenceFallback, governance.MatchFallback, "", 1)
	svc := ownershipService(t, db, 0)

	res, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if res.EvaluatedCertificates != n || res.BecameOwned != n {
		t.Fatalf("res = %+v; want evaluated=%d becameOwned=%d", res, n, n)
	}
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix'`); got != n {
		t.Fatalf("ownership rows = %d; want %d", got, n)
	}
}

func TestOwnershipWALAmplificationMeasured(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-wal")
	const n = 500
	bulkSeedCerts(t, db, ctx, "anchorix", "cert-wal-", n)
	seedOwnershipRule(t, db, ctx, "rule-wal-fb", "svc-wal", governance.PrecedenceFallback, governance.MatchFallback, "", 1)
	svc := ownershipService(t, db, 0)

	before := walLSN(t, db, ctx)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	after := walLSN(t, db, ctx)
	var bytesWritten int64
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint`, after, before).Scan(&bytesWritten)
	}); err != nil {
		t.Fatalf("wal diff: %v", err)
	}
	if bytesWritten <= 0 {
		t.Fatalf("WAL bytes = %d; want > 0", bytesWritten)
	}
	// Planning anchor, not an SLO: log the per-changed-cert figure so a
	// regression that 10x's the write cost is visible in review.
	t.Logf("WAL amplification: %d bytes for %d bulk-owned certs (%.1f bytes/cert)",
		bytesWritten, n, float64(bytesWritten)/float64(n))
}

func TestOwnershipConcurrentRecomputeSerializes(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-conc")
	bulkSeedCerts(t, db, ctx, "anchorix", "cert-conc-", 50)
	seedOwnershipRule(t, db, ctx, "rule-conc-fb", "svc-conc", governance.PrecedenceFallback, governance.MatchFallback, "", 1)
	svc := ownershipService(t, db, 0)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = svc.Recompute(ctx, "anchorix", "op")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent recompute %d failed (lock should serialize, not error): %v", i, err)
		}
	}
	// No duplicate-key fallout: exactly one ownership row per cert.
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix'`); got != 50 {
		t.Fatalf("ownership rows = %d; want 50", got)
	}
}

func bulkSeedCerts(t *testing.T, db *postgres.DB, ctx context.Context, org, prefix string, n int) {
	t.Helper()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		for i := 0; i < n; i++ {
			id := prefix + padInt(i)
			if _, err := tx.Exec(ctx, `
				INSERT INTO certificates (id, organization_id, fingerprint_sha256, subject, issuer,
					serial_number_hex, signature_algorithm, public_key_algorithm,
					public_key_bits, not_before, not_after, pem)
				VALUES ($1,$2,$1,'CN=bulk','CN=ca','01','SHA256-RSA','RSA',2048,
					now()-interval '30 days', now()+interval '365 days','x')`, id, org); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("bulk seed certs: %v", err)
	}
}

func padInt(i int) string {
	const width = 6
	s := ""
	for n := i; ; n /= 10 {
		s = string(rune('0'+n%10)) + s
		if n < 10 {
			break
		}
	}
	for len(s) < width {
		s = "0" + s
	}
	return s
}

func walLSN(t *testing.T, db *postgres.DB, ctx context.Context) string {
	t.Helper()
	var lsn string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT pg_current_wal_lsn()::text`).Scan(&lsn)
	}); err != nil {
		t.Fatalf("wal lsn: %v", err)
	}
	return lsn
}

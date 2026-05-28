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

func TestOwnershipSameOwnerReclassificationRefreshesMetadata(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-shared")
	seedCertMeta(t, db, ctx, "anchorix", "cert-recl", "CN=a.example", "CN=ca", []string{"a.example"})
	// Pass 1: only a fallback rule (→ svc-shared, low confidence).
	seedOwnershipRule(t, db, ctx, "rule-recl-fb", "svc-shared", governance.PrecedenceFallback, governance.MatchFallback, "", 1000)
	svc := ownershipService(t, db, 0)
	repo := postgres.NewOwnershipRepository(db)

	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("run1: %v", err)
	}
	co1, _ := repo.GetCertificateOwnership(ctx, "anchorix", "cert-recl")
	if co1.WinningRuleID == nil || *co1.WinningRuleID != "rule-recl-fb" || co1.Confidence != governance.ConfidenceLow {
		t.Fatalf("pass1 ownership = %+v; want fallback/low", co1)
	}
	assignedBefore := auditCount(t, db, ctx, "anchorix", "ownership.assigned")

	// Pass 2: add a higher-precedence SAN rule ALSO pointing at the
	// SAME service. Owner does not change; the basis does.
	seedOwnershipRule(t, db, ctx, "rule-recl-san", "svc-shared", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)
	res, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("run2: %v", err)
	}
	if res.Reclassified != 1 || res.BecameOwned != 0 || res.FlippedOwner != 0 {
		t.Fatalf("run2 = %+v; want reclassified=1, becameOwned=0, flippedOwner=0", res)
	}

	co2, _ := repo.GetCertificateOwnership(ctx, "anchorix", "cert-recl")
	if co2.ServiceID == nil || *co2.ServiceID != "svc-shared" {
		t.Fatalf("owner must stay svc-shared: %+v", co2)
	}
	if co2.WinningRuleID == nil || *co2.WinningRuleID != "rule-recl-san" {
		t.Fatalf("winning_rule_id not refreshed: %+v; want rule-recl-san", co2)
	}
	if co2.Confidence != governance.ConfidenceMedium {
		t.Fatalf("confidence not refreshed: %s; want medium", co2.Confidence)
	}
	if co2.ExplanationID == co1.ExplanationID {
		t.Fatalf("explanation_id not refreshed on reclassification")
	}
	if !co2.LastChangedAt.Equal(co1.LastChangedAt) {
		t.Fatalf("last_changed_at must be preserved (owner unchanged): %s → %s", co1.LastChangedAt, co2.LastChangedAt)
	}
	if !co2.LastEvaluatedAt.After(co1.LastEvaluatedAt) {
		t.Fatalf("last_evaluated_at must advance: %s → %s", co1.LastEvaluatedAt, co2.LastEvaluatedAt)
	}
	// No transition audit spam: pass 2 emits no new assigned/flipped.
	if got := auditCount(t, db, ctx, "anchorix", "ownership.assigned"); got != assignedBefore {
		t.Fatalf("reclassification emitted ownership.assigned: %d → %d", assignedBefore, got)
	}
	if got := auditCount(t, db, ctx, "anchorix", "ownership.flipped"); got != 0 {
		t.Fatalf("reclassification emitted ownership.flipped = %d; want 0", got)
	}
}

func TestOwnershipServiceMemberTierIsInert(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-member")
	seedService(t, db, ctx, "svc-fb")
	seedCertMeta(t, db, ctx, "anchorix", "cert-sm", "CN=a.example", "CN=ca", []string{"a.example"})
	// A reserved service_member rule (ordinal 2, outranks fallback) +
	// a fallback. The CHECK constraint permits the value, but the
	// engine must treat it as inert: the fallback must win.
	seedOwnershipRule(t, db, ctx, "rule-sm", "svc-member", governance.PrecedenceServiceMember, governance.MatchFallback, "", 1)
	seedOwnershipRule(t, db, ctx, "rule-sm-fb", "svc-fb", governance.PrecedenceFallback, governance.MatchFallback, "", 1000)
	svc := ownershipService(t, db, 0)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	co, err := postgres.NewOwnershipRepository(db).GetCertificateOwnership(ctx, "anchorix", "cert-sm")
	if err != nil {
		t.Fatalf("get ownership: %v", err)
	}
	if co.ServiceID == nil || *co.ServiceID != "svc-fb" {
		t.Fatalf("service_member rule must be inert; owner = %+v, want svc-fb", co)
	}
	if co.WinningRuleID == nil || *co.WinningRuleID != "rule-sm-fb" {
		t.Fatalf("winner = %v; want rule-sm-fb (service_member skipped)", co.WinningRuleID)
	}
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

func TestOwnershipExpiredOverrideAutoCleared(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-exp-rule")
	seedService(t, db, ctx, "svc-exp-pin")
	seedCertMeta(t, db, ctx, "anchorix", "cert-exp", "CN=a.example", "CN=ca", []string{"a.example"})
	seedOwnershipRule(t, db, ctx, "rule-exp", "svc-exp-rule", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)
	repo := postgres.NewOwnershipRepository(db)
	past := time.Now().UTC().Add(-time.Hour)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-exp", OrganizationID: "anchorix", CertificateID: "cert-exp", ServiceID: "svc-exp-pin",
		Reason: "pin", SetBy: "op", SetAt: time.Now().UTC().Add(-2 * time.Hour), ExpiresAt: &past,
	}); err != nil {
		t.Fatalf("create override: %v", err)
	}
	svc := ownershipService(t, db, 0)

	res, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	if res.ExpiredOverrides != 1 {
		t.Fatalf("expired overrides = %d; want 1", res.ExpiredOverrides)
	}
	// The override row is now cleared (slot freed).
	if got, _ := repo.GetActiveOwnershipOverride(ctx, "anchorix", "cert-exp"); got != nil {
		t.Fatalf("expired override still active: %+v", got)
	}
	cleared, err := repo.GetOwnershipOverride(ctx, "anchorix", "ovr-exp")
	if err != nil {
		t.Fatalf("get override: %v", err)
	}
	if cleared.ClearedAt == nil || cleared.ClearedBy == nil || *cleared.ClearedBy != "system" {
		t.Fatalf("override not auto-cleared by system: %+v", cleared)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.override_expired"); n != 1 {
		t.Fatalf("override_expired audit = %d; want 1", n)
	}
	// Decision re-derived from the rule (override gone).
	co, _ := repo.GetCertificateOwnership(ctx, "anchorix", "cert-exp")
	if co.Decision != governance.DecisionMatched || co.ServiceID == nil || *co.ServiceID != "svc-exp-rule" {
		t.Fatalf("cert should re-derive to the rule's service: %+v", co)
	}
	// The freed slot accepts a replacement override (no conflict).
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-exp-2", OrganizationID: "anchorix", CertificateID: "cert-exp", ServiceID: "svc-exp-pin",
		Reason: "re-pin", SetBy: "op", SetAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("replacement override should be creatable after auto-clear: %v", err)
	}
}

func TestOwnershipFirstAssignedAtResetOnFirstOwnership(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-fa")
	seedCertMeta(t, db, ctx, "anchorix", "cert-fa", "CN=a.example", "CN=ca", []string{"a.example"})
	svc := ownershipService(t, db, 0)
	repo := postgres.NewOwnershipRepository(db)

	// Pass 1: no rules → unowned. first_assigned_at = materialization.
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("run1: %v", err)
	}
	co1, _ := repo.GetCertificateOwnership(ctx, "anchorix", "cert-fa")
	unownedAt := co1.FirstAssignedAt

	time.Sleep(10 * time.Millisecond)
	// Pass 2: add a rule → cert becomes owned for the FIRST time.
	seedOwnershipRule(t, db, ctx, "rule-fa", "svc-fa", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("run2: %v", err)
	}
	co2, _ := repo.GetCertificateOwnership(ctx, "anchorix", "cert-fa")
	if co2.ServiceID == nil {
		t.Fatalf("cert not owned after rule added: %+v", co2)
	}
	if !co2.FirstAssignedAt.After(unownedAt) {
		t.Fatalf("first_assigned_at not reset on first ownership: unowned=%s owned=%s", unownedAt, co2.FirstAssignedAt)
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

// TestOwnershipMergeHandlesNewCertInterleavedAmongOwned exercises the
// merge's interleaved-pairing path: pass 2 sees signals for {1,2,3,4,5}
// but prior ownership only for {1,3,5}, so 1/3/5 must pair with their
// prior rows via the `ownCur == sig` exact match and 2/4 must be
// treated as new (no prior) without disturbing the alignment. This
// test does NOT hit the `ownCur < sig` skip-loop (every ownership
// cert here has a matching signal, so ownCur is never strictly less
// than sig). Skip-loop coverage lives in
// TestOwnershipMergeSkipLoopHandlesOrphanOwnershipRows.
func TestOwnershipMergeHandlesNewCertInterleavedAmongOwned(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-merge")
	seedOwnershipRule(t, db, ctx, "rule-merge-fb", "svc-merge", governance.PrecedenceFallback, governance.MatchFallback, "", 1)
	svc := ownershipService(t, db, 0)
	svc.SetPageSizeForTest(2) // force multi-page walks on both streams

	// Phase 1: only the odd certs exist → owned after pass 1.
	for _, n := range []string{"1", "3", "5"} {
		seedCertMeta(t, db, ctx, "anchorix", "cert-merge-"+n, "CN=x", "CN=ca", nil)
	}
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("pass1: %v", err)
	}

	// Phase 2: add the even certs whose ids sort BETWEEN the owned
	// ones. They have no prior ownership row; the owned ones do.
	for _, n := range []string{"2", "4"} {
		seedCertMeta(t, db, ctx, "anchorix", "cert-merge-"+n, "CN=x", "CN=ca", nil)
	}
	res, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("pass2: %v", err)
	}
	if res.EvaluatedCertificates != 5 {
		t.Fatalf("evaluated = %d; want 5 (no cert skipped/duplicated)", res.EvaluatedCertificates)
	}
	if res.BecameOwned != 2 {
		t.Fatalf("becameOwned = %d; want 2 (certs 2 and 4)", res.BecameOwned)
	}
	if res.UnchangedCertificates != 3 {
		t.Fatalf("unchanged = %d; want 3 (certs 1,3,5 paired with prior — not re-assigned)", res.UnchangedCertificates)
	}
	if res.ChangedCertificates != 2 {
		t.Fatalf("changed = %d; want 2", res.ChangedCertificates)
	}
	// Every cert owned exactly once.
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix'`); got != 5 {
		t.Fatalf("ownership rows = %d; want 5", got)
	}
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix' AND service_id='svc-merge'`); got != 5 {
		t.Fatalf("owned-by-svc-merge rows = %d; want 5", got)
	}
}

// TestOwnershipMergeSkipLoopHandlesOrphanOwnershipRows exercises the
// `for ownHas && ownCur.CertificateID < sig.CertificateID` skip-loop
// in streamAndDecide — the defensive path where an ownership row has
// no matching signal and must be skipped without consuming a signal
// or wrongly pairing it with a later one.
//
// To make the skip-loop reachable we have to inject orphan ownership
// rows, which the (ON DELETE CASCADE) FK normally prevents. We delete
// the parent cert rows inside one transaction with
// SET LOCAL session_replication_role = 'replica', which makes
// PostgreSQL bypass FK-cascade triggers (and the LOCAL scope reverts
// the role on commit so the connection returns to the pool clean).
// The orphans (certificate_ownership + ownership_match_explanations
// rows whose cert is gone) survive until the next test's
// freshDatabase truncates them.
//
// Two services + a SAN rule per service make mis-pairing detectable:
// if a buggy merge paired sig=cert-orph-2 (svc-even) with the orphan
// prior for cert-orph-1 (svc-odd), the diff would report a flip;
// correctly skipping the orphan yields all-unchanged.
func TestOwnershipMergeSkipLoopHandlesOrphanOwnershipRows(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-odd")
	seedService(t, db, ctx, "svc-even")
	seedCertMeta(t, db, ctx, "anchorix", "cert-orph-1", "CN=x", "CN=ca", []string{"h1.odd.x"})
	seedCertMeta(t, db, ctx, "anchorix", "cert-orph-2", "CN=x", "CN=ca", []string{"h2.even.x"})
	seedCertMeta(t, db, ctx, "anchorix", "cert-orph-3", "CN=x", "CN=ca", []string{"h3.odd.x"})
	seedCertMeta(t, db, ctx, "anchorix", "cert-orph-4", "CN=x", "CN=ca", []string{"h4.even.x"})
	seedCertMeta(t, db, ctx, "anchorix", "cert-orph-5", "CN=x", "CN=ca", []string{"h5.even.x"})
	seedOwnershipRule(t, db, ctx, "rule-orph-odd", "svc-odd", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.odd.x", 100)
	seedOwnershipRule(t, db, ctx, "rule-orph-even", "svc-even", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.even.x", 100)
	svc := ownershipService(t, db, 0)
	svc.SetPageSizeForTest(2)
	repo := postgres.NewOwnershipRepository(db)

	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("pass1: %v", err)
	}

	// Bypass FK cascade so DELETE cert leaves the ownership row
	// behind as an orphan. SET LOCAL is tx-scoped.
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = 'replica'"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`DELETE FROM certificates WHERE organization_id='anchorix' AND id = ANY($1)`,
			[]string{"cert-orph-1", "cert-orph-3"})
		return err
	}); err != nil {
		t.Fatalf("orphan delete: %v", err)
	}
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificates WHERE organization_id='anchorix'`); got != 3 {
		t.Fatalf("live certs = %d; want 3", got)
	}
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix'`); got != 5 {
		t.Fatalf("ownership rows = %d; want 5 (2 orphans + 3 live)", got)
	}

	// Pass 2: signals = {2,4,5}; ownership stream = {1,2,3,4,5}.
	// The merge MUST advance ownCur=1 past sig=2 (skip-loop), pair
	// sig=2 with its own prior, then advance ownCur=3 past sig=4
	// (skip-loop again), pair sig=4 and sig=5 with their own priors.
	res, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("pass2: %v", err)
	}
	if res.EvaluatedCertificates != 3 {
		t.Fatalf("evaluated = %d; want 3 (orphan ownership rows must not become signals)", res.EvaluatedCertificates)
	}
	if res.UnchangedCertificates != 3 || res.ChangedCertificates != 0 || res.FlippedOwner != 0 {
		t.Fatalf("res = %+v; want unchanged=3 changed=0 flipped=0 — a non-zero flip count would indicate the skip-loop mis-paired a live signal with an orphan prior", res)
	}
	for _, c := range []struct{ id, svc string }{
		{"cert-orph-2", "svc-even"}, {"cert-orph-4", "svc-even"}, {"cert-orph-5", "svc-even"},
	} {
		co, err := repo.GetCertificateOwnership(ctx, "anchorix", c.id)
		if err != nil {
			t.Fatalf("get ownership %s: %v", c.id, err)
		}
		if co.ServiceID == nil || *co.ServiceID != c.svc {
			t.Fatalf("%s owner = %v; want %s", c.id, co.ServiceID, c.svc)
		}
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

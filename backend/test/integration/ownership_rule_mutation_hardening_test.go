//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// ownershipServiceWithFailingAudit builds an ownership.Service whose
// audit recorder fails on the given action, against the real
// postgres.DB transactor — so a forced audit failure exercises the
// genuine rollback path (the service unit fakes cannot).
func ownershipServiceWithFailingAudit(t *testing.T, db *postgres.DB, failOn string) *ownership.Service {
	t.Helper()
	failing := &failingAuditRecorder{delegate: postgres.NewAuditRecorder(db, clock.System{}), failOn: failOn}
	repo := &governance.Repo{
		Ownership:     postgres.NewOwnershipRepository(db),
		Policy:        postgres.NewPolicyRepository(db),
		RecomputeRuns: postgres.NewGovernanceRecomputeRunsRepository(db),
	}
	svc, err := ownership.NewService(repo, db, failing, clock.System{},
		postgres.NewOwnershipRuleTargetResolver(db), ownership.ServiceConfig{})
	if err != nil {
		t.Fatalf("ownership.NewService: %v", err)
	}
	return svc
}

func seedRuleDirect(t *testing.T, db *postgres.DB, ctx context.Context, org, id, name, serviceID, kind, value string, priority int) {
	t.Helper()
	tier := map[string]string{
		"fallback": "fallback", "san_glob": "san_pattern", "san_regex": "san_pattern",
		"subject_cn_glob": "subject_pattern", "agent_group": "agent_group",
		"issuer_dn": "issuer_store", "store_location": "issuer_store", "tag": "tag",
	}[kind]
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO ownership_rules (id, organization_id, name, service_id, precedence_tier, priority, match_kind, match_value, created_by)
		   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'op')`,
		[]any{id, org, name, serviceID, tier, priority, kind, value},
	}); err != nil {
		t.Fatalf("seed rule %s: %v", id, err)
	}
}

func ruleColumnString(t *testing.T, db *postgres.DB, ctx context.Context, ruleID, column string) string {
	t.Helper()
	var v string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT "+column+"::text FROM ownership_rules WHERE id=$1", ruleID).Scan(&v)
	}); err != nil {
		t.Fatalf("read rule %s.%s: %v", ruleID, column, err)
	}
	return v
}

// --- PATCH explicit-zero semantics ----------------------------------

// TestOwnershipRulePatchExplicitZeroVsOmitted pins that an explicit
// priority:0 is honored (distinct from omitted) and that omitting
// priority on a subsequent PATCH preserves the explicit 0 — i.e. the
// pointer-merge correctly round-trips the zero value.
func TestOwnershipRulePatchExplicitZeroVsOmitted(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-zero")

	_, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"zero-rule","service_id":"svc-zero","match_kind":"san_glob","match_value":"*.z.example","priority":42}`)
	ruleID := ruleIDFromBody(t, body)

	// Explicit priority:0 → applied.
	if status, b := httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+ruleID, `{"priority":0}`); status != http.StatusOK {
		t.Fatalf("explicit priority=0 status=%d body=%s; want 200", status, b)
	}
	if got := ruleColumnString(t, db, ctx, ruleID, "priority"); got != "0" {
		t.Fatalf("priority after explicit 0 = %s; want 0", got)
	}
	// Now a description-only PATCH must PRESERVE the explicit 0 (not
	// reset to the stored value via some default).
	if status, _ := httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+ruleID, `{"description":"d"}`); status != http.StatusOK {
		t.Fatalf("description-only PATCH after zero: want 200")
	}
	if got := ruleColumnString(t, db, ctx, ruleID, "priority"); got != "0" {
		t.Fatalf("priority after description-only PATCH = %s; want preserved 0", got)
	}
	if got := ruleColumnString(t, db, ctx, ruleID, "match_value"); got != "*.z.example" {
		t.Fatalf("match_value drifted: %s", got)
	}
	// Empty-body PATCH ({}) is a no-op merge: everything preserved.
	if status, _ := httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+ruleID, `{}`); status != http.StatusOK {
		t.Fatalf("empty-body PATCH: want 200")
	}
	if got := ruleColumnString(t, db, ctx, ruleID, "priority"); got != "0" {
		t.Fatalf("priority after empty PATCH = %s; want 0", got)
	}
}

// --- disabled-target rejection --------------------------------------

// TestOwnershipRuleRejectsDisabledTargets pins that a rule cannot be
// created against a disabled service or a disabled agent group — the
// resolver's `disabled_at IS NULL` predicate treats a soft-deleted
// target as nonexistent.
func TestOwnershipRuleRejectsDisabledTargets(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)

	// Disabled service.
	seedService(t, db, ctx, "svc-disabled")
	if err := execRawSQL(ctx, db, rawStmt{`UPDATE services SET disabled_at = now() WHERE id='svc-disabled'`, nil}); err != nil {
		t.Fatalf("disable service: %v", err)
	}
	status, sbody := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"r-disabled-svc","service_id":"svc-disabled","match_kind":"fallback","priority":1}`)
	if status != http.StatusBadRequest || !strings.Contains(string(sbody), "ownership_rule_service_not_found") {
		t.Fatalf("disabled-service create status=%d body=%s; want 400 service_not_found", status, sbody)
	}

	// Disabled agent group (with an active service so only the group is bad).
	seedService(t, db, ctx, "svc-ok")
	seedAgentGroupOnly(t, db, ctx, "anchorix", "grp-disabled")
	if err := execRawSQL(ctx, db, rawStmt{`UPDATE agent_groups SET disabled_at = now() WHERE id='grp-disabled'`, nil}); err != nil {
		t.Fatalf("disable group: %v", err)
	}
	status, gbody := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"r-disabled-grp","service_id":"svc-ok","match_kind":"agent_group","match_value":"grp-disabled","priority":1}`)
	if status != http.StatusBadRequest || !strings.Contains(string(gbody), "ownership_rule_target_not_found") {
		t.Fatalf("disabled-group create status=%d body=%s; want 400 target_not_found", status, gbody)
	}
	// Nothing persisted; no audit.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_rules WHERE organization_id='anchorix'`); n != 0 {
		t.Fatalf("ownership_rules = %d; want 0", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_created"); n != 0 {
		t.Fatalf("rule_created audit = %d; want 0", n)
	}
}

// TestOwnershipRuleUpdateRejectsDisabledAgentGroup pins that updating
// an agent_group rule's match_value to a disabled group is rejected,
// and the stored value is unchanged.
func TestOwnershipRuleUpdateRejectsDisabledAgentGroup(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-aup")
	seedAgentGroupOnly(t, db, ctx, "anchorix", "grp-live")
	seedAgentGroupOnly(t, db, ctx, "anchorix", "grp-dead")
	if err := execRawSQL(ctx, db, rawStmt{`UPDATE agent_groups SET disabled_at = now() WHERE id='grp-dead'`, nil}); err != nil {
		t.Fatalf("disable group: %v", err)
	}
	_, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"ag-rule","service_id":"svc-aup","match_kind":"agent_group","match_value":"grp-live","priority":1}`)
	ruleID := ruleIDFromBody(t, body)

	status, ubody := httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+ruleID,
		`{"match_value":"grp-dead"}`)
	if status != http.StatusBadRequest || !strings.Contains(string(ubody), "ownership_rule_target_not_found") {
		t.Fatalf("update-to-disabled-group status=%d body=%s; want 400 target_not_found", status, ubody)
	}
	if got := ruleColumnString(t, db, ctx, ruleID, "match_value"); got != "grp-live" {
		t.Fatalf("match_value mutated despite rejected update: %s", got)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_updated"); n != 0 {
		t.Fatalf("rule_updated audit = %d; want 0 (rejected update must not audit)", n)
	}
}

// --- audit rollback on every mutation -------------------------------

// TestOwnershipRuleMutationAuditRollback proves the binding atomicity
// claim across ALL four mutations: a forced audit failure rolls back
// the state change at the postgres layer — no state change, no audit
// row. PR-1 only had a create-path rollback test; this covers
// update / enable / disable too.
func TestOwnershipRuleMutationAuditRollback(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-rb")

	t.Run("update rolls back", func(t *testing.T) {
		seedRuleDirect(t, db, ctx, "anchorix", "rule-rb-upd", "rb-upd", "svc-rb", "san_glob", "*.orig.example", 10)
		svc := ownershipServiceWithFailingAudit(t, db, "ownership.rule_updated")
		nv := "*.changed.example"
		np := 99
		_, err := svc.UpdateRule(ctx, ownership.UpdateRuleInput{
			OrganizationID: "anchorix", ActorUserID: "op", RuleID: "rule-rb-upd",
			MatchValue: &nv, Priority: &np,
		})
		if err == nil {
			t.Fatalf("UpdateRule succeeded despite forced audit failure")
		}
		if got := ruleColumnString(t, db, ctx, "rule-rb-upd", "match_value"); got != "*.orig.example" {
			t.Fatalf("match_value persisted despite audit failure: %s", got)
		}
		if got := ruleColumnString(t, db, ctx, "rule-rb-upd", "priority"); got != "10" {
			t.Fatalf("priority persisted despite audit failure: %s", got)
		}
		if n := countRows(t, db, ctx, `SELECT count(*) FROM audit_events WHERE action='ownership.rule_updated'`); n != 0 {
			t.Fatalf("rule_updated audit written despite forced failure: %d", n)
		}
	})

	t.Run("disable rolls back", func(t *testing.T) {
		seedRuleDirect(t, db, ctx, "anchorix", "rule-rb-dis", "rb-dis", "svc-rb", "fallback", "", 1)
		svc := ownershipServiceWithFailingAudit(t, db, "ownership.rule_disabled")
		if _, err := svc.DisableRule(ctx, "anchorix", "op", "rule-rb-dis"); err == nil {
			t.Fatalf("DisableRule succeeded despite forced audit failure")
		}
		if got := ruleColumnString(t, db, ctx, "rule-rb-dis", "enabled"); got != "true" {
			t.Fatalf("rule disabled despite audit failure: enabled=%s", got)
		}
		if n := countRows(t, db, ctx, `SELECT count(*) FROM audit_events WHERE action='ownership.rule_disabled'`); n != 0 {
			t.Fatalf("rule_disabled audit written despite forced failure: %d", n)
		}
	})

	t.Run("enable rolls back", func(t *testing.T) {
		seedRuleDirect(t, db, ctx, "anchorix", "rule-rb-en", "rb-en", "svc-rb", "fallback", "", 1)
		if err := execRawSQL(ctx, db, rawStmt{`UPDATE ownership_rules SET enabled=false, disabled_at=now() WHERE id='rule-rb-en'`, nil}); err != nil {
			t.Fatalf("pre-disable: %v", err)
		}
		svc := ownershipServiceWithFailingAudit(t, db, "ownership.rule_enabled")
		if _, err := svc.EnableRule(ctx, "anchorix", "op", "rule-rb-en"); err == nil {
			t.Fatalf("EnableRule succeeded despite forced audit failure")
		}
		if got := ruleColumnString(t, db, ctx, "rule-rb-en", "enabled"); got != "false" {
			t.Fatalf("rule enabled despite audit failure: enabled=%s", got)
		}
		if n := countRows(t, db, ctx, `SELECT count(*) FROM audit_events WHERE action='ownership.rule_enabled'`); n != 0 {
			t.Fatalf("rule_enabled audit written despite forced failure: %d", n)
		}
	})
}

// --- exactly-once audit per successful mutation ----------------------

// TestOwnershipRuleExactlyOnceAuditPerMutation pins that each
// successful mutation writes exactly one audit row of the matching
// action and nothing else.
func TestOwnershipRuleExactlyOnceAuditPerMutation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-once")

	_, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"once-rule","service_id":"svc-once","match_kind":"san_glob","match_value":"*.o.example","priority":1}`)
	ruleID := ruleIDFromBody(t, body)
	httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+ruleID, `{"priority":2}`)
	httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules/"+ruleID+"/disable", "")
	httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules/"+ruleID+"/enable", "")

	for action, want := range map[string]int{
		"ownership.rule_created":  1,
		"ownership.rule_updated":  1,
		"ownership.rule_disabled": 1,
		"ownership.rule_enabled":  1,
	} {
		if n := auditCount(t, db, ctx, "anchorix", action); n != want {
			t.Fatalf("%s audit = %d; want %d", action, n, want)
		}
		if n := scalarInt(t, db, ctx,
			`SELECT count(*) FROM audit_events WHERE organization_id='anchorix' AND action=$1 AND metadata->>'severity'='security'`, action); n != want {
			t.Fatalf("%s security-severity audit = %d; want %d", action, n, want)
		}
	}
}

// --- duplicate conflict stability -----------------------------------

// TestOwnershipRuleDuplicateConflictStable pins that the (org,name)
// conflict is deterministic across repeated attempts and that a
// disabled rule still holds the name (no resurrection by re-create).
func TestOwnershipRuleDuplicateConflictStable(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-dupe")

	mk := `{"name":"dupe","service_id":"svc-dupe","match_kind":"fallback","priority":1}`
	if status, _ := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules", mk); status != http.StatusCreated {
		t.Fatalf("first create: want 201")
	}
	// Three more attempts → all deterministic 409 with the same code.
	for i := 0; i < 3; i++ {
		status, b := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules", mk)
		if status != http.StatusConflict || !strings.Contains(string(b), "ownership_rule_conflict") {
			t.Fatalf("attempt %d status=%d body=%s; want stable 409 ownership_rule_conflict", i, status, b)
		}
	}
	// Disable the original; the name is still taken → re-create still 409.
	var firstID string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM ownership_rules WHERE organization_id='anchorix' AND name='dupe'`).Scan(&firstID)
	}); err != nil {
		t.Fatalf("lookup id: %v", err)
	}
	if status, _ := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules/"+firstID+"/disable", ""); status != http.StatusOK {
		t.Fatalf("disable: want 200")
	}
	if status, b := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules", mk); status != http.StatusConflict {
		t.Fatalf("re-create after disable status=%d body=%s; want 409 (disabled rule keeps the name)", status, b)
	}
	// Exactly one create audited across all of this.
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_created"); n != 1 {
		t.Fatalf("rule_created audit = %d; want 1", n)
	}
}

// --- malformed JSON / unknown fields --------------------------------

// TestOwnershipRuleMalformedAndUnknownFields pins body-parsing
// behavior: malformed / trailing JSON → 400 bad_request with no
// mutation; unknown fields are ignored (additive-evolution
// convention) and the known fields still apply.
func TestOwnershipRuleMalformedAndUnknownFields(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-json")

	// Malformed bodies → 400, nothing created.
	for _, bad := range []string{
		`{`,                    // truncated
		`{"name":}`,            // invalid value
		`{"name":"x"} {"y":1}`, // trailing JSON
		`not json at all`,      // garbage
	} {
		status, b := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules", bad)
		if status != http.StatusBadRequest || !strings.Contains(string(b), "bad_request") {
			t.Fatalf("malformed body %q status=%d body=%s; want 400 bad_request", bad, status, b)
		}
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_rules WHERE organization_id='anchorix'`); n != 0 {
		t.Fatalf("ownership_rules = %d after malformed bodies; want 0", n)
	}

	// Unknown fields are ignored; the valid known fields create the rule.
	status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"with-extra","service_id":"svc-json","match_kind":"fallback","priority":1,"bogus_field":"ignored","another":42}`)
	if status != http.StatusCreated {
		t.Fatalf("unknown-fields create status=%d body=%s; want 201 (unknown fields ignored)", status, body)
	}
}

// --- deterministic error codes --------------------------------------

// TestOwnershipRuleDeterministicErrorCodes pins the exact envelope
// code for each rejection class, so the wire contract is stable.
func TestOwnershipRuleDeterministicErrorCodes(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-codes")

	cases := []struct {
		body       string
		wantStatus int
		wantCode   string
	}{
		{`{"name":"c1","service_id":"svc-codes","match_kind":"san_glob","precedence_tier":"service_member","match_value":"*.x","priority":1}`, 400, "ownership_rule_tier_reserved"},
		{`{"name":"c2","service_id":"svc-missing","match_kind":"fallback","priority":1}`, 400, "ownership_rule_service_not_found"},
		{`{"name":"c3","service_id":"svc-codes","match_kind":"agent_group","match_value":"grp-nope","priority":1}`, 400, "ownership_rule_target_not_found"},
		{`{"name":"c4","service_id":"svc-codes","match_kind":"san_regex","match_value":"[","priority":1}`, 400, "bad_request"},
		{`{"name":"c5","service_id":"svc-codes","match_kind":"bogus","priority":1}`, 400, "bad_request"},
	}
	for _, c := range cases {
		status, b := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules", c.body)
		if status != c.wantStatus || !strings.Contains(string(b), c.wantCode) {
			t.Fatalf("body=%s → status=%d code-want=%q; got body=%s", c.body, status, c.wantCode, b)
		}
	}
	// Unknown rule id on update/enable/disable → 404 not_found.
	for _, req := range []struct{ method, path, body string }{
		{http.MethodPatch, "/api/v1/ownership-rules/nope/", ""},
		{http.MethodPatch, "/api/v1/ownership-rules/nope", `{"priority":1}`},
		{http.MethodPost, "/api/v1/ownership-rules/nope/enable", ""},
		{http.MethodPost, "/api/v1/ownership-rules/nope/disable", ""},
	} {
		if req.path == "/api/v1/ownership-rules/nope/" {
			continue // skip trailing-slash variant; not a registered route
		}
		status, b := httpJSONWithBody(t, client, req.method, srvURL+req.path, req.body)
		if status != http.StatusNotFound || !strings.Contains(string(b), "not_found") {
			t.Fatalf("%s %s status=%d body=%s; want 404 not_found", req.method, req.path, status, b)
		}
	}
}

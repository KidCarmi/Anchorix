//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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

// httpJSONWithBody issues a method+body request and returns
// (status, raw body). Used by the rule-mutation tests which POST/PATCH
// JSON payloads (the shared httpPostJSON sends no body).
func httpJSONWithBody(t *testing.T, client *http.Client, method, url, jsonBody string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader([]byte(jsonBody)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// seedAgentGroupOnly inserts an active agent_group row (no membership).
func seedAgentGroupOnly(t *testing.T, db *postgres.DB, ctx context.Context, orgID, groupID string) {
	t.Helper()
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO agent_groups (id, organization_id, slug, display_name)
		   VALUES ($1, $2, $1, 'grp') ON CONFLICT (organization_id, id) DO NOTHING`,
		[]any{groupID, orgID},
	}); err != nil {
		t.Fatalf("seed agent group %s: %v", groupID, err)
	}
}

func ruleIDFromBody(t *testing.T, body []byte) string {
	t.Helper()
	var row struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &row); err != nil {
		t.Fatalf("decode rule body: %v; body=%s", err, body)
	}
	return row.ID
}

func TestOwnershipRuleCreateHappyPathAndAudit(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-create")

	status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"billing-san","service_id":"svc-create","match_kind":"san_glob","match_value":"*.billing.example","priority":100}`)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d body=%s; want 201", status, body)
	}
	var row struct {
		ID             string `json:"id"`
		PrecedenceTier string `json:"precedence_tier"`
		Enabled        bool   `json:"enabled"`
		CreatedBy      string `json:"created_by"`
	}
	if err := json.Unmarshal(body, &row); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Tier was derived from match_kind.
	if row.PrecedenceTier != "san_pattern" {
		t.Fatalf("precedence_tier = %q; want san_pattern (derived)", row.PrecedenceTier)
	}
	if !row.Enabled {
		t.Fatalf("new rule should be enabled")
	}
	// Exactly one severity:"security" audit row for the create.
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_created"); n != 1 {
		t.Fatalf("ownership.rule_created = %d; want 1", n)
	}
	if n := scalarInt(t, db, ctx,
		`SELECT count(*) FROM audit_events WHERE organization_id='anchorix' AND action='ownership.rule_created' AND metadata->>'severity'='security'`); n != 1 {
		t.Fatalf("security-severity rule_created rows = %d; want 1", n)
	}
}

func TestOwnershipRuleCreateValidationRejections(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-val")

	cases := []struct {
		name     string
		body     string
		wantCode string // error envelope code
	}{
		{
			"service_member tier rejected",
			`{"name":"r1","service_id":"svc-val","match_kind":"san_glob","precedence_tier":"service_member","match_value":"*.x","priority":1}`,
			"ownership_rule_tier_reserved",
		},
		{
			"invalid regex rejected",
			`{"name":"r2","service_id":"svc-val","match_kind":"san_regex","match_value":"[","priority":1}`,
			"bad_request",
		},
		{
			"excessive regex rejected",
			`{"name":"r3","service_id":"svc-val","match_kind":"san_regex","match_value":"` + strings.Repeat("a", 2000) + `","priority":1}`,
			"bad_request",
		},
		{
			"nonexistent service rejected",
			`{"name":"r4","service_id":"svc-missing","match_kind":"san_glob","match_value":"*.x","priority":1}`,
			"ownership_rule_service_not_found",
		},
		{
			"nonexistent agent group rejected",
			`{"name":"r5","service_id":"svc-val","match_kind":"agent_group","match_value":"grp-missing","priority":1}`,
			"ownership_rule_target_not_found",
		},
		{
			"unknown match_kind rejected",
			`{"name":"r6","service_id":"svc-val","match_kind":"bogus","match_value":"x","priority":1}`,
			"bad_request",
		},
		{
			"tier/kind mismatch rejected",
			`{"name":"r7","service_id":"svc-val","match_kind":"san_glob","precedence_tier":"tag","match_value":"*.x","priority":1}`,
			"bad_request",
		},
		{
			"empty name rejected",
			`{"name":"","service_id":"svc-val","match_kind":"san_glob","match_value":"*.x","priority":1}`,
			"bad_request",
		},
		{
			"fallback with value rejected",
			`{"name":"r8","service_id":"svc-val","match_kind":"fallback","match_value":"x","priority":1}`,
			"bad_request",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules", c.body)
			if status != http.StatusBadRequest && status != http.StatusConflict {
				t.Fatalf("status=%d body=%s; want 4xx", status, body)
			}
			if !strings.Contains(string(body), c.wantCode) {
				t.Fatalf("body=%s; want error code %q", body, c.wantCode)
			}
		})
	}
	// No rule should have been created, and no rule_created audit emitted.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_rules WHERE organization_id='anchorix'`); n != 0 {
		t.Fatalf("ownership_rules = %d; want 0 (all creates rejected)", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_created"); n != 0 {
		t.Fatalf("ownership.rule_created = %d; want 0 (no audit on failed mutation)", n)
	}
}

func TestOwnershipRuleCreateAgentGroupTargetAccepted(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-ag")
	seedAgentGroupOnly(t, db, ctx, "anchorix", "grp-web")

	status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"web-by-group","service_id":"svc-ag","match_kind":"agent_group","match_value":"grp-web","priority":50}`)
	if status != http.StatusCreated {
		t.Fatalf("agent_group rule create status=%d body=%s; want 201", status, body)
	}
}

func TestOwnershipRuleDuplicateConflict(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-dup")

	mk := `{"name":"dup-name","service_id":"svc-dup","match_kind":"fallback","priority":1}`
	if status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules", mk); status != http.StatusCreated {
		t.Fatalf("first create status=%d body=%s; want 201", status, body)
	}
	status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules", mk)
	if status != http.StatusConflict {
		t.Fatalf("duplicate create status=%d body=%s; want 409", status, body)
	}
	if !strings.Contains(string(body), "ownership_rule_conflict") {
		t.Fatalf("duplicate body=%s; want ownership_rule_conflict", body)
	}
	// Exactly one create audited (the conflict emitted none).
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_created"); n != 1 {
		t.Fatalf("ownership.rule_created = %d; want 1 (conflict must not audit)", n)
	}
}

func TestOwnershipRuleUpdateLifecycle(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-upd")

	_, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"upd-rule","service_id":"svc-upd","match_kind":"san_glob","match_value":"*.a.example","priority":100}`)
	ruleID := ruleIDFromBody(t, body)

	// PATCH mutable fields.
	status, ubody := httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+ruleID,
		`{"description":"tighter","match_value":"*.b.example","priority":50}`)
	if status != http.StatusOK {
		t.Fatalf("update status=%d body=%s; want 200", status, ubody)
	}
	var row struct {
		MatchValue  string `json:"match_value"`
		Priority    int    `json:"priority"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(ubody, &row); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	if row.MatchValue != "*.b.example" || row.Priority != 50 || row.Description != "tighter" {
		t.Fatalf("update did not stick: %+v", row)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_updated"); n != 1 {
		t.Fatalf("ownership.rule_updated = %d; want 1", n)
	}

	// Invalid update (bad regex against the rule's kind) is rejected;
	// PATCH a san_regex rule for that. First create one.
	_, rbody := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"rx-rule","service_id":"svc-upd","match_kind":"san_regex","match_value":"^ok$","priority":1}`)
	rxID := ruleIDFromBody(t, rbody)
	if status, _ := httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+rxID,
		`{"match_value":"[","priority":1}`); status != http.StatusBadRequest {
		t.Fatalf("invalid-regex update status=%d; want 400", status)
	}
}

// TestOwnershipRulePatchPreservesOmittedFields pins PATCH-merge
// semantics: a partial body updates only the supplied fields and
// preserves the stored values of omitted ones. Without merge,
// {"description":...} would send match_value="" + priority=0,
// rejecting the (non-fallback) rule and zeroing its priority.
func TestOwnershipRulePatchPreservesOmittedFields(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-patch")

	_, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"patch-rule","service_id":"svc-patch","match_kind":"san_glob","match_value":"*.keep.example","priority":77}`)
	ruleID := ruleIDFromBody(t, body)

	// PATCH only description: match_value + priority must survive.
	status, ubody := httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+ruleID,
		`{"description":"desc only"}`)
	if status != http.StatusOK {
		t.Fatalf("description-only PATCH status=%d body=%s; want 200", status, ubody)
	}
	var row struct {
		Description string `json:"description"`
		MatchValue  string `json:"match_value"`
		Priority    int    `json:"priority"`
	}
	if err := json.Unmarshal(ubody, &row); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if row.Description != "desc only" {
		t.Fatalf("description = %q; want updated", row.Description)
	}
	if row.MatchValue != "*.keep.example" {
		t.Fatalf("match_value = %q; want preserved *.keep.example (omitted field must not blank)", row.MatchValue)
	}
	if row.Priority != 77 {
		t.Fatalf("priority = %d; want preserved 77 (omitted field must not reset to 0)", row.Priority)
	}

	// PATCH only priority: description + match_value must survive.
	status, pbody := httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+ruleID,
		`{"priority":5}`)
	if status != http.StatusOK {
		t.Fatalf("priority-only PATCH status=%d body=%s; want 200", status, pbody)
	}
	json.Unmarshal(pbody, &row)
	if row.Priority != 5 || row.MatchValue != "*.keep.example" || row.Description != "desc only" {
		t.Fatalf("priority-only PATCH did not merge correctly: %+v", row)
	}

	// Explicit priority:0 IS honored (distinct from omitted).
	status, zbody := httpJSONWithBody(t, client, http.MethodPatch, srvURL+"/api/v1/ownership-rules/"+ruleID,
		`{"priority":0}`)
	if status != http.StatusOK {
		t.Fatalf("priority=0 PATCH status=%d; want 200", status)
	}
	json.Unmarshal(zbody, &row)
	if row.Priority != 0 {
		t.Fatalf("explicit priority=0 not honored: priority=%d", row.Priority)
	}
}

func TestOwnershipRuleEnableDisableLifecycle(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-ed")

	_, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"ed-rule","service_id":"svc-ed","match_kind":"fallback","priority":1}`)
	ruleID := ruleIDFromBody(t, body)

	// Disable.
	status, dbody := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules/"+ruleID+"/disable", "")
	if status != http.StatusOK {
		t.Fatalf("disable status=%d body=%s; want 200", status, dbody)
	}
	var drow struct {
		Enabled    bool    `json:"enabled"`
		DisabledAt *string `json:"disabled_at"`
	}
	json.Unmarshal(dbody, &drow)
	if drow.Enabled || drow.DisabledAt == nil {
		t.Fatalf("disable did not stick: %+v", drow)
	}
	// Re-enable.
	status, ebody := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules/"+ruleID+"/enable", "")
	if status != http.StatusOK {
		t.Fatalf("enable status=%d body=%s; want 200", status, ebody)
	}
	var erow struct {
		Enabled    bool    `json:"enabled"`
		DisabledAt *string `json:"disabled_at"`
	}
	json.Unmarshal(ebody, &erow)
	if !erow.Enabled || erow.DisabledAt != nil {
		t.Fatalf("enable did not clear flags: %+v", erow)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_disabled"); n != 1 {
		t.Fatalf("ownership.rule_disabled = %d; want 1", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.rule_enabled"); n != 1 {
		t.Fatalf("ownership.rule_enabled = %d; want 1", n)
	}
}

// TestOwnershipRuleMutationsCrossOrgIsolation pins that an operator in
// one org cannot create against another org's service, nor
// update/enable/disable another org's rule (→ 404).
func TestOwnershipRuleMutationsCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedOrganization(t, db, "other", "Other")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)

	// Seed a service + rule entirely in the FOREIGN org.
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO services (id, organization_id, slug, display_name) VALUES ('svc-foreign','other','svc-foreign','svc')`, nil,
	}); err != nil {
		t.Fatalf("seed foreign service: %v", err)
	}
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO ownership_rules (id, organization_id, name, service_id, precedence_tier, priority, match_kind, match_value, created_by)
		   VALUES ('rule-foreign','other','foreign-rule','svc-foreign','fallback',1,'fallback','','op')`, nil,
	}); err != nil {
		t.Fatalf("seed foreign rule: %v", err)
	}

	// Create against the foreign service → service-not-found (the
	// anchorix-scoped resolver does not see it).
	status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/ownership-rules",
		`{"name":"x","service_id":"svc-foreign","match_kind":"fallback","priority":1}`)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "ownership_rule_service_not_found") {
		t.Fatalf("cross-org create status=%d body=%s; want 400 service_not_found", status, body)
	}

	// Update / enable / disable the foreign rule → 404.
	for _, req := range []struct{ method, path, body string }{
		{http.MethodPatch, "/api/v1/ownership-rules/rule-foreign", `{"priority":2}`},
		{http.MethodPost, "/api/v1/ownership-rules/rule-foreign/enable", ""},
		{http.MethodPost, "/api/v1/ownership-rules/rule-foreign/disable", ""},
	} {
		status, body := httpJSONWithBody(t, client, req.method, srvURL+req.path, req.body)
		if status != http.StatusNotFound {
			t.Fatalf("%s %s cross-org status=%d body=%s; want 404", req.method, req.path, status, body)
		}
	}
	// The foreign rule is untouched.
	var prio int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT priority FROM ownership_rules WHERE id='rule-foreign'`).Scan(&prio)
	}); err != nil {
		t.Fatalf("read foreign rule: %v", err)
	}
	if prio != 1 {
		t.Fatalf("foreign rule mutated cross-org: priority=%d; want 1", prio)
	}
	// No audit rows leaked into the foreign org from anchorix actions.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='other' AND action LIKE 'ownership.rule_%'`); n != 0 {
		t.Fatalf("foreign-org rule audit rows = %d; want 0", n)
	}
}

// TestOwnershipRuleCreateAuditRollback proves the binding atomicity
// claim (CLAUDE.md §9): when the ownership.rule_created audit row
// fails to write, the ownership_rules INSERT in the same transaction
// is rolled back at the postgres layer — no rule row, no audit row.
// Uses the real postgres.DB.WithTx transactor (the service unit-level
// fakes cannot prove the actual rollback).
func TestOwnershipRuleCreateAuditRollback(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-rollback")

	failing := &failingAuditRecorder{delegate: postgres.NewAuditRecorder(db, clock.System{}), failOn: "ownership.rule_created"}
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

	_, err = svc.CreateRule(ctx, ownership.CreateRuleInput{
		OrganizationID: "anchorix",
		ActorUserID:    "operator-1",
		Name:           "rollback-rule",
		ServiceID:      "svc-rollback",
		MatchKind:      governance.MatchFallback,
		Priority:       1,
	})
	if err == nil {
		t.Fatalf("CreateRule succeeded despite forced audit failure")
	}
	// The injected failure is not one of the typed validation
	// sentinels — it must surface as an error, and nothing persists.
	if errors.Is(err, ownership.ErrInvalidRule) {
		t.Fatalf("err = %v; want a non-validation (audit) failure", err)
	}
	if n := countRows(t, db, ctx, `SELECT COUNT(*) FROM ownership_rules WHERE organization_id='anchorix' AND name='rollback-rule'`); n != 0 {
		t.Fatalf("rule row leaked despite audit failure: count=%d", n)
	}
	if n := countRows(t, db, ctx, `SELECT COUNT(*) FROM audit_events WHERE action='ownership.rule_created'`); n != 0 {
		t.Fatalf("audit row written despite forced failure: count=%d", n)
	}
}

// TestOwnershipRuleMutationAuthRequired pins anonymous → 401 and
// gate-off → 404 for the mutation routes.
func TestOwnershipRuleMutationAuthRequired(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServerWithOptions(t, db, testServerOpts{IdentityEnabled: true, OwnershipEnabled: true})
	anon := &http.Client{Timeout: 5 * time.Second}
	for _, req := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/ownership-rules"},
		{http.MethodPatch, "/api/v1/ownership-rules/any"},
		{http.MethodPost, "/api/v1/ownership-rules/any/enable"},
		{http.MethodPost, "/api/v1/ownership-rules/any/disable"},
	} {
		if status, _ := httpJSONWithBody(t, anon, req.method, srv.URL+req.path, "{}"); status != http.StatusUnauthorized {
			t.Fatalf("anonymous %s %s status=%d; want 401", req.method, req.path, status)
		}
	}

	// Gate off: routes absent → 404 even when authenticated.
	srv2, svc2 := testServerWithOptions(t, db, testServerOpts{IdentityEnabled: true, OwnershipEnabled: false})
	authed := signInAdmin(t, stringerURL{srv2.URL}, svc2)
	if status, _ := httpJSONWithBody(t, authed, http.MethodPost, srv2.URL+"/api/v1/ownership-rules", "{}"); status != http.StatusNotFound {
		t.Fatalf("gate-off POST status=%d; want 404", status)
	}
}

//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// TestDuplicateCreateReturnsConflict pins that every Create*
// endpoint surfaces a unique-constraint violation as 409
// already_exists, never as a raw 500. The H-026A2 review
// noted this: before the fix, duplicate slugs / keys /
// assignment pairs flowed through to the generic 500
// internal_error envelope, which hides a routine operator
// misstep behind a server-fault code.
func TestDuplicateCreateReturnsConflict(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// tags: (org, key, value) unique.
	var tag1 identityTag
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags",
		map[string]any{"key": "env", "value": "prod"}, http.StatusCreated, &tag1)
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags",
		map[string]any{"key": "env", "value": "prod"}, http.StatusConflict, nil)

	// services: (org, slug) unique.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/services",
		map[string]any{"slug": "billing", "display_name": "Billing"},
		http.StatusCreated, nil)
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/services",
		map[string]any{"slug": "billing", "display_name": "Billing v2"},
		http.StatusConflict, nil)

	// service_groups: (org, slug) unique.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups",
		map[string]any{"slug": "payments", "display_name": "Payments"},
		http.StatusCreated, nil)
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups",
		map[string]any{"slug": "payments", "display_name": "Payments v2"},
		http.StatusConflict, nil)

	// agent_groups: (org, slug) unique.
	var ag identityAgentGroup
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/agent-groups",
		map[string]any{"slug": "dc", "display_name": "DC"},
		http.StatusCreated, &ag)
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/agent-groups",
		map[string]any{"slug": "dc", "display_name": "DC v2"},
		http.StatusConflict, nil)

	// tag_assignments: (org, tag, target_type, target_id) unique.
	seedCertificate(t, db, ctxOf(t), "cert-dup-1")
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags/"+tag1.ID+"/assignments",
		map[string]any{"target_type": "certificate", "target_id": "cert-dup-1"},
		http.StatusCreated, nil)
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags/"+tag1.ID+"/assignments",
		map[string]any{"target_type": "certificate", "target_id": "cert-dup-1"},
		http.StatusConflict, nil)

	// agent_group memberships: (org, agent, group) unique.
	if err := execRawSQL(ctxOf(t), db, rawStmt{
		`INSERT INTO agents (id, organization_id, hostname, status, public_key_fingerprint)
		 VALUES ('agent-dup-1', 'anchorix', 'h', 'active', 'fp-dup-1')`, nil,
	}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/agent-groups/"+ag.ID+"/members",
		map[string]any{"agent_id": "agent-dup-1"}, http.StatusNoContent, nil)
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/agent-groups/"+ag.ID+"/members",
		map[string]any{"agent_id": "agent-dup-1"}, http.StatusConflict, nil)
}

// TestPatchServiceSlugRejected pins the service_slug_immutable
// contract: PATCH /services/{id} that ships a `slug` field —
// even one equal to the stored value — is rejected with 400.
// The previous behavior silently ignored the field via Go's
// JSON decoding tolerating unknown keys; an operator who
// thought they renamed a service via PATCH would walk away
// with the same slug and never know.
func TestPatchServiceSlugRejected(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	var s identityService
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/services",
		map[string]any{"slug": "checkout", "display_name": "Checkout"},
		http.StatusCreated, &s)

	// Attempt to rename via PATCH — rejected.
	doJSON(t, client, http.MethodPatch, srv.URL+"/api/v1/services/"+s.ID,
		map[string]any{"slug": "checkout-v2"},
		http.StatusBadRequest, nil)

	// Even submitting the SAME slug is rejected — the
	// contract is "field absent", not "field equals stored".
	doJSON(t, client, http.MethodPatch, srv.URL+"/api/v1/services/"+s.ID,
		map[string]any{"slug": "checkout"},
		http.StatusBadRequest, nil)

	// Service slug unchanged.
	var got identityService
	doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/services/"+s.ID,
		nil, http.StatusOK, &got)
	if got.Slug != "checkout" {
		t.Fatalf("slug mutated unexpectedly: %q", got.Slug)
	}
}

// TestFeatureGateOffReturns404 stands the server up with
// IdentityEnabled=false (mirrors
// ANCHORIX_GOVERNANCE_API_ENABLED=false in production). Every
// identity route MUST return 404 — the router skips
// registering them, and an unrecognized path produces 404 from
// http.ServeMux. Pins the regression where a future change
// might always register the routes despite the gate.
func TestFeatureGateOffReturns404(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, authSvc := testServerWithOptions(t, db, testServerOpts{IdentityEnabled: false})
	client := signInAdmin(t, urlSrv{url: srv.URL}, authSvc)

	// One probe per top-level identity resource. A 404 on the
	// list confirms the entire subtree is unrouted.
	routes := []string{
		"/api/v1/tags",
		"/api/v1/services",
		"/api/v1/service-groups",
		"/api/v1/agent-groups",
	}
	for _, p := range routes {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+p, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s with feature gate off = %d; want 404", p, resp.StatusCode)
		}
	}
}

// TestEveryStateChangeWritesExactlyOneAuditRow exercises every
// state-changing identity endpoint and asserts the
// audit_events table grows by exactly one row per call. A
// regression that double-emits (e.g. an extra Record() before
// the WithTx commit) would silently inflate audit history; a
// regression that drops a Record() would silently weaken the
// security trail. Both are caught here.
func TestEveryStateChangeWritesExactlyOneAuditRow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Helper closure: take an audit count snapshot before,
	// run the call, and assert exactly +1 row in the
	// identity-prefix actions.
	expectOne := func(name, method, path string, body any, status int, out any) {
		t.Helper()
		before := countIdentityAuditEvents(t, db)
		doJSON(t, client, method, srv.URL+path, body, status, out)
		after := countIdentityAuditEvents(t, db)
		if delta := after - before; delta != 1 {
			t.Errorf("%s wrote %d audit rows; want 1", name, delta)
		}
	}

	// tags
	var tag identityTag
	expectOne("tag.created", http.MethodPost, "/api/v1/tags",
		map[string]any{"key": "x1a-env", "value": "prod"}, http.StatusCreated, &tag)
	expectOne("tag.updated", http.MethodPatch, "/api/v1/tags/"+tag.ID,
		map[string]any{"description": "updated"}, http.StatusOK, nil)
	expectOne("tag.disabled", http.MethodPost, "/api/v1/tags/"+tag.ID+"/disable",
		map[string]any{"reason": "obsolete"}, http.StatusNoContent, nil)
	expectOne("tag.enabled", http.MethodPost, "/api/v1/tags/"+tag.ID+"/enable",
		nil, http.StatusNoContent, nil)

	// services
	var s identityService
	expectOne("service.created", http.MethodPost, "/api/v1/services",
		map[string]any{"slug": "x1a-svc", "display_name": "X"}, http.StatusCreated, &s)
	expectOne("service.updated", http.MethodPatch, "/api/v1/services/"+s.ID,
		map[string]any{"description": "u"}, http.StatusOK, nil)
	expectOne("service.disabled", http.MethodPost, "/api/v1/services/"+s.ID+"/disable",
		map[string]any{"reason": "x"}, http.StatusNoContent, nil)
	expectOne("service.enabled", http.MethodPost, "/api/v1/services/"+s.ID+"/enable",
		nil, http.StatusNoContent, nil)

	// service_groups
	var sg identityServiceGroup
	expectOne("service_group.created", http.MethodPost, "/api/v1/service-groups",
		map[string]any{"slug": "x1a-sg", "display_name": "X"}, http.StatusCreated, &sg)
	expectOne("service_group.disabled", http.MethodPost, "/api/v1/service-groups/"+sg.ID+"/disable",
		map[string]any{"reason": "x"}, http.StatusNoContent, nil)

	// agent_groups
	var ag identityAgentGroup
	expectOne("agent_group.created", http.MethodPost, "/api/v1/agent-groups",
		map[string]any{"slug": "x1a-ag", "display_name": "X"}, http.StatusCreated, &ag)
	expectOne("agent_group.disabled", http.MethodPost, "/api/v1/agent-groups/"+ag.ID+"/disable",
		map[string]any{"reason": "x"}, http.StatusNoContent, nil)
}

// countIdentityAuditEvents counts audit_events rows whose
// action matches the H-026A2 identity-domain action prefixes.
// We scope by prefix (rather than counting every row) so the
// admin-login audit from signInAdmin and any other unrelated
// rows don't pollute the delta math.
func countIdentityAuditEvents(t *testing.T, db *postgres.DB) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT COUNT(*) FROM audit_events
			 WHERE action LIKE 'tag.%'
			    OR action LIKE 'service.%'
			    OR action LIKE 'service_group.%'
			    OR action LIKE 'agent_group.%'
		`).Scan(&n)
	}); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// ensure strings import stays used regardless of build-tag
// pruning by future refactors.
var _ = strings.Contains

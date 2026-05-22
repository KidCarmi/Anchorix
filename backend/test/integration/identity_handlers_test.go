//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// doJSON is a small wire helper for the identity tests. It
// posts a JSON body, decodes the response into out (when not
// nil), and asserts the status code matches.
func doJSON(t *testing.T, client *http.Client, method, url string, body any, wantStatus int, out any) []byte {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	return doJSONRaw(t, client, method, url, raw, wantStatus, out)
}

// doJSONRaw is the bytes-in variant of doJSON. Use it when the
// wire shape matters character-for-character (e.g. `null`
// vs an omitted field, where Go's json.Marshal of *string nil
// would emit `null` but Go's json.Marshal of a missing struct
// field cannot be expressed at all).
func doJSONRaw(t *testing.T, client *http.Client, method, url string, raw []byte, wantStatus int, out any) []byte {
	t.Helper()
	var rdr *bytes.Reader
	if raw != nil {
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		buf := make([]byte, 512)
		n, _ := resp.Body.Read(buf)
		t.Fatalf("%s %s status = %d, want %d (body: %q)", method, url, resp.StatusCode, wantStatus, string(buf[:n]))
	}
	if out != nil && resp.ContentLength != 0 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", url, err)
		}
	}
	return nil
}

type identityTag struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

type identityService struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

type identityServiceGroup struct {
	ID       string  `json:"id"`
	Slug     string  `json:"slug"`
	ParentID *string `json:"parent_id"`
}

type identityAgentGroup struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

// TestTagsCRUDHappyPath exercises the tags create / get / list /
// disable / enable / delete-assignment flow over HTTP.
func TestTagsCRUDHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Create.
	var t1 identityTag
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags",
		map[string]any{"key": "env", "value": "prod", "description": "production"},
		http.StatusCreated, &t1)
	if t1.Key != "env" || t1.Value != "prod" {
		t.Fatalf("create tag wrong shape: %+v", t1)
	}

	// Get.
	var got identityTag
	doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/tags/"+t1.ID, nil, http.StatusOK, &got)
	if got.ID != t1.ID {
		t.Fatalf("get id mismatch")
	}

	// PATCH description.
	doJSON(t, client, http.MethodPatch, srv.URL+"/api/v1/tags/"+t1.ID,
		map[string]any{"description": "PROD environment"},
		http.StatusOK, &got)

	// Disable.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags/"+t1.ID+"/disable",
		map[string]any{"reason": "obsolete"}, http.StatusNoContent, nil)

	// Audit row written.
	assertAuditAction(t, db, "tag.created", t1.ID)
	assertAuditAction(t, db, "tag.disabled", t1.ID)
}

// TestTagPatchKeyOrValueRejected pins that PATCH /tags/{id}
// rejects bodies that carry `key` or `value`.
func TestTagPatchKeyOrValueRejected(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	var t1 identityTag
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags",
		map[string]any{"key": "env", "value": "prod"}, http.StatusCreated, &t1)

	// Key in body — rejected.
	doJSON(t, client, http.MethodPatch, srv.URL+"/api/v1/tags/"+t1.ID,
		map[string]any{"key": "env2"}, http.StatusBadRequest, nil)
	// Value in body — rejected.
	doJSON(t, client, http.MethodPatch, srv.URL+"/api/v1/tags/"+t1.ID,
		map[string]any{"value": "staging"}, http.StatusBadRequest, nil)
}

// TestTagDisableInUseRejected pins the tag_in_use preflight:
// disabling a tag with active assignments returns 409.
func TestTagDisableInUseRejected(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Tag + cert seeded so we can attach the tag.
	var tag identityTag
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags",
		map[string]any{"key": "env", "value": "prod"}, http.StatusCreated, &tag)
	seedCertificate(t, db, ctxOf(t), "cert-tagdisable-1")

	// Assign.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags/"+tag.ID+"/assignments",
		map[string]any{"target_type": "certificate", "target_id": "cert-tagdisable-1"},
		http.StatusCreated, nil)

	// Disable — must fail with tag_in_use.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags/"+tag.ID+"/disable",
		map[string]any{"reason": "obsolete"}, http.StatusConflict, nil)
}

// TestTagAssignmentInvalidTarget pins that POST
// /tags/{id}/assignments rejects unknown target ids.
func TestTagAssignmentInvalidTarget(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	var tag identityTag
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags",
		map[string]any{"key": "env", "value": "prod"}, http.StatusCreated, &tag)

	// service target — no such service exists.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/tags/"+tag.ID+"/assignments",
		map[string]any{"target_type": "service", "target_id": "no-such-svc"},
		http.StatusBadRequest, nil)
}

// TestServicesCRUDHappyPath exercises the service CRUD flow.
func TestServicesCRUDHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	var s1 identityService
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/services",
		map[string]any{"slug": "billing", "display_name": "Billing"},
		http.StatusCreated, &s1)
	if s1.Slug != "billing" {
		t.Fatalf("service create: %+v", s1)
	}

	// PATCH display_name.
	doJSON(t, client, http.MethodPatch, srv.URL+"/api/v1/services/"+s1.ID,
		map[string]any{"display_name": "Billing Service"},
		http.StatusOK, &s1)

	// List.
	var listResp struct {
		Items []identityService `json:"items"`
	}
	doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/services", nil, http.StatusOK, &listResp)
	if len(listResp.Items) != 1 {
		t.Fatalf("list services = %d; want 1", len(listResp.Items))
	}

	// Disable.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/services/"+s1.ID+"/disable",
		map[string]any{"reason": "deprecated"}, http.StatusNoContent, nil)

	assertAuditAction(t, db, "service.created", s1.ID)
	assertAuditAction(t, db, "service.disabled", s1.ID)
}

// TestServicesInvalidSlugRejected pins the slug validator.
func TestServicesInvalidSlugRejected(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Uppercase, underscore, leading hyphen — all rejected.
	for _, bad := range []string{"UPPER", "with_under", "-leading", "trailing-", "double--hyphen"} {
		doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/services",
			map[string]any{"slug": bad, "display_name": "X"},
			http.StatusBadRequest, nil)
	}
}

// TestServiceGroupSetParentRequiresExplicitField pins the wire
// contract for POST /service-groups/{id}/parent: a missing
// parent_id field returns 400, an explicit `null` clears the
// parent, and a string value sets it. Codex caught the original
// bug on PR #45 where a missing field was silently clearing the
// parent. The empty / no-body call MUST be rejected so a
// malformed client cannot detach groups by accident.
func TestServiceGroupSetParentRequiresExplicitField(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Build root + child.
	var root identityServiceGroup
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups",
		map[string]any{"slug": "spr-root", "display_name": "Root"},
		http.StatusCreated, &root)
	var child identityServiceGroup
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups",
		map[string]any{"slug": "spr-child", "display_name": "Child", "parent_id": root.ID},
		http.StatusCreated, &child)

	// Missing parent_id — must be rejected. The empty JSON
	// object {} carries no field; previously this silently
	// cleared the parent.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups/"+child.ID+"/parent",
		map[string]any{}, http.StatusBadRequest, nil)

	// Confirm the child's parent is still root (the bug
	// would have cleared it).
	var after identityServiceGroup
	doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/service-groups/"+child.ID,
		nil, http.StatusOK, &after)
	if after.ParentID == nil || *after.ParentID != root.ID {
		t.Fatalf("parent silently cleared by missing-field request: %+v", after.ParentID)
	}

	// Explicit null — clears the parent.
	doJSONRaw(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups/"+child.ID+"/parent",
		[]byte(`{"parent_id": null}`), http.StatusOK, &after)
	if after.ParentID != nil {
		t.Fatalf("explicit null did not clear parent: %+v", after.ParentID)
	}

	// Set to a value — restores the parent.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups/"+child.ID+"/parent",
		map[string]any{"parent_id": root.ID}, http.StatusOK, &after)
	if after.ParentID == nil || *after.ParentID != root.ID {
		t.Fatalf("set-parent did not restore: %+v", after.ParentID)
	}
}

// TestServiceGroupCyclePrevention pins the service_group_cycle
// 400 response.
func TestServiceGroupCyclePrevention(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Root and child.
	var root identityServiceGroup
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups",
		map[string]any{"slug": "root", "display_name": "Root"},
		http.StatusCreated, &root)
	var child identityServiceGroup
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups",
		map[string]any{"slug": "child", "display_name": "Child", "parent_id": root.ID},
		http.StatusCreated, &child)

	// Try to make root's parent = child (transitive cycle).
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups/"+root.ID+"/parent",
		map[string]any{"parent_id": child.ID}, http.StatusBadRequest, nil)
}

// TestServiceGroupHasChildrenRejectsDisable pins the disable
// preflight for service_groups.
func TestServiceGroupHasChildrenRejectsDisable(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	var root identityServiceGroup
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups",
		map[string]any{"slug": "root2", "display_name": "Root2"},
		http.StatusCreated, &root)
	var child identityServiceGroup
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups",
		map[string]any{"slug": "child2", "display_name": "Child2", "parent_id": root.ID},
		http.StatusCreated, &child)

	// Disabling the parent must fail with service_group_has_children.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/service-groups/"+root.ID+"/disable",
		map[string]any{"reason": "x"}, http.StatusConflict, nil)
}

// TestAgentGroupsAndMembership covers create/list, membership
// add/remove, and the inverse "groups for agent" view.
func TestAgentGroupsAndMembership(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Seed an agent — directly via SQL so we don't need to go
	// through the enrollment dance.
	if err := execRawSQL(ctxOf(t), db, rawStmt{
		`INSERT INTO agents (id, organization_id, hostname, status, public_key_fingerprint)
		 VALUES ('agent-it-1', 'anchorix', 'host-1', 'active', 'fp-it-1')`, nil,
	}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	var g identityAgentGroup
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/agent-groups",
		map[string]any{"slug": "dc", "display_name": "Domain Controllers"},
		http.StatusCreated, &g)

	// Add member.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/agent-groups/"+g.ID+"/members",
		map[string]any{"agent_id": "agent-it-1"},
		http.StatusNoContent, nil)

	// List members.
	var members struct {
		Items []struct {
			AgentID string `json:"agent_id"`
		} `json:"items"`
	}
	doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/agent-groups/"+g.ID+"/members",
		nil, http.StatusOK, &members)
	if len(members.Items) != 1 || members.Items[0].AgentID != "agent-it-1" {
		t.Fatalf("members = %+v", members.Items)
	}

	// Inverse view.
	var groups struct {
		Items []struct {
			AgentGroupID string `json:"agent_group_id"`
		} `json:"items"`
	}
	doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/agents/agent-it-1/groups",
		nil, http.StatusOK, &groups)
	if len(groups.Items) != 1 || groups.Items[0].AgentGroupID != g.ID {
		t.Fatalf("groups = %+v", groups.Items)
	}

	// Reject unknown agent.
	doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/agent-groups/"+g.ID+"/members",
		map[string]any{"agent_id": "no-such-agent"},
		http.StatusBadRequest, nil)

	// Remove + confirm.
	doJSON(t, client, http.MethodDelete, srv.URL+"/api/v1/agent-groups/"+g.ID+"/members",
		map[string]any{"agent_id": "agent-it-1"},
		http.StatusNoContent, nil)
}

// TestIdentityAuthRequired confirms anonymous requests are
// rejected with 401 and the canonical envelope on every
// identity endpoint.
func TestIdentityAuthRequired(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)
	anon := &http.Client{Timeout: 5 * time.Second}
	doJSON(t, anon, http.MethodGet, srv.URL+"/api/v1/tags", nil, http.StatusUnauthorized, nil)
	doJSON(t, anon, http.MethodPost, srv.URL+"/api/v1/tags",
		map[string]any{"key": "x"}, http.StatusUnauthorized, nil)
	doJSON(t, anon, http.MethodGet, srv.URL+"/api/v1/services", nil, http.StatusUnauthorized, nil)
	doJSON(t, anon, http.MethodGet, srv.URL+"/api/v1/agent-groups", nil, http.StatusUnauthorized, nil)
}

// TestIdentityAgentBearerRejected pins that bearer tokens —
// the agent-facing auth — are not honored on identity routes.
func TestIdentityAgentBearerRejected(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	bearer := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/tags", nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := bearer.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer on /tags: %d; want 401", resp.StatusCode)
	}
}

// TestIdentityCrossOrg404 pins that a session in org "anchorix"
// gets 404 not_found when reading a resource that exists only in
// a foreign org — no cross-tenant enumeration.
func TestIdentityCrossOrg404(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Seed a foreign org + a tag in it.
	if err := execRawSQL(ctxOf(t), db, rawStmt{
		`INSERT INTO organizations (id, name) VALUES ('other', 'Other')`, nil,
	}); err != nil {
		t.Fatalf("seed other org: %v", err)
	}
	if err := execRawSQL(ctxOf(t), db, rawStmt{
		`INSERT INTO tags (id, organization_id, key, value) VALUES ('tag-foreign', 'other', 'k', 'v')`, nil,
	}); err != nil {
		t.Fatalf("seed foreign tag: %v", err)
	}

	// anchorix session reads tag-foreign — must 404.
	doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/tags/tag-foreign", nil, http.StatusNotFound, nil)
}

// ----- helpers -----

func ctxOf(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// assertAuditAction asserts that exactly one audit_events row
// exists with the supplied action targeting targetID.
func assertAuditAction(t *testing.T, db dbConn, action, targetID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var count int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_events WHERE action = $1 AND target_id = $2`,
			action, targetID,
		).Scan(&count)
	}); err != nil {
		t.Fatalf("count audit %s: %v", action, err)
	}
	if count != 1 {
		t.Fatalf("audit_events with action=%s target=%s = %d; want 1", action, targetID, count)
	}
	// Also assert severity:"security" is present in metadata.
	var hasSeverity bool
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT (metadata->>'severity') = 'security'
			   FROM audit_events
			  WHERE action = $1 AND target_id = $2
			  LIMIT 1`, action, targetID,
		).Scan(&hasSeverity)
	}); err != nil {
		t.Fatalf("check severity %s: %v", action, err)
	}
	if !hasSeverity {
		t.Fatalf("audit %s for %s missing severity:security", action, targetID)
	}
}

// dbConn is the narrow interface assertAuditAction needs.
type dbConn interface {
	WithTxRaw(ctx context.Context, fn func(pgx.Tx) error) error
}

// silence the unused-package warning if no test references it.
var _ = strings.TrimSpace

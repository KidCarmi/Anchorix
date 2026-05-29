//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// ownershipRowOf reads the current certificate_ownership decision +
// service for a cert (empty service => NULL).
func ownershipDecisionService(t *testing.T, db *postgres.DB, ctx context.Context, org, certID string) (string, string) {
	t.Helper()
	var decision, svc string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT decision, COALESCE(service_id,'') FROM certificate_ownership WHERE organization_id=$1 AND certificate_id=$2`,
			org, certID).Scan(&decision, &svc)
	}); err != nil {
		t.Fatalf("read ownership %s: %v", certID, err)
	}
	return decision, svc
}

func TestOwnershipOverrideCreateHappyPathImmediateEffect(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-rule")
	seedService(t, db, ctx, "svc-pin")
	// Cert matched by a SAN rule → svc-rule, plus a second cert that
	// must NOT be touched by the override re-derivation.
	seedCertMeta(t, db, ctx, "anchorix", "cert-ovr", "CN=a.example", "CN=ca", []string{"a.example"})
	seedCertMeta(t, db, ctx, "anchorix", "cert-other", "CN=b.example", "CN=ca", []string{"b.example"})
	seedOwnershipRule(t, db, ctx, "rule-san", "svc-rule", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)

	// Establish baseline ownership for both certs via a full recompute.
	svc := ownershipService(t, db, 0)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("baseline recompute: %v", err)
	}
	if dec, s := ownershipDecisionService(t, db, ctx, "anchorix", "cert-ovr"); dec != "matched" || s != "svc-rule" {
		t.Fatalf("baseline cert-ovr = %s/%s; want matched/svc-rule", dec, s)
	}
	otherExpBefore := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_match_explanations WHERE certificate_id='cert-other'`)

	// Override cert-ovr → svc-pin. Immediate effect: decision flips to
	// overridden before the response returns.
	status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/cert-ovr/ownership/override",
		`{"service_id":"svc-pin","reason":"manual pin"}`)
	if status != http.StatusCreated {
		t.Fatalf("create override status=%d body=%s; want 201", status, body)
	}
	if dec, s := ownershipDecisionService(t, db, ctx, "anchorix", "cert-ovr"); dec != "overridden" || s != "svc-pin" {
		t.Fatalf("post-override cert-ovr = %s/%s; want overridden/svc-pin (immediate effect)", dec, s)
	}
	// Exactly one security audit for the create.
	if n := auditCount(t, db, ctx, "anchorix", "ownership.overridden"); n != 1 {
		t.Fatalf("ownership.overridden audit = %d; want 1", n)
	}
	if n := scalarInt(t, db, ctx,
		`SELECT count(*) FROM audit_events WHERE action='ownership.overridden' AND metadata->>'severity'='security'`); n != 1 {
		t.Fatalf("security-severity overridden audit = %d; want 1", n)
	}
	// The OTHER cert was not re-derived (no new explanation row).
	otherExpAfter := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_match_explanations WHERE certificate_id='cert-other'`)
	if otherExpAfter != otherExpBefore {
		t.Fatalf("cert-other explanations changed (%d → %d); override must refresh ONLY the target", otherExpBefore, otherExpAfter)
	}
	if dec, s := ownershipDecisionService(t, db, ctx, "anchorix", "cert-other"); dec != "matched" || s != "svc-rule" {
		t.Fatalf("cert-other drifted to %s/%s; want matched/svc-rule untouched", dec, s)
	}
}

func TestOwnershipOverrideClearHappyPathRederivesFromRules(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-rule")
	seedService(t, db, ctx, "svc-pin")
	seedCertMeta(t, db, ctx, "anchorix", "cert-clr", "CN=a.example", "CN=ca", []string{"a.example"})
	seedOwnershipRule(t, db, ctx, "rule-san", "svc-rule", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100)

	svc := ownershipService(t, db, 0)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	// Pin then clear.
	if status, b := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/cert-clr/ownership/override",
		`{"service_id":"svc-pin","reason":"pin"}`); status != http.StatusCreated {
		t.Fatalf("create override: status=%d body=%s", status, b)
	}
	if dec, _ := ownershipDecisionService(t, db, ctx, "anchorix", "cert-clr"); dec != "overridden" {
		t.Fatalf("pre-clear decision = %s; want overridden", dec)
	}
	status, body := httpJSONWithBody(t, client, http.MethodDelete, srvURL+"/api/v1/certificates/cert-clr/ownership/override",
		`{"reason":"no longer needed"}`)
	if status != http.StatusOK {
		t.Fatalf("clear override status=%d body=%s; want 200", status, body)
	}
	// Re-derived from rules → back to the SAN rule's service.
	if dec, s := ownershipDecisionService(t, db, ctx, "anchorix", "cert-clr"); dec != "matched" || s != "svc-rule" {
		t.Fatalf("post-clear = %s/%s; want matched/svc-rule (re-derived from rules)", dec, s)
	}
	// The override row is soft-cleared, slot freed.
	if n := scalarInt(t, db, ctx,
		`SELECT count(*) FROM certificate_ownership_overrides WHERE certificate_id='cert-clr' AND cleared_at IS NULL`); n != 0 {
		t.Fatalf("active overrides after clear = %d; want 0", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.override_cleared"); n != 1 {
		t.Fatalf("override_cleared audit = %d; want 1", n)
	}
}

func TestOwnershipOverrideExpirySupport(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-pin")
	seedCertMeta(t, db, ctx, "anchorix", "cert-exp", "CN=x", "CN=ca", nil)

	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/cert-exp/ownership/override",
		`{"service_id":"svc-pin","reason":"temp","expires_at":"`+future+`"}`)
	if status != http.StatusCreated {
		t.Fatalf("create with future expiry status=%d body=%s; want 201", status, body)
	}
	var row struct {
		ExpiresAt *string `json:"expires_at"`
	}
	json.Unmarshal(body, &row)
	if row.ExpiresAt == nil {
		t.Fatalf("expires_at not persisted")
	}

	// Past expiry → 400 ownership_override_expiry_in_past.
	seedCertMeta(t, db, ctx, "anchorix", "cert-exp2", "CN=y", "CN=ca", nil)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	status, pbody := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/cert-exp2/ownership/override",
		`{"service_id":"svc-pin","reason":"temp","expires_at":"`+past+`"}`)
	if status != http.StatusBadRequest || !strings.Contains(string(pbody), "ownership_override_expiry_in_past") {
		t.Fatalf("past-expiry status=%d body=%s; want 400 expiry_in_past", status, pbody)
	}
	// Invalid RFC3339 → 400 bad_request.
	if status, _ := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/cert-exp2/ownership/override",
		`{"service_id":"svc-pin","reason":"t","expires_at":"not-a-time"}`); status != http.StatusBadRequest {
		t.Fatalf("invalid expires_at status=%d; want 400", status)
	}
}

func TestOwnershipOverrideDuplicateConflict(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-pin")
	seedCertMeta(t, db, ctx, "anchorix", "cert-dup", "CN=x", "CN=ca", nil)

	mk := `{"service_id":"svc-pin","reason":"first"}`
	if status, _ := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/cert-dup/ownership/override", mk); status != http.StatusCreated {
		t.Fatalf("first override: want 201")
	}
	for i := 0; i < 3; i++ {
		status, b := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/cert-dup/ownership/override", mk)
		if status != http.StatusConflict || !strings.Contains(string(b), "ownership_override_conflict") {
			t.Fatalf("dup attempt %d status=%d body=%s; want stable 409 ownership_override_conflict", i, status, b)
		}
	}
	// Exactly one create audited.
	if n := auditCount(t, db, ctx, "anchorix", "ownership.overridden"); n != 1 {
		t.Fatalf("overridden audit = %d; want 1 (conflict must not audit)", n)
	}
	// Exactly one active override row.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE certificate_id='cert-dup' AND cleared_at IS NULL`); n != 1 {
		t.Fatalf("active overrides = %d; want 1", n)
	}
}

func TestOwnershipOverrideValidationRejections(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-ok")
	seedCertMeta(t, db, ctx, "anchorix", "cert-v", "CN=x", "CN=ca", nil)

	// Disabled service.
	seedService(t, db, ctx, "svc-disabled")
	if err := execRawSQL(ctx, db, rawStmt{`UPDATE services SET disabled_at=now() WHERE id='svc-disabled'`, nil}); err != nil {
		t.Fatalf("disable service: %v", err)
	}

	cases := []struct {
		name       string
		cert       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"nonexistent cert", "cert-missing", `{"service_id":"svc-ok","reason":"r"}`, 404, "not_found"},
		{"nonexistent service", "cert-v", `{"service_id":"svc-missing","reason":"r"}`, 400, "ownership_override_service_not_found"},
		{"disabled service", "cert-v", `{"service_id":"svc-disabled","reason":"r"}`, 400, "ownership_override_service_not_found"},
		{"missing service_id", "cert-v", `{"reason":"r"}`, 400, "bad_request"},
		{"missing reason", "cert-v", `{"service_id":"svc-ok"}`, 400, "bad_request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, b := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/"+c.cert+"/ownership/override", c.body)
			if status != c.wantStatus || !strings.Contains(string(b), c.wantCode) {
				t.Fatalf("status=%d body=%s; want %d %q", status, b, c.wantStatus, c.wantCode)
			}
		})
	}
	// No override or audit produced by any rejection.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE organization_id='anchorix'`); n != 0 {
		t.Fatalf("overrides created by rejected requests = %d; want 0", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.overridden"); n != 0 {
		t.Fatalf("overridden audit on validation failure = %d; want 0", n)
	}
}

func TestOwnershipOverrideCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedOrganization(t, db, "other", "Other")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)

	// Foreign-org cert + service + active override.
	seedCertMeta(t, db, ctx, "other", "cert-foreign", "CN=x", "CN=ca", nil)
	if err := execRawSQL(ctx, db, rawStmt{`INSERT INTO services (id, organization_id, slug, display_name) VALUES ('svc-foreign','other','svc-foreign','svc')`, nil}); err != nil {
		t.Fatalf("seed foreign service: %v", err)
	}
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO certificate_ownership_overrides (id, organization_id, certificate_id, service_id, reason, set_by, set_at)
		   VALUES ('ovr-foreign','other','cert-foreign','svc-foreign','pin','op',now())`, nil}); err != nil {
		t.Fatalf("seed foreign override: %v", err)
	}

	// Create against foreign cert → 404 (not leaked), nothing written.
	status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/cert-foreign/ownership/override",
		`{"service_id":"svc-foreign","reason":"x"}`)
	if status != http.StatusNotFound || !strings.Contains(string(body), "not_found") {
		t.Fatalf("cross-org create status=%d body=%s; want 404 not_found", status, body)
	}
	// Clear the foreign override from anchorix → 404, foreign override untouched.
	status, cbody := httpJSONWithBody(t, client, http.MethodDelete, srvURL+"/api/v1/certificates/cert-foreign/ownership/override",
		`{"reason":"x"}`)
	if status != http.StatusNotFound {
		t.Fatalf("cross-org clear status=%d body=%s; want 404", status, cbody)
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE id='ovr-foreign' AND cleared_at IS NULL`); n != 1 {
		t.Fatalf("foreign override cleared cross-org; active count=%d want 1", n)
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='other' AND action LIKE 'ownership.override%'`); n != 0 {
		t.Fatalf("foreign-org override audit leaked = %d; want 0", n)
	}
}

func TestOwnershipOverrideClearNonexistentNotLeaked(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedCertMeta(t, db, ctx, "anchorix", "cert-noovr", "CN=x", "CN=ca", nil)

	// Clear when no active override exists (real cert) → 404.
	status1, _ := httpJSONWithBody(t, client, http.MethodDelete, srvURL+"/api/v1/certificates/cert-noovr/ownership/override", `{"reason":"x"}`)
	// Clear a wholly nonexistent cert → 404, identical shape.
	status2, _ := httpJSONWithBody(t, client, http.MethodDelete, srvURL+"/api/v1/certificates/cert-ghost/ownership/override", `{"reason":"x"}`)
	if status1 != http.StatusNotFound || status2 != http.StatusNotFound {
		t.Fatalf("clear no-override=%d ghost=%d; want both 404 (indistinguishable)", status1, status2)
	}
}

// TestOwnershipOverrideAuditRollback proves create + clear roll back
// at the postgres layer when the audit write fails: no override state
// change, no cert re-derivation, no audit row.
func TestOwnershipOverrideAuditRollback(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-rb")
	seedCertMeta(t, db, ctx, "anchorix", "cert-rb", "CN=x", "CN=ca", nil)

	t.Run("create rolls back", func(t *testing.T) {
		svc := ownershipServiceWithFailingAudit(t, db, "ownership.overridden")
		_, err := svc.CreateOverride(ctx, ownership.CreateOverrideInput{
			OrganizationID: "anchorix", ActorUserID: "op", CertificateID: "cert-rb",
			ServiceID: "svc-rb", Reason: "pin",
		})
		if err == nil {
			t.Fatalf("CreateOverride succeeded despite forced audit failure")
		}
		if n := countRows(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE certificate_id='cert-rb'`); n != 0 {
			t.Fatalf("override row persisted despite audit failure: %d", n)
		}
		if n := countRows(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE certificate_id='cert-rb'`); n != 0 {
			t.Fatalf("ownership row persisted despite audit failure: %d (single-cert re-derivation must roll back too)", n)
		}
		if n := countRows(t, db, ctx, `SELECT count(*) FROM audit_events WHERE action='ownership.overridden'`); n != 0 {
			t.Fatalf("overridden audit written despite forced failure: %d", n)
		}
	})

	t.Run("clear rolls back", func(t *testing.T) {
		// Seed an active override directly so clear has a target.
		if err := execRawSQL(ctx, db, rawStmt{
			`INSERT INTO certificate_ownership_overrides (id, organization_id, certificate_id, service_id, reason, set_by, set_at)
			   VALUES ('ovr-rb','anchorix','cert-rb','svc-rb','pin','op',now())`, nil}); err != nil {
			t.Fatalf("seed override: %v", err)
		}
		svc := ownershipServiceWithFailingAudit(t, db, "ownership.override_cleared")
		_, err := svc.ClearOverride(ctx, ownership.ClearOverrideInput{
			OrganizationID: "anchorix", ActorUserID: "op", CertificateID: "cert-rb", Reason: "x",
		})
		if err == nil {
			t.Fatalf("ClearOverride succeeded despite forced audit failure")
		}
		// Override still active (clear rolled back).
		if n := countRows(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE id='ovr-rb' AND cleared_at IS NULL`); n != 1 {
			t.Fatalf("override cleared despite audit failure: active count=%d want 1", n)
		}
		if n := countRows(t, db, ctx, `SELECT count(*) FROM audit_events WHERE action='ownership.override_cleared'`); n != 0 {
			t.Fatalf("override_cleared audit written despite forced failure: %d", n)
		}
	})
}

func TestOwnershipOverrideAuthAndGate(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	// anonymous → 401.
	srv, _ := testServerWithOptions(t, db, testServerOpts{IdentityEnabled: true, OwnershipEnabled: true})
	anon := &http.Client{Timeout: 5 * time.Second}
	if status, _ := httpJSONWithBody(t, anon, http.MethodPost, srv.URL+"/api/v1/certificates/x/ownership/override", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("anon POST override status=%d; want 401", status)
	}
	if status, _ := httpJSONWithBody(t, anon, http.MethodDelete, srv.URL+"/api/v1/certificates/x/ownership/override", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("anon DELETE override status=%d; want 401", status)
	}
	// gate off → 404 even authenticated.
	srv2, svc2 := testServerWithOptions(t, db, testServerOpts{IdentityEnabled: true, OwnershipEnabled: false})
	authed := signInAdmin(t, stringerURL{srv2.URL}, svc2)
	if status, _ := httpJSONWithBody(t, authed, http.MethodPost, srv2.URL+"/api/v1/certificates/x/ownership/override", `{"service_id":"s","reason":"r"}`); status != http.StatusNotFound {
		t.Fatalf("gate-off POST override status=%d; want 404", status)
	}
}

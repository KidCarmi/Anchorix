//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// latestRecomputedActor returns (actor, actor_type) of the most
// recent governance.recomputed audit row for the org.
func latestRecomputedActor(t *testing.T, db *postgres.DB, ctx context.Context, org string) (string, string) {
	t.Helper()
	var actor, actorType string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT actor, actor_type FROM audit_events
			  WHERE organization_id=$1 AND action='governance.recomputed'
			  ORDER BY occurred_at DESC, id DESC LIMIT 1`, org).Scan(&actor, &actorType)
	}); err != nil {
		t.Fatalf("latest recomputed actor: %v", err)
	}
	return actor, actorType
}

func adminUserID(t *testing.T, db *postgres.DB, ctx context.Context) string {
	t.Helper()
	var id string
	// testEmail is the address seedAdmin/signInAdmin authenticate as.
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM users WHERE email=$1`, testEmail).Scan(&id)
	}); err != nil {
		t.Fatalf("admin user id: %v", err)
	}
	return id
}

// TestOwnershipManualRecomputeAuditAttributedToOperator pins that a
// recompute triggered via the HTTP endpoint writes exactly one
// governance.recomputed audit row attributed to the OPERATOR
// (actor = the signed-in user's id, actor_type = "user") — not
// "system" or "scheduler". This is the audit-visibility contract the
// threat model §3.1/§3.6 relies on for manual-recompute accountability.
func TestOwnershipManualRecomputeAuditAttributedToOperator(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedCertMeta(t, db, ctx, "anchorix", "cert-audit-1", "CN=x", "CN=ca", nil)

	httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &recomputeTriggerDTO{})

	if n := auditCount(t, db, ctx, "anchorix", "governance.recomputed"); n != 1 {
		t.Fatalf("governance.recomputed rows = %d; want exactly 1 per manual recompute", n)
	}
	actor, actorType := latestRecomputedActor(t, db, ctx, "anchorix")
	if actorType != "user" {
		t.Fatalf("actor_type = %q; want \"user\" (manual recompute is operator-attributed)", actorType)
	}
	if actor == "system" || actor == "scheduler" || actor == "" {
		t.Fatalf("actor = %q; want the operator user id, not system/scheduler/empty", actor)
	}
	if want := adminUserID(t, db, ctx); actor != want {
		t.Fatalf("actor = %q; want signed-in admin id %q", actor, want)
	}
	// nowait path must be attributed identically. Assert the POST
	// itself returns 200 AND that it produced a NEW governance.recomputed
	// row before checking attribution — otherwise a regression where
	// ?nowait=true returns non-200 without writing an audit row would
	// silently re-read the previous blocking recompute's row and pass.
	before := auditCount(t, db, ctx, "anchorix", "governance.recomputed")
	if status, body := httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute?nowait=true", &recomputeTriggerDTO{}); status != http.StatusOK {
		t.Fatalf("nowait recompute status=%d body=%s; want 200", status, body)
	}
	after := auditCount(t, db, ctx, "anchorix", "governance.recomputed")
	if after != before+1 {
		t.Fatalf("governance.recomputed count = %d; want %d (nowait must write a new audit row)", after, before+1)
	}
	actor2, type2 := latestRecomputedActor(t, db, ctx, "anchorix")
	if type2 != "user" || actor2 != adminUserID(t, db, ctx) {
		t.Fatalf("nowait recompute actor=%q type=%q; want operator/user", actor2, type2)
	}
}

// TestOwnershipStaleDurationBounds pins that the /ownership/stale
// `older_than` override cannot be abused: negative and zero are
// rejected with 400, an overflowing duration is rejected with 400
// (time.ParseDuration errors), and a huge-but-valid duration is
// handled gracefully (no 500/panic — it simply matches no rows).
func TestOwnershipStaleDurationBounds(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedCertMeta(t, db, ctx, "anchorix", "cert-dur-1", "CN=x", "CN=ca", nil)
	httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &recomputeTriggerDTO{})

	// Negative → 400.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/ownership/stale?older_than=-1h"); status != http.StatusBadRequest {
		t.Fatalf("older_than=-1h status=%d; want 400", status)
	}
	// Zero → 400.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/ownership/stale?older_than=0s"); status != http.StatusBadRequest {
		t.Fatalf("older_than=0s status=%d; want 400", status)
	}
	// Overflowing duration → ParseDuration error → 400 (not 500).
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/ownership/stale?older_than=100000000000h"); status != http.StatusBadRequest {
		t.Fatalf("overflow older_than status=%d; want 400 (graceful, not 500)", status)
	}
	// Garbage → 400.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/ownership/stale?older_than=abc"); status != http.StatusBadRequest {
		t.Fatalf("garbage older_than status=%d; want 400", status)
	}
	// Huge-but-valid (≈100 years) → 200, no rows match (nothing is that
	// old), and no panic/500.
	var huge ownershipListDTO
	httpGetJSON(t, client, srvURL+"/api/v1/ownership/stale?older_than=876000h", &huge)
	if len(huge.Items) != 0 || huge.NextCursor != nil {
		t.Fatalf("huge older_than returned %d items / cursor=%v; want empty (nothing 100y old)", len(huge.Items), huge.NextCursor)
	}
}

// TestOwnershipOverrideReadCrossOrgNoLeak pins that
// GET /certificates/{id}/ownership/override does not leak whether a
// foreign-org certificate exists: a cert that exists with an active
// override in another org returns {"active": null} to an operator in
// a different org — identical to a wholly nonexistent id.
func TestOwnershipOverrideReadCrossOrgNoLeak(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedOrganization(t, db, "other", "Other")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)

	// Foreign-org cert WITH an active override.
	seedCertMeta(t, db, ctx, "other", "cert-foreign-ovr", "CN=x", "CN=ca", nil)
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO services (id, organization_id, slug, display_name) VALUES ('svc-foreign','other','svc-foreign','svc')`, nil,
	}); err != nil {
		t.Fatalf("seed foreign service: %v", err)
	}
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-foreign", OrganizationID: "other", CertificateID: "cert-foreign-ovr",
		ServiceID: "svc-foreign", Reason: "pin", SetBy: "op", SetAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed foreign override: %v", err)
	}

	// Compare the COMPLETE raw response bodies, not just the `active`
	// field: a regression that added an enumeration side-channel (e.g.
	// {"active":null,"exists":true} for the foreign cert vs
	// {"active":null} for a nonexistent id) would be invisible to a
	// struct decode that only captures `active`. Byte-equal bodies +
	// equal status is the real "indistinguishable" assertion.
	foreignStatus, foreignBody := httpGetStatus(t, client, srvURL+"/api/v1/certificates/cert-foreign-ovr/ownership/override")
	bogusStatus, bogusBody := httpGetStatus(t, client, srvURL+"/api/v1/certificates/no-such-cert-xyz/ownership/override")
	if foreignStatus != http.StatusOK || bogusStatus != http.StatusOK {
		t.Fatalf("override read status: foreign=%d bogus=%d; want both 200", foreignStatus, bogusStatus)
	}
	if string(foreignBody) != string(bogusBody) {
		t.Fatalf("override responses distinguishable — foreign-cert existence leaks:\n foreign=%s\n bogus=%s", foreignBody, bogusBody)
	}
	// Defensive: confirm the shared shape is in fact the no-override one
	// (so the test fails loudly if both ever started leaking the same
	// non-null payload).
	if string(foreignBody) != `{"active":null}` && string(foreignBody) != "{\"active\":null}\n" {
		t.Fatalf("override read body = %q; want {\"active\":null}", foreignBody)
	}
}

// TestGovernanceRecomputeRunsCrossOrgIsolation pins that the
// recompute-runs list is org-scoped: an operator never sees another
// org's runs.
func TestGovernanceRecomputeRunsCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedOrganization(t, db, "other", "Other")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)

	// Seed a finished recompute run in the FOREIGN org directly.
	runsRepo := postgres.NewGovernanceRecomputeRunsRepository(db)
	now := time.Now().UTC()
	run := &governance.GovernanceRecomputeRun{
		ID: "run-foreign", OrganizationID: "other", Kind: governance.RecomputeKindOwnership,
		StartedAt: now, Actor: "op", ActorKind: governance.RecomputeActorUser, EngineVersion: 1,
	}
	if err := runsRepo.StartRecomputeRun(ctx, run); err != nil {
		t.Fatalf("seed foreign run: %v", err)
	}

	// anchorix runs its own recompute, then lists.
	seedCertMeta(t, db, ctx, "anchorix", "cert-runs-iso", "CN=x", "CN=ca", nil)
	httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &recomputeTriggerDTO{})

	var runs struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	httpGetJSON(t, client, srvURL+"/api/v1/governance/recompute-runs?kind=ownership", &runs)
	if len(runs.Items) != 1 {
		t.Fatalf("recompute-runs = %d; want 1 (only anchorix's own run, not the foreign one)", len(runs.Items))
	}
	for _, r := range runs.Items {
		if r.ID == "run-foreign" {
			t.Fatalf("foreign-org recompute run leaked into anchorix list")
		}
	}
}

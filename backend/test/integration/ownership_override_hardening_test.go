//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// hookedTransactor wraps the real *postgres.DB transactor and runs a
// one-shot hook the first time WithTxLockedOwnership is entered —
// i.e. AFTER the override mutation's prechecks but BEFORE the locked
// transaction body. That lets a test deterministically inject the
// concurrent state change that the precheck→tx window allows, without
// real goroutine racing. The hook fires exactly once.
type hookedTransactor struct {
	*postgres.DB
	once sync.Once
	hook func()
}

func (h *hookedTransactor) WithTxLockedOwnership(ctx context.Context, org string, fn func(ctx context.Context) error) error {
	h.once.Do(func() {
		if h.hook != nil {
			h.hook()
		}
	})
	return h.DB.WithTxLockedOwnership(ctx, org, fn)
}

// ownershipServiceHooked builds an ownership.Service whose transactor
// fires `hook` in the precheck→locked-tx window of the first
// override mutation.
func ownershipServiceHooked(t *testing.T, db *postgres.DB, hook func()) *ownership.Service {
	t.Helper()
	repo := &governance.Repo{
		Ownership:     postgres.NewOwnershipRepository(db),
		Policy:        postgres.NewPolicyRepository(db),
		RecomputeRuns: postgres.NewGovernanceRecomputeRunsRepository(db),
	}
	svc, err := ownership.NewService(repo, &hookedTransactor{DB: db, hook: hook}, postgres.NewAuditRecorder(db, clock.System{}),
		clock.System{}, postgres.NewOwnershipRuleTargetResolver(db), ownership.ServiceConfig{})
	if err != nil {
		t.Fatalf("ownership.NewService: %v", err)
	}
	return svc
}

// TestOverrideCreateRaceActiveOverrideAppears proves the precheck→tx
// window for a duplicate override is closed by the active
// partial-unique index: if an active override appears after
// CreateOverride's prechecks but before its locked tx, the create
// fails closed with the deterministic ErrOverrideConflict (→ 409) and
// emits no audit. (CreateOverride does no pre-tx override existence
// check — the index is the sole, race-proof gate.)
func TestOverrideCreateRaceActiveOverrideAppears(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-race")
	seedCertMeta(t, db, ctx, "anchorix", "cert-race", "CN=x", "CN=ca", nil)

	// The hook inserts a competing active override in the window.
	svc := ownershipServiceHooked(t, db, func() {
		if err := execRawSQL(ctx, db, rawStmt{
			`INSERT INTO certificate_ownership_overrides (id, organization_id, certificate_id, service_id, reason, set_by, set_at)
			   VALUES ('ovr-winner','anchorix','cert-race','svc-race','first','op',now())`, nil}); err != nil {
			t.Errorf("hook insert: %v", err)
		}
	})

	_, err := svc.CreateOverride(ctx, ownership.CreateOverrideInput{
		OrganizationID: "anchorix", ActorUserID: "op", CertificateID: "cert-race",
		ServiceID: "svc-race", Reason: "second",
	})
	if err == nil || !strings.Contains(err.Error(), "active override already exists") {
		t.Fatalf("CreateOverride err = %v; want ErrOverrideConflict", err)
	}
	// Exactly one active override (the racer); the loser rolled back.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE certificate_id='cert-race' AND cleared_at IS NULL`); n != 1 {
		t.Fatalf("active overrides = %d; want 1 (loser must roll back)", n)
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE id='ovr-winner'`); n != 1 {
		t.Fatalf("winner override missing: %d", n)
	}
	// The losing create emitted no audit.
	if n := auditCount(t, db, ctx, "anchorix", "ownership.overridden"); n != 0 {
		t.Fatalf("overridden audit = %d; want 0 (conflict must not audit)", n)
	}
}

// TestOverrideCreateConcurrentDuplicateDeterministic runs two
// CreateOverride calls for the same cert concurrently and asserts
// exactly one wins (201-equivalent: returns the override) and the
// other gets the deterministic conflict — never two active rows,
// never a 500.
func TestOverrideCreateConcurrentDuplicateDeterministic(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-conc")
	seedCertMeta(t, db, ctx, "anchorix", "cert-conc", "CN=x", "CN=ca", nil)
	svc := ownershipService(t, db, 0)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = svc.CreateOverride(ctx, ownership.CreateOverrideInput{
				OrganizationID: "anchorix", ActorUserID: "op", CertificateID: "cert-conc",
				ServiceID: "svc-conc", Reason: "concurrent",
			})
		}(i)
	}
	wg.Wait()

	okCount, conflictCount := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			okCount++
		case strings.Contains(err.Error(), "active override already exists"):
			conflictCount++
		default:
			t.Fatalf("unexpected concurrent err = %v; want nil or conflict (no 500)", err)
		}
	}
	if okCount != 1 || conflictCount != 1 {
		t.Fatalf("concurrent results: ok=%d conflict=%d; want exactly 1/1", okCount, conflictCount)
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE certificate_id='cert-conc' AND cleared_at IS NULL`); n != 1 {
		t.Fatalf("active overrides = %d; want exactly 1", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.overridden"); n != 1 {
		t.Fatalf("overridden audit = %d; want exactly 1 (winner only)", n)
	}
}

// TestOverrideClearRaceOverrideClearedInWindow proves the
// precheck→tx window for clear is closed by the row-count guard: if
// the active override is cleared (by auto-expiry / another clear)
// after ClearOverride's GetActiveOwnershipOverride precheck but before
// its locked clear, the in-tx ClearOwnershipOverride affects zero rows
// → ErrOverrideCertNotFound (→ 404), no audit, no 500.
func TestOverrideClearRaceOverrideClearedInWindow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-clr")
	seedCertMeta(t, db, ctx, "anchorix", "cert-clr", "CN=x", "CN=ca", nil)
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO certificate_ownership_overrides (id, organization_id, certificate_id, service_id, reason, set_by, set_at)
		   VALUES ('ovr-clr','anchorix','cert-clr','svc-clr','pin','op',now())`, nil}); err != nil {
		t.Fatalf("seed override: %v", err)
	}

	// Hook clears the override out from under the locked clear.
	svc := ownershipServiceHooked(t, db, func() {
		if err := execRawSQL(ctx, db, rawStmt{
			`UPDATE certificate_ownership_overrides SET cleared_at=now(), cleared_by='system', cleared_reason='auto-expired' WHERE id='ovr-clr'`, nil}); err != nil {
			t.Errorf("hook clear: %v", err)
		}
	})

	_, err := svc.ClearOverride(ctx, ownership.ClearOverrideInput{
		OrganizationID: "anchorix", ActorUserID: "op", CertificateID: "cert-clr", Reason: "operator clear",
	})
	if err == nil || !strings.Contains(err.Error(), "override certificate not found") {
		t.Fatalf("ClearOverride err = %v; want ErrOverrideCertNotFound (lost race → 404)", err)
	}
	// The operator clear emitted no audit (it lost the race).
	if n := auditCount(t, db, ctx, "anchorix", "ownership.override_cleared"); n != 0 {
		t.Fatalf("override_cleared audit = %d; want 0 (lost-race clear must not audit)", n)
	}
}

// TestOverrideCreateRaceServiceDisabledInWindow documents the
// accepted eventual-consistency behavior when the pinned service is
// disabled in the precheck→tx window: the override still commits
// (DisableService's preflight does not block on overrides, and the
// override table has no active-service FK), and the create succeeds
// with its audit. This is by design — an explicit operator override
// outranks service-active state, and a disabled service surfaces via
// findings/recompute, not by silently dropping the pin. The test pins
// the behavior so a future change is a conscious decision.
func TestOverrideCreateRaceServiceDisabledInWindow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-dz")
	seedCertMeta(t, db, ctx, "anchorix", "cert-dz", "CN=x", "CN=ca", nil)

	svc := ownershipServiceHooked(t, db, func() {
		if err := execRawSQL(ctx, db, rawStmt{`UPDATE services SET disabled_at=now() WHERE id='svc-dz'`, nil}); err != nil {
			t.Errorf("hook disable: %v", err)
		}
	})

	ov, err := svc.CreateOverride(ctx, ownership.CreateOverrideInput{
		OrganizationID: "anchorix", ActorUserID: "op", CertificateID: "cert-dz",
		ServiceID: "svc-dz", Reason: "pin",
	})
	if err != nil {
		t.Fatalf("CreateOverride err = %v; want success (override outranks late service-disable)", err)
	}
	if ov == nil || ov.ServiceID != "svc-dz" {
		t.Fatalf("override = %+v; want pinned to svc-dz", ov)
	}
	if dec, s := overrideDecisionService(t, db, ctx, "anchorix", "cert-dz"); dec != "overridden" || s != "svc-dz" {
		t.Fatalf("ownership = %s/%s; want overridden/svc-dz", dec, s)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.overridden"); n != 1 {
		t.Fatalf("overridden audit = %d; want 1", n)
	}
}

// TestOverrideCreateRaceCertDeletedInWindow proves the create path
// fails closed and rolls back fully when the target cert is deleted in
// the precheck→tx window. Note the gate that actually fires: because
// certificate_ownership_overrides has a composite FK to certificates
// with ON DELETE CASCADE, deleting the cert removes any rows and the
// subsequent override INSERT fails the FK inside the locked tx — so
// the mutation aborts BEFORE rederiveCertificate runs. Either way the
// whole tx rolls back (no override row, no ownership row, no audit),
// which is the property that matters here. rederiveCertificate's own
// nil-signal fail-closed branch is covered directly by the white-box
// unit test TestRederiveCertificateFailsClosedOnMissingSignals in
// internal/governance/ownership (it is unreachable via the service
// entry points precisely because of this FK cascade).
func TestOverrideCreateRaceCertDeletedInWindow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-del")
	seedCertMeta(t, db, ctx, "anchorix", "cert-del", "CN=x", "CN=ca", nil)

	svc := ownershipServiceHooked(t, db, func() {
		// Deleting the cert cascades to any override rows; the
		// in-tx override INSERT then fails its composite FK.
		if err := execRawSQL(ctx, db, rawStmt{`DELETE FROM certificates WHERE id='cert-del'`, nil}); err != nil {
			t.Errorf("hook delete cert: %v", err)
		}
	})

	_, err := svc.CreateOverride(ctx, ownership.CreateOverrideInput{
		OrganizationID: "anchorix", ActorUserID: "op", CertificateID: "cert-del",
		ServiceID: "svc-del", Reason: "pin",
	})
	if err == nil {
		t.Fatalf("CreateOverride succeeded despite cert deletion mid-tx; want failure")
	}
	// Everything rolled back: no override, no ownership, no audit. (The
	// cert itself is gone — the cascade also removed it from
	// certificates — so we assert on the override/ownership/audit rows.)
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership_overrides WHERE certificate_id='cert-del'`); n != 0 {
		t.Fatalf("override row persisted despite rollback: %d", n)
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE certificate_id='cert-del'`); n != 0 {
		t.Fatalf("ownership row persisted despite rollback: %d", n)
	}
	if n := auditCount(t, db, ctx, "anchorix", "ownership.overridden"); n != 0 {
		t.Fatalf("overridden audit = %d; want 0", n)
	}
}

// overrideDecisionService reads decision + service for a cert.
func overrideDecisionService(t *testing.T, db *postgres.DB, ctx context.Context, org, certID string) (string, string) {
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

// TestOverrideCreateNoFleetScanExplain pins that the override create
// path touches only the target certificate's rows — no fleet-wide
// scan. We seed many certs, create one override, and assert that
// exactly one certificate_ownership row and one explanation row were
// produced/updated for the target, and none for the others.
func TestOverrideCreateTargetOnlyAcrossManyCerts(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	seedService(t, db, ctx, "svc-many")
	// 50 certs, none yet evaluated (no recompute run).
	for i := 0; i < 50; i++ {
		seedCertMeta(t, db, ctx, "anchorix", "cert-many-"+padInt(i), "CN=x", "CN=ca", nil)
	}
	srvURL, client := ownershipServer(t, db)

	status, body := httpJSONWithBody(t, client, http.MethodPost, srvURL+"/api/v1/certificates/cert-many-"+padInt(7)+"/ownership/override",
		`{"service_id":"svc-many","reason":"pin one"}`)
	if status != http.StatusCreated {
		t.Fatalf("create override status=%d body=%s; want 201", status, body)
	}
	// Only the target got an ownership + explanation row.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix'`); n != 1 {
		t.Fatalf("certificate_ownership rows = %d; want 1 (target only — no fleet sweep)", n)
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_match_explanations WHERE organization_id='anchorix'`); n != 1 {
		t.Fatalf("explanation rows = %d; want 1 (target only)", n)
	}
	if dec, _ := overrideDecisionService(t, db, ctx, "anchorix", "cert-many-"+padInt(7)); dec != "overridden" {
		t.Fatalf("target decision = %s; want overridden", dec)
	}
}

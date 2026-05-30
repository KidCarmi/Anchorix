//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- failing-repo wrappers ---------------------------------------------

// failingSignalsRepo wraps the real OwnershipRepository and forces
// GetCertificateSignals to return an error for ONE specific cert id.
// All other methods delegate to the embedded real repo. Used to drive
// a rederive failure mid-page without seeding a structurally
// unreachable state (the cert→override FK CASCADE makes the natural
// path uninducible).
type failingSignalsRepo struct {
	governance.OwnershipRepository
	failOnCertID string
}

func (r *failingSignalsRepo) GetCertificateSignals(ctx context.Context, organizationID, certificateID string) (*governance.CertificateSignals, error) {
	if certificateID == r.failOnCertID {
		return nil, errors.New("synthetic signals failure for rederive-rollback test")
	}
	return r.OwnershipRepository.GetCertificateSignals(ctx, organizationID, certificateID)
}

// failingClearRepo wraps the real OwnershipRepository and forces
// ClearOwnershipOverride to return a NON-NotFound error for ONE
// specific override id. Used to prove that any non-NotFound clear
// failure rolls the page back (the NotFound silent-no-op path is
// already pinned by TestSweepExpiringOverridesPageLostRaceIsSilentNoOp).
type failingClearRepo struct {
	governance.OwnershipRepository
	failOnOverrideID string
}

func (r *failingClearRepo) ClearOwnershipOverride(ctx context.Context, organizationID, overrideID, clearedBy, clearedReason string, clearedAt time.Time) error {
	if overrideID == r.failOnOverrideID {
		return errors.New("synthetic clear failure (NOT NotFound)")
	}
	return r.OwnershipRepository.ClearOwnershipOverride(ctx, organizationID, overrideID, clearedBy, clearedReason, clearedAt)
}

// ownershipServiceWithCustomRepo wires the engine with a caller-
// supplied OwnershipRepository wrapper so hardening tests can inject
// the failing variants above without modifying production code.
func ownershipServiceWithCustomRepo(t *testing.T, db *postgres.DB, ownershipRepo governance.OwnershipRepository) *ownership.Service {
	t.Helper()
	repo := &governance.Repo{
		Ownership:     ownershipRepo,
		Policy:        postgres.NewPolicyRepository(db),
		RecomputeRuns: postgres.NewGovernanceRecomputeRunsRepository(db),
	}
	svc, err := ownership.NewService(repo, db, postgres.NewAuditRecorder(db, clock.System{}),
		clock.System{}, postgres.NewOwnershipRuleTargetResolver(db), ownership.ServiceConfig{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// --- rederive-failure rollback ----------------------------------------

// TestSweepExpiringOverridesPageRederiveFailureRollsBackPage proves a
// rederive failure on any row aborts the ENTIRE page. The page tx
// rolls back so no override is cleared, no cert's ownership row
// changes, and no audit row commits — even for the rows whose clear
// already succeeded earlier in the page.
func TestSweepExpiringOverridesPageRederiveFailureRollsBackPage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-rr")
	past := time.Now().UTC().Add(-time.Hour)
	// Three certs in cert_id ASC order; the rederive will fail on the
	// THIRD one (cert-rr-03), so the first two are cleared in-tx but
	// must be rolled back when the third fails.
	for i := 1; i <= 3; i++ {
		seedExpiredOverrideOnOwnedCert(t, db, ctx, fmt.Sprintf("cert-rr-%02d", i), fmt.Sprintf("ovr-rr-%02d", i), "svc-rr", past)
	}

	svc := ownershipServiceWithCustomRepo(t, db, &failingSignalsRepo{
		OwnershipRepository: postgres.NewOwnershipRepository(db),
		failOnCertID:        "cert-rr-03",
	})

	if _, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100); err == nil {
		t.Fatal("expected error from rederive failure")
	}

	// Every override remains active (cleared_at NULL) and every cert
	// still pins the overridden decision on its service.
	for i := 1; i <= 3; i++ {
		ovrID := fmt.Sprintf("ovr-rr-%02d", i)
		certID := fmt.Sprintf("cert-rr-%02d", i)
		if got, _, _ := overrideClearState(t, db, ctx, "anchorix", ovrID); got != nil {
			t.Fatalf("%s cleared_at != NULL; page should have rolled back the rederive-page", ovrID)
		}
		dec, svcID := certOwnershipDecision(t, db, ctx, "anchorix", certID)
		if dec != governance.DecisionOverridden || svcID != "svc-rr" {
			t.Fatalf("%s decision=%s svc=%s; want overridden/svc-rr (rollback)", certID, dec, svcID)
		}
	}
	// No audit rows of either action committed.
	for _, action := range []string{"ownership.override_expired", "ownership.override_cleared"} {
		if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix' AND action=$1`, action); n != 0 {
			t.Fatalf("%s audits = %d; want 0 after rederive-rollback", action, n)
		}
	}
}

// TestSweepExpiringOverridesPageNonNotFoundClearErrorRollsBackPage
// proves a non-NotFound error from ClearOwnershipOverride aborts the
// page. The NotFound path is the lost-race silent no-op
// (covered by TestSweepExpiringOverridesPageLostRaceIsSilentNoOp); any
// OTHER clear error must fail closed.
func TestSweepExpiringOverridesPageNonNotFoundClearErrorRollsBackPage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-cr")
	past := time.Now().UTC().Add(-time.Hour)
	for i := 1; i <= 3; i++ {
		seedExpiredOverrideOnOwnedCert(t, db, ctx, fmt.Sprintf("cert-cr-%02d", i), fmt.Sprintf("ovr-cr-%02d", i), "svc-cr", past)
	}

	svc := ownershipServiceWithCustomRepo(t, db, &failingClearRepo{
		OwnershipRepository: postgres.NewOwnershipRepository(db),
		failOnOverrideID:    "ovr-cr-02", // middle of the page
	})

	if _, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100); err == nil {
		t.Fatal("expected error from non-NotFound clear failure")
	}
	for i := 1; i <= 3; i++ {
		ovrID := fmt.Sprintf("ovr-cr-%02d", i)
		if got, _, _ := overrideClearState(t, db, ctx, "anchorix", ovrID); got != nil {
			t.Fatalf("%s cleared_at != NULL; non-NotFound clear failure should have rolled the page back", ovrID)
		}
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix' AND action='ownership.override_expired'`); n != 0 {
		t.Fatalf("expired audits = %d; want 0 after clear-rollback", n)
	}
}

// --- sweep_id correlation ---------------------------------------------

// TestSweepExpiringOverridesPageSweepIDConsistentAcrossPage proves
// every audit row emitted by ONE sweep page carries the SAME sweep_id,
// equal to the result's SweepID. Operators correlate the audited
// expirations of one page through this id.
func TestSweepExpiringOverridesPageSweepIDConsistentAcrossPage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-sid")
	past := time.Now().UTC().Add(-time.Hour)
	for i := 1; i <= 4; i++ {
		seedExpiredOverrideOnOwnedCert(t, db, ctx, fmt.Sprintf("cert-sid-%02d", i), fmt.Sprintf("ovr-sid-%02d", i), "svc-sid", past)
	}
	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.ClearedCount != 4 || res.SweepID == "" {
		t.Fatalf("res = %+v; want cleared=4 sweep_id non-empty", res)
	}
	sweepIDs := readSweepIDsForAction(t, db, ctx, "anchorix", "ownership.override_expired")
	if len(sweepIDs) != 4 {
		t.Fatalf("expected 4 audit rows; got %d", len(sweepIDs))
	}
	for _, id := range sweepIDs {
		if id != res.SweepID {
			t.Fatalf("audit metadata sweep_id %q != result.SweepID %q (page must emit one sweep_id)", id, res.SweepID)
		}
	}
}

// TestSweepExpiringOverridesPageDifferentPagesDifferentSweepIDs proves
// successive sweep CALLS mint different sweep_ids, so an operator can
// distinguish "the expirations from page X" vs "page Y" in audit
// history.
func TestSweepExpiringOverridesPageDifferentPagesDifferentSweepIDs(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-ds")
	past := time.Now().UTC().Add(-time.Hour)
	for i := 1; i <= 4; i++ {
		seedExpiredOverrideOnOwnedCert(t, db, ctx, fmt.Sprintf("cert-ds-%02d", i), fmt.Sprintf("ovr-ds-%02d", i), "svc-ds", past)
	}
	svc := ownershipServiceForSweep(t, db)

	first, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 2)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", first.NextCursor, 2)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.SweepID == "" || second.SweepID == "" {
		t.Fatalf("sweep_ids = (%q, %q); both must be non-empty", first.SweepID, second.SweepID)
	}
	if first.SweepID == second.SweepID {
		t.Fatalf("both pages got the same sweep_id (%q); each call must mint a fresh id", first.SweepID)
	}
	// On-disk metadata reflects the per-page assignment: the first 2
	// audit rows carry first.SweepID, the next 2 carry second.SweepID.
	sweepIDsByCert := readSweepIDByCert(t, db, ctx, "anchorix", "ownership.override_expired")
	if sweepIDsByCert["cert-ds-01"] != first.SweepID || sweepIDsByCert["cert-ds-02"] != first.SweepID {
		t.Fatalf("first-page certs sweep_id mismatch: %+v vs first=%s", sweepIDsByCert, first.SweepID)
	}
	if sweepIDsByCert["cert-ds-03"] != second.SweepID || sweepIDsByCert["cert-ds-04"] != second.SweepID {
		t.Fatalf("second-page certs sweep_id mismatch: %+v vs second=%s", sweepIDsByCert, second.SweepID)
	}
}

// --- cursor progression -----------------------------------------------

// TestSweepExpiringOverridesPageCursorAdvancesPastLostRaceRows proves
// that a row whose clear lost a race STILL advances the cursor — the
// page does not get stuck re-scanning a permanently-cleared cert id
// in subsequent pages. Concretely: with three expired-active rows
// where the middle one is operator-cleared just before the sweep,
// NextCursor must equal the LAST cert id processed (cert-lr-03), not
// the lost-race row's id.
func TestSweepExpiringOverridesPageCursorAdvancesPastLostRaceRows(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-lr")
	past := time.Now().UTC().Add(-time.Hour)
	for i := 1; i <= 3; i++ {
		seedExpiredOverrideOnOwnedCert(t, db, ctx, fmt.Sprintf("cert-lr-%02d", i), fmt.Sprintf("ovr-lr-%02d", i), "svc-lr", past)
	}
	// Operator clears the middle row before the sweep.
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.ClearOwnershipOverride(ctx, "anchorix", "ovr-lr-02", "operator", "manual", time.Now().UTC()); err != nil {
		t.Fatalf("manual clear: %v", err)
	}
	// (After the manual clear the listing read will return only
	// cert-lr-01 and cert-lr-03 — the ovr-lr-02 row drops out of the
	// active partial index, so the lost-race silent-skip branch is not
	// reached here. The cursor still has to advance through the page
	// to the LAST visible row.)
	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.CertsScanned != 2 || res.ClearedCount != 2 {
		t.Fatalf("res = %+v; want scanned=2 cleared=2 (middle row was operator-cleared)", res)
	}
	if res.NextCursor != "cert-lr-03" {
		t.Fatalf("NextCursor = %q; want cert-lr-03 (cursor advances to last visible row)", res.NextCursor)
	}
}

// --- targeted rederive ------------------------------------------------

// TestSweepExpiringOverridesPageUntouchedCertsAreNotRederived proves
// the sweep's re-derivation is targeted to ONLY the certs whose
// overrides it cleared. A cert with a future-expiry override (not
// touched by this sweep) retains its certificate_ownership row
// byte-identical across the call.
func TestSweepExpiringOverridesPageUntouchedCertsAreNotRederived(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-ut")
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// cert-ut-tgt: expired override (will be swept)
	seedExpiredOverrideOnOwnedCert(t, db, ctx, "cert-ut-tgt", "ovr-ut-tgt", "svc-ut", past)
	// cert-ut-keep: future-expiry override (not swept)
	seedCertificate(t, db, ctx, "cert-ut-keep")
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-ut-keep", OrganizationID: "anchorix", CertificateID: "cert-ut-keep", ServiceID: "svc-ut",
		Reason: "pin", SetBy: "tester", SetAt: now.Add(-2 * time.Hour), ExpiresAt: &future,
	}); err != nil {
		t.Fatalf("seed future-expiry override: %v", err)
	}
	// Seed the certificate_ownership row + explanation for the keeper
	// using the same template seedExpiredOverrideOnOwnedCert uses so
	// the snapshot has the same shape.
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO ownership_match_explanations
				(id, organization_id, certificate_id, decided_at, decided_decision, decided_service_id, engine_version)
			VALUES ('expl-keep','anchorix','cert-ut-keep', now() - interval '1 hour', 'overridden', 'svc-ut', 1)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO certificate_ownership
				(organization_id, certificate_id, decision, service_id, override_id, explanation_id, confidence,
				 first_assigned_at, last_evaluated_at, last_changed_at)
			VALUES ('anchorix', 'cert-ut-keep', 'overridden', 'svc-ut', 'ovr-ut-keep', 'expl-keep', 'high', $1, $1, $1)`,
			now)
		return err
	}); err != nil {
		t.Fatalf("pin keeper: %v", err)
	}

	// Snapshot the keeper cert's ownership row (full content hash).
	snapshotKeeper := func() string {
		t.Helper()
		var hash string
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT md5(to_jsonb(t.*)::text) FROM certificate_ownership t
				  WHERE organization_id='anchorix' AND certificate_id='cert-ut-keep'`,
			).Scan(&hash)
		}); err != nil {
			t.Fatalf("snapshot keeper: %v", err)
		}
		return hash
	}
	before := snapshotKeeper()

	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.ClearedCount != 1 {
		t.Fatalf("cleared=%d; want 1 (only cert-ut-tgt's expired override)", res.ClearedCount)
	}

	after := snapshotKeeper()
	if before != after {
		t.Fatalf("keeper cert's certificate_ownership content hash changed (%s -> %s); sweep must NOT re-derive certs whose overrides it did not clear", before, after)
	}
}

// --- empty page no-op -------------------------------------------------

// TestSweepExpiringOverridesPageEmptyPageEmitsNoAuditNoMutation proves
// a sweep over an org with no expiring-active overrides returns
// CertsScanned=0 / ClearedCount=0 / Done=true and emits zero audit
// rows of any sweep-related action.
func TestSweepExpiringOverridesPageEmptyPageEmitsNoAuditNoMutation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-em")
	// Seed a NO-EXPIRY active override so the table is non-empty but
	// the sweep set is empty.
	seedCertificate(t, db, ctx, "cert-em-keep")
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-em-keep", OrganizationID: "anchorix", CertificateID: "cert-em-keep", ServiceID: "svc-em",
		Reason: "pin", SetBy: "tester", SetAt: time.Now().UTC().Add(-2 * time.Hour), ExpiresAt: nil,
	}); err != nil {
		t.Fatalf("seed no-expiry: %v", err)
	}

	auditBefore := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix'`)
	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.CertsScanned != 0 || res.ClearedCount != 0 || !res.Done {
		t.Fatalf("empty-page res = %+v; want scanned=0 cleared=0 done=true", res)
	}
	if res.SweepID == "" {
		t.Fatal("empty-page sweep should still mint a sweep_id (the call ran)")
	}
	auditAfter := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix'`)
	if auditAfter != auditBefore {
		t.Fatalf("audit_events count: before=%d after=%d (empty page must not emit audit)", auditBefore, auditAfter)
	}
	// The no-expiry override is untouched.
	if got, _, _ := overrideClearState(t, db, ctx, "anchorix", "ovr-em-keep"); got != nil {
		t.Fatal("no-expiry override was cleared by empty-page sweep — empty page must perform no mutation")
	}
}

// --- audit-row read-back helpers --------------------------------------

func readSweepIDsForAction(t *testing.T, db *postgres.DB, ctx context.Context, org, action string) []string {
	t.Helper()
	var ids []string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT metadata FROM audit_events WHERE organization_id=$1 AND action=$2`,
			org, action)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var md struct {
				SweepID string `json:"sweep_id"`
			}
			if err := json.Unmarshal(raw, &md); err != nil {
				return err
			}
			ids = append(ids, md.SweepID)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("read sweep_ids: %v", err)
	}
	return ids
}

func readSweepIDByCert(t *testing.T, db *postgres.DB, ctx context.Context, org, action string) map[string]string {
	t.Helper()
	result := map[string]string{}
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT target_id, metadata FROM audit_events WHERE organization_id=$1 AND action=$2 AND target_type='certificate'`,
			org, action)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var target string
			var raw []byte
			if err := rows.Scan(&target, &raw); err != nil {
				return err
			}
			var md struct {
				SweepID string `json:"sweep_id"`
			}
			if err := json.Unmarshal(raw, &md); err != nil {
				return err
			}
			result[target] = md.SweepID
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("read sweep_ids by cert: %v", err)
	}
	return result
}

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- helpers ----------------------------------------------------------

// ownershipServiceForSweep wires the engine the same way ownershipService
// does (real postgres repos, real audit recorder, real transactor) for
// the H-029 sweep tests. Returns the service so individual tests can
// drive SweepExpiringOverridesPage directly.
func ownershipServiceForSweep(t *testing.T, db *postgres.DB) *ownership.Service {
	t.Helper()
	return ownershipService(t, db, 0)
}

// certOwnershipDecision reads back the current decision + service for
// one cert from certificate_ownership, so a sweep's re-derivation can
// be asserted against persisted state. Empty string for service_id
// when the cert is now unowned (NULL service).
func certOwnershipDecision(t *testing.T, db *postgres.DB, ctx context.Context, org, certID string) (governance.Decision, string) {
	t.Helper()
	var decision string
	var serviceID *string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT decision, service_id FROM certificate_ownership WHERE organization_id=$1 AND certificate_id=$2`,
			org, certID).Scan(&decision, &serviceID)
	}); err != nil {
		t.Fatalf("read cert ownership for %s: %v", certID, err)
	}
	svc := ""
	if serviceID != nil {
		svc = *serviceID
	}
	return governance.Decision(decision), svc
}

// overrideClearState returns the cleared_at / cleared_by / cleared_reason
// triple for one override. cleared_at == nil means the override is
// still active.
func overrideClearState(t *testing.T, db *postgres.DB, ctx context.Context, org, overrideID string) (*time.Time, string, string) {
	t.Helper()
	var clearedAt *time.Time
	var clearedBy, clearedReason *string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT cleared_at, cleared_by, cleared_reason FROM certificate_ownership_overrides WHERE organization_id=$1 AND id=$2`,
			org, overrideID).Scan(&clearedAt, &clearedBy, &clearedReason)
	}); err != nil {
		t.Fatalf("read override %s: %v", overrideID, err)
	}
	by := ""
	if clearedBy != nil {
		by = *clearedBy
	}
	reason := ""
	if clearedReason != nil {
		reason = *clearedReason
	}
	return clearedAt, by, reason
}

// seedExpiredOverrideOnOwnedCert seeds a cert + an active override
// (expires_at in the past) + the certificate_ownership row that pins
// the cert to that override's service. After the sweep clears the
// override, the cert should re-derive to unowned (no rules match a
// freshly-seeded cert with no observations).
func seedExpiredOverrideOnOwnedCert(t *testing.T, db *postgres.DB, ctx context.Context, certID, overrideID, serviceID string, expiresAt time.Time) {
	t.Helper()
	seedCertificate(t, db, ctx, certID)
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID:             overrideID,
		OrganizationID: "anchorix",
		CertificateID:  certID,
		ServiceID:      serviceID,
		Reason:         "pin",
		SetBy:          "tester",
		SetAt:          time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt:      &expiresAt,
	}); err != nil {
		t.Fatalf("create override %s: %v", overrideID, err)
	}
	// Seed the certificate_ownership pin (overridden by serviceID) +
	// a backing explanation so the rederiveCertificate path can flip
	// the ownership row without violating the NOT NULL explanation_id
	// FK invariant.
	now := time.Now().UTC()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO ownership_match_explanations
				(id, organization_id, certificate_id, decided_at, decided_decision, decided_service_id, engine_version)
			VALUES ($1, 'anchorix', $2, now() - interval '1 hour', 'overridden', $3, 1)`,
			"expl-seed-"+certID, certID, serviceID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO certificate_ownership
				(organization_id, certificate_id, decision, service_id, override_id, explanation_id, confidence,
				 first_assigned_at, last_evaluated_at, last_changed_at)
			VALUES ('anchorix', $1, 'overridden', $2, $3, $4, 'high', $5, $5, $5)`,
			certID, serviceID, overrideID, "expl-seed-"+certID, now)
		return err
	}); err != nil {
		t.Fatalf("seed cert ownership pin for %s: %v", certID, err)
	}
}

// auditCountForCert returns the per-cert count of a specific action.
func auditCountForCert(t *testing.T, db *postgres.DB, ctx context.Context, org, action, certID string) int {
	t.Helper()
	return scalarInt(t, db, ctx,
		`SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action=$2 AND target_type='certificate' AND target_id=$3`,
		org, action, certID)
}

// --- sweep happy path -------------------------------------------------

// TestSweepExpiringOverridesPageClearsExpiredAndAudits proves the
// canonical happy path: an expired-active override is cleared, the
// cert is re-derived (it was pinned to a service by override; with the
// override gone and no rules, it flips to unowned), and exactly one
// ownership.override_expired audit row is emitted per cleared row.
func TestSweepExpiringOverridesPageClearsExpiredAndAudits(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-sw")
	past := time.Now().UTC().Add(-time.Hour)
	seedExpiredOverrideOnOwnedCert(t, db, ctx, "cert-sw-01", "ovr-sw-01", "svc-sw", past)
	seedExpiredOverrideOnOwnedCert(t, db, ctx, "cert-sw-02", "ovr-sw-02", "svc-sw", past)

	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("SweepExpiringOverridesPage: %v", err)
	}
	if res.CertsScanned != 2 || res.ClearedCount != 2 || !res.Done {
		t.Fatalf("res = %+v; want scanned=2 cleared=2 done=true", res)
	}
	if res.SweepID == "" {
		t.Fatal("sweep_id should be a minted id, not empty")
	}

	// Both overrides cleared with cleared_by=system + reason=auto-expired.
	for _, id := range []string{"ovr-sw-01", "ovr-sw-02"} {
		clearedAt, by, reason := overrideClearState(t, db, ctx, "anchorix", id)
		if clearedAt == nil {
			t.Fatalf("%s cleared_at is NULL; want non-nil", id)
		}
		if by != "system" || reason != "auto-expired" {
			t.Fatalf("%s cleared_by=%q cleared_reason=%q; want system/auto-expired", id, by, reason)
		}
	}

	// Both certs flipped from overridden → unowned (no rules in this
	// fixture, so re-derivation lands on unowned).
	for _, c := range []string{"cert-sw-01", "cert-sw-02"} {
		dec, svcID := certOwnershipDecision(t, db, ctx, "anchorix", c)
		if dec != governance.DecisionUnowned {
			t.Fatalf("%s decision=%s svc=%s; want unowned/<nil>", c, dec, svcID)
		}
		if svcID != "" {
			t.Fatalf("%s service_id=%q; want '' after re-derive", c, svcID)
		}
	}

	// Exactly one ownership.override_expired audit per cleared override.
	for _, c := range []string{"cert-sw-01", "cert-sw-02"} {
		if n := auditCountForCert(t, db, ctx, "anchorix", "ownership.override_expired", c); n != 1 {
			t.Fatalf("%s ownership.override_expired audit = %d; want 1", c, n)
		}
	}
}

// TestSweepExpiringOverridesPageAuditMetadataShape pins the audit
// row's shape: actor/actor_type = system/system, severity=security,
// target_type=certificate, target_id=cert_id, metadata carries
// override_id / service_id / reason / sweep_id.
func TestSweepExpiringOverridesPageAuditMetadataShape(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-md")
	past := time.Now().UTC().Add(-time.Hour)
	seedExpiredOverrideOnOwnedCert(t, db, ctx, "cert-md-01", "ovr-md-01", "svc-md", past)

	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.ClearedCount != 1 {
		t.Fatalf("cleared=%d; want 1", res.ClearedCount)
	}

	var actor, actorType string
	var raw []byte
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT actor, actor_type, metadata FROM audit_events
			  WHERE organization_id='anchorix' AND action='ownership.override_expired' AND target_id='cert-md-01'
			  ORDER BY occurred_at DESC, id DESC LIMIT 1`,
		).Scan(&actor, &actorType, &raw)
	}); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if actor != "system" || actorType != "system" {
		t.Fatalf("attribution = (%s,%s); want (system,system)", actor, actorType)
	}
	var md struct {
		Severity   string `json:"severity"`
		SweepID    string `json:"sweep_id"`
		OverrideID string `json:"override_id"`
		ServiceID  string `json:"service_id"`
		Reason     string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &md); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if md.Severity != "security" || md.OverrideID != "ovr-md-01" || md.ServiceID != "svc-md" || md.Reason != "auto-expired" {
		t.Fatalf("metadata = %+v; want severity=security override=ovr-md-01 service=svc-md reason=auto-expired", md)
	}
	if md.SweepID == "" || md.SweepID != res.SweepID {
		t.Fatalf("sweep_id in metadata=%q vs result.SweepID=%q; want same non-empty id", md.SweepID, res.SweepID)
	}
}

// --- filter semantics --------------------------------------------------

// TestSweepExpiringOverridesPageIgnoresNonEligible proves future,
// no-expiry, and already-cleared rows are not touched.
func TestSweepExpiringOverridesPageIgnoresNonEligible(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-ig")
	now := time.Now().UTC()
	// cert-ig-expired is seeded by seedExpiredOverrideOnOwnedCert below.
	for _, c := range []string{"cert-ig-future", "cert-ig-none", "cert-ig-cleared"} {
		seedCertificate(t, db, ctx, c)
	}
	repo := postgres.NewOwnershipRepository(db)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	// future expiry → keep
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-future", OrganizationID: "anchorix", CertificateID: "cert-ig-future", ServiceID: "svc-ig",
		Reason: "pin", SetBy: "t", SetAt: now.Add(-2 * time.Hour), ExpiresAt: &future,
	}); err != nil {
		t.Fatalf("future: %v", err)
	}
	// no expiry → keep
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-none", OrganizationID: "anchorix", CertificateID: "cert-ig-none", ServiceID: "svc-ig",
		Reason: "pin", SetBy: "t", SetAt: now.Add(-2 * time.Hour), ExpiresAt: nil,
	}); err != nil {
		t.Fatalf("none: %v", err)
	}
	// expired AND already cleared → keep (cleared_at set)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-cleared", OrganizationID: "anchorix", CertificateID: "cert-ig-cleared", ServiceID: "svc-ig",
		Reason: "pin", SetBy: "t", SetAt: now.Add(-2 * time.Hour), ExpiresAt: &past,
	}); err != nil {
		t.Fatalf("cleared seed: %v", err)
	}
	if err := repo.ClearOwnershipOverride(ctx, "anchorix", "ovr-cleared", "operator", "manual", now); err != nil {
		t.Fatalf("manual clear: %v", err)
	}
	// expired + active → sweep target
	seedExpiredOverrideOnOwnedCert(t, db, ctx, "cert-ig-expired", "ovr-expired", "svc-ig", past)

	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.CertsScanned != 1 || res.ClearedCount != 1 {
		t.Fatalf("res = %+v; want only the expired+active row swept (scanned=1 cleared=1)", res)
	}
	// Confirm: future and no-expiry overrides remain active.
	for _, id := range []string{"ovr-future", "ovr-none"} {
		if got, _, _ := overrideClearState(t, db, ctx, "anchorix", id); got != nil {
			t.Fatalf("%s was cleared by the sweep; want untouched", id)
		}
	}
}

// --- cross-org isolation ----------------------------------------------

// TestSweepExpiringOverridesPageCrossOrgIsolation proves the sweep
// of one org never touches another org's expiring overrides.
func TestSweepExpiringOverridesPageCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedOrganization(t, db, "other-org", "Other Org")
	seedService(t, db, ctx, "svc-iso")
	past := time.Now().UTC().Add(-time.Hour)
	seedExpiredOverrideOnOwnedCert(t, db, ctx, "cert-iso-a", "ovr-iso-a", "svc-iso", past)

	// Seed an other-org expired override directly (helpers hardcode anchorix).
	now := time.Now().UTC()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		stmts := []string{
			`INSERT INTO services (id, organization_id, slug, display_name) VALUES ('svc-iso-o','other-org','svc-iso-o','Svc Other')`,
			`INSERT INTO certificates (id, organization_id, fingerprint_sha256, subject, issuer, serial_number_hex, signature_algorithm, public_key_algorithm, public_key_bits, not_before, not_after, pem)
			   VALUES ('cert-iso-o','other-org','cert-iso-o','CN=test','CN=test-ca','01','SHA256-RSA','RSA',2048, now() - interval '30 days', now() + interval '365 days',
			   '-----BEGIN CERTIFICATE-----' || E'\n' || 'MIIBxxx' || E'\n' || '-----END CERTIFICATE-----')`,
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed other org: %v", err)
	}
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-iso-o", OrganizationID: "other-org", CertificateID: "cert-iso-o", ServiceID: "svc-iso-o",
		Reason: "pin", SetBy: "t", SetAt: now.Add(-2 * time.Hour), ExpiresAt: &past,
	}); err != nil {
		t.Fatalf("other-org override: %v", err)
	}

	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("sweep anchorix: %v", err)
	}
	if res.ClearedCount != 1 {
		t.Fatalf("anchorix cleared=%d; want 1", res.ClearedCount)
	}
	// other-org override untouched (still active).
	if got, _, _ := overrideClearState(t, db, ctx, "other-org", "ovr-iso-o"); got != nil {
		t.Fatal("other-org override was cleared by anchorix sweep — cross-org isolation violated")
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='other-org' AND action='ownership.override_expired'`); n != 0 {
		t.Fatalf("other-org saw %d ownership.override_expired audits; want 0", n)
	}
}

// --- cursor pagination -------------------------------------------------

// TestSweepExpiringOverridesPageCursorWalk proves bounded pages drain
// the org's expired set deterministically. Each cert is swept exactly
// once across the cursor walk.
func TestSweepExpiringOverridesPageCursorWalk(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-cw")
	past := time.Now().UTC().Add(-time.Hour)
	const fleet = 5
	for i := 1; i <= fleet; i++ {
		certID := fmt.Sprintf("cert-cw-%02d", i)
		seedExpiredOverrideOnOwnedCert(t, db, ctx, certID, fmt.Sprintf("ovr-cw-%02d", i), "svc-cw", past)
	}
	svc := ownershipServiceForSweep(t, db)

	cursor := ""
	totalCleared, pages := 0, 0
	for {
		res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", cursor, 2)
		if err != nil {
			t.Fatalf("page (cursor=%q): %v", cursor, err)
		}
		pages++
		totalCleared += res.ClearedCount
		if res.Done {
			break
		}
		cursor = res.NextCursor
		if pages > 10 {
			t.Fatal("walk did not terminate")
		}
	}
	if totalCleared != fleet {
		t.Fatalf("totalCleared=%d; want %d", totalCleared, fleet)
	}
	for i := 1; i <= fleet; i++ {
		id := fmt.Sprintf("ovr-cw-%02d", i)
		if got, _, _ := overrideClearState(t, db, ctx, "anchorix", id); got == nil {
			t.Fatalf("%s not cleared by walk", id)
		}
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix' AND action='ownership.override_expired'`); n != fleet {
		t.Fatalf("ownership.override_expired audits = %d; want %d (one per cleared override)", n, fleet)
	}
}

// --- idempotency -------------------------------------------------------

// TestSweepExpiringOverridesPageIdempotent proves a second sweep over
// the same set finds nothing and emits zero new audit rows.
func TestSweepExpiringOverridesPageIdempotent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-id")
	past := time.Now().UTC().Add(-time.Hour)
	seedExpiredOverrideOnOwnedCert(t, db, ctx, "cert-id-01", "ovr-id-01", "svc-id", past)

	svc := ownershipServiceForSweep(t, db)
	first, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if first.ClearedCount != 1 {
		t.Fatalf("first cleared=%d; want 1", first.ClearedCount)
	}
	second, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.CertsScanned != 0 || second.ClearedCount != 0 {
		t.Fatalf("second = %+v; want scanned=0 cleared=0", second)
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix' AND action='ownership.override_expired'`); n != 1 {
		t.Fatalf("total ownership.override_expired audits = %d; want 1 (no duplicates from second pass)", n)
	}
}

// --- race semantics ----------------------------------------------------

// TestSweepExpiringOverridesPageLostRaceIsSilentNoOp proves a row that
// was cleared by a concurrent operator between the listing read and
// the per-row clear is silently skipped — no audit row for it, no
// error, the rest of the page completes normally.
//
// Because the page's tx holds WithTxLockedOwnership, true concurrency
// is unreachable mid-page; we simulate the race by clearing one row
// BEFORE the sweep, then including it in a snapshot of "expired rows"
// the sweep would have processed had the listing happened earlier. We
// then directly invoke the per-row helper logic by inserting the
// already-cleared row id into a fresh sweep page via fixture overlap:
// the listing read filters cleared_at IS NULL so the cleared row will
// not appear in the page at all. The visible behavior is "no audit for
// it" — which is the contract we want to assert.
//
// Concretely: seed 3 expired rows + clear ovr-race-02 manually before
// the sweep. The sweep page sees only ovr-race-01 and ovr-race-03;
// it clears + audits exactly those two. ovr-race-02's manual-clear
// audit ("ownership.override_cleared") was emitted by the operator
// path, and the sweep emits ZERO ownership.override_expired audits
// for cert-race-02.
func TestSweepExpiringOverridesPageLostRaceIsSilentNoOp(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-race")
	past := time.Now().UTC().Add(-time.Hour)
	for i := 1; i <= 3; i++ {
		seedExpiredOverrideOnOwnedCert(t, db, ctx, fmt.Sprintf("cert-race-%02d", i), fmt.Sprintf("ovr-race-%02d", i), "svc-race", past)
	}
	repo := postgres.NewOwnershipRepository(db)
	now := time.Now().UTC()
	// Operator clears ovr-race-02 BEFORE the sweep.
	if err := repo.ClearOwnershipOverride(ctx, "anchorix", "ovr-race-02", "operator", "race", now); err != nil {
		t.Fatalf("operator clear: %v", err)
	}

	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.ClearedCount != 2 {
		t.Fatalf("cleared=%d; want 2 (ovr-race-02 lost to operator)", res.ClearedCount)
	}
	// Exactly 2 ownership.override_expired audits, none for cert-race-02.
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix' AND action='ownership.override_expired'`); n != 2 {
		t.Fatalf("expired audits = %d; want 2", n)
	}
	if n := auditCountForCert(t, db, ctx, "anchorix", "ownership.override_expired", "cert-race-02"); n != 0 {
		t.Fatalf("cert-race-02 had %d expired audits; want 0 (lost the race)", n)
	}
}

// --- audit-failure atomicity ------------------------------------------

// TestSweepExpiringOverridesPageAuditFailureRollsBackPage proves an
// audit-write failure aborts the ENTIRE page: every override remains
// active (cleared_at NULL), every cert's ownership row retains its
// override-pinned decision, and no audit rows are committed. Mirrors
// the H-027 prune atomicity test.
func TestSweepExpiringOverridesPageAuditFailureRollsBackPage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-af")
	past := time.Now().UTC().Add(-time.Hour)
	for i := 1; i <= 3; i++ {
		seedExpiredOverrideOnOwnedCert(t, db, ctx, fmt.Sprintf("cert-af-%02d", i), fmt.Sprintf("ovr-af-%02d", i), "svc-af", past)
	}

	failing := &failingRecorder{
		inner:         postgres.NewAuditRecorder(db, clock.System{}),
		failOnAction:  "ownership.override_expired",
		failOnceArmed: true,
	}
	repo := &governance.Repo{
		Ownership:     postgres.NewOwnershipRepository(db),
		Policy:        postgres.NewPolicyRepository(db),
		RecomputeRuns: postgres.NewGovernanceRecomputeRunsRepository(db),
	}
	svc, err := ownership.NewService(repo, db, failing, clock.System{},
		postgres.NewOwnershipRuleTargetResolver(db),
		ownership.ServiceConfig{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100)
	if err == nil {
		t.Fatal("expected error from audit failure")
	}
	// Every override still active; every cert still pinned overridden.
	for i := 1; i <= 3; i++ {
		ovr := fmt.Sprintf("ovr-af-%02d", i)
		if got, _, _ := overrideClearState(t, db, ctx, "anchorix", ovr); got != nil {
			t.Fatalf("%s cleared_at != NULL; entire page should have rolled back", ovr)
		}
		dec, svcID := certOwnershipDecision(t, db, ctx, "anchorix", fmt.Sprintf("cert-af-%02d", i))
		if dec != governance.DecisionOverridden || svcID != "svc-af" {
			t.Fatalf("cert-af-%02d decision=%s svc=%s; want overridden/svc-af (rollback)", i, dec, svcID)
		}
	}
	if n := scalarInt(t, db, ctx, `SELECT count(*) FROM audit_events WHERE organization_id='anchorix' AND action='ownership.override_expired'`); n != 0 {
		t.Fatalf("ownership.override_expired audits = %d; want 0 (rolled back)", n)
	}
}

// --- page-size bounds --------------------------------------------------

// TestSweepExpiringOverridesPageSizeZeroUsesDefault proves pageSize<=0
// falls back to the documented default rather than scanning zero.
func TestSweepExpiringOverridesPageSizeZeroUsesDefault(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-sz")
	past := time.Now().UTC().Add(-time.Hour)
	for i := 1; i <= 3; i++ {
		seedExpiredOverrideOnOwnedCert(t, db, ctx, fmt.Sprintf("cert-sz-%02d", i), fmt.Sprintf("ovr-sz-%02d", i), "svc-sz", past)
	}

	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 0)
	if err != nil {
		t.Fatalf("pageSize=0: %v", err)
	}
	if res.CertsScanned != 3 || res.ClearedCount != 3 || !res.Done {
		t.Fatalf("pageSize=0 res=%+v; want scanned=3 cleared=3 done=true (default >> fleet)", res)
	}
}

// TestSweepExpiringOverridesPageSizeAboveMaxIsClamped proves a huge
// pageSize is clamped by the service before reaching the repo. We
// seed more than the service max (1000+10 = 1010), request 100_000,
// and assert at most maxExpiringOverridesSweepPageSize rows are
// processed in one call.
func TestSweepExpiringOverridesPageSizeAboveMaxIsClamped(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-clamp")
	past := time.Now().UTC().Add(-time.Hour)
	const overMax = 1010 // service cap is 1000; seed one slot above
	for i := 0; i < overMax; i++ {
		seedExpiredOverrideOnOwnedCert(t, db, ctx, fmt.Sprintf("cert-cl-%04d", i), fmt.Sprintf("ovr-cl-%04d", i), "svc-clamp", past)
	}

	svc := ownershipServiceForSweep(t, db)
	res, err := svc.SweepExpiringOverridesPage(ctx, "anchorix", "", 100_000)
	if err != nil {
		t.Fatalf("oversize pageSize: %v", err)
	}
	if res.CertsScanned > 1000 {
		t.Fatalf("CertsScanned=%d; want <= 1000 (clamped)", res.CertsScanned)
	}
	if res.Done {
		t.Fatal("Done=true with > 1000 overrides remaining; pageSize was not clamped")
	}
}

// --- fail-closed inputs ------------------------------------------------

// TestSweepExpiringOverridesPageEmptyOrgFailsClosed proves an empty
// organization id is rejected before any side effect.
func TestSweepExpiringOverridesPageEmptyOrgFailsClosed(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	svc := ownershipServiceForSweep(t, db)
	if _, err := svc.SweepExpiringOverridesPage(ctx, "  ", "", 100); err == nil {
		t.Fatal("expected error for empty organization id")
	}
}

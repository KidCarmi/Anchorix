//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kidcarmi/anchorix/backend/internal/ids"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- H-014 storage-layer integration tests -----------------------
//
// These tests exercise the postgres CertificateInventoryRepository
// against a real database, covering the matrix the user's H-014
// instructions enumerate: dedup, multi-store observations, cross-
// agent shared cert rows, composite-FK cross-org rejection,
// reappear/clear, absent/mark-removed reconciliation, and the
// out-of-order collected_at guard.

// seedAgent inserts an agent row directly (bypassing the
// enrollment HTTP flow, which is operationally orthogonal here).
// Returns the agent's id. The agent belongs to the supplied org.
func seedAgent(t *testing.T, db *postgres.DB, orgID, label string) string {
	t.Helper()
	id := ids.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agents
				(id, organization_id, hostname, version, status, enrolled_at, last_seen_at)
			 VALUES ($1, $2, $3, '', 'active', now(), now())`,
			id, orgID, "host-"+label)
		return err
	}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	return id
}

// seedOrganization inserts an organization row beyond the default
// 'anchorix' that freshDatabase seeds. Used by the cross-org FK
// tests.
func seedOrganization(t *testing.T, db *postgres.DB, id, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ($1, $2)`, id, name)
		return err
	}); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
}

// newCertificate builds a domain Certificate populated with
// reasonable values for the storage tests. The fingerprint is
// caller-supplied so a test can deliberately collide or diverge
// without re-deriving from cert bytes — pure storage tests don't
// need real X.509.
func newCertificate(orgID, fingerprint, subject string, notAfter time.Time) *inventory.Certificate {
	return &inventory.Certificate{
		ID:                ids.New(),
		OrganizationID:    orgID,
		FingerprintSHA256: fingerprint,
		Subject:           subject,
		Issuer:            "CN=Test Internal CA",
		SerialNumberHex:   "01ab",
		SignatureAlg:      "SHA256-RSA",
		PublicKeyAlg:      "RSA",
		PublicKeyBits:     2048,
		NotBefore:         time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          notAfter,
		SANs:              []string{subject},
		KeyUsages:         []string{"DigitalSignature"},
		ExtKeyUsages:      []string{"ServerAuth"},
		IsSelfSigned:      false,
		IsCA:              false,
		PEM:               "-----BEGIN CERTIFICATE-----\nfake-" + fingerprint + "\n-----END CERTIFICATE-----\n",
	}
}

// newObservation builds a domain CertificateObservation. CertID
// must come from a prior UpsertCertificate so the composite FK
// resolves.
func newObservation(orgID, certID, agentID, storeLocation, friendlyName string) *inventory.CertificateObservation {
	return &inventory.CertificateObservation{
		ID:             ids.New(),
		OrganizationID: orgID,
		CertificateID:  certID,
		AgentID:        agentID,
		StoreLocation:  storeLocation,
		FriendlyName:   friendlyName,
	}
}

// countObservations runs a focused COUNT(*) for assertions on row
// presence. Helpers avoid raw SQL leaking into every test body.
func countObservations(t *testing.T, db *postgres.DB, where string, args ...any) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			"SELECT COUNT(*) FROM certificate_observations WHERE "+where, args...,
		).Scan(&n)
	}); err != nil {
		t.Fatalf("count observations: %v", err)
	}
	return n
}

// readObservationState returns last_seen_at + removed_at for one
// observation row.
func readObservationState(t *testing.T, db *postgres.DB, orgID, certID, agentID, store string) (time.Time, *time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var (
		lastSeen  time.Time
		removedAt *time.Time
	)
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT last_seen_at, removed_at FROM certificate_observations
			  WHERE organization_id = $1 AND certificate_id = $2
			    AND agent_id = $3 AND store_location = $4`,
			orgID, certID, agentID, store,
		).Scan(&lastSeen, &removedAt)
	}); err != nil {
		t.Fatalf("read observation state: %v", err)
	}
	return lastSeen, removedAt
}

// TestCertificateInventoryMigrationApplies confirms migration 0005
// applies cleanly on a fresh database and the resulting tables
// have the expected columns and composite-FK structure. The
// freshDatabase helper already runs migrate up; this test asserts
// the H-005 schema is what we expect.
func TestCertificateInventoryMigrationApplies(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var version int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT MAX(version) FROM schema_migrations`).Scan(&version)
	}); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if version < 5 {
		t.Fatalf("schema_migrations max version = %d; want >= 5 (H-014)", version)
	}

	// Composite UNIQUE on certificates(organization_id, id) — the
	// FK target on observations.
	var hasCertsOrgIDUniq bool
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM pg_constraint
				 WHERE conname = 'certificates_org_id_uniq')`,
		).Scan(&hasCertsOrgIDUniq)
	}); err != nil {
		t.Fatalf("probe certificates_org_id_uniq: %v", err)
	}
	if !hasCertsOrgIDUniq {
		t.Error("certificates_org_id_uniq constraint missing — composite FK target")
	}

	// Composite UNIQUE on observations.
	var hasObsUniq bool
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM pg_indexes
				 WHERE tablename = 'certificate_observations'
				   AND indexdef LIKE '%UNIQUE%organization_id%certificate_id%agent_id%store_location%')`,
		).Scan(&hasObsUniq)
	}); err != nil {
		t.Fatalf("probe observations unique: %v", err)
	}
	if !hasObsUniq {
		t.Error("certificate_observations UNIQUE (organization_id, certificate_id, agent_id, store_location) missing")
	}

	// The three documented indexes from §10.
	for _, idx := range []string{
		"certificate_observations_org_agent_idx",
		"certificate_observations_org_certificate_idx",
		"certificate_observations_org_removed_idx",
	} {
		var exists bool
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = $1)`, idx,
			).Scan(&exists)
		}); err != nil {
			t.Fatalf("probe index %s: %v", idx, err)
		}
		if !exists {
			t.Errorf("index %s missing", idx)
		}
	}
}

// TestCertificateDedupByFingerprint confirms two UpsertCertificate
// calls with the same (org, fingerprint) deduplicate to one row,
// the second call returns the existing id, and last_seen_at is
// bumped forward.
func TestCertificateDedupByFingerprint(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()

	t0 := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Hour)

	cert1 := newCertificate("anchorix", "fp-shared-001", "CN=alpha", t0.AddDate(1, 0, 0))
	stored1, err := repo.UpsertCertificate(ctx, cert1, t0)
	if err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	if stored1.ID != cert1.ID {
		t.Errorf("first insert ID = %q, want caller-minted %q", stored1.ID, cert1.ID)
	}

	cert2 := newCertificate("anchorix", "fp-shared-001", "CN=alpha", t0.AddDate(1, 0, 0))
	stored2, err := repo.UpsertCertificate(ctx, cert2, t1)
	if err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if stored2.ID != stored1.ID {
		t.Errorf("dedup failed: second ID = %q, want existing %q", stored2.ID, stored1.ID)
	}
	if !stored2.LastSeenAt.Equal(t1) {
		t.Errorf("last_seen_at = %v, want %v (bumped on conflict)", stored2.LastSeenAt, t1)
	}

	// Exactly one row exists for this fingerprint.
	ctxQ, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int
	if err := db.WithTxRaw(ctxQ, func(tx pgx.Tx) error {
		return tx.QueryRow(ctxQ,
			`SELECT COUNT(*) FROM certificates
			  WHERE organization_id = 'anchorix' AND fingerprint_sha256 = 'fp-shared-001'`,
		).Scan(&n)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("row count = %d, want 1 (dedup)", n)
	}
}

// TestSameCertMultipleStoresMultipleObservations confirms the same
// cert observed in multiple stores on the same agent produces
// multiple observation rows but ONE cert row.
func TestSameCertMultipleStoresMultipleObservations(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	agentID := seedAgent(t, db, "anchorix", "multi-store")

	t0 := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	cert, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-multi-store", "CN=multi", t0.AddDate(1, 0, 0)), t0)
	if err != nil {
		t.Fatalf("upsert cert: %v", err)
	}

	for _, store := range []string{"LocalMachine\\My", "LocalMachine\\WebHosting"} {
		if err := repo.UpsertObservation(ctx,
			newObservation("anchorix", cert.ID, agentID, store, ""), t0); err != nil {
			t.Fatalf("upsert observation (%s): %v", store, err)
		}
	}

	obs, err := repo.ListObservationsForCertificate(ctx, "anchorix", cert.ID)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	if len(obs) != 2 {
		t.Errorf("observation count = %d, want 2 (one per store)", len(obs))
	}
	stores := map[string]bool{}
	for _, o := range obs {
		stores[o.StoreLocation] = true
	}
	if !stores["LocalMachine\\My"] || !stores["LocalMachine\\WebHosting"] {
		t.Errorf("expected both stores in observations; got %v", stores)
	}
}

// TestSameCertMultipleAgentsSharedCertRow confirms the same cert
// observed by multiple agents shares ONE cert row and produces
// one observation per agent.
func TestSameCertMultipleAgentsSharedCertRow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	agentA := seedAgent(t, db, "anchorix", "agent-a")
	agentB := seedAgent(t, db, "anchorix", "agent-b")

	t0 := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	cert, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-fleet-shared", "CN=fleet", t0.AddDate(1, 0, 0)), t0)
	if err != nil {
		t.Fatalf("upsert cert: %v", err)
	}

	for _, agentID := range []string{agentA, agentB} {
		if err := repo.UpsertObservation(ctx,
			newObservation("anchorix", cert.ID, agentID, "LocalMachine\\My", ""), t0); err != nil {
			t.Fatalf("upsert observation: %v", err)
		}
	}

	// One cert row, two observation rows.
	ctxQ, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var certRows int
	if err := db.WithTxRaw(ctxQ, func(tx pgx.Tx) error {
		return tx.QueryRow(ctxQ,
			`SELECT COUNT(*) FROM certificates WHERE id = $1`, cert.ID,
		).Scan(&certRows)
	}); err != nil {
		t.Fatalf("count certs: %v", err)
	}
	if certRows != 1 {
		t.Errorf("cert row count = %d, want 1 (shared)", certRows)
	}

	obs, err := repo.ListObservationsForCertificate(ctx, "anchorix", cert.ID)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	if len(obs) != 2 {
		t.Errorf("observation count = %d, want 2 (one per agent)", len(obs))
	}
}

// TestCrossOrgObservationCompositeFKRejected confirms the
// composite FK on certificate_observations prevents inserting an
// observation whose (org, agent) or (org, certificate_id) doesn't
// match the parent row's organization. The product flow never
// constructs such an insert; the test goes through raw SQL to
// exercise the defense-in-depth FK.
func TestCrossOrgObservationCompositeFKRejected(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	homeAgent := seedAgent(t, db, "anchorix", "home")

	// Cert lives in 'anchorix'.
	cert, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-anchorix", "CN=anchorix-cert",
			time.Now().AddDate(1, 0, 0)),
		time.Now().UTC())
	if err != nil {
		t.Fatalf("upsert cert: %v", err)
	}

	// Stand up another org for the cross-org attempts.
	seedOrganization(t, db, "other-org", "Other Org")

	ctxQ, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt 1: observation says 'other-org' but the cert is in
	// 'anchorix'. The composite FK on (organization_id, certificate_id)
	// must reject with 23503 foreign_key_violation.
	err = db.WithTxRaw(ctxQ, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctxQ,
			`INSERT INTO certificate_observations
				(id, organization_id, certificate_id, agent_id,
				 store_location, last_seen_at)
			 VALUES ($1, 'other-org', $2, $3, 'LocalMachine\My', now())`,
			ids.New(), cert.ID, homeAgent)
		return e
	})
	if err == nil {
		t.Fatal("composite FK did not reject cross-org cert insert")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("cross-org cert SQLSTATE = %v, want 23503", pgErr)
	}

	// Attempt 2: observation says 'other-org', agent is in
	// 'anchorix'. The composite FK on (organization_id, agent_id)
	// catches this even if we also use a foreign cert id.
	otherAgent := seedAgent(t, db, "other-org", "other")
	err = db.WithTxRaw(ctxQ, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctxQ,
			`INSERT INTO certificate_observations
				(id, organization_id, certificate_id, agent_id,
				 store_location, last_seen_at)
			 VALUES ($1, 'anchorix', $2, $3, 'LocalMachine\My', now())`,
			ids.New(), cert.ID, otherAgent)
		return e
	})
	if err == nil {
		t.Fatal("composite FK did not reject cross-org agent insert")
	}
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("cross-org agent SQLSTATE = %v, want 23503", pgErr)
	}
}

// TestUpsertObservationReappearClearsRemovedAt confirms that
// re-upserting an observation whose row currently has removed_at
// set clears removed_at back to NULL and bumps last_seen_at.
func TestUpsertObservationReappearClearsRemovedAt(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	agentID := seedAgent(t, db, "anchorix", "reappear")

	t0 := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Hour)
	t2 := t1.Add(1 * time.Hour)
	cert, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-reappear", "CN=reappear", t0.AddDate(1, 0, 0)), t0)
	if err != nil {
		t.Fatalf("upsert cert: %v", err)
	}

	if err := repo.UpsertObservation(ctx,
		newObservation("anchorix", cert.ID, agentID, "LocalMachine\\My", ""), t0); err != nil {
		t.Fatalf("upsert observation: %v", err)
	}

	// Reconcile with an empty observation set — the cert disappears
	// from coverage, so removed_at gets set.
	if err := repo.MarkMissingObservationsRemoved(ctx,
		"anchorix", agentID,
		[]string{"LocalMachine\\My"},
		[]string{}, t1); err != nil {
		t.Fatalf("mark removed: %v", err)
	}
	_, removed := readObservationState(t, db, "anchorix", cert.ID, agentID, "LocalMachine\\My")
	if removed == nil {
		t.Fatal("removed_at = NULL after reconciliation; want set")
	}

	// Re-upsert: cert reappears in a later batch. removed_at must
	// clear and last_seen_at must advance.
	if err := repo.UpsertObservation(ctx,
		newObservation("anchorix", cert.ID, agentID, "LocalMachine\\My", ""), t2); err != nil {
		t.Fatalf("upsert observation (reappear): %v", err)
	}
	lastSeen, removedAfter := readObservationState(t, db, "anchorix", cert.ID, agentID, "LocalMachine\\My")
	if removedAfter != nil {
		t.Errorf("removed_at = %v after reappear; want NULL", removedAfter)
	}
	if !lastSeen.Equal(t2) {
		t.Errorf("last_seen_at = %v after reappear; want %v", lastSeen, t2)
	}
}

// TestMarkMissingObservationsRemovedAbsentCert is the symmetric
// case: an observation that exists but is NOT in the batch's
// observedCertIDs gets removed_at set.
func TestMarkMissingObservationsRemovedAbsentCert(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	agentID := seedAgent(t, db, "anchorix", "absent")

	t0 := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Hour)

	// Two certs, both observed at t0.
	certA, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-keep", "CN=keep", t0.AddDate(1, 0, 0)), t0)
	if err != nil {
		t.Fatalf("upsert cert A: %v", err)
	}
	certB, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-gone", "CN=gone", t0.AddDate(1, 0, 0)), t0)
	if err != nil {
		t.Fatalf("upsert cert B: %v", err)
	}
	for _, c := range []*inventory.Certificate{certA, certB} {
		if err := repo.UpsertObservation(ctx,
			newObservation("anchorix", c.ID, agentID, "LocalMachine\\My", ""), t0); err != nil {
			t.Fatalf("upsert observation: %v", err)
		}
	}

	// Reconcile with only certA present; certB should be marked
	// removed_at.
	if err := repo.MarkMissingObservationsRemoved(ctx,
		"anchorix", agentID,
		[]string{"LocalMachine\\My"},
		[]string{certA.ID}, t1); err != nil {
		t.Fatalf("mark removed: %v", err)
	}

	_, removedA := readObservationState(t, db, "anchorix", certA.ID, agentID, "LocalMachine\\My")
	if removedA != nil {
		t.Errorf("certA removed_at = %v, want NULL (was in batch)", removedA)
	}
	_, removedB := readObservationState(t, db, "anchorix", certB.ID, agentID, "LocalMachine\\My")
	if removedB == nil {
		t.Error("certB removed_at = NULL, want set (was NOT in batch)")
	} else if !removedB.Equal(t1) {
		t.Errorf("certB removed_at = %v, want %v", removedB, t1)
	}
}

// TestOutOfOrderBatchDoesNotOverwriteNewerState pins the
// last_seen_at <= collectedAt guard for both UpsertObservation
// and MarkMissingObservationsRemoved. An older batch arriving
// after a newer one must NOT overwrite the newer state.
func TestOutOfOrderBatchDoesNotOverwriteNewerState(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	agentID := seedAgent(t, db, "anchorix", "out-of-order")

	tOld := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	tNew := tOld.Add(1 * time.Hour)
	cert, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-out-of-order", "CN=ooo", tOld.AddDate(1, 0, 0)), tOld)
	if err != nil {
		t.Fatalf("upsert cert: %v", err)
	}

	// Newer batch arrives first.
	if err := repo.UpsertObservation(ctx,
		newObservation("anchorix", cert.ID, agentID, "LocalMachine\\My", ""), tNew); err != nil {
		t.Fatalf("upsert (new): %v", err)
	}

	// Older batch arrives second — should be ignored.
	if err := repo.UpsertObservation(ctx,
		newObservation("anchorix", cert.ID, agentID, "LocalMachine\\My", ""), tOld); err != nil {
		t.Fatalf("upsert (old): %v", err)
	}

	lastSeen, removed := readObservationState(t, db, "anchorix", cert.ID, agentID, "LocalMachine\\My")
	if !lastSeen.Equal(tNew) {
		t.Errorf("last_seen_at = %v after out-of-order; want %v (newer wins)", lastSeen, tNew)
	}
	if removed != nil {
		t.Errorf("removed_at = %v after out-of-order upsert; want NULL", removed)
	}

	// Older reconciliation also cannot overwrite the newer state.
	// Try to mark the cert removed with the older timestamp.
	if err := repo.MarkMissingObservationsRemoved(ctx,
		"anchorix", agentID,
		[]string{"LocalMachine\\My"},
		[]string{}, tOld); err != nil {
		t.Fatalf("mark removed (older): %v", err)
	}
	_, removedAfter := readObservationState(t, db, "anchorix", cert.ID, agentID, "LocalMachine\\My")
	if removedAfter != nil {
		t.Errorf("removed_at = %v after older reconciliation; want NULL (newer state preserved)", removedAfter)
	}
}

// TestUpsertObservationNoDuplicateUnderUniqueKey confirms that
// repeated UpsertObservation calls with the same (org, cert,
// agent, store) tuple produce exactly one row, not duplicates.
func TestUpsertObservationNoDuplicateUnderUniqueKey(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	agentID := seedAgent(t, db, "anchorix", "dedup")

	t0 := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	cert, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-dedup", "CN=dedup", t0.AddDate(1, 0, 0)), t0)
	if err != nil {
		t.Fatalf("upsert cert: %v", err)
	}

	// Five UpsertObservation calls with progressively newer
	// collectedAt values.
	for i := 0; i < 5; i++ {
		if err := repo.UpsertObservation(ctx,
			newObservation("anchorix", cert.ID, agentID, "LocalMachine\\My", ""),
			t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("upsert iteration %d: %v", i, err)
		}
	}

	n := countObservations(t, db,
		"organization_id = $1 AND certificate_id = $2 AND agent_id = $3 AND store_location = $4",
		"anchorix", cert.ID, agentID, "LocalMachine\\My")
	if n != 1 {
		t.Errorf("row count = %d, want 1 (UPSERT must not duplicate under unique key)", n)
	}
}

// TestMarkMissingObservationsRemovedRejectsEmptyCoverage confirms
// the storage-layer defense-in-depth check from the H-014 design:
// an empty store_coverage MUST surface ErrInvalidReconciliation,
// not silently reconcile nothing.
func TestMarkMissingObservationsRemovedRejectsEmptyCoverage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	agentID := seedAgent(t, db, "anchorix", "empty-coverage")

	err := repo.MarkMissingObservationsRemoved(ctx,
		"anchorix", agentID,
		nil,
		[]string{}, time.Now().UTC())
	if !errors.Is(err, inventory.ErrInvalidReconciliation) {
		t.Errorf("nil coverage err = %v, want ErrInvalidReconciliation", err)
	}

	err = repo.MarkMissingObservationsRemoved(ctx,
		"anchorix", agentID,
		[]string{},
		[]string{}, time.Now().UTC())
	if !errors.Is(err, inventory.ErrInvalidReconciliation) {
		t.Errorf("empty coverage err = %v, want ErrInvalidReconciliation", err)
	}
}

// TestMarkMissingObservationsRemovedHandlesNilObservedCertIDs is
// the Codex P1 regression test: a caller passing nil (not an
// explicit empty slice) for observedCertIDs MUST result in every
// observation in the covered stores being marked removed_at —
// just as an empty slice would. Without the nil → []string{}
// normalization in the repository, pgx encodes nil as SQL NULL,
// `NOT (certificate_id = ANY(NULL))` evaluates to NULL, and the
// WHERE clause silently matches zero rows.
func TestMarkMissingObservationsRemovedHandlesNilObservedCertIDs(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	agentID := seedAgent(t, db, "anchorix", "nil-observed-ids")

	t0 := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Hour)

	// Two observations both currently active.
	for i, fp := range []string{"fp-nil-1", "fp-nil-2"} {
		cert, err := repo.UpsertCertificate(ctx,
			newCertificate("anchorix", fp, "CN=nil-"+fp, t0.AddDate(1, 0, 0)), t0)
		if err != nil {
			t.Fatalf("upsert cert %d: %v", i, err)
		}
		if err := repo.UpsertObservation(ctx,
			newObservation("anchorix", cert.ID, agentID, "LocalMachine\\My", ""), t0); err != nil {
			t.Fatalf("upsert observation %d: %v", i, err)
		}
	}

	// Pass nil — semantically equivalent to "the batch reported
	// zero certs in the covered stores". Both observations must
	// be marked removed_at.
	if err := repo.MarkMissingObservationsRemoved(ctx,
		"anchorix", agentID,
		[]string{"LocalMachine\\My"},
		nil, // <-- the case under test
		t1); err != nil {
		t.Fatalf("mark removed: %v", err)
	}

	activeCount := countObservations(t, db,
		"organization_id = $1 AND agent_id = $2 AND removed_at IS NULL",
		"anchorix", agentID)
	if activeCount != 0 {
		t.Errorf("active observation count = %d after nil-coverage reconciliation; want 0 (nil must behave like empty slice)", activeCount)
	}

	removedCount := countObservations(t, db,
		"organization_id = $1 AND agent_id = $2 AND removed_at = $3",
		"anchorix", agentID, t1)
	if removedCount != 2 {
		t.Errorf("removed observation count = %d, want 2", removedCount)
	}
}

// TestMarkMissingObservationsRemovedStoreCoverageScoping confirms
// observations in stores NOT covered by the batch are left
// untouched — the reconciliation is scoped to declared stores
// only.
func TestMarkMissingObservationsRemovedStoreCoverageScoping(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()
	agentID := seedAgent(t, db, "anchorix", "scoped")

	t0 := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Hour)
	cert, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-scoped", "CN=scoped", t0.AddDate(1, 0, 0)), t0)
	if err != nil {
		t.Fatalf("upsert cert: %v", err)
	}
	// Two observations in two stores.
	for _, store := range []string{"LocalMachine\\My", "LocalMachine\\Root"} {
		if err := repo.UpsertObservation(ctx,
			newObservation("anchorix", cert.ID, agentID, store, ""), t0); err != nil {
			t.Fatalf("upsert observation (%s): %v", store, err)
		}
	}

	// Reconcile only My — empty batch → mark cert removed in My
	// only; Root must stay untouched.
	if err := repo.MarkMissingObservationsRemoved(ctx,
		"anchorix", agentID,
		[]string{"LocalMachine\\My"},
		[]string{}, t1); err != nil {
		t.Fatalf("mark removed: %v", err)
	}

	_, removedMy := readObservationState(t, db, "anchorix", cert.ID, agentID, "LocalMachine\\My")
	if removedMy == nil {
		t.Error("My removed_at = NULL, want set")
	}
	_, removedRoot := readObservationState(t, db, "anchorix", cert.ID, agentID, "LocalMachine\\Root")
	if removedRoot != nil {
		t.Errorf("Root removed_at = %v, want NULL (Root not in coverage)", removedRoot)
	}
}

// TestGetCertificateCrossOrgReturnsNotFound confirms a cross-org
// id lookup surfaces as ErrCertificateNotFound, matching the
// established not_found-not-forbidden posture (CLAUDE.md §6).
func TestGetCertificateCrossOrgReturnsNotFound(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewCertificateInventoryRepository(db)
	ctx := context.Background()

	t0 := time.Now().UTC()
	cert, err := repo.UpsertCertificate(ctx,
		newCertificate("anchorix", "fp-cross-org-get", "CN=cross", t0.AddDate(1, 0, 0)), t0)
	if err != nil {
		t.Fatalf("upsert cert: %v", err)
	}

	seedOrganization(t, db, "other-org", "Other Org")

	_, err = repo.GetCertificate(ctx, "other-org", cert.ID)
	if !errors.Is(err, inventory.ErrCertificateNotFound) {
		t.Errorf("cross-org GetCertificate err = %v, want ErrCertificateNotFound", err)
	}

	// Same id in correct org works.
	got, err := repo.GetCertificate(ctx, "anchorix", cert.ID)
	if err != nil {
		t.Fatalf("same-org GetCertificate: %v", err)
	}
	if got.ID != cert.ID {
		t.Errorf("got.ID = %q, want %q", got.ID, cert.ID)
	}
}

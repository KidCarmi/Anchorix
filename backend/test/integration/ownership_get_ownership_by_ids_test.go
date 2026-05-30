//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- helpers ----------------------------------------------------------

// seedCertOwnershipPin inserts a certificate_ownership row for one cert
// in one org with a deterministic shape (decision=overridden, pinned to
// the given service). The row is shaped so the recompute treats it as
// "this cert has a prior ownership decision".
func seedCertOwnershipPin(t *testing.T, db *postgres.DB, ctx context.Context, org, certID, serviceID, explanationID string) {
	t.Helper()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO ownership_match_explanations
				(id, organization_id, certificate_id, decided_at, decided_decision, decided_service_id, engine_version)
			VALUES ($1, $2, $3, now() - interval '1 hour', 'overridden', $4, 1)`,
			explanationID, org, certID, serviceID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO certificate_ownership
				(organization_id, certificate_id, decision, service_id, explanation_id, confidence,
				 first_assigned_at, last_evaluated_at, last_changed_at)
			VALUES ($1, $2, 'overridden', $3, $4, 'high', now(), now(), now())`,
			org, certID, serviceID, explanationID)
		return err
	}); err != nil {
		t.Fatalf("seed cert ownership for %s: %v", certID, err)
	}
}

// --- empty / nil input ------------------------------------------------

// TestGetCertificateOwnershipByCertificateIDsEmptyInputNoOp proves
// nil / empty input short-circuits to an empty map with no DB
// round-trip and no error.
func TestGetCertificateOwnershipByCertificateIDsEmptyInputNoOp(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Seed a row so we'd notice if the empty-input path accidentally
	// returned everything.
	seedService(t, db, ctx, "svc-empty")
	seedCertificate(t, db, ctx, "cert-empty")
	seedCertOwnershipPin(t, db, ctx, "anchorix", "cert-empty", "svc-empty", "expl-empty")

	repo := postgres.NewOwnershipRepository(db)
	for label, input := range map[string][]string{
		"nil":   nil,
		"empty": {},
	} {
		got, err := repo.GetCertificateOwnershipByCertificateIDs(ctx, "anchorix", input)
		if err != nil {
			t.Fatalf("%s input: %v", label, err)
		}
		if len(got) != 0 {
			t.Fatalf("%s input returned %d rows; want 0", label, len(got))
		}
	}
}

// --- happy path / map keying ------------------------------------------

// TestGetCertificateOwnershipByCertificateIDsHappyPath proves the
// method returns the matching rows keyed on certificate_id and skips
// missing-row ids without error.
func TestGetCertificateOwnershipByCertificateIDsHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-hp")
	for _, c := range []string{"cert-hp-a", "cert-hp-b", "cert-hp-c"} {
		seedCertificate(t, db, ctx, c)
		seedCertOwnershipPin(t, db, ctx, "anchorix", c, "svc-hp", "expl-"+c)
	}
	// cert-hp-missing has no ownership row.
	seedCertificate(t, db, ctx, "cert-hp-missing")

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.GetCertificateOwnershipByCertificateIDs(ctx, "anchorix",
		[]string{"cert-hp-a", "cert-hp-b", "cert-hp-c", "cert-hp-missing"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len(got) = %d; want 3 (missing-row id silently absent)", len(got))
	}
	for _, c := range []string{"cert-hp-a", "cert-hp-b", "cert-hp-c"} {
		row, ok := got[c]
		if !ok {
			t.Fatalf("missing %s from result map", c)
		}
		if row.CertificateID != c {
			t.Fatalf("%s: map key %s vs row.CertificateID %s", c, c, row.CertificateID)
		}
		if row.ServiceID == nil || *row.ServiceID != "svc-hp" {
			t.Fatalf("%s: service_id = %v; want svc-hp", c, row.ServiceID)
		}
	}
	if _, present := got["cert-hp-missing"]; present {
		t.Fatal("missing-row id appeared in result map")
	}
}

// --- duplicate input ids ----------------------------------------------

// TestGetCertificateOwnershipByCertificateIDsDuplicateInputSafe proves
// duplicate input ids produce no duplicate output rows — the SQL
// ANY filter de-duplicates and the map collapses by key.
func TestGetCertificateOwnershipByCertificateIDsDuplicateInputSafe(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-dup")
	seedCertificate(t, db, ctx, "cert-dup-a")
	seedCertOwnershipPin(t, db, ctx, "anchorix", "cert-dup-a", "svc-dup", "expl-dup")

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.GetCertificateOwnershipByCertificateIDs(ctx, "anchorix",
		[]string{"cert-dup-a", "cert-dup-a", "cert-dup-a"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d; want 1 (duplicates collapsed)", len(got))
	}
}

// --- cross-org isolation ----------------------------------------------

// TestGetCertificateOwnershipByCertificateIDsCrossOrgIsolation proves
// foreign-org cert ids do not match — the WHERE organization_id = $1
// is the binding org scope.
func TestGetCertificateOwnershipByCertificateIDsCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedOrganization(t, db, "other-org", "Other Org")
	seedService(t, db, ctx, "svc-anchor")
	seedCertificate(t, db, ctx, "cert-anchor")
	seedCertOwnershipPin(t, db, ctx, "anchorix", "cert-anchor", "svc-anchor", "expl-anchor")

	// Seed other-org cert + ownership row directly.
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		stmts := []string{
			`INSERT INTO services (id, organization_id, slug, display_name) VALUES ('svc-other','other-org','svc-other','Svc Other')`,
			`INSERT INTO certificates (id, organization_id, fingerprint_sha256, subject, issuer, serial_number_hex, signature_algorithm, public_key_algorithm, public_key_bits, not_before, not_after, pem)
			   VALUES ('cert-other','other-org','cert-other','CN=test','CN=test-ca','01','SHA256-RSA','RSA',2048, now() - interval '30 days', now() + interval '365 days',
			   '-----BEGIN CERTIFICATE-----' || E'\n' || 'MIIBxxx' || E'\n' || '-----END CERTIFICATE-----')`,
			`INSERT INTO ownership_match_explanations (id, organization_id, certificate_id, decided_at, decided_decision, decided_service_id, engine_version)
			   VALUES ('expl-other','other-org','cert-other', now() - interval '1 hour', 'overridden', 'svc-other', 1)`,
			`INSERT INTO certificate_ownership (organization_id, certificate_id, decision, service_id, explanation_id, confidence, first_assigned_at, last_evaluated_at, last_changed_at)
			   VALUES ('other-org','cert-other','overridden','svc-other','expl-other','high', now(), now(), now())`,
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed other-org: %v", err)
	}

	repo := postgres.NewOwnershipRepository(db)
	// Query anchorix with BOTH cert ids — foreign-org id must be absent.
	got, err := repo.GetCertificateOwnershipByCertificateIDs(ctx, "anchorix",
		[]string{"cert-anchor", "cert-other"})
	if err != nil {
		t.Fatalf("anchorix query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("anchorix len(got) = %d; want 1 (cross-org id must not match)", len(got))
	}
	if _, present := got["cert-other"]; present {
		t.Fatal("anchorix returned other-org's row — cross-org isolation violated")
	}

	// Symmetric: other-org query must not return anchorix's row.
	gotOther, err := repo.GetCertificateOwnershipByCertificateIDs(ctx, "other-org",
		[]string{"cert-anchor", "cert-other"})
	if err != nil {
		t.Fatalf("other-org query: %v", err)
	}
	if _, present := gotOther["cert-anchor"]; present {
		t.Fatal("other-org returned anchorix's row — cross-org isolation violated")
	}
}

// --- oversize batch fail-closed ---------------------------------------

// TestGetCertificateOwnershipByCertificateIDsOversizeFailsClosed proves
// a batch larger than MaxOwnershipByIDsBatchSize is rejected with an
// error — defensive guard against a buggy caller.
func TestGetCertificateOwnershipByCertificateIDsOversizeFailsClosed(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	repo := postgres.NewOwnershipRepository(db)
	oversized := make([]string, postgres.MaxOwnershipByIDsBatchSize+1)
	for i := range oversized {
		oversized[i] = fmt.Sprintf("cert-%d", i)
	}
	_, err := repo.GetCertificateOwnershipByCertificateIDs(ctx, "anchorix", oversized)
	if err == nil {
		t.Fatal("oversized batch: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "batch size") {
		t.Fatalf("error should mention batch size, got: %v", err)
	}
}

// --- map-keyed (order-independent) ------------------------------------

// TestGetCertificateOwnershipByCertificateIDsMapKeyedNotOrderDependent
// proves the result is a map keyed on certificate_id, so the caller
// does NOT depend on the DB returning rows in any particular order.
// Running the same query twice yields the same set of keys, and the
// lookup-by-key result is identical regardless of insertion order.
func TestGetCertificateOwnershipByCertificateIDsMapKeyedNotOrderDependent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-ord")
	for _, c := range []string{"cert-ord-c", "cert-ord-a", "cert-ord-b"} {
		seedCertificate(t, db, ctx, c)
		seedCertOwnershipPin(t, db, ctx, "anchorix", c, "svc-ord", "expl-"+c)
	}

	repo := postgres.NewOwnershipRepository(db)
	// Query with the input in a different order each time.
	in1 := []string{"cert-ord-a", "cert-ord-b", "cert-ord-c"}
	in2 := []string{"cert-ord-c", "cert-ord-b", "cert-ord-a"}
	got1, err := repo.GetCertificateOwnershipByCertificateIDs(ctx, "anchorix", in1)
	if err != nil {
		t.Fatalf("got1: %v", err)
	}
	got2, err := repo.GetCertificateOwnershipByCertificateIDs(ctx, "anchorix", in2)
	if err != nil {
		t.Fatalf("got2: %v", err)
	}
	if len(got1) != 3 || len(got2) != 3 {
		t.Fatalf("counts diverged: got1=%d got2=%d", len(got1), len(got2))
	}
	for _, c := range []string{"cert-ord-a", "cert-ord-b", "cert-ord-c"} {
		r1, ok1 := got1[c]
		r2, ok2 := got2[c]
		if !ok1 || !ok2 {
			t.Fatalf("%s: present in got1=%v got2=%v", c, ok1, ok2)
		}
		if r1.CertificateID != r2.CertificateID {
			t.Fatalf("%s: map lookups diverged", c)
		}
	}
}

// --- EXPLAIN ----------------------------------------------------------

// TestGetCertificateOwnershipByCertificateIDsExplainIndexed proves the
// query has an indexed lookup path available via the
// certificate_ownership PK. On a small test fixture (20 rows here)
// PostgreSQL correctly picks Seq Scan because it's cheaper than the
// index — that's not a defect. We assert the STRUCTURAL property "an
// index path exists for this query" by disabling Seq Scan in the
// session and re-running EXPLAIN; the resulting plan must use the
// index, with no fleet-wide Group Key surprise. The plan is
// deliberately NOT an Index Only Scan — the projected columns exceed
// the PK (H-030 design §8).
func TestGetCertificateOwnershipByCertificateIDsExplainIndexed(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-ex")
	for i := 0; i < 20; i++ {
		c := fmt.Sprintf("cert-ex-%02d", i)
		seedCertificate(t, db, ctx, c)
		seedCertOwnershipPin(t, db, ctx, "anchorix", c, "svc-ex", "expl-ex-"+c)
	}

	var plan string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL enable_seqscan = off"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			"EXPLAIN "+postgres.GetCertificateOwnershipByCertificateIDsQuery,
			"anchorix", []string{"cert-ex-01", "cert-ex-05", "cert-ex-10"})
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			plan += line + "\n"
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	if strings.Contains(plan, "Group Key") {
		t.Fatalf("plan must not fleet-aggregate (Group Key), got:\n%s", plan)
	}
	if !strings.Contains(plan, "Index Scan") && !strings.Contains(plan, "Bitmap Index Scan") {
		t.Fatalf("plan must use Index Scan or Bitmap Index Scan when seqscan is disabled, got:\n%s", plan)
	}
	if strings.Contains(plan, "Index Only Scan") {
		t.Fatalf("plan unexpectedly used Index Only Scan; H-030 design §8 explicitly states the PK does not cover the projection, got:\n%s", plan)
	}
}

// --- governance.OwnershipRepository interface satisfaction -----------

// TestPostgresImplSatisfiesOwnershipRepositoryWithNewMethod is a
// compile-time guard: assigning *postgres.OwnershipRepository to a
// governance.OwnershipRepository fails to compile if the new method
// is missing. This catches the "added to one side, forgot the other"
// regression in CI's `go test ./...` phase.
func TestPostgresImplSatisfiesOwnershipRepositoryWithNewMethod(t *testing.T) {
	var _ governance.OwnershipRepository = (*postgres.OwnershipRepository)(nil)
}

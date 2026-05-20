//go:build perf

package perf

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/inventory/fixtures"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// testDB is the local equivalent of the integration suite's
// testDB helper. Kept package-private so the perf tier owns its
// own connection-management story — the integration suite's
// testDB lives behind `//go:build integration` and is not
// imported across build-tag boundaries.
func testDB(t *testing.T) *postgres.DB {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping perf test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := postgres.Open(ctx, url)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// freshDatabase migrates up and truncates the domain tables.
// Tracks the integration tier's pattern at the SQL level so a
// schema change shows up in both tiers at once.
func freshDatabase(t *testing.T, db *postgres.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	migrations, err := postgres.LoadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("LoadEmbeddedMigrations: %v", err)
	}
	if _, err := db.MigrateUp(ctx, migrations); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	err = db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		stmts := []string{
			"DELETE FROM sessions",
			"DELETE FROM agent_enrollment_tokens",
			"DELETE FROM findings",
			"DELETE FROM certificate_observations",
			"DELETE FROM certificates",
			"DELETE FROM agents",
			"DELETE FROM deployment_packages",
			"TRUNCATE TABLE audit_events",
			"DELETE FROM users",
			"DELETE FROM organizations",
			`INSERT INTO organizations (id, name) VALUES ('anchorix', 'Anchorix')`,
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// TestPerfSmallv01FixtureWritesCleanly is the perf-tier smoke
// test: build the Smallv01 fixture, write it to a real
// PostgreSQL, confirm cardinalities match the in-memory build.
// Substantive perf assertions (statement counts, page
// latencies) land in follow-up PRs against this harness.
//
// Runs only when `-tags perf` is supplied AND `DATABASE_URL`
// is set; the default `go test ./...` pass and developer
// machines without postgres see this test skipped.
func TestPerfSmallv01FixtureWritesCleanly(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	fleet, err := fixtures.NewFleetBuilder(42, fixtures.Smallv01(), now).Build()
	if err != nil {
		t.Fatalf("build fleet: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := fleet.WriteTo(ctx, db); err != nil {
		t.Fatalf("write fleet: %v", err)
	}

	// Confirm row counts match the in-memory build. A future
	// regression that drops rows during persistence shows up
	// here as a count mismatch.
	want := map[string]int{
		"agents":                   len(fleet.Agents),
		"certificates":             len(fleet.Certificates),
		"certificate_observations": len(fleet.Observations),
	}
	for table, expected := range want {
		var n int
		err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n)
		})
		if err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != expected {
			t.Errorf("%s rows = %d, want %d", table, n, expected)
		}
	}
}

// TestPerfSmallv01PreSeedFindings exercises the
// rule-pre-seed path. The substantive recompute-perf assertion
// belongs to H-024B; this test guards the pre-seed itself —
// without it H-024B's diff-comparison test would have nothing
// to diff against.
func TestPerfSmallv01PreSeedFindings(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	fleet, err := fixtures.NewFleetBuilder(42, fixtures.Smallv01(), now).Build()
	if err != nil {
		t.Fatalf("build fleet: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := fleet.WriteTo(ctx, db); err != nil {
		t.Fatalf("write fleet: %v", err)
	}

	// Import findings only inside the test body so the
	// per-package import graph stays minimal — the helpers
	// above don't need it.
	rules := defaultRules()
	inserted, acknowledged, suppressed, err := fleet.PreSeedFindings(ctx, db, rules)
	if err != nil {
		t.Fatalf("pre-seed findings: %v", err)
	}
	if inserted == 0 {
		t.Fatalf("inserted = 0; Smallv01 should produce at least one rule match")
	}
	// Acknowledged + suppressed must not exceed inserted.
	if acknowledged+suppressed > inserted {
		t.Errorf("override totals exceed inserted: ack=%d sup=%d inserted=%d",
			acknowledged, suppressed, inserted)
	}
	t.Logf("pre-seed: inserted=%d acknowledged=%d suppressed=%d",
		inserted, acknowledged, suppressed)
}

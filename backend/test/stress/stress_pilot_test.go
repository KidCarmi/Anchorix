//go:build stress

package stress

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/inventory/fixtures"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// testDB / freshDatabase are local to the stress package for
// the same reason they are local to the perf package — build
// tags isolate the suites at the file level, so cross-tier
// helper imports are not possible.
func testDB(t *testing.T) *postgres.DB {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping stress test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := postgres.Open(ctx, url)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func freshDatabase(t *testing.T, db *postgres.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

// TestStressPilotFleetWritesCleanly is the stress-tier smoke
// test. Build the Pilot fixture, persist it, confirm row
// counts. Wall-clock budget assertions belong to H-024B; the
// `t.Logf` durations here exist so an operator running the
// suite locally can eyeball the numbers without committing
// the team to a specific threshold yet.
func TestStressPilotFleetWritesCleanly(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	startBuild := time.Now()
	fleet, err := fixtures.NewFleetBuilder(2026, fixtures.Pilot(), now).Build()
	if err != nil {
		t.Fatalf("build fleet: %v", err)
	}
	t.Logf("build pilot: agents=%d certs=%d observations=%d duration=%s",
		len(fleet.Agents), len(fleet.Certificates), len(fleet.Observations),
		time.Since(startBuild))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	startWrite := time.Now()
	if err := fleet.WriteTo(ctx, db); err != nil {
		t.Fatalf("write fleet: %v", err)
	}
	t.Logf("write pilot: duration=%s", time.Since(startWrite))

	// Row-count parity is a correctness check; without it the
	// stress harness could silently lose rows during the long
	// insert loop.
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

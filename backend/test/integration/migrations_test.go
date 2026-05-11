//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

func TestMigrationsApplyAndIdempotent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	migrations, err := postgres.LoadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("LoadEmbeddedMigrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migrations embedded")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First MigrateUp already happened in freshDatabase. Status should
	// show binary == DB.
	st, err := db.Status(ctx, migrations)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.DBVersion != st.BinaryVersion {
		t.Fatalf("db %d != binary %d", st.DBVersion, st.BinaryVersion)
	}

	// Re-applying migrations is a no-op (CLAUDE.md §16: deterministic
	// + idempotent).
	applied, err := db.MigrateUp(ctx, migrations)
	if err != nil {
		t.Fatalf("MigrateUp (second pass): %v", err)
	}
	if applied != 0 {
		t.Fatalf("second pass applied %d migrations; want 0", applied)
	}
}

func TestEnsureSchemaPassesAtCurrent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	migrations, err := postgres.LoadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("LoadEmbeddedMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.EnsureSchema(ctx, migrations); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
}

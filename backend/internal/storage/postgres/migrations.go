package postgres

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/migrations"
)

// Migration is one parsed entry from the embedded migrations FS.
// Version is the integer prefix (e.g. 0001 → 1); the SQL body is the
// full file contents.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// ErrSchemaMismatch is returned by EnsureSchema when the database is
// at a version newer than the binary expects. The control plane
// refuses to start in that case (CLAUDE.md §16, §6.12 fail-closed).
var ErrSchemaMismatch = errors.New("postgres: schema version newer than binary expects")

// LoadEmbeddedMigrations returns the migrations baked into the
// binary, sorted by version ascending. Filenames must match the
// pattern NNNN_<slug>.sql (NNNN is a zero-padded decimal integer).
func LoadEmbeddedMigrations() ([]Migration, error) {
	return loadFromFS(migrations.FS, ".")
}

func loadFromFS(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("postgres: read migrations dir: %w", err)
	}
	out := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, name, err := parseMigrationName(e.Name())
		if err != nil {
			return nil, fmt.Errorf("postgres: %s: %w", e.Name(), err)
		}
		body, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("postgres: read %s: %w", e.Name(), err)
		}
		out = append(out, Migration{Version: version, Name: name, SQL: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	if err := assertSequential(out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseMigrationName(filename string) (int, string, error) {
	base := strings.TrimSuffix(filename, ".sql")
	parts := strings.SplitN(base, "_", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, "", fmt.Errorf("invalid migration filename %q (want NNNN_<slug>.sql)", filename)
	}
	version, err := strconv.Atoi(parts[0])
	if err != nil || version <= 0 {
		return 0, "", fmt.Errorf("invalid migration version in %q: %v", filename, err)
	}
	return version, parts[1], nil
}

func assertSequential(ms []Migration) error {
	for i, m := range ms {
		if m.Version != i+1 {
			return fmt.Errorf("migration version gap: file at index %d has version %d (expected %d)", i, m.Version, i+1)
		}
	}
	return nil
}

// MigrateUp applies every migration with a version greater than the
// highest recorded in schema_migrations. Each migration runs in its
// own transaction; on error, the transaction rolls back and the
// caller sees the wrapped error.
//
// Idempotent: re-running against an already-migrated DB is a no-op.
// Deterministic: the same embedded migrations + the same DB state
// always produce the same final schema (CLAUDE.md §16).
func (db *DB) MigrateUp(ctx context.Context, migrations []Migration) (applied int, err error) {
	if err := db.ensureMigrationsTable(ctx); err != nil {
		return 0, err
	}
	current, err := db.currentSchemaVersion(ctx)
	if err != nil {
		return 0, err
	}
	for _, m := range migrations {
		if m.Version <= current {
			continue
		}
		if err := db.applyMigration(ctx, m); err != nil {
			return applied, fmt.Errorf("apply %04d_%s: %w", m.Version, m.Name, err)
		}
		applied++
	}
	return applied, nil
}

// MigrationStatus reports the highest version embedded in the binary
// and the highest version applied to the database. Used by the
// `anchorix migrate status` subcommand.
type MigrationStatus struct {
	BinaryVersion int
	DBVersion     int
}

// Status returns the current schema status.
func (db *DB) Status(ctx context.Context, migrations []Migration) (MigrationStatus, error) {
	if err := db.ensureMigrationsTable(ctx); err != nil {
		return MigrationStatus{}, err
	}
	current, err := db.currentSchemaVersion(ctx)
	if err != nil {
		return MigrationStatus{}, err
	}
	binaryVersion := 0
	if len(migrations) > 0 {
		binaryVersion = migrations[len(migrations)-1].Version
	}
	return MigrationStatus{BinaryVersion: binaryVersion, DBVersion: current}, nil
}

// EnsureSchema verifies that the DB has had every embedded migration
// applied. Returns ErrSchemaMismatch if the DB version is newer than
// the binary expects (operator must redeploy or reconcile manually).
// Returns a wrapped error if the DB is behind (operator must run
// `anchorix migrate up`).
//
// Called at `anchorix serve` startup (CLAUDE.md §16: no auto-mutate
// at runtime; the runner is explicit).
func (db *DB) EnsureSchema(ctx context.Context, migrations []Migration) error {
	if err := db.ensureMigrationsTable(ctx); err != nil {
		return err
	}
	current, err := db.currentSchemaVersion(ctx)
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return nil
	}
	expected := migrations[len(migrations)-1].Version
	switch {
	case current == expected:
		return nil
	case current < expected:
		return fmt.Errorf("postgres: schema at version %d; binary requires %d (run `anchorix migrate up`)", current, expected)
	default:
		return fmt.Errorf("%w: schema at %d, binary expects %d", ErrSchemaMismatch, current, expected)
	}
}

func (db *DB) ensureMigrationsTable(ctx context.Context) error {
	// schema_migrations is created by 0001_init.sql itself; for a
	// pristine DB the first migration provisions it. To bootstrap
	// correctly we only need to touch it after migrate. This helper
	// is a no-op on an already-migrated DB and creates the bare
	// minimum so currentSchemaVersion can read 0 on a fresh one.
	const stmt = `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER     PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`
	if _, err := db.pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("postgres: ensure schema_migrations: %w", err)
	}
	return nil
}

func (db *DB) currentSchemaVersion(ctx context.Context) (int, error) {
	var v int
	row := db.pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err := row.Scan(&v); err != nil {
		return 0, fmt.Errorf("postgres: read schema version: %w", err)
	}
	return v, nil
}

func (db *DB) applyMigration(ctx context.Context, m Migration) error {
	return db.WithTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			return fmt.Errorf("exec: %w", err)
		}
		// 0001_init.sql inserts the version row itself (legacy);
		// later migrations rely on the runner to record their version.
		// Re-insert idempotently so both shapes work.
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)
			 ON CONFLICT (version) DO NOTHING`, m.Version); err != nil {
			return fmt.Errorf("record version: %w", err)
		}
		return nil
	})
}

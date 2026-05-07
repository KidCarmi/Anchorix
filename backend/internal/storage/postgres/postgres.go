// Package postgres is the concrete storage implementation backed by
// PostgreSQL. The pgx driver is the chosen client (added in Phase 1).
//
// All SQL lives here. Domain modules MUST NOT contain SQL. Queries use
// parameter binding only; never string concatenation (CLAUDE.md §6.7).
package postgres

import (
	"context"
	"errors"
)

// DB is the placeholder for the pgx connection pool. Phase 1 replaces this
// with a real *pgxpool.Pool. We keep the type defined now so dependent
// packages can compile against the intended shape.
type DB struct{}

// Open returns an initialized DB. The signature is stable; the body lands
// in Phase 1 with pgx wiring and migration runner integration.
func Open(_ context.Context, _ string) (*DB, error) {
	return nil, errors.New("postgres.Open not yet implemented (Phase 1)")
}

// Close releases connection pool resources. Always safe to call.
func (db *DB) Close() {}

// Ping verifies database connectivity. Used by /readyz.
func (db *DB) Ping(_ context.Context) error {
	return errors.New("postgres.Ping not yet implemented (Phase 1)")
}

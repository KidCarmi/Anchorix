package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB owns the pgx connection pool. Construct exactly one per process
// in the composition root (cmd/anchorix). Repository types take a
// *DB by reference and use its accessor methods; they do not
// construct their own pool.
type DB struct {
	pool *pgxpool.Pool
}

// Open establishes the pool against the given DATABASE_URL.
// The caller is responsible for Close.
//
// Open honors ctx so callers can bound startup time. Individual
// query timeouts are set at the call site (CLAUDE.md §8.11).
func Open(ctx context.Context, databaseURL string) (*DB, error) {
	if databaseURL == "" {
		return nil, errors.New("postgres: empty DATABASE_URL")
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse DATABASE_URL: %w", err)
	}
	// Conservative pool defaults — production tuning lands later.
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: new pool: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close releases pool resources. Safe to call from graceful-shutdown.
func (db *DB) Close() {
	if db == nil || db.pool == nil {
		return
	}
	db.pool.Close()
}

// Ping verifies database connectivity. Used by the /readyz probe
// registered in cmd/anchorix.
func (db *DB) Ping(ctx context.Context) error {
	if db == nil || db.pool == nil {
		return errors.New("postgres: pool not initialized")
	}
	return db.pool.Ping(ctx)
}

// pool exposes the underlying *pgxpool.Pool to sibling repository
// files in this package only (unexported).
func (db *DB) querier() *pgxpool.Pool { return db.pool }

// WithTx runs fn inside a single transaction. Commits on nil return;
// rolls back on any error or panic. CLAUDE.md §18: ctx is always
// honored; non-nil returns from fn never leave a dangling tx.
func (db *DB) WithTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("postgres: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	committed = true
	return nil
}

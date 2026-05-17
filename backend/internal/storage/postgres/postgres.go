package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB owns the pgx connection pool. Construct exactly one per process
// in the composition root (cmd/anchorix). Repository types hold a
// *DB pointer and route every query through db.querierFor(ctx), so
// the same code runs inside or outside a transaction depending on
// whether the caller wrapped the operation in DB.WithTx.
type DB struct {
	pool *pgxpool.Pool
}

// Open establishes the pool against the given DATABASE_URL.
// The caller is responsible for Close.
func Open(ctx context.Context, databaseURL string) (*DB, error) {
	if databaseURL == "" {
		return nil, errors.New("postgres: empty DATABASE_URL")
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse DATABASE_URL: %w", err)
	}
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

// querier is the small subset of the pgxpool API that repositories
// actually need. Both *pgxpool.Pool and pgx.Tx satisfy it, which is
// what makes the ctx-carrying transaction pattern work: a repository
// method that does `db.querierFor(ctx).QueryRow(...)` automatically
// participates in any transaction the caller wrapped it in.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type txKey struct{}

func contextWithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

func txFromContext(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(pgx.Tx)
	return tx, ok
}

// querierFor returns the active tx if one is bound to ctx, otherwise
// the pool itself. Callers do not need to know which they got.
func (db *DB) querierFor(ctx context.Context) querier {
	if tx, ok := txFromContext(ctx); ok {
		return tx
	}
	return db.pool
}

// WithTx runs fn inside a single transaction. Every repository call
// made with the ctx passed to fn participates in the same transaction.
// On nil return from fn the tx commits; on any error or panic, the
// tx rolls back. This is the domain-facing transactional API — it
// does not leak pgx.Tx outside this package (CLAUDE.md §8.6: no
// pgx imports in domain or httpapi).
func (db *DB) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return db.withRawTx(ctx, func(tx pgx.Tx) error {
		return fn(contextWithTx(ctx, tx))
	})
}

// WithTxLockedAgent runs fn inside a single transaction with an
// exclusive transaction-scope advisory lock keyed by agentID,
// namespaced to certificate ingestion. The lock serializes
// concurrent ingestion batches for the same agent — exactly the
// guarantee H-017 calls for, and the guarantee
// CERTIFICATE_INVENTORY.md §3 requires for set reconciliation
// (two concurrent batches for the same agent could otherwise mark
// each other's freshly-upserted observations as removed_at).
//
// Lock namespace + key: pg_advisory_xact_lock takes two int32s;
// we hash 'cert-inventory' for the namespace and the agent id for
// the key. PostgreSQL's hashtext is stable and deterministic
// across the same major version, which is the only stability
// promise we need (the lock keyspace lives only for the
// transaction's lifetime).
//
// The advisory lock is released automatically when the transaction
// commits or rolls back; the caller never has to release it
// explicitly. Two batches for the SAME agent serialize; batches
// for DIFFERENT agents run in parallel.
//
// CLAUDE.md §8.10 concurrency discipline: the lock has a documented
// owner (this function), a deterministic release path (tx end),
// and a bounded lifetime (the caller's transaction).
func (db *DB) WithTxLockedAgent(ctx context.Context, agentID string, fn func(ctx context.Context) error) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.querierFor(ctx).Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtext('cert-inventory'), hashtext($1))`,
			agentID); err != nil {
			return fmt.Errorf("postgres: advisory lock agent %s: %w", agentID, err)
		}
		return fn(ctx)
	})
}

// WithTxRaw exposes the underlying pgx.Tx for callers inside this
// package (migrations.go) and for integration tests that need to
// exercise raw SQL (audit-events-are-append-only). Production
// domain code MUST use WithTx instead.
func (db *DB) WithTxRaw(ctx context.Context, fn func(pgx.Tx) error) error {
	return db.withRawTx(ctx, fn)
}

func (db *DB) withRawTx(ctx context.Context, fn func(pgx.Tx) error) error {
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

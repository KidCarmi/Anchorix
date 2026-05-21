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

// WithTxLockedFindings runs fn inside a single transaction with
// an exclusive transaction-scope advisory lock keyed by
// organizationID, namespaced to findings recompute. The lock
// serializes concurrent recompute calls for the SAME org —
// addresses the H-021 race where two simultaneous recomputes
// load the same in-memory snapshot of existing findings, both
// decide a `(cert_id, rule_id)` pair is "new", and both try to
// INSERT the same triple. Without the lock the second INSERT
// would violate the
// `UNIQUE (organization_id, certificate_id, rule_id)`
// constraint, surfacing as a 500 and rolling back the second
// recompute — non-idempotent under concurrent operator
// requests.
//
// Lock namespace + key: hashtext('findings-recompute') for the
// namespace, hashtext(organization_id) for the key. Different
// orgs recompute in parallel.
//
// Released automatically at tx commit/rollback. CLAUDE.md §8.10
// concurrency discipline: documented owner, deterministic
// release path, bounded lifetime.
func (db *DB) WithTxLockedFindings(ctx context.Context, organizationID string, fn func(ctx context.Context) error) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.querierFor(ctx).Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtext('findings-recompute'), hashtext($1))`,
			organizationID); err != nil {
			return fmt.Errorf("postgres: advisory lock findings org %s: %w", organizationID, err)
		}
		return fn(ctx)
	})
}

// WithTxLockedFindingsRepeatableRead is the H-024B sibling of
// WithTxLockedFindings. Same advisory-lock semantics (same
// namespace, same key) — concurrent recomputes for the same
// org still serialize — but the wrapping transaction runs at
// `REPEATABLE READ` isolation so every paginated `SELECT`
// inside fn reads from a single consistent snapshot of the
// inputs.
//
// Why this is binding (CLAUDE.md §6.12 fail-closed):
//
// Cert ingestion (`WithTxLockedAgent`) holds its lock under a
// DIFFERENT advisory-lock namespace (`'cert-inventory'`). The
// findings advisory lock does NOT block ingestion. Under
// PostgreSQL's default `READ COMMITTED`, each new statement
// inside the recompute tx reads a fresh snapshot — so a
// concurrent ingestion commit between two paginated reads
// would let later cert pages see rows that earlier pages did
// not. The streaming recompute would silently diverge from
// the determinism guarantee
// `docs/engineering/CERTIFICATE_FINDINGS.md` §5 promises.
//
// Why the SESSION-scope lock (not xact-scope):
//
// PostgreSQL takes the REPEATABLE READ snapshot at the FIRST
// statement of the tx, INCLUDING `SELECT pg_advisory_xact_lock(...)`.
// If two concurrent recomputes both open a REPEATABLE READ tx
// and use the xact-scope advisory lock pattern, the second
// tx's snapshot is fixed at the moment its lock-acquisition
// SELECT BEGINS — i.e. BEFORE the first tx commits. The
// second tx then doesn't see the first tx's inserts and tries
// to re-insert the same (org, cert, rule) triple, surfacing
// as a unique-violation. This was caught by the existing
// TestFindingsRecomputeConcurrentSafety regression test.
//
// The fix is the canonical PostgreSQL idiom: take a
// session-scope lock on a borrowed connection BEFORE opening
// the REPEATABLE READ tx, then commit/rollback the tx, then
// release the lock and the connection. The snapshot is taken
// AFTER the lock is held, so the second concurrent recompute
// snapshots state AFTER the first commits.
//
// Override paths (Service.AcknowledgeFinding / SuppressFinding)
// keep using `WithTxLockedFindings` (READ COMMITTED + xact
// lock). They touch a single row and don't need snapshot
// isolation; the simpler xact-scope pattern is appropriate.
//
// CLAUDE.md §8.10 concurrency discipline: documented owner
// (the streaming recompute path), deterministic release
// (deferred), bounded lifetime (single connection acquisition).
func (db *DB) WithTxLockedFindingsRepeatableRead(ctx context.Context, organizationID string, fn func(ctx context.Context) error) error {
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres: acquire connection for findings recompute lock: %w", err)
	}
	// connReleased toggles to true once we've handed the
	// connection back to the pool — either via Release() in
	// the happy path or via Hijack()+Close() when unlock
	// fails. The final defer below uses it to ensure we
	// don't double-release.
	connReleased := false
	defer func() {
		if !connReleased {
			conn.Release()
		}
	}()

	// Session-scope lock — held until pg_advisory_unlock or
	// connection close. Acquired BEFORE the tx so the
	// REPEATABLE READ snapshot below sees state after any
	// previous holder committed.
	if _, err := conn.Exec(ctx,
		`SELECT pg_advisory_lock(hashtext('findings-recompute'), hashtext($1))`,
		organizationID); err != nil {
		return fmt.Errorf("postgres: advisory lock findings org %s (session): %w", organizationID, err)
	}
	defer func() {
		// Release the lock explicitly. The connection will
		// return to the pool with a clean lock state; if this
		// fails, the pool would otherwise hand a still-locked
		// connection to the next caller (under PostgreSQL's
		// session-lock semantics).
		//
		// Use a fresh context for unlock so a cancelled
		// caller-ctx does not prevent us from releasing the
		// lock. A 5-second budget is generous.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx,
			`SELECT pg_advisory_unlock(hashtext('findings-recompute'), hashtext($1))`,
			organizationID); err != nil {
			// Defensive cleanup: if the unlock SQL failed
			// (timeout, network error, etc.) the session
			// lock state on this connection is undefined —
			// it MAY still be held. Returning the
			// connection to the pool would let a subsequent
			// borrower inherit the lock (`pg_advisory_lock`
			// is reentrant per-session; an unreleased lock
			// stays held across borrowers on the same
			// physical connection).
			//
			// pgx's pool DOES discard connections that look
			// broken on Release(), but a healthy-looking
			// connection with a timed-out query body is NOT
			// guaranteed to be detected. Be explicit: hijack
			// the connection out of the pool and close the
			// underlying conn. Closing the TCP connection
			// drops every session-scope lock the backend was
			// holding for it (PostgreSQL releases advisory
			// locks on session end).
			//
			// The hijacked conn is closed with a fresh ctx
			// so a cancelled caller-ctx can't prevent the
			// close — same rationale as the unlock ctx.
			if hijacked := conn.Hijack(); hijacked != nil {
				closeCtx, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelClose()
				_ = hijacked.Close(closeCtx)
			}
			connReleased = true
		}
	}()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return fmt.Errorf("postgres: begin repeatable-read tx for findings org %s: %w", organizationID, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if err := fn(contextWithTx(ctx, tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit findings recompute tx: %w", err)
	}
	committed = true
	return nil
}

// WithTxRaw exposes the underlying pgx.Tx for callers inside this
// package (migrations.go) and for integration tests that need to
// exercise raw SQL (audit-events-are-append-only). Production
// domain code MUST use WithTx instead.
func (db *DB) WithTxRaw(ctx context.Context, fn func(pgx.Tx) error) error {
	return db.withRawTx(ctx, fn)
}

func (db *DB) withRawTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return db.withRawTxWithOptions(ctx, pgx.TxOptions{}, fn)
}

// withRawTxWithOptions is the shared transaction primitive that
// both withRawTx (default isolation) and
// WithTxLockedFindingsRepeatableRead (REPEATABLE READ) layer on
// top of. Keeping the rollback / commit plumbing in one place
// makes future isolation-level additions a one-line change.
func (db *DB) withRawTxWithOptions(ctx context.Context, opts pgx.TxOptions, fn func(pgx.Tx) error) error {
	tx, err := db.pool.BeginTx(ctx, opts)
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

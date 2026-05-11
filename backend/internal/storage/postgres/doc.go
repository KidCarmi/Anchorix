// Package postgres is the only place in Anchorix that knows SQL.
//
// Responsibility: implement the repository interfaces declared by
// domain packages (auth.Repository, agents.Repository, audit.Recorder,
// and so on) using a pgx v5 connection pool. Also owns the migration
// runner and the postgres readiness probe.
//
// Allowed imports: domain packages (only for their types and
// interfaces — never their service implementations), internal/clock,
// internal/ids, internal/logger, and the pgx driver.
//
// Forbidden imports: internal/httpapi/*. Domain modules never import
// this package directly; the composition root in cmd/anchorix is the
// only caller that knows the concrete implementation. This keeps the
// CLAUDE.md §8.6 forbidden edge (handlers → storage/postgres) closed.
//
// Architectural role: storage layer (CLAUDE.md §5, §10, §16). All SQL
// queries use parameter binding (CLAUDE.md §6.7); no string concat.
// Migrations are append-only numbered files loaded via go:embed and
// applied through an explicit, deterministic runner — never at
// process startup, never implicit (CLAUDE.md §16).
package postgres

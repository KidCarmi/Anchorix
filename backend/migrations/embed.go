// Package migrations embeds the SQL migration files so the
// anchorix binary carries its expected schema with it. Per
// CLAUDE.md §16, schema changes go through numbered append-only
// .sql files in this directory; the storage/postgres runner
// applies them in order and never auto-mutates at runtime.
//
// This package is intentionally trivial. The embedded fs.FS is the
// single export; the application of these migrations to a database
// lives in internal/storage/postgres.
package migrations

import "embed"

// FS is the embedded filesystem of all migrations. Each file is
// named NNNN_<slug>.sql and is loaded in version order at startup.
//
//go:embed *.sql
var FS embed.FS

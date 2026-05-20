-- ============================================================
-- Anchorix v0.1 — migration 0008: H-024A perf indexes.
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
--
-- Scope: H-024A (groundwork). Lands two indexes that the existing
-- read paths can use immediately; the streaming-recompute changes
-- that fully exploit them are H-024B and are NOT in this PR.
--
-- Design source of truth:
--   docs/engineering/H024_PERFORMANCE_PLAN.md §6.4, §9.A item 1.
-- ============================================================

BEGIN;

-- ----------------------------------------
-- certificate_observations_org_cert_active_idx
--
-- Partial index supporting the "currently observed" filter used by
-- the operator certificate list endpoints' EXISTS subquery
-- (`internal/storage/postgres/certificate_inventory_list_repository.go`
-- `ListCertificates` — the `q.CurrentOnly` branch composes
-- `EXISTS (SELECT 1 FROM certificate_observations o WHERE
--   o.organization_id = c.organization_id AND
--   o.certificate_id  = c.id AND o.removed_at IS NULL)`).
--
-- Migration 0005's `certificate_observations_org_certificate_idx`
-- covers the same lookup keys but indexes every row, including the
-- ever-growing tail of removed observations the `current_only`
-- filter exists to exclude. This partial index lets PostgreSQL skip
-- the removed tail entirely and stays small at fleet scale (the
-- v0.1 / pilot / fleet targets in H024_PERFORMANCE_PLAN.md §3 put
-- removed observations at 5–15% of the population, so the partial
-- index is ~20× smaller than the full one and serves the hot read
-- path directly).
--
-- The full index from 0005 stays — it serves the
-- "include-removed" path used by H-020's `?current_only=false`
-- operator queries and the existing recompute load.
-- ----------------------------------------
CREATE INDEX certificate_observations_org_cert_active_idx
    ON certificate_observations(organization_id, certificate_id)
    WHERE removed_at IS NULL;

-- ----------------------------------------
-- certificates_org_last_seen_idx
--
-- Composite index on (organization_id, last_seen_at DESC, id ASC)
-- matching the ORDER BY tuple of the operator certificate list
-- endpoint (`ListCertificates` in
-- `internal/storage/postgres/certificate_inventory_list_repository.go`
-- — `ORDER BY c.last_seen_at DESC, c.id ASC`). The cursor encodes
-- the same `(last_seen_at, id)` tuple, so the WHERE clause for
-- pagination's "after-cursor" predicate
-- `(c.last_seen_at < $N OR (c.last_seen_at = $N AND c.id > $M))`
-- composes with the ordering into an index-only walk.
--
-- Migration 0001's `certificates_org_idx` is on `organization_id`
-- alone — sufficient at v0.1 scale but forces a sort to satisfy
-- the ordering. As the cert table grows past the pilot/fleet
-- targets in H024_PERFORMANCE_PLAN.md §3, the sort cost shows up
-- on every list-endpoint page; this index removes it.
-- ----------------------------------------
CREATE INDEX certificates_org_last_seen_idx
    ON certificates(organization_id, last_seen_at DESC, id ASC);

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (8);

COMMIT;

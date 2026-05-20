-- ============================================================
-- Anchorix v0.1 — migration 0007: findings override columns
-- (H-023).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
-- ============================================================

BEGIN;

-- ----------------------------------------
-- Override metadata columns for the H-023 acknowledge / suppress
-- workflow.
--
-- The findings table already carries `status` (CHECK constraint
-- in migration 0001 admits `open` / `acknowledged` /
-- `suppressed` / `resolved`). H-021 used only `open` /
-- `resolved`; H-023 is what finally writes the override values
-- into the column.
--
-- The four new columns persist the OPERATOR'S CURRENT INTENT.
-- The immutable history of override actions lives in
-- audit_events (`finding.acknowledged` / `finding.suppressed`
-- rows). The columns here are denormalized current-state so
-- the operator GET endpoints can return "who set this and
-- why" without a JOIN against audit_events.
--
-- All four are nullable: a finding that has never been
-- overridden (status remains `open` / `resolved`) carries
-- NULL in each. When recompute auto-transitions an
-- overridden finding away from acknowledged/suppressed (rule
-- no longer matches, suppression expired), the columns are
-- cleared back to NULL so the current state correctly
-- reflects "no operator intent on this row right now". The
-- prior override remains visible in audit_events forever.
-- ----------------------------------------
ALTER TABLE findings
    ADD COLUMN status_reason       TEXT,
    ADD COLUMN status_actor        TEXT,
    ADD COLUMN status_changed_at   TIMESTAMPTZ,
    ADD COLUMN suppress_expires_at TIMESTAMPTZ;

-- No new indexes. The status filter is already served by
-- migration 0006's findings_org_status_idx. The override
-- columns are read alongside the row (every operator GET) and
-- written transactionally; query patterns that filter ON the
-- override columns (e.g. "suppressed-expiring-soon") are not
-- in v0.1 scope.

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (7);

COMMIT;

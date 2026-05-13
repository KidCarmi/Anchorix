-- ============================================================
-- Anchorix v0.1 — migration 0003: agents.credential_hash index +
-- uniqueness (PR-016 / H-007 follow-up).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
-- ============================================================

BEGIN;

-- ----------------------------------------
-- Partial unique index on agents.credential_hash.
--
-- Why partial: 0002 added the column as nullable so the v0.1
-- bearer flow can write NULL for legacy paths (and so the future
-- mTLS migration can populate the column for some agents but not
-- all during the transition). PostgreSQL UNIQUE constraints treat
-- multiple NULLs as distinct under default semantics, but the
-- WHERE clause makes the intent explicit and lets the planner
-- skip null rows entirely.
--
-- Why UNIQUE: two agents must never share the same credential
-- hash. SHA-256 collisions are astronomically improbable, but the
-- index defends against repository bugs that would otherwise let
-- a regression create duplicate rows.
--
-- Why an index at all: the agent-bearer auth middleware
-- (internal/httpapi/middleware/agent_auth.go) runs
--   SELECT ... FROM agents WHERE credential_hash = $1
-- on every authenticated agent request. Without an index the
-- query would seq-scan the agents table on every call, which
-- breaks at fleet sizes that v0.1 explicitly targets (SCCM-style
-- bulk rollouts produce thousands of agents per organization).
-- The unique index converts the lookup to an index probe.
-- ----------------------------------------
CREATE UNIQUE INDEX agents_credential_hash_uniq
    ON agents(credential_hash)
    WHERE credential_hash IS NOT NULL;

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (3);

COMMIT;

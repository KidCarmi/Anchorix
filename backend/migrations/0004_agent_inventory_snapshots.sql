-- ============================================================
-- Anchorix v0.1 — migration 0004: agent inventory snapshots
-- (PR-018).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
-- ============================================================

BEGIN;

-- ----------------------------------------
-- agent_inventory_snapshots: one *current* host-facts snapshot per
-- agent. This is operational state sync (like the agent's
-- last_seen_at heartbeat column), not an event stream — the row is
-- REPLACED on every successful POST /agent/inventory, and there is
-- no history table in v0.1. Certificate inventory is a separate
-- domain (internal/inventory) and is NOT touched by this migration.
--
-- Snapshot semantics:
--   - one row per (organization_id, agent_id),
--   - UPSERT on every inventory submission,
--   - no per-batch row, no audit row on success (matches the
--     heartbeat cost model in AGENT_ENROLLMENT.md),
--   - `received_at` is server-assigned; `installed_at` is whatever
--     the agent reported (nullable — early installers may not
--     supply it),
--   - `local_ips` is JSONB so the application can store the
--     reported address list verbatim; the column shape is
--     identical to agents.labels (0002) so downstream code reuses
--     the same JSON encoding.
--
-- Org scoping: organization_id is denormalized off the agent row so
-- the operator-side read endpoint can scope by org without an
-- agents-table join. The FK on agent_id keeps the two columns in
-- agreement; a future revoke / delete of the agent cascades to its
-- snapshot.
-- ----------------------------------------
CREATE TABLE agent_inventory_snapshots (
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    agent_id        TEXT        NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    hostname        TEXT        NOT NULL DEFAULT '',
    os_name         TEXT        NOT NULL DEFAULT '',
    os_version      TEXT        NOT NULL DEFAULT '',
    agent_version   TEXT        NOT NULL DEFAULT '',
    machine_arch    TEXT        NOT NULL DEFAULT '',
    local_ips       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    installed_at    TIMESTAMPTZ,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, agent_id)
);

-- agent_inventory_snapshots_agent_idx supports the operator read
-- endpoint GET /api/v1/agents/{id}/inventory: lookup by agent_id is
-- the hot path, and the primary key (organization_id, agent_id) does
-- not by itself cover an agent-id-only WHERE clause efficiently
-- because organization_id leads the key.
CREATE INDEX agent_inventory_snapshots_agent_idx
    ON agent_inventory_snapshots(agent_id);

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (4);

COMMIT;

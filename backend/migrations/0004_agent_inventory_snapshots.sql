-- ============================================================
-- Anchorix v0.1 — migration 0004: agent inventory snapshots
-- (PR-018).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
-- ============================================================

BEGIN;

-- ----------------------------------------
-- agents_org_id_uniq: UNIQUE on (organization_id, id).
--
-- agents.id is already PRIMARY KEY and therefore unique on its
-- own; this constraint is NOT about preventing id collisions. It
-- exists so the COMPOSITE foreign key on
-- agent_inventory_snapshots (below) has a valid referenced key —
-- PostgreSQL requires the columns a FK references to form a
-- unique constraint or index on the parent table.
--
-- Without this constraint, the FK below would have to be a
-- single-column reference to agents(id), which guarantees the
-- agent exists but does NOT guarantee the snapshot's
-- organization_id matches the agent's organization_id. That gap
-- is exactly what the composite FK closes (CLAUDE.md §6.12 fail
-- closed, §16 DB-level invariants).
-- ----------------------------------------
ALTER TABLE agents
    ADD CONSTRAINT agents_org_id_uniq UNIQUE (organization_id, id);

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
-- Org-agent integrity (composite FK):
--   organization_id is denormalized off the agent row so the
--   operator-side read endpoint can scope by org without an
--   agents-table join. The denormalization is only safe because
--   of the COMPOSITE foreign key
--
--     (organization_id, agent_id) -> agents(organization_id, id)
--
--   declared below. That constraint is what guarantees, at the
--   DB level, that a snapshot's organization_id matches the
--   organization_id on the agent's own row. A single-column FK
--   on agent_id alone would only prove the agent exists; the
--   composite FK additionally rejects a buggy repository, a
--   direct SQL path, or a future ETL job that tries to write a
--   snapshot whose organization_id disagrees with the agent's
--   own org (CLAUDE.md §6.8 default deny, §16 DB-owns-invariants).
--
-- ON DELETE CASCADE preserves the agent-delete behavior a
-- single-column FK on agent_id alone would have provided: when
-- an agent row is deleted, its snapshot row is deleted too.
-- ----------------------------------------
CREATE TABLE agent_inventory_snapshots (
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    agent_id        TEXT        NOT NULL,
    hostname        TEXT        NOT NULL DEFAULT '',
    os_name         TEXT        NOT NULL DEFAULT '',
    os_version      TEXT        NOT NULL DEFAULT '',
    agent_version   TEXT        NOT NULL DEFAULT '',
    machine_arch    TEXT        NOT NULL DEFAULT '',
    local_ips       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    installed_at    TIMESTAMPTZ,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, agent_id),
    -- Composite FK: the (org, agent) pair MUST match a real agent
    -- row in the same org. See the table comment above for the
    -- denormalization-safety argument this constraint backs.
    FOREIGN KEY (organization_id, agent_id)
        REFERENCES agents(organization_id, id)
        ON DELETE CASCADE
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

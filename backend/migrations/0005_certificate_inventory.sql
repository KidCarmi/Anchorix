-- ============================================================
-- Anchorix v0.1 — migration 0005: certificate inventory storage
-- foundation (H-014).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
-- ============================================================

BEGIN;

-- ----------------------------------------
-- certificates_org_id_uniq: UNIQUE on (organization_id, id).
--
-- certificates.id is already PRIMARY KEY and therefore unique on
-- its own; this constraint is NOT about collisions. It exists so
-- the COMPOSITE foreign key on certificate_observations (below)
-- has a valid referenced key — PostgreSQL requires the columns a
-- FK references to form a unique constraint or index on the
-- parent table.
--
-- Mirrors agents_org_id_uniq from migration 0004, which made the
-- same accommodation for agent_inventory_snapshots' composite FK
-- to agents(organization_id, id). The same denormalization-safety
-- argument applies: a buggy repository or direct SQL path could
-- otherwise create a snapshot or observation whose
-- organization_id disagrees with the parent row's own
-- organization_id, defeating the org-scoping invariant the v0.1
-- design depends on (CLAUDE.md §6.12, §16).
-- ----------------------------------------
ALTER TABLE certificates
    ADD CONSTRAINT certificates_org_id_uniq UNIQUE (organization_id, id);

-- ----------------------------------------
-- certificate_observations: rebuilt from the 0001 schema.
--
-- Migration 0001 declared certificate_observations with single-
-- column FKs to certificates(id) and agents(id), a unique key
-- missing organization_id, a `hostname` column, and a single
-- `observed_at` timestamp. That shape predates the H-011 design
-- (docs/engineering/CERTIFICATE_INVENTORY.md) which committed to:
--
--   - composite FKs that bind (organization_id, agent_id) and
--     (organization_id, certificate_id) to the parent rows in the
--     same organization,
--   - the unique key (organization_id, certificate_id, agent_id,
--     store_location),
--   - the first_seen_at / last_seen_at / removed_at timestamp
--     model that supports set-reconciliation per store_coverage,
--   - dropping `hostname` (the H-006 / H-011 designs make agent_id
--     the stable identity axis; hostname is descriptive only).
--
-- The 0001 table has never been wired to application code and has
-- never carried production data. CLAUDE.md §16's destructive
-- two-phase migration pattern applies when there is a live caller
-- of the old shape to protect; there is none. DROP+CREATE here is
-- the cleanest path to the H-011 design.
-- ----------------------------------------
DROP TABLE certificate_observations;

CREATE TABLE certificate_observations (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    certificate_id  TEXT        NOT NULL,
    agent_id        TEXT        NOT NULL,
    store_location  TEXT        NOT NULL,
    friendly_name   TEXT        NOT NULL DEFAULT '',
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL,
    removed_at      TIMESTAMPTZ,
    UNIQUE (organization_id, certificate_id, agent_id, store_location),
    -- Composite FKs (PR-019 H-009 pattern). The observation's
    -- (organization_id, agent_id) MUST match a real agent row in
    -- the same org; same for (organization_id, certificate_id).
    -- ON DELETE CASCADE keeps observation rows in sync with their
    -- parent rows (an agent or cert deletion takes its
    -- observations with it).
    FOREIGN KEY (organization_id, agent_id)
        REFERENCES agents(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, certificate_id)
        REFERENCES certificates(organization_id, id) ON DELETE CASCADE
);

-- Indexes per CERTIFICATE_INVENTORY.md §10.
--
-- certificate_observations_org_agent_idx supports "what's on agent
-- X?" queries — the hot path for the future
-- GET /api/v1/agents/{id}/certificates operator endpoint
-- (H-016). The primary key (organization_id, certificate_id,
-- agent_id, store_location) leads with certificate_id, so an
-- agent-id-only WHERE clause doesn't use it efficiently.
CREATE INDEX certificate_observations_org_agent_idx
    ON certificate_observations(organization_id, agent_id);

-- certificate_observations_org_certificate_idx supports "who has
-- cert X?" queries — the hot path for the future
-- GET /api/v1/certificates/{id}/observations operator endpoint
-- (H-016).
CREATE INDEX certificate_observations_org_certificate_idx
    ON certificate_observations(organization_id, certificate_id);

-- certificate_observations_org_removed_idx supports
-- "currently observed" filtering (`removed_at IS NULL`), which is
-- the default in CERTIFICATE_INVENTORY.md §12 and Phase 4
-- findings will rely on heavily.
CREATE INDEX certificate_observations_org_removed_idx
    ON certificate_observations(organization_id, removed_at);

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (5);

COMMIT;

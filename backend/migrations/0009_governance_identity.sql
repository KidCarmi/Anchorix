-- ============================================================
-- Anchorix v0.x — migration 0009: governance identity vocabulary
-- (H-026A1).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
--
-- Scope: the identity-layer half of the H-026 trust governance
-- foundation. Tags, services, service groups, agent groups, and
-- their assignment / membership tables. The ownership and policy
-- halves land in migrations 0010 and 0011; H-026B turns on the
-- inference engine that consumes all three.
--
-- Design source of truth:
--   docs/engineering/H026_TRUST_GOVERNANCE_PLAN.md §3.3–§3.6, §11.1.
--
-- Composite-FK pattern: every parent table that is a child's
-- composite-FK target carries `UNIQUE (organization_id, id)`.
-- Mirrors certificates_org_id_uniq (0005) and agents_org_id_uniq
-- (0004). PostgreSQL requires the referenced column tuple to carry
-- a unique constraint; the PK on `id` alone does NOT satisfy a
-- composite reference on `(organization_id, id)`. The constraint
-- enforces cross-org safety at the DB level (CLAUDE.md §6.12, §16).
-- ============================================================

BEGIN;

-- ----------------------------------------
-- tags: operator-curated (key, value) classification metadata.
--
-- A tag is first-class so it can be renamed, described, and
-- disabled without cascading deletes through assignment rows.
-- The (key, value) pair is the operator-visible identity within
-- an organization; the engine-facing id is opaque.
--
-- `value` may be empty — the tag then acts as a boolean flag.
--
-- Disable is soft: `disabled_at` records when, but the row stays
-- so future explanations / assignments can resolve historical
-- references unambiguously.
-- ----------------------------------------
CREATE TABLE tags (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    key             TEXT        NOT NULL,
    value           TEXT        NOT NULL DEFAULT '',
    description     TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at     TIMESTAMPTZ,
    UNIQUE (organization_id, id),                            -- H-009 composite-FK target
    UNIQUE (organization_id, key, value)
);
-- tags_org_disabled_idx supports the operator list endpoint's
-- "active only" default — the partial form keeps it small even
-- after long-running orgs accumulate disabled rows.
CREATE INDEX tags_org_active_idx
    ON tags(organization_id, key)
    WHERE disabled_at IS NULL;

-- ----------------------------------------
-- tag_assignments: polymorphic attachment of a tag to one target.
--
-- target_type is bounded by a CHECK constraint matching the v0.1
-- enum convention (CLAUDE.md §16 spirit; see users.role,
-- audit_events.actor_type). Cross-table FK integrity for target_id
-- cannot be expressed in pure SQL across multiple parent tables;
-- the service layer (H-026A2) resolves target_type → repository
-- and verifies target_id exists in the same organization before
-- inserting.
--
-- Dangling-row risk: a target_type='certificate' row whose cert
-- is later deleted becomes dangling. v0.1 keeps every certificate
-- forever (CERTIFICATE_INVENTORY.md §10), so this is unreachable
-- in v0.x. A future retention policy would have to cascade
-- through tag_assignments explicitly.
-- ----------------------------------------
CREATE TABLE tag_assignments (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    tag_id          TEXT        NOT NULL,
    target_type     TEXT        NOT NULL
        CHECK (target_type IN ('certificate','agent','service','service_group','agent_group')),
    target_id       TEXT        NOT NULL,
    assigned_by     TEXT        NOT NULL,                   -- user id; 'system' reserved
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, tag_id, target_type, target_id),
    FOREIGN KEY (organization_id, tag_id) REFERENCES tags(organization_id, id) ON DELETE CASCADE
);
-- tag_assignments_target_idx backs "all tags on this target" —
-- the hot read path for the operator detail views (e.g. "what's
-- tagged on certificate X").
CREATE INDEX tag_assignments_target_idx
    ON tag_assignments(organization_id, target_type, target_id);

-- ----------------------------------------
-- services: the named ownership unit. The "thing" a cert is
-- attributed to and that a finding is routed to.
--
-- slug is stable + operator-defined; display_name is for humans.
-- owner_email / owner_team are descriptive — a future
-- notification provider can read them without a new migration.
-- ----------------------------------------
CREATE TABLE services (
    id                       TEXT        PRIMARY KEY,
    organization_id          TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug                     TEXT        NOT NULL,
    display_name             TEXT        NOT NULL,
    description              TEXT        NOT NULL DEFAULT '',
    owner_email              TEXT        NOT NULL DEFAULT '',
    owner_team               TEXT        NOT NULL DEFAULT '',
    business_unit            TEXT        NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at              TIMESTAMPTZ,
    UNIQUE (organization_id, id),                            -- H-009 composite-FK target
    UNIQUE (organization_id, slug)
);
-- services_org_active_idx backs "list active services" — the
-- common operator view excludes disabled services by default.
CREATE INDEX services_org_active_idx
    ON services(organization_id, slug)
    WHERE disabled_at IS NULL;

-- ----------------------------------------
-- service_groups: hierarchical container for services (e.g.
-- Payments > Billing > Checkout).
--
-- parent_id is a self-FK; the composite (organization_id,
-- parent_id) → service_groups(organization_id, id) prevents
-- cross-org parenting. NULL parent_id means "root".
--
-- Cycle prevention is the service layer's job — PostgreSQL has
-- no native acyclic constraint for self-references. The service
-- walks parents on every write and refuses if the walk revisits
-- a node.
-- ----------------------------------------
CREATE TABLE service_groups (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug            TEXT        NOT NULL,
    display_name    TEXT        NOT NULL,
    parent_id       TEXT,
    description     TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at     TIMESTAMPTZ,
    UNIQUE (organization_id, id),                            -- H-009 composite-FK target (incl. self-FK)
    UNIQUE (organization_id, slug),
    FOREIGN KEY (organization_id, parent_id) REFERENCES service_groups(organization_id, id) ON DELETE RESTRICT
);
-- service_groups_parent_idx supports ancestor walks (parent →
-- root) and child enumeration; both are evaluation-time queries.
CREATE INDEX service_groups_parent_idx
    ON service_groups(organization_id, parent_id);

-- ----------------------------------------
-- service_group_memberships: which service belongs to which
-- direct group. One direct group per service in H-026A; the PK
-- on (organization_id, service_id) enforces this.
--
-- Multi-parent (DAG) memberships are deferred — when operator
-- demand surfaces, a follow-up migration can replace the PK with
-- a composite that admits multiple rows per service.
-- ----------------------------------------
CREATE TABLE service_group_memberships (
    organization_id  TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    service_id       TEXT        NOT NULL,
    service_group_id TEXT        NOT NULL,
    assigned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, service_id),
    FOREIGN KEY (organization_id, service_id) REFERENCES services(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_group_id) REFERENCES service_groups(organization_id, id) ON DELETE RESTRICT
);
-- service_group_memberships_group_idx supports the inverse view
-- ("which services are in this group?"). The PK is leading-keyed
-- by service_id, so a group-id-only filter cannot use it.
CREATE INDEX service_group_memberships_group_idx
    ON service_group_memberships(organization_id, service_group_id);

-- ----------------------------------------
-- agent_groups: operational grouping of agents (e.g. "Domain
-- Controllers", "PCI Web Tier").
--
-- Separate vocabulary from service_groups deliberately — agent
-- groups describe infrastructure shape; service groups describe
-- business ownership. Ownership rules can reference an agent
-- group as a match signal (precedence tier 3, see §4.2 of the
-- governance plan).
-- ----------------------------------------
CREATE TABLE agent_groups (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug            TEXT        NOT NULL,
    display_name    TEXT        NOT NULL,
    description     TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at     TIMESTAMPTZ,
    UNIQUE (organization_id, id),                            -- H-009 composite-FK target
    UNIQUE (organization_id, slug)
);
-- agent_groups_org_active_idx mirrors services_org_active_idx;
-- backs "list active groups".
CREATE INDEX agent_groups_org_active_idx
    ON agent_groups(organization_id, slug)
    WHERE disabled_at IS NULL;

-- ----------------------------------------
-- agent_group_memberships: one agent → many groups.
--
-- agent_group_memberships is intentionally distinct from
-- agents.group_name (the deployment-package hint set at install
-- time, see AGENT_ENROLLMENT.md). The text column on agents is
-- the installer's claim; this table is the operator's curated
-- membership.
-- ----------------------------------------
CREATE TABLE agent_group_memberships (
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    agent_id        TEXT        NOT NULL,
    agent_group_id  TEXT        NOT NULL,
    assigned_by     TEXT        NOT NULL,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, agent_id, agent_group_id),
    FOREIGN KEY (organization_id, agent_id) REFERENCES agents(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, agent_group_id) REFERENCES agent_groups(organization_id, id) ON DELETE RESTRICT
);
-- agent_group_memberships_group_idx supports "which agents are
-- in this group?" — the PK leads with agent_id and cannot serve
-- a group-id-only filter efficiently.
CREATE INDEX agent_group_memberships_group_idx
    ON agent_group_memberships(organization_id, agent_group_id);

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (9);

COMMIT;

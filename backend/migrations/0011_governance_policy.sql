-- ============================================================
-- Anchorix v0.x — migration 0011: governance policy tables
-- (H-026A1).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
--
-- Scope: policy_definitions, policy_assignments, policy_waivers,
-- governance_recompute_runs. The H-026D engine reads these and
-- emits policy violation findings; H-026A1 stops at the schema
-- so the storage layer is testable without engine code.
--
-- Design source of truth:
--   docs/engineering/H026_TRUST_GOVERNANCE_PLAN.md §3.11–§3.14,
--   §5 (policy scoping).
-- ============================================================

BEGIN;

-- ----------------------------------------
-- policy_definitions: a named bundle of rules.
--
-- Two version columns, two purposes:
--   - `version` is the operator-facing per-slug counter; bumps
--     when an operator publishes new rule contents under the
--     same slug. Older (slug, version) rows stay for explanation
--     history.
--   - `schema_version` is the engine-side JSONB-shape version;
--     bumps when the H-026D engine learns a new rule `kind` or
--     changes a param shape. The engine refuses to parse a row
--     whose schema_version is higher than the binary supports
--     (fail closed per CLAUDE.md §6.12).
--
-- `rules` JSONB carries a list of {rule_local_id, kind, params,
-- severity} objects. Service-layer validation (H-026A2 / H-026B)
-- parses + validates on every write; the JSONB column is the
-- serialization format, not the source of truth.
-- ----------------------------------------
CREATE TABLE policy_definitions (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug                TEXT        NOT NULL,
    display_name        TEXT        NOT NULL,
    description         TEXT        NOT NULL DEFAULT '',
    rules               JSONB       NOT NULL,
    schema_version      INTEGER     NOT NULL DEFAULT 1,
    version             INTEGER     NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          TEXT        NOT NULL,
    disabled_at         TIMESTAMPTZ,
    UNIQUE (organization_id, id),                              -- H-009 composite-FK target
    UNIQUE (organization_id, slug, version)
);
-- policy_definitions_org_slug_latest_idx supports "give me the
-- latest version of this slug" — a hot path for the operator
-- list endpoint and the resolver.
CREATE INDEX policy_definitions_org_slug_idx
    ON policy_definitions(organization_id, slug, version DESC);

-- ----------------------------------------
-- policy_assignments: bind a policy definition to a scope.
--
-- scope_kind is CHECK-fenced. scope_id integrity across the four
-- possible parent tables (organizations / service_groups /
-- services / certificates) is enforced at the service layer
-- (same polymorphic pattern as tag_assignments and audit_events).
--
-- One ACTIVE assignment per (definition, scope) is enforced by
-- a partial unique index below.
-- ----------------------------------------
CREATE TABLE policy_assignments (
    id                       TEXT        PRIMARY KEY,
    organization_id          TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    policy_definition_id     TEXT        NOT NULL,
    scope_kind               TEXT        NOT NULL
        CHECK (scope_kind IN ('organization','service_group','service','certificate')),
    scope_id                 TEXT        NOT NULL,
    assigned_by              TEXT        NOT NULL,
    assigned_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    cleared_at               TIMESTAMPTZ,
    cleared_by               TEXT,
    FOREIGN KEY (organization_id, policy_definition_id) REFERENCES policy_definitions(organization_id, id) ON DELETE RESTRICT
);
-- policy_assignments_active_idx enforces "one active assignment
-- per (definition, scope)" while keeping cleared history.
CREATE UNIQUE INDEX policy_assignments_active_idx
    ON policy_assignments(organization_id, policy_definition_id, scope_kind, scope_id)
    WHERE cleared_at IS NULL;
-- policy_assignments_scope_active_idx backs "which active
-- policies apply to this scope?" — the engine's scope-chain
-- walk reads this on every recompute pass.
CREATE INDEX policy_assignments_scope_active_idx
    ON policy_assignments(organization_id, scope_kind, scope_id)
    WHERE cleared_at IS NULL;

-- ----------------------------------------
-- policy_waivers: time-bounded exception for one
-- (policy_rule_local_id, scope) tuple.
--
-- Waivers MUST expire — expires_at is NOT NULL. The
-- `policy_waivers_expires_after_granted` CHECK enforces this at
-- the DB level: granted_at < expires_at, always. Past-or-equal
-- expiries are refused even if the service layer is bypassed.
--
-- Maximum TTL is operator-policy, not schema. The service layer
-- (H-026A2 / H-026C) rejects expires_at - now > the configured
-- ANCHORIX_POLICY_WAIVER_MAX_TTL knob with 400
-- policy_waiver_ttl_too_long.
--
-- Active uniqueness is enforced by a partial unique index below.
-- ----------------------------------------
CREATE TABLE policy_waivers (
    id                       TEXT        PRIMARY KEY,
    organization_id          TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    policy_definition_id     TEXT        NOT NULL,
    policy_rule_local_id     TEXT        NOT NULL,
    scope_kind               TEXT        NOT NULL
        CHECK (scope_kind IN ('organization','service_group','service','certificate')),
    scope_id                 TEXT        NOT NULL,
    reason                   TEXT        NOT NULL,
    granted_by               TEXT        NOT NULL,
    granted_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at               TIMESTAMPTZ NOT NULL,
    cleared_at               TIMESTAMPTZ,
    cleared_by               TEXT,
    CONSTRAINT policy_waivers_expires_after_granted CHECK (expires_at > granted_at),
    FOREIGN KEY (organization_id, policy_definition_id) REFERENCES policy_definitions(organization_id, id) ON DELETE RESTRICT
);
-- policy_waivers_active_idx enforces "one active waiver per
-- (definition, rule_local_id, scope)" while keeping cleared
-- history.
CREATE UNIQUE INDEX policy_waivers_active_idx
    ON policy_waivers(organization_id, policy_definition_id, policy_rule_local_id, scope_kind, scope_id)
    WHERE cleared_at IS NULL;
-- policy_waivers_scope_active_idx supports "what waivers apply
-- to this scope?" — the engine reads this during the merge
-- phase.
CREATE INDEX policy_waivers_scope_active_idx
    ON policy_waivers(organization_id, scope_kind, scope_id)
    WHERE cleared_at IS NULL;

-- ----------------------------------------
-- governance_recompute_runs: per-pass operational record.
--
-- Complementary to audit_events. Each pass writes:
--   - one row here with the counter set + timing + outcome,
--   - one `governance.recomputed` audit row (H-026B wiring)
--     that points back at this row via its `run_id` metadata.
--
-- kind / actor_kind are CHECK-fenced text enums. succeeded is
-- BOOLEAN-but-NULLABLE — the row is INSERTed with a NULL when
-- the pass starts and UPDATEd with the final outcome on commit.
-- ----------------------------------------
CREATE TABLE governance_recompute_runs (
    id                       TEXT        PRIMARY KEY,
    organization_id          TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    kind                     TEXT        NOT NULL
        CHECK (kind IN ('ownership','policy')),
    started_at               TIMESTAMPTZ NOT NULL,
    finished_at              TIMESTAMPTZ,
    actor                    TEXT        NOT NULL,
    actor_kind               TEXT        NOT NULL
        CHECK (actor_kind IN ('user','system','preview')),
    succeeded                BOOLEAN,
    error_class              TEXT        NOT NULL DEFAULT '',
    evaluated_count          INTEGER     NOT NULL DEFAULT 0,
    changed_count            INTEGER     NOT NULL DEFAULT 0,
    unchanged_count          INTEGER     NOT NULL DEFAULT 0,
    became_owned_count       INTEGER     NOT NULL DEFAULT 0,
    became_unowned_count     INTEGER     NOT NULL DEFAULT 0,
    flipped_owner_count      INTEGER     NOT NULL DEFAULT 0,
    engine_version           INTEGER     NOT NULL
);
-- governance_recompute_runs_org_kind_recent_idx backs the
-- operator "recent recomputes" list, ordered newest first.
CREATE INDEX governance_recompute_runs_org_kind_recent_idx
    ON governance_recompute_runs(organization_id, kind, started_at DESC);

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (11);

COMMIT;

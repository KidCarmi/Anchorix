-- ============================================================
-- Anchorix v0.1 — migration 0002: deployment packages + agent
-- enrollment foundation (PR-013).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
-- ============================================================

BEGIN;

-- ----------------------------------------
-- Deployment packages: controlled enrollment artifacts an admin
-- creates so a fleet-management tool (SCCM, Intune, GPO, etc.) can
-- silently install agents that auto-enroll on first run.
--
-- The plaintext `bootstrap_secret` lives only in the API response of
-- the package-creation call; the database stores only a SHA-256 hash
-- (CLAUDE.md §6.1: no plaintext secrets). Lookup at enrollment time
-- is by hash, so the secret never has to be revealed back to the
-- server in plaintext form during search.
--
-- `max_uses`, `expires_at`, and `revoked_at` are the three independent
-- lifecycle bounds. All three are checked on every enrollment and
-- the atomicity is enforced by a conditional UPDATE that increments
-- `uses_count` only if all three conditions still hold.
-- ----------------------------------------
CREATE TABLE deployment_packages (
    id                      TEXT        PRIMARY KEY,
    organization_id         TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    name                    TEXT        NOT NULL,
    description             TEXT        NOT NULL DEFAULT '',
    package_type            TEXT        NOT NULL
        CHECK (package_type IN ('baseline','bulk_sccm','technician','vip','lab')),
    agent_version           TEXT        NOT NULL DEFAULT '',
    -- SHA-256 of the plaintext bootstrap secret. Never stored
    -- plaintext, never logged.
    bootstrap_secret_hash   BYTEA       NOT NULL UNIQUE,
    max_uses                INTEGER     NOT NULL CHECK (max_uses > 0),
    uses_count              INTEGER     NOT NULL DEFAULT 0 CHECK (uses_count >= 0),
    expires_at              TIMESTAMPTZ NOT NULL,
    revoked_at              TIMESTAMPTZ,
    revoked_by_user_id      TEXT        REFERENCES users(id) ON DELETE RESTRICT,
    revoked_reason          TEXT        NOT NULL DEFAULT '',
    created_by_user_id      TEXT        NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at            TIMESTAMPTZ,
    -- Optional metadata copied onto each enrolled agent. Used by the
    -- future UI to organize fleets without a full group/label CRUD.
    default_group_name      TEXT        NOT NULL DEFAULT '',
    default_labels          JSONB       NOT NULL DEFAULT '[]'::jsonb,
    -- Defense in depth: uses_count cannot exceed max_uses.
    CONSTRAINT deployment_packages_uses_bounded CHECK (uses_count <= max_uses)
);
-- Most enrollment lookups go through bootstrap_secret_hash, which is
-- already UNIQUE (line above) — that index covers the hot path.
-- org_idx supports the operator-side list view.
CREATE INDEX deployment_packages_org_idx ON deployment_packages(organization_id);
-- expires_at index supports operator filters ("show me expiring packages").
CREATE INDEX deployment_packages_expires_idx ON deployment_packages(expires_at);

-- ----------------------------------------
-- Extend agents to support deployment-package enrollment + the
-- v0.1 bearer-credential identity model.
--
-- The 0001 schema modeled agents as public-key-pinned (the field
-- `public_key_fingerprint` was NOT NULL). PR-013 moves the v0.1
-- identity primitive to a server-issued bearer credential (mTLS
-- deferred per CLAUDE.md §6.4 + AUTH_FOUNDATION non-goals). We
-- relax public_key_fingerprint to NULL so it can be populated by a
-- future mTLS migration without losing the existing column.
-- ----------------------------------------
ALTER TABLE agents ALTER COLUMN public_key_fingerprint DROP NOT NULL;

-- display_name: friendly label for operator UX; may differ from hostname.
ALTER TABLE agents ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

-- deployment_package_id: which deployment package this agent enrolled
-- through. NULL is permitted so future direct-enrollment paths (or
-- back-fills of legacy data) do not require a synthetic package row.
ALTER TABLE agents ADD COLUMN deployment_package_id TEXT
    REFERENCES deployment_packages(id) ON DELETE SET NULL;
CREATE INDEX agents_deployment_package_idx ON agents(deployment_package_id);

-- machine_fingerprint_hash: SHA-256 of an installer-provided machine
-- fingerprint (registry GUID, BIOS UUID, etc.). Stored only as hash
-- so a fingerprint leak from the DB cannot link to a specific host.
ALTER TABLE agents ADD COLUMN machine_fingerprint_hash BYTEA;

-- install_id: a stable installer-generated id (per machine, per install).
-- Used for idempotent reinstall handling. NULL is permitted because
-- early installers may not supply one; when present it is unique per
-- organization so the same installer cannot double-enroll silently.
ALTER TABLE agents ADD COLUMN install_id TEXT;
CREATE UNIQUE INDEX agents_org_install_uniq
    ON agents(organization_id, install_id)
    WHERE install_id IS NOT NULL;

-- group_name + labels: enrollment-time metadata copied from the
-- deployment package. Operator UI uses these to organize the fleet
-- view without a separate group/label CRUD surface in v0.1.
ALTER TABLE agents ADD COLUMN group_name TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN labels JSONB NOT NULL DEFAULT '[]'::jsonb;

-- credential_hash: SHA-256 of the bearer credential issued at
-- enrollment. The plaintext credential is returned exactly once in
-- the enrollment response and never persisted server-side.
ALTER TABLE agents ADD COLUMN credential_hash BYTEA;

-- updated_at: bookkeeping for repository mutations.
ALTER TABLE agents ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (2);

COMMIT;

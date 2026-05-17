-- ============================================================
-- Anchorix v0.1 — migration 0006: certificate findings
-- lifecycle columns (H-021).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
-- ============================================================

BEGIN;

-- ----------------------------------------
-- Lifecycle columns for the findings table.
--
-- Migration 0001 introduced findings(id, organization_id,
-- certificate_id, rule_id, severity, status, title, evidence,
-- opened_at, updated_at) with status restricted to
-- open/acknowledged/suppressed/resolved and the unique key
-- (organization_id, certificate_id, rule_id). v0.1 has never
-- wired this table to application code (the router stubs return
-- 501); the table has carried no production data.
--
-- H-021 layers a deterministic rule-based recompute on top.
-- The recompute needs three pieces of state the 0001 schema did
-- not anticipate:
--
--   * last_seen_at — every recompute that re-confirms a finding
--     bumps this; lets the operator UI tell "still real, last
--     re-confirmed minutes ago" from "stale, last seen weeks
--     ago" without inspecting recompute audit rows.
--   * resolved_at — when a finding transitions open → resolved
--     because the underlying rule no longer matches. Distinct
--     from updated_at (which moves on any state change).
--   * rule_version — the integer version of the rule that
--     produced the finding, so re-evaluating with an updated
--     rule body can be distinguished from a no-op re-confirm.
--
-- opened_at retains its 0001 meaning: the timestamp the finding
-- was FIRST detected. It is the API-facing `first_seen_at` and
-- is preserved across resolve → reopen cycles.
-- ----------------------------------------
ALTER TABLE findings
    ADD COLUMN last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN resolved_at  TIMESTAMPTZ,
    ADD COLUMN rule_version INTEGER     NOT NULL DEFAULT 1;

-- ----------------------------------------
-- Composite FK on (organization_id, certificate_id).
--
-- Migration 0001 declared certificate_id as a single-column FK
-- to certificates(id). Migration 0005 added the
-- certificates_org_id_uniq UNIQUE (organization_id, id)
-- constraint specifically so child tables (observations,
-- findings) can carry a composite FK that binds them to the
-- SAME organization as the parent certificate row. The
-- single-column FK alone admits a hypothetical buggy
-- repository writing a finding whose organization_id disagrees
-- with the cert's own organization_id — the composite FK
-- rejects that at the DB level (CLAUDE.md §6.12, §16
-- DB-owns-invariants).
--
-- The original constraint never enforced cross-org safety, so
-- replacing it now is a same-shape upgrade, not a destructive
-- migration (CLAUDE.md §16 destructive pattern). No data has
-- ever been written via the API.
-- ----------------------------------------
ALTER TABLE findings DROP CONSTRAINT findings_certificate_id_fkey;
ALTER TABLE findings ADD CONSTRAINT findings_org_certificate_fkey
    FOREIGN KEY (organization_id, certificate_id)
    REFERENCES certificates(organization_id, id) ON DELETE CASCADE;

-- ----------------------------------------
-- Stable composite-uniqueness for (organization_id, id).
--
-- Required so future child tables (suppression overrides, audit
-- linkage, etc.) can carry a composite FK referencing
-- findings(organization_id, id) instead of the bare PK. Mirrors
-- certificates_org_id_uniq from 0005 and agents_org_id_uniq from
-- 0004.
-- ----------------------------------------
ALTER TABLE findings
    ADD CONSTRAINT findings_org_id_uniq UNIQUE (organization_id, id);

-- ----------------------------------------
-- Indexes for the operator GET /findings query patterns.
--
-- findings_status_sev_idx already covers (status, severity)
-- joins. The H-021 operator surface filters per (org, rule_id)
-- and per (org, status), neither of which the existing single-
-- column org index serves efficiently when many findings exist.
-- ----------------------------------------
CREATE INDEX findings_org_rule_idx     ON findings(organization_id, rule_id);
CREATE INDEX findings_org_status_idx   ON findings(organization_id, status);
CREATE INDEX findings_org_last_seen_idx ON findings(organization_id, last_seen_at DESC, id ASC);

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (6);

COMMIT;

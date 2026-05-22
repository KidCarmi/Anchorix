-- ============================================================
-- Anchorix v0.x — migration 0010: governance ownership tables
-- (H-026A1).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
--
-- Scope: ownership_rules, certificate_ownership_overrides,
-- ownership_match_explanations, certificate_ownership. The
-- H-026B engine reads ownership_rules + signals from the
-- inventory tables and writes certificate_ownership +
-- ownership_match_explanations.
--
-- Design source of truth:
--   docs/engineering/H026_TRUST_GOVERNANCE_PLAN.md §3.7–§3.10,
--   §4 (engine + precedence).
--
-- Declaration order: ownership_rules → overrides → explanations
-- → certificate_ownership. The cert-ownership row carries FKs to
-- all three of its predecessors, so the predecessors must exist
-- before its FK constraints are created (per §3.2 of the plan).
-- ============================================================

BEGIN;

-- ----------------------------------------
-- ownership_rules: an operator-authored pattern → service rule.
--
-- The (precedence_tier, priority, created_at, id) tuple is the
-- deterministic global walk order — the H-026B engine evaluates
-- tiers in the order pinned by the CHECK enum, then `priority`
-- ASC within tier, then `created_at` ASC, then lexicographic
-- `id` ASC for the final tiebreaker. CHECK constraints fence
-- both `precedence_tier` and `match_kind` so a buggy insert
-- cannot silently widen the enum.
--
-- Soft-delete via `disabled_at` + `enabled`: `enabled` is the
-- runtime flag the engine reads, `disabled_at` is the audit
-- timestamp. The pair lets operators toggle a rule without
-- losing the original disable time.
--
-- ON DELETE RESTRICT on the service FK: a service that has rules
-- pointing at it cannot be physically deleted (soft-delete via
-- services.disabled_at is the operator path).
-- ----------------------------------------
CREATE TABLE ownership_rules (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    name                TEXT        NOT NULL,
    description         TEXT        NOT NULL DEFAULT '',
    service_id          TEXT        NOT NULL,
    precedence_tier     TEXT        NOT NULL
        CHECK (precedence_tier IN ('explicit','service_member','agent_group','san_pattern','subject_pattern','tag','issuer_store','fallback')),
    priority            INTEGER     NOT NULL,
    match_kind          TEXT        NOT NULL
        CHECK (match_kind IN ('san_glob','san_regex','subject_cn_glob','agent_group','issuer_dn','store_location','tag','fallback')),
    match_value         TEXT        NOT NULL,
    enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          TEXT        NOT NULL,
    disabled_at         TIMESTAMPTZ,
    UNIQUE (organization_id, id),                              -- H-009 composite-FK target
    UNIQUE (organization_id, name),
    FOREIGN KEY (organization_id, service_id) REFERENCES services(organization_id, id) ON DELETE RESTRICT
);
-- ownership_rules_org_enabled_walk_idx serves the engine's
-- per-pass rule walk in the deterministic tier/priority/tiebreak
-- order. Partial-on-enabled keeps the index small even after
-- long-running orgs accumulate disabled rules.
CREATE INDEX ownership_rules_org_enabled_walk_idx
    ON ownership_rules(organization_id, precedence_tier, priority, created_at, id)
    WHERE enabled = TRUE;
-- ownership_rules_org_service_idx supports the operator-facing
-- view "show me every rule pointing at service X" and the
-- service-disable preflight check.
CREATE INDEX ownership_rules_org_service_idx
    ON ownership_rules(organization_id, service_id);

-- ----------------------------------------
-- certificate_ownership_overrides: operator pin that always wins
-- in the engine (precedence_tier 'explicit', §4.2 of the plan).
--
-- Soft-delete via (cleared_at, cleared_by, cleared_reason).
-- Exactly one ACTIVE override per cert is enforced by a partial
-- unique index below — table-level partial UNIQUE constraints
-- are not valid SQL, the predicate is only accepted on indexes
-- (per the H-026 post-design hardening pass, PR #41 + #42).
--
-- expires_at lifecycle (auto-expire): when an ownership recompute
-- pass observes `expires_at <= now`, it sets cleared_at = now,
-- cleared_by = 'system', cleared_reason = 'auto-expired' inside
-- the same transaction as the cert's re-derivation and emits an
-- `ownership.override_expired` audit row (engine wiring lands in
-- H-026B; the schema is shape-compatible today).
-- ----------------------------------------
CREATE TABLE certificate_ownership_overrides (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    certificate_id      TEXT        NOT NULL,
    service_id          TEXT        NOT NULL,
    reason              TEXT        NOT NULL,
    set_by              TEXT        NOT NULL,
    set_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ,
    cleared_at          TIMESTAMPTZ,
    cleared_by          TEXT,
    cleared_reason      TEXT,
    UNIQUE (organization_id, id),                              -- H-009 composite-FK target
    FOREIGN KEY (organization_id, certificate_id) REFERENCES certificates(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_id) REFERENCES services(organization_id, id) ON DELETE RESTRICT
);
-- certificate_ownership_overrides_active_idx enforces "one
-- active override per cert" via a partial unique index. A
-- racing operator POST hits the unique violation; the handler
-- (H-026B) translates the unique-violation into
-- 409 ownership_override_conflict.
CREATE UNIQUE INDEX certificate_ownership_overrides_active_idx
    ON certificate_ownership_overrides(organization_id, certificate_id)
    WHERE cleared_at IS NULL;
-- certificate_ownership_overrides_org_cert_idx supports
-- "history for this cert" queries (active + cleared rows
-- ordered by set_at DESC).
CREATE INDEX certificate_ownership_overrides_org_cert_idx
    ON certificate_ownership_overrides(organization_id, certificate_id, set_at DESC);

-- ----------------------------------------
-- ownership_match_explanations: snapshot of the engine's
-- reasoning for one (cert, recompute-that-changed-the-decision)
-- pair.
--
-- Recomputes that re-confirm an existing decision do NOT write
-- a new explanation — they bump certificate_ownership
-- last_evaluated_at only. This caps cardinality.
--
-- losing_rules JSONB is bounded at K=8 entries by the H-026B
-- service layer (the K highest-precedence non-winning rules).
-- signals_seen captures the inputs the engine considered
-- (subject/SANs/issuer/store locations/observing agents/agent
-- groups/tags) so an operator can reconstruct the decision
-- without re-running the engine.
--
-- decided_decision is mirrored from certificate_ownership.decision
-- and CHECK-constrained to the same enum so an operator-facing
-- timeline can render it without joining.
--
-- FK to ownership_rules / services for winning_rule_id /
-- decided_service_id keeps explanations referentially honest;
-- ON DELETE RESTRICT prevents soft-deleted rules from being
-- physically deleted while an explanation still points at them.
-- ----------------------------------------
CREATE TABLE ownership_match_explanations (
    id                  TEXT        PRIMARY KEY,
    organization_id     TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    certificate_id      TEXT        NOT NULL,
    decided_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_decision    TEXT        NOT NULL
        CHECK (decided_decision IN ('matched','overridden','unowned','ambiguous')),
    decided_service_id  TEXT,
    winning_rule_id     TEXT,
    losing_rules        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    signals_seen        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    engine_version      INTEGER     NOT NULL,
    UNIQUE (organization_id, id),                              -- H-009 composite-FK target
    FOREIGN KEY (organization_id, certificate_id) REFERENCES certificates(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, winning_rule_id) REFERENCES ownership_rules(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, decided_service_id) REFERENCES services(organization_id, id) ON DELETE RESTRICT
);
-- ownership_match_explanations_cert_timeline_idx backs the
-- "show me the explanation timeline for this cert" endpoint
-- (decided_at DESC). The composite leads with certificate_id
-- so the per-cert filter pushes down before the sort.
CREATE INDEX ownership_match_explanations_cert_timeline_idx
    ON ownership_match_explanations(organization_id, certificate_id, decided_at DESC);

-- ----------------------------------------
-- certificate_ownership: derived current ownership, one row per
-- cert. Denormalized for the operator read path so
-- "who owns this cert?" never joins through explanation history.
--
-- decision and confidence are CHECK-fenced text enums.
-- decision flips audit at engine-level (H-026B).
--
-- FK fan-out:
--   - certificate_id  → certificates (CASCADE: cert delete drops the row)
--   - service_id      → services (RESTRICT: services can't be physically deleted)
--   - winning_rule_id → ownership_rules (RESTRICT)
--   - override_id     → certificate_ownership_overrides (RESTRICT)
--   - explanation_id  → ownership_match_explanations (RESTRICT)
--
-- explanation_id is NOT NULL — every cert_ownership row has a
-- backing explanation. The engine writes the explanation BEFORE
-- the cert_ownership UPSERT, then references the new id.
-- ----------------------------------------
CREATE TABLE certificate_ownership (
    organization_id          TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    certificate_id           TEXT        NOT NULL,
    service_id               TEXT,
    decision                 TEXT        NOT NULL
        CHECK (decision IN ('matched','overridden','unowned','ambiguous')),
    winning_rule_id          TEXT,
    override_id              TEXT,
    explanation_id           TEXT        NOT NULL,
    confidence               TEXT        NOT NULL
        CHECK (confidence IN ('high','medium','low')),
    first_assigned_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_evaluated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_changed_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, certificate_id),
    FOREIGN KEY (organization_id, certificate_id) REFERENCES certificates(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_id) REFERENCES services(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, winning_rule_id) REFERENCES ownership_rules(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, override_id) REFERENCES certificate_ownership_overrides(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, explanation_id) REFERENCES ownership_match_explanations(organization_id, id) ON DELETE RESTRICT
);
-- certificate_ownership_service_idx backs "all certs this
-- service owns" (operator service detail view).
CREATE INDEX certificate_ownership_service_idx
    ON certificate_ownership(organization_id, service_id);
-- certificate_ownership_decision_idx backs "show me unowned /
-- ambiguous certs" — the unowned-triage operator workflow.
CREATE INDEX certificate_ownership_decision_idx
    ON certificate_ownership(organization_id, decision);

-- ----------------------------------------
-- Record the migration version.
-- ----------------------------------------
INSERT INTO schema_migrations(version) VALUES (10);

COMMIT;

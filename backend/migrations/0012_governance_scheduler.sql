-- ============================================================
-- Anchorix v0.x — migration 0012: governance scheduler state
-- (B4 PR-1).
--
-- Append-only migration. CLAUDE.md §16. Do not edit after merge —
-- add a new numbered migration if the schema needs to evolve.
--
-- Scope: the dormant state/config foundation for the B4 Governance
-- Scheduler. This migration adds ONE table, governance_scheduler_job,
-- that persists per-(org, job) scheduling state — enable flag, paged
-- cursor, next-due time, last-run status, and backoff state — so a
-- future scheduler loop (B4 PR-2+) can drive the dormant H-027/H-029
-- maintenance primitives in bounded, resumable, crash-safe passes.
--
-- NOTHING in this migration activates a maintenance primitive. There
-- is no scheduler loop, no goroutine, no ticker, no job registry, and
-- no job runner in this phase. The table exists so PR-2 has a stable
-- storage contract; until a job row is explicitly enabled and the
-- loop is wired and turned on, the table has zero runtime effect.
--
-- Design source of truth:
--   docs/governance/B4-governance-scheduler-design.md §7 (persistence),
--   §8 (advisory lock), §9 (config), §6.5 (re-arm / fairness).
--
-- org id type: TEXT, matching organizations(id) (migration 0001) and
-- the rest of the governance schema. The B4 design sketched UUID
-- illustratively; the real schema is TEXT (server-minted ids), so
-- this migration uses TEXT to keep the FK type-compatible.
-- ============================================================

BEGIN;

-- ----------------------------------------
-- governance_scheduler_job: one row per (organization, job_name).
--
-- This is OPERATIONAL state, not an audit log. It is updated in
-- place (cursor advances, next_due_at moves, status changes). The
-- authoritative audit trail of what governance state actually
-- changed remains the maintenance primitives' own audit_events rows
-- (H-027 governance.explanation_pruned, H-029
-- ownership.override_expired) — this table never duplicates them
-- (CLAUDE.md §9: no duplicate logging layers).
--
-- Columns:
--   - enabled: default FALSE. A registered-but-disabled job is never
--     selected as due (B4 design §6.4). Disabled is the safe default
--     for a newly initialized job row.
--   - cursor: opaque, job-owned pagination token (a certificate id
--     for the H-027/H-029 primitives). '' (empty) is the start
--     sentinel; the scheduler stores and replays it verbatim and
--     never interprets it. NOT NULL keeps the start state explicit.
--   - next_due_at: when this (org, job) is next eligible to run. The
--     due-selection scan orders by this column ASC; a partial run is
--     re-armed strictly behind not-yet-served due rows
--     (now + partial_requeue_delay) so a served prefix cannot starve
--     later items (B4 design §4.3 / §6.5 fairness).
--   - last_started_at / last_finished_at: bracket the most recent run
--     for operator visibility (CLAUDE.md §7.3 transparency).
--   - last_status: explicit state-machine label (B4 design §18 — no
--     implicit string comparison). CHECK-fenced.
--   - last_error: redacted error summary (CLAUDE.md §6.9 / §9
--     redaction allow-list). NULL when the last run was clean.
--   - consecutive_failures: drives the capped exponential backoff
--     (B4 design §10.3). Reset to 0 on any run that made forward
--     progress (completed or partial); incremented on error.
--   - updated_at: last write to this row.
--
-- Cross-org isolation: the PRIMARY KEY (organization_id, job_name)
-- is the uniqueness + lookup key. Every repository read/write binds
-- organization_id; there is no cross-org statement except the
-- bounded due-selection scan, which orders deterministically and is
-- LIMIT-bounded.
-- ----------------------------------------
CREATE TABLE governance_scheduler_job (
    organization_id      TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    job_name             TEXT        NOT NULL,
    enabled              BOOLEAN     NOT NULL DEFAULT FALSE,
    cursor               TEXT        NOT NULL DEFAULT '',
    next_due_at          TIMESTAMPTZ NOT NULL,
    last_started_at      TIMESTAMPTZ,
    last_finished_at     TIMESTAMPTZ,
    last_status          TEXT        NOT NULL DEFAULT 'pending'
        CHECK (last_status IN ('pending', 'running', 'completed', 'partial', 'error')),
    last_error           TEXT,
    consecutive_failures INTEGER     NOT NULL DEFAULT 0
        CHECK (consecutive_failures >= 0),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, job_name)
);

-- governance_scheduler_job_due_idx serves the hot due-selection scan:
-- "enabled jobs whose next_due_at <= now, ordered by next_due_at ASC,
-- bounded by the per-tick fan-out cap" (B4 design §3.3 / §7.2).
--
-- Partial index (PostgreSQL feature, CLAUDE.md §16 requires explicit
-- rationale): the scan never wants disabled rows, and the disabled
-- set can dominate once jobs are registered-but-off by default, so
-- indexing only enabled rows keeps the due path scanning live work
-- exclusively. The full ordering (next_due_at ASC, organization_id
-- ASC, job_name ASC) is completed by a sort over the small bounded
-- result; organization_id / job_name are the PK, so the tiebreak is
-- cheap and deterministic.
CREATE INDEX governance_scheduler_job_due_idx
    ON governance_scheduler_job (next_due_at)
    WHERE enabled = TRUE;

COMMIT;

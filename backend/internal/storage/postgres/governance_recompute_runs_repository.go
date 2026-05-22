package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// GovernanceRecomputeRunsRepository implements
// governance.GovernanceRecomputeRunsRepository against
// PostgreSQL. Schema lives in migration 0011.
//
// Two engines (ownership in H-026B, policy in H-026D) will both
// write here; the table is the operational record companion to
// audit_events for per-pass detail.
type GovernanceRecomputeRunsRepository struct {
	db *DB
}

// NewGovernanceRecomputeRunsRepository wires the repo.
// CLAUDE.md §8.8.
func NewGovernanceRecomputeRunsRepository(db *DB) *GovernanceRecomputeRunsRepository {
	return &GovernanceRecomputeRunsRepository{db: db}
}

func (r *GovernanceRecomputeRunsRepository) StartRecomputeRun(
	ctx context.Context,
	run *governance.GovernanceRecomputeRun,
) error {
	if run == nil {
		return errors.New("postgres: nil recompute run")
	}
	const q = `
		INSERT INTO governance_recompute_runs (
			id, organization_id, kind, started_at, finished_at,
			actor, actor_kind, succeeded, error_class,
			evaluated_count, changed_count, unchanged_count,
			became_owned_count, became_unowned_count, flipped_owner_count,
			engine_version
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15,
			$16
		)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		run.ID, run.OrganizationID, string(run.Kind), run.StartedAt, run.FinishedAt,
		run.Actor, string(run.ActorKind), run.Succeeded, run.ErrorClass,
		run.EvaluatedCount, run.ChangedCount, run.UnchangedCount,
		run.BecameOwnedCount, run.BecameUnownedCount, run.FlippedOwnerCount,
		run.EngineVersion,
	); err != nil {
		return fmt.Errorf("postgres: start recompute run: %w", err)
	}
	return nil
}

func (r *GovernanceRecomputeRunsRepository) FinishRecomputeRun(
	ctx context.Context,
	run *governance.GovernanceRecomputeRun,
) error {
	if run == nil {
		return errors.New("postgres: nil recompute run")
	}
	const q = `
		UPDATE governance_recompute_runs
		   SET finished_at          = $3,
		       succeeded            = $4,
		       error_class          = $5,
		       evaluated_count      = $6,
		       changed_count        = $7,
		       unchanged_count      = $8,
		       became_owned_count   = $9,
		       became_unowned_count = $10,
		       flipped_owner_count  = $11
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q,
		run.OrganizationID, run.ID,
		run.FinishedAt, run.Succeeded, run.ErrorClass,
		run.EvaluatedCount, run.ChangedCount, run.UnchangedCount,
		run.BecameOwnedCount, run.BecameUnownedCount, run.FlippedOwnerCount,
	)
	if err != nil {
		return fmt.Errorf("postgres: finish recompute run: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return governance.ErrGovernanceRecomputeRunNotFound
	}
	return nil
}

func (r *GovernanceRecomputeRunsRepository) GetRecomputeRun(
	ctx context.Context,
	organizationID, runID string,
) (*governance.GovernanceRecomputeRun, error) {
	const q = `
		SELECT id, organization_id, kind, started_at, finished_at,
		       actor, actor_kind, succeeded, error_class,
		       evaluated_count, changed_count, unchanged_count,
		       became_owned_count, became_unowned_count, flipped_owner_count,
		       engine_version
		  FROM governance_recompute_runs
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, runID)
	run, err := scanRecomputeRun(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrGovernanceRecomputeRunNotFound
		}
		return nil, fmt.Errorf("postgres: get recompute run: %w", err)
	}
	return run, nil
}

// defaultRecentRunsLimit caps the per-call response when the
// caller passes limit <= 0. Sized for the operator "recent
// runs" UI view; H-026C tunes this once the operator surface
// exists.
const defaultRecentRunsLimit = 50

func (r *GovernanceRecomputeRunsRepository) ListRecentRecomputeRuns(
	ctx context.Context,
	organizationID string,
	kind governance.RecomputeKind,
	limit int,
) ([]governance.GovernanceRecomputeRun, error) {
	if limit <= 0 {
		limit = defaultRecentRunsLimit
	}
	const q = `
		SELECT id, organization_id, kind, started_at, finished_at,
		       actor, actor_kind, succeeded, error_class,
		       evaluated_count, changed_count, unchanged_count,
		       became_owned_count, became_unowned_count, flipped_owner_count,
		       engine_version
		  FROM governance_recompute_runs
		 WHERE organization_id = $1 AND kind = $2
		 ORDER BY started_at DESC, id DESC
		 LIMIT $3`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, string(kind), limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list recent recompute runs: %w", err)
	}
	defer rows.Close()
	var out []governance.GovernanceRecomputeRun
	for rows.Next() {
		run, err := scanRecomputeRun(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan recompute run: %w", err)
		}
		out = append(out, *run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate recompute runs: %w", err)
	}
	return out, nil
}

func scanRecomputeRun(r rowScanner) (*governance.GovernanceRecomputeRun, error) {
	var run governance.GovernanceRecomputeRun
	var kind, actorKind string
	if err := r.Scan(
		&run.ID, &run.OrganizationID, &kind, &run.StartedAt, &run.FinishedAt,
		&run.Actor, &actorKind, &run.Succeeded, &run.ErrorClass,
		&run.EvaluatedCount, &run.ChangedCount, &run.UnchangedCount,
		&run.BecameOwnedCount, &run.BecameUnownedCount, &run.FlippedOwnerCount,
		&run.EngineVersion,
	); err != nil {
		return nil, err
	}
	run.Kind = governance.RecomputeKind(kind)
	run.ActorKind = governance.RecomputeActorKind(actorKind)
	return &run, nil
}

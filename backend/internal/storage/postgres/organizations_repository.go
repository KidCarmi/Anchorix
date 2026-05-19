package postgres

import (
	"context"
	"fmt"
)

// OrganizationsRepository exposes the minimal cross-org read
// methods other domain packages need. v0.1 only has one
// concrete consumer — the findings scheduler (H-022) — but the
// package is shaped so future cross-org readers (a fleet-wide
// audit summary, a deployment-package report) can satisfy
// their own narrow consumer-owned interfaces against it without
// the repo growing per-feature methods.
type OrganizationsRepository struct {
	db *DB
}

// NewOrganizationsRepository wires the repo. CLAUDE.md §8.8.
func NewOrganizationsRepository(db *DB) *OrganizationsRepository {
	return &OrganizationsRepository{db: db}
}

// ListOrganizationIDs returns every organization id currently
// in the `organizations` table. Order is `id ASC` for
// repeatability — the scheduler iterates the result and any
// determinism it expects (e.g. between two ticks with the same
// org set, sweep them in the same order) comes from this
// ordering.
//
// Result is small in v0.1 (1 org per CLAUDE.md §13; the
// schema permits more but there's no provisioning path). At
// fleet-of-orgs scale a paginated variant is needed; tracked
// implicitly under H-024-style perf follow-ups when that scale
// arrives.
func (r *OrganizationsRepository) ListOrganizationIDs(ctx context.Context) ([]string, error) {
	const q = `SELECT id FROM organizations ORDER BY id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("postgres: list organization ids: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("postgres: scan organization id: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate organization ids: %w", err)
	}
	return out, nil
}

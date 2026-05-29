package postgres

import (
	"context"
	"fmt"
)

// OwnershipRuleTargetResolver answers the bounded existence questions
// the H-026B3B ownership-rule validator asks before a mutation:
//
//   - does the target service exist and is it active (not disabled)?
//   - does the agent group referenced by an agent_group rule exist
//     and is it active?
//
// Each method is a single-row `SELECT EXISTS` keyed by the composite
// (organization_id, id) — no fleet-wide scan, no unbounded read. The
// interface is consumer-owned in the ownership package; this is the
// concrete postgres implementation wired at the composition root.
type OwnershipRuleTargetResolver struct {
	db *DB
}

// NewOwnershipRuleTargetResolver wires the resolver. CLAUDE.md §8.8.
func NewOwnershipRuleTargetResolver(db *DB) *OwnershipRuleTargetResolver {
	return &OwnershipRuleTargetResolver{db: db}
}

// ActiveServiceExists reports whether serviceID names an active
// (disabled_at IS NULL) service in the organization. A disabled
// service is treated as nonexistent for rule-creation purposes — a
// rule must point at a live ownership target.
func (r *OwnershipRuleTargetResolver) ActiveServiceExists(ctx context.Context, organizationID, serviceID string) (bool, error) {
	const q = `
		SELECT EXISTS (
			SELECT 1 FROM services
			 WHERE organization_id = $1 AND id = $2 AND disabled_at IS NULL
		)`
	var exists bool
	if err := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, serviceID).Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: active service exists: %w", err)
	}
	return exists, nil
}

// ActiveAgentGroupExists reports whether agentGroupID names an active
// agent group in the organization. Used to validate the match_value
// of an agent_group rule (the value is an agent_group id).
func (r *OwnershipRuleTargetResolver) ActiveAgentGroupExists(ctx context.Context, organizationID, agentGroupID string) (bool, error) {
	const q = `
		SELECT EXISTS (
			SELECT 1 FROM agent_groups
			 WHERE organization_id = $1 AND id = $2 AND disabled_at IS NULL
		)`
	var exists bool
	if err := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, agentGroupID).Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: active agent group exists: %w", err)
	}
	return exists, nil
}

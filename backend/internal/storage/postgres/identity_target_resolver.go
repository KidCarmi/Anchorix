package postgres

import (
	"context"
	"fmt"
)

// IdentityTargetResolver implements identity.TargetResolver by
// running narrow EXISTS queries against the existing
// certificates and agents tables. Created in the composition
// root and handed to identity.NewService.
//
// Living in the postgres package (rather than internal/identity
// alongside an inventory adapter) keeps the SQL in one place
// and avoids inverting the dependency direction across
// internal/identity → internal/inventory, which CLAUDE.md §8.6
// forbids.
type IdentityTargetResolver struct {
	db *DB
}

// NewIdentityTargetResolver wires the resolver.
func NewIdentityTargetResolver(db *DB) *IdentityTargetResolver {
	return &IdentityTargetResolver{db: db}
}

// CertificateExists reports whether the (org, cert) pair
// resolves to a real row. Same enumeration-safe contract as
// AgentExistsInOrg — cross-org and truly-missing both return
// false.
func (r *IdentityTargetResolver) CertificateExists(
	ctx context.Context,
	organizationID, certificateID string,
) (bool, error) {
	const q = `SELECT EXISTS (
		SELECT 1 FROM certificates
		 WHERE organization_id = $1 AND id = $2
	)`
	var exists bool
	if err := r.db.querierFor(ctx).QueryRow(ctx, q,
		organizationID, certificateID,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: certificate existence check: %w", err)
	}
	return exists, nil
}

// AgentExists reports whether the (org, agent) pair resolves
// to a real row. Mirrors AgentExistsInOrg on the cert inventory
// repo; redeclared here so the identity package doesn't need
// to import internal/inventory.
func (r *IdentityTargetResolver) AgentExists(
	ctx context.Context,
	organizationID, agentID string,
) (bool, error) {
	const q = `SELECT EXISTS (
		SELECT 1 FROM agents
		 WHERE organization_id = $1 AND id = $2
	)`
	var exists bool
	if err := r.db.querierFor(ctx).QueryRow(ctx, q,
		organizationID, agentID,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: agent existence check: %w", err)
	}
	return exists, nil
}

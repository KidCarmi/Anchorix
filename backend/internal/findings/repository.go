package findings

import (
	"context"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// Repository is the storage contract for the findings domain.
// The concrete implementation lives in
// internal/storage/postgres; this interface is owned by the
// consumer (CLAUDE.md §8.8).
type Repository interface {
	// InsertFinding inserts a brand-new finding row. The
	// caller (Service.Recompute) sets all fields including ID
	// (the repository does NOT mint ids on its own — that
	// keeps finding identity in service hands). Returns an
	// error if the unique key (organization_id, certificate_id,
	// rule_id) collides — Service.Recompute should never reach
	// this case because it pre-loads existing findings and
	// calls UpdateFinding instead, but the constraint stands
	// as defense in depth.
	InsertFinding(ctx context.Context, f *Finding) error

	// UpdateFinding writes the supplied state to an existing
	// row identified by f.ID + f.OrganizationID. The caller
	// MUST have set UpdatedAt on the finding (the service
	// passes the recompute's `now`). Returns
	// ErrFindingNotFound if no row matches.
	UpdateFinding(ctx context.Context, f *Finding) error

	// GetFinding returns a single finding by id within an
	// organization. Returns ErrFindingNotFound when no row
	// matches. The org column is part of the WHERE clause so
	// cross-org ids surface as not-found, never as forbidden
	// (CLAUDE.md §6 deterministic auth).
	GetFinding(ctx context.Context, organizationID, findingID string) (*Finding, error)

	// ListAllForOrg returns every finding row for the
	// organization, regardless of status. Used by
	// Service.Recompute to compute the diff against the
	// freshly-evaluated rule matches. v0.1 fleet scale keeps
	// this small (≤ a few thousand rows per org); a paginated
	// variant becomes necessary at findings-era scale.
	ListAllForOrg(ctx context.Context, organizationID string) ([]Finding, error)

	// ListFindings returns one paginated page of findings for
	// the operator GET /findings endpoint. Filters live on the
	// ListQuery struct. Ordering: last_seen_at DESC, id ASC —
	// matches the H-010 list-pattern precedent.
	ListFindings(ctx context.Context, q ListQuery) ([]Finding, error)
}

// CertificateLister is the narrow read interface Service.Recompute
// needs from the inventory package. Defining it here (the
// consumer side) instead of taking the full inventory.Repository
// keeps the cert-list dependency surface honest: the findings
// service only reads cert summaries; it never writes or
// observes.
type CertificateLister interface {
	// ListAllCertificateSummariesForOrg returns all cert
	// summaries for one organization. NO pagination — the
	// recompute pass needs a coherent snapshot of the org's
	// cert inventory in one read. The cap belongs in the
	// implementation; callers that exceed it surface
	// operationally rather than silently truncating.
	ListAllCertificateSummariesForOrg(ctx context.Context, organizationID string) ([]inventory.CertificateSummary, error)
}

// Transactor runs fn inside a single transaction. Used by
// Service.Recompute so the diff-apply + audit-write live in one
// atomic unit (an audit failure rolls back the finding state
// changes per the H-021 brief).
//
// Mirrors the storage/postgres.DB.WithTx signature; the concrete
// type satisfies this interface.
type Transactor interface {
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// nowProvider is the minimal clock surface Service.Recompute
// uses. Matches clock.Clock so the system clock can be passed
// directly; tests inject a fixed clock to pin the boundary
// behavior of expiring/expired rules.
type nowProvider interface {
	Now() time.Time
}

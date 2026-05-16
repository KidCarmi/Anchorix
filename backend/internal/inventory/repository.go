package inventory

import (
	"context"
	"time"
)

// Repository is the storage contract for the certificate inventory
// domain. The concrete implementation lives in
// internal/storage/postgres; this interface is owned by the
// consumer (CLAUDE.md §8.8).
//
// H-014 introduces the storage-layer methods the future H-015
// ingestion service will compose into the batch reconciliation
// flow documented in
// docs/engineering/CERTIFICATE_INVENTORY.md §3, §4.
type Repository interface {
	// UpsertCertificate inserts the certificate if no row exists for
	// (organization_id, fingerprint_sha256); otherwise bumps the
	// existing row's last_seen_at (subject to the out-of-order
	// guard — observedAt must be >= the stored last_seen_at). The
	// returned *Certificate carries the canonical stored ID and
	// timestamps: on conflict, the existing row's ID is returned,
	// not the caller's freshly minted one. Callers MUST treat the
	// returned ID as authoritative.
	//
	// Stores the public-cert PEM as-is. Private-key rejection is
	// the API boundary's responsibility (future H-015); the
	// storage layer trusts what it is handed.
	UpsertCertificate(ctx context.Context, c *Certificate, observedAt time.Time) (*Certificate, error)

	// UpsertObservation creates the observation row for
	// (organization_id, certificate_id, agent_id, store_location)
	// or refreshes the existing row's last_seen_at and clears
	// removed_at. The out-of-order guard prevents an older batch
	// from overwriting newer state: when the stored last_seen_at
	// is strictly greater than observedAt, the row is left
	// untouched. The composite FKs guarantee both (org, agent_id)
	// and (org, certificate_id) reference real parent rows in the
	// same organization.
	UpsertObservation(ctx context.Context, o *CertificateObservation, observedAt time.Time) error

	// MarkMissingObservationsRemoved is the set-reconciliation
	// primitive. For (organization_id, agent_id, store_location IN
	// storeCoverage), every observation whose certificate_id is
	// NOT in observedCertIDs gets removed_at = collectedAt — but
	// only when:
	//
	//   - removed_at IS NULL (idempotent: a row already marked
	//     removed is not bumped to a newer collectedAt), and
	//   - last_seen_at <= collectedAt (out-of-order guard: an
	//     older batch cannot mark a row removed that a newer
	//     batch has refreshed).
	//
	// storeCoverage MUST be non-empty (per
	// CERTIFICATE_INVENTORY.md §3 / §4: an empty store_coverage
	// would silently disable reconciliation). The caller (the
	// future H-015 ingestion service) enforces this at the API
	// boundary; the repository surfaces an explicit error if it
	// receives an empty slice as defense in depth.
	//
	// observedCertIDs may be empty — that case means "the batch
	// reported NO certs in the covered stores, mark ALL existing
	// observations in those stores as removed". This is a valid
	// real-world state (e.g. an agent emptied its trust store).
	MarkMissingObservationsRemoved(
		ctx context.Context,
		organizationID, agentID string,
		storeCoverage []string,
		observedCertIDs []string,
		collectedAt time.Time,
	) error

	// GetCertificate returns a single certificate row by id within
	// an organization. Returns ErrCertificateNotFound when no row
	// matches. The org column is in the WHERE clause for defense
	// in depth even when the caller already proved the operator's
	// org binding upstream.
	GetCertificate(ctx context.Context, organizationID, certificateID string) (*Certificate, error)

	// ListObservationsForCertificate returns every observation
	// (current and removed) for one certificate within an
	// organization, ordered by last_seen_at DESC then agent_id
	// ASC. Used by tests and the future H-016 operator endpoint
	// GET /api/v1/certificates/{id}/observations.
	ListObservationsForCertificate(
		ctx context.Context,
		organizationID, certificateID string,
	) ([]CertificateObservation, error)
}

// ListQuery captures the supported filters for the future
// operator-facing list endpoint GET /api/v1/certificates (H-016).
// Carried in the storage layer's surface so the H-016
// implementation can translate URL query params into this struct
// without changing the public interface.
type ListQuery struct {
	OrganizationID string
	Search         string
	ExpiringBefore string
	Limit          int
	Cursor         string
}

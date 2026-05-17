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
	// would silently disable reconciliation). The H-015 ingestion
	// service enforces this at the API boundary; the repository
	// surfaces an explicit error if it receives an empty slice as
	// defense in depth.
	//
	// observedCertIDs may be empty — that case means "the batch
	// reported NO certs in the covered stores, mark ALL existing
	// observations in those stores as removed". This is a valid
	// real-world state (e.g. an agent emptied its trust store).
	//
	// Returns the number of observation rows affected — used by
	// the HTTP handler to populate `reconciled_absent` in the
	// response envelope (CERTIFICATE_INVENTORY.md §4).
	MarkMissingObservationsRemoved(
		ctx context.Context,
		organizationID, agentID string,
		storeCoverage []string,
		observedCertIDs []string,
		collectedAt time.Time,
	) (int, error)

	// GetCertificate returns a single certificate row by id within
	// an organization. Returns ErrCertificateNotFound when no row
	// matches. The org column is in the WHERE clause for defense
	// in depth even when the caller already proved the operator's
	// org binding upstream.
	GetCertificate(ctx context.Context, organizationID, certificateID string) (*Certificate, error)

	// ListObservationsForCertificate returns every observation
	// (current and removed) for one certificate within an
	// organization, ordered by last_seen_at DESC then agent_id
	// ASC. Returns the full set without pagination; used by the
	// inventory test suite and other callers that need the
	// complete picture at small scale. Operator-facing pagination
	// goes through ListObservationsPage.
	ListObservationsForCertificate(
		ctx context.Context,
		organizationID, certificateID string,
	) ([]CertificateObservation, error)

	// ListCertificates returns one page of CertificateSummary
	// rows for the H-020 operator list endpoints
	// (`GET /certificates` and `GET /agents/{id}/certificates`).
	// The query carries already-validated filter values; the
	// repository is responsible for the SQL translation but NOT
	// for argument validation (that lives in the service).
	//
	// Ordering: last_seen_at DESC, id ASC. The caller asked for
	// q.Limit rows (Limit already includes the +1 sentinel — the
	// service strips it before returning to the HTTP layer).
	ListCertificates(ctx context.Context, q CertificateListQuery) ([]CertificateSummary, error)

	// CountObservations returns (total, active) observation
	// counts for one certificate in one organization. Used by
	// GetCertificateDetail to populate the same two counters the
	// list endpoint already includes per row.
	CountObservations(ctx context.Context, organizationID, certificateID string) (total int, active int, err error)

	// ListObservationsPage returns one page of ObservationListItem
	// rows for the H-020 `GET /certificates/{id}/observations`
	// endpoint. Joins to the agent_inventory_snapshots table to
	// populate Hostname (best-effort — empty when the agent has
	// never submitted an inventory snapshot). Ordering:
	// last_seen_at DESC, agent_id ASC, store_location ASC.
	ListObservationsPage(ctx context.Context, q ObservationListQuery) ([]ObservationListItem, error)

	// AgentExistsInOrg reports whether an agent row exists for
	// (organization_id, agent_id). Used by ListAgentCertificates
	// so the HTTP layer can return 404 for cross-org / missing
	// agent ids without enumerating per-agent state via an
	// empty-items 200.
	AgentExistsInOrg(ctx context.Context, organizationID, agentID string) (bool, error)
}

// Transactor runs fn inside a single transaction with an exclusive
// transaction-scope advisory lock keyed by the agent id. The
// implementation (storage/postgres.DB) binds the tx to ctx so
// repository calls inside fn auto-enlist, and takes
// pg_advisory_xact_lock so two concurrent ingestion batches for
// the same agent serialize (H-017: without serialization, batch A
// can mark batch B's freshly-upserted observation as removed
// before A's own upserts land).
//
// The lock is released automatically on commit / rollback;
// batches for DIFFERENT agents run in parallel.
//
// Interface owned by the consumer per CLAUDE.md §8.8.
type Transactor interface {
	WithTxLockedAgent(ctx context.Context, agentID string, fn func(ctx context.Context) error) error
}

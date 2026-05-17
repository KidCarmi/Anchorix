package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/ids"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// CertificateInventoryRepository implements inventory.Repository
// against PostgreSQL. The schema lives in migration 0005
// (backend/migrations/0005_certificate_inventory.sql); the
// composite-FK pattern follows the PR-019 H-009 precedent that
// agent_inventory_snapshots adopted, ensuring snapshot.org always
// matches both the agent's and the certificate's organization at
// the DB level.
type CertificateInventoryRepository struct {
	db *DB
}

// NewCertificateInventoryRepository wires the repo. CLAUDE.md §8.8:
// constructor-based DI; no globals.
func NewCertificateInventoryRepository(db *DB) *CertificateInventoryRepository {
	return &CertificateInventoryRepository{db: db}
}

// UpsertCertificate inserts the cert if no row exists for
// (organization_id, fingerprint_sha256); otherwise merges
// timestamps with the existing row.
//
// Timestamp semantics (H-018 fix):
//
//   - first_seen_at = LEAST(stored, incoming) — the EARLIEST
//     observedAt across all batches wins, regardless of arrival
//     order. An older batch arriving after a newer one
//     correctly retreats first_seen_at to the true first
//     observation.
//   - last_seen_at = GREATEST(stored, incoming) — the LATEST
//     observedAt wins. An older batch cannot retreat
//     last_seen_at; a newer batch advances it.
//
// On conflict the EXISTING row's id is returned, not the
// caller's freshly minted one. The repo re-reads the canonical
// row after the upsert so the returned *Certificate carries the
// stored subject/issuer/PEM/etc., not the caller's potentially
// stale input — important for out-of-order arrival where the
// caller's metadata may differ from the canonical bytes already
// in the DB.
func (r *CertificateInventoryRepository) UpsertCertificate(
	ctx context.Context,
	c *inventory.Certificate,
	observedAt time.Time,
) (*inventory.Certificate, error) {
	sans, err := json.Marshal(c.SANs)
	if err != nil {
		return nil, fmt.Errorf("postgres: marshal sans: %w", err)
	}
	keyUsages, err := json.Marshal(c.KeyUsages)
	if err != nil {
		return nil, fmt.Errorf("postgres: marshal key_usages: %w", err)
	}
	extKeyUsages, err := json.Marshal(c.ExtKeyUsages)
	if err != nil {
		return nil, fmt.Errorf("postgres: marshal ext_key_usages: %w", err)
	}

	// The DO UPDATE clause runs unconditionally (no WHERE guard).
	// LEAST/GREATEST express the per-column policy directly so
	// out-of-order arrival cannot leave first_seen_at reflecting
	// the order of *arrival* instead of the order of
	// *observation* (the H-018 fix). RETURNING always emits a row
	// — there is no longer an out-of-order fallback path.
	const q = `
		INSERT INTO certificates (
			id, organization_id, fingerprint_sha256, subject, issuer,
			serial_number_hex, signature_algorithm, public_key_algorithm,
			public_key_bits, not_before, not_after, sans, key_usages,
			ext_key_usages, is_self_signed, is_ca, pem,
			first_seen_at, last_seen_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, $15, $16, $17,
			$18, $18
		)
		ON CONFLICT (organization_id, fingerprint_sha256) DO UPDATE
		   SET first_seen_at = LEAST(certificates.first_seen_at, EXCLUDED.first_seen_at),
		       last_seen_at  = GREATEST(certificates.last_seen_at, EXCLUDED.last_seen_at)
		RETURNING id`

	candidateID := strings.TrimSpace(c.ID)
	if candidateID == "" {
		candidateID = ids.New()
	}

	var gotID string
	if err := r.db.querierFor(ctx).QueryRow(ctx, q,
		candidateID, c.OrganizationID, c.FingerprintSHA256, c.Subject, c.Issuer,
		c.SerialNumberHex, c.SignatureAlg, c.PublicKeyAlg,
		c.PublicKeyBits, c.NotBefore, c.NotAfter, sans, keyUsages,
		extKeyUsages, c.IsSelfSigned, c.IsCA, c.PEM,
		observedAt,
	).Scan(&gotID); err != nil {
		return nil, fmt.Errorf("postgres: upsert certificate: %w", err)
	}

	// Re-read the canonical row by id. The DO UPDATE only touched
	// first_seen_at and last_seen_at, so on conflict the stored
	// subject/issuer/PEM/etc. may differ from the caller's input
	// (the stored row carries the bytes from the FIRST insert,
	// which IS the canonical certificate for this fingerprint).
	// Returning the canonical row keeps the contract honest.
	return r.GetCertificate(ctx, c.OrganizationID, gotID)
}

// UpsertObservation creates or merges the observation row for
// (organization_id, certificate_id, agent_id, store_location).
//
// Timestamp + state semantics (H-018 fix):
//
//   - first_seen_at = LEAST(stored, incoming). The EARLIEST
//     observedAt across all batches wins; an older batch
//     arriving after a newer batch correctly retreats
//     first_seen_at to the true first observation.
//   - last_seen_at = GREATEST(stored, incoming). The LATEST
//     observedAt wins; older batches cannot retreat this.
//   - removed_at: cleared only when the incoming batch is at
//     least as new as the stored last_seen_at (i.e., this is the
//     most recent thing for the row). An older batch arriving
//     after a newer batch leaves removed_at untouched.
//   - friendly_name: updated only when the incoming batch is at
//     least as new as the stored last_seen_at AND the incoming
//     value is non-empty (COALESCE + NULLIF idiom — matches the
//     heartbeat handler's preservation pattern from PR-017).
//
// The unconditional DO UPDATE (no WHERE guard) ensures
// first_seen_at gets merged for every conflict, including
// out-of-order arrival where the older batch's
// observedAt is smaller than the stored last_seen_at — exactly
// the case the prior WHERE-guarded variant suppressed entirely.
func (r *CertificateInventoryRepository) UpsertObservation(
	ctx context.Context,
	o *inventory.CertificateObservation,
	observedAt time.Time,
) error {
	const q = `
		INSERT INTO certificate_observations (
			id, organization_id, certificate_id, agent_id,
			store_location, friendly_name,
			first_seen_at, last_seen_at, removed_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6,
			$7, $7, NULL
		)
		ON CONFLICT (organization_id, certificate_id, agent_id, store_location)
		DO UPDATE
		   SET first_seen_at = LEAST(certificate_observations.first_seen_at, EXCLUDED.first_seen_at),
		       last_seen_at  = GREATEST(certificate_observations.last_seen_at, EXCLUDED.last_seen_at),
		       removed_at = CASE
		           WHEN EXCLUDED.last_seen_at >= certificate_observations.last_seen_at THEN NULL
		           ELSE certificate_observations.removed_at
		       END,
		       friendly_name = CASE
		           WHEN EXCLUDED.last_seen_at >= certificate_observations.last_seen_at
		               THEN COALESCE(NULLIF(EXCLUDED.friendly_name, ''), certificate_observations.friendly_name)
		           ELSE certificate_observations.friendly_name
		       END`

	candidateID := strings.TrimSpace(o.ID)
	if candidateID == "" {
		candidateID = ids.New()
	}

	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		candidateID, o.OrganizationID, o.CertificateID, o.AgentID,
		o.StoreLocation, o.FriendlyName,
		observedAt,
	); err != nil {
		return fmt.Errorf("postgres: upsert certificate observation: %w", err)
	}
	return nil
}

// MarkMissingObservationsRemoved marks observations as removed_at
// for (organization_id, agent_id, store_location IN storeCoverage)
// whose certificate_id is NOT in observedCertIDs, subject to:
//
//   - removed_at IS NULL (idempotent — already-removed rows are
//     not bumped to a newer collectedAt),
//   - last_seen_at <= collectedAt (out-of-order guard — an older
//     batch cannot mark a row that a newer batch refreshed).
//
// storeCoverage MUST be non-empty (defense in depth — the H-015
// ingestion service rejects empty coverage at the API boundary
// with 400 bad_request).
func (r *CertificateInventoryRepository) MarkMissingObservationsRemoved(
	ctx context.Context,
	organizationID, agentID string,
	storeCoverage []string,
	observedCertIDs []string,
	collectedAt time.Time,
) (int, error) {
	if strings.TrimSpace(organizationID) == "" {
		return 0, fmt.Errorf("%w: organization id required", inventory.ErrInvalidReconciliation)
	}
	if strings.TrimSpace(agentID) == "" {
		return 0, fmt.Errorf("%w: agent id required", inventory.ErrInvalidReconciliation)
	}
	if len(storeCoverage) == 0 {
		return 0, fmt.Errorf("%w: store_coverage must be non-empty", inventory.ErrInvalidReconciliation)
	}

	// observedCertIDs may legitimately be empty (the batch reported
	// no certs in the covered stores → mark all existing
	// observations in those stores as removed). pgx encodes a nil
	// []string as SQL NULL, which would make
	// `certificate_id = ANY(NULL::text[])` evaluate to NULL — and
	// `NOT NULL` is NULL too, so the WHERE clause would never
	// match any row and reconciliation would silently do nothing.
	// Normalize nil → empty slice so pgx sends an empty array,
	// which `ANY()` correctly treats as FALSE → `NOT FALSE` →
	// TRUE for every row. (Codex P1 fix.)
	if observedCertIDs == nil {
		observedCertIDs = []string{}
	}
	const q = `
		UPDATE certificate_observations
		   SET removed_at = $4
		 WHERE organization_id = $1
		   AND agent_id = $2
		   AND store_location = ANY($3::text[])
		   AND NOT (certificate_id = ANY($5::text[]))
		   AND removed_at IS NULL
		   AND last_seen_at <= $4`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q,
		organizationID, agentID, storeCoverage, collectedAt, observedCertIDs,
	)
	if err != nil {
		return 0, fmt.Errorf("postgres: mark missing observations removed: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// GetCertificate returns the certificate row for the
// (organizationID, certificateID) pair. Returns
// inventory.ErrCertificateNotFound when no row matches. The org
// column is part of the WHERE clause so cross-org ids surface as
// not-found, never as forbidden (CLAUDE.md §6 deterministic
// auth).
func (r *CertificateInventoryRepository) GetCertificate(
	ctx context.Context,
	organizationID, certificateID string,
) (*inventory.Certificate, error) {
	const q = `
		SELECT id, organization_id, fingerprint_sha256, subject, issuer,
		       serial_number_hex, signature_algorithm, public_key_algorithm,
		       public_key_bits, not_before, not_after, sans, key_usages,
		       ext_key_usages, is_self_signed, is_ca, pem,
		       first_seen_at, last_seen_at
		  FROM certificates
		 WHERE id = $1 AND organization_id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, certificateID, organizationID)
	c, err := scanCertificate(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, inventory.ErrCertificateNotFound
		}
		return nil, fmt.Errorf("postgres: get certificate: %w", err)
	}
	return c, nil
}

// ListObservationsForCertificate returns every observation
// (current and removed) for the certificate within the
// organization, ordered by last_seen_at DESC then agent_id ASC.
// The composite FKs guarantee no cross-org rows can be returned;
// the WHERE clause keeps the SQL planner honest on per-org
// queries.
func (r *CertificateInventoryRepository) ListObservationsForCertificate(
	ctx context.Context,
	organizationID, certificateID string,
) ([]inventory.CertificateObservation, error) {
	const q = `
		SELECT id, organization_id, certificate_id, agent_id,
		       store_location, friendly_name,
		       first_seen_at, last_seen_at, removed_at
		  FROM certificate_observations
		 WHERE organization_id = $1 AND certificate_id = $2
		 ORDER BY last_seen_at DESC, agent_id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, certificateID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list observations: %w", err)
	}
	defer rows.Close()

	var out []inventory.CertificateObservation
	for rows.Next() {
		obs, err := scanObservation(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan observation: %w", err)
		}
		out = append(out, *obs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate observations: %w", err)
	}
	return out, nil
}

func scanCertificate(row pgx.Row) (*inventory.Certificate, error) {
	var (
		c                               inventory.Certificate
		sansRaw, keyUsagesRaw, extKURaw []byte
	)
	if err := row.Scan(
		&c.ID, &c.OrganizationID, &c.FingerprintSHA256, &c.Subject, &c.Issuer,
		&c.SerialNumberHex, &c.SignatureAlg, &c.PublicKeyAlg,
		&c.PublicKeyBits, &c.NotBefore, &c.NotAfter, &sansRaw, &keyUsagesRaw,
		&extKURaw, &c.IsSelfSigned, &c.IsCA, &c.PEM,
		&c.FirstSeenAt, &c.LastSeenAt,
	); err != nil {
		return nil, err
	}
	if len(sansRaw) > 0 {
		if err := json.Unmarshal(sansRaw, &c.SANs); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal sans: %w", err)
		}
	}
	if len(keyUsagesRaw) > 0 {
		if err := json.Unmarshal(keyUsagesRaw, &c.KeyUsages); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal key_usages: %w", err)
		}
	}
	if len(extKURaw) > 0 {
		if err := json.Unmarshal(extKURaw, &c.ExtKeyUsages); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal ext_key_usages: %w", err)
		}
	}
	return &c, nil
}

func scanObservation(row pgx.Row) (*inventory.CertificateObservation, error) {
	var (
		o         inventory.CertificateObservation
		removedAt *time.Time
	)
	if err := row.Scan(
		&o.ID, &o.OrganizationID, &o.CertificateID, &o.AgentID,
		&o.StoreLocation, &o.FriendlyName,
		&o.FirstSeenAt, &o.LastSeenAt, &removedAt,
	); err != nil {
		return nil, err
	}
	o.RemovedAt = removedAt
	return &o, nil
}

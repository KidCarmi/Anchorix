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
// (organization_id, fingerprint_sha256); otherwise bumps the
// existing row's last_seen_at to observedAt. The out-of-order
// guard suppresses the bump when the stored last_seen_at is
// already newer than observedAt.
//
// On conflict the EXISTING row's id is returned, not the caller's
// freshly minted one. Callers MUST use the returned ID as
// authoritative — feeding the caller's minted id back to
// UpsertObservation would violate the composite FK on the next
// upsert if the caller's id never made it into the certificates
// table.
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

	// The caller-supplied id is the candidate id for an INSERT. On
	// conflict, EXCLUDED.id is the candidate; we deliberately do
	// NOT overwrite the stored id during DO UPDATE — RETURNING
	// gives back the existing row's id so the caller can use it
	// for the subsequent observation upsert.
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
		   SET last_seen_at = EXCLUDED.last_seen_at
		 WHERE certificates.last_seen_at <= EXCLUDED.last_seen_at
		RETURNING id, first_seen_at, last_seen_at`

	candidateID := strings.TrimSpace(c.ID)
	if candidateID == "" {
		candidateID = ids.New()
	}

	// Note: when the ON CONFLICT WHERE clause is FALSE (stored
	// last_seen_at is newer than the incoming observedAt), the
	// UPDATE is suppressed AND no row is returned by RETURNING.
	// We then need to SELECT the existing row to give the caller a
	// canonical *Certificate to operate on.
	row := r.db.querierFor(ctx).QueryRow(ctx, q,
		candidateID, c.OrganizationID, c.FingerprintSHA256, c.Subject, c.Issuer,
		c.SerialNumberHex, c.SignatureAlg, c.PublicKeyAlg,
		c.PublicKeyBits, c.NotBefore, c.NotAfter, sans, keyUsages,
		extKeyUsages, c.IsSelfSigned, c.IsCA, c.PEM,
		observedAt,
	)
	var (
		gotID                     string
		gotFirstSeen, gotLastSeen time.Time
	)
	if err := row.Scan(&gotID, &gotFirstSeen, &gotLastSeen); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Out-of-order arrival: stored last_seen_at is newer than
			// observedAt, so the UPDATE was suppressed. Read the
			// existing row by (org, fingerprint) and hand it back.
			existing, err := r.getCertificateByFingerprint(ctx, c.OrganizationID, c.FingerprintSHA256)
			if err != nil {
				return nil, err
			}
			return existing, nil
		}
		return nil, fmt.Errorf("postgres: upsert certificate: %w", err)
	}

	cp := *c
	cp.ID = gotID
	cp.FirstSeenAt = gotFirstSeen
	cp.LastSeenAt = gotLastSeen
	return &cp, nil
}

// UpsertObservation creates or refreshes the observation row.
// On conflict (the same observation already exists), the DO
// UPDATE clause bumps last_seen_at and clears removed_at, but
// only when the incoming observedAt is at least as new as the
// stored last_seen_at. An older batch leaves the row untouched.
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
		   SET last_seen_at = EXCLUDED.last_seen_at,
		       friendly_name = EXCLUDED.friendly_name,
		       removed_at = NULL
		 WHERE certificate_observations.last_seen_at <= EXCLUDED.last_seen_at`

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
) error {
	if strings.TrimSpace(organizationID) == "" {
		return fmt.Errorf("%w: organization id required", inventory.ErrInvalidReconciliation)
	}
	if strings.TrimSpace(agentID) == "" {
		return fmt.Errorf("%w: agent id required", inventory.ErrInvalidReconciliation)
	}
	if len(storeCoverage) == 0 {
		return fmt.Errorf("%w: store_coverage must be non-empty", inventory.ErrInvalidReconciliation)
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
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		organizationID, agentID, storeCoverage, collectedAt, observedCertIDs,
	); err != nil {
		return fmt.Errorf("postgres: mark missing observations removed: %w", err)
	}
	return nil
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

// getCertificateByFingerprint is an internal lookup used by the
// out-of-order branch of UpsertCertificate when the ON CONFLICT
// guard suppresses the DO UPDATE. The stored row is fully
// canonical; we hand it back unchanged.
func (r *CertificateInventoryRepository) getCertificateByFingerprint(
	ctx context.Context,
	organizationID, fingerprint string,
) (*inventory.Certificate, error) {
	const q = `
		SELECT id, organization_id, fingerprint_sha256, subject, issuer,
		       serial_number_hex, signature_algorithm, public_key_algorithm,
		       public_key_bits, not_before, not_after, sans, key_usages,
		       ext_key_usages, is_self_signed, is_ca, pem,
		       first_seen_at, last_seen_at
		  FROM certificates
		 WHERE organization_id = $1 AND fingerprint_sha256 = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, fingerprint)
	c, err := scanCertificate(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, inventory.ErrCertificateNotFound
		}
		return nil, fmt.Errorf("postgres: get certificate by fingerprint: %w", err)
	}
	return c, nil
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

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// FindingsRepository implements findings.Repository against
// PostgreSQL. Schema introduced in migration 0001 and extended
// with lifecycle columns + composite FK in migration 0006.
//
// Column / domain field mapping (the SQL column on the left,
// the Go field on the right):
//
//	id              -> Finding.ID
//	organization_id -> Finding.OrganizationID
//	certificate_id  -> Finding.CertificateID
//	rule_id         -> Finding.RuleID
//	rule_version    -> Finding.RuleVersion           (0006)
//	severity        -> Finding.Severity
//	status          -> Finding.Status                  (open/resolved in v0.1)
//	title           -> Finding.Title
//	evidence        -> Finding.Evidence               (JSONB)
//	opened_at       -> Finding.FirstSeenAt            (0001 column kept for API-rename
//	                                                    avoidance per migration 0006 comment)
//	last_seen_at    -> Finding.LastSeenAt             (0006)
//	resolved_at     -> Finding.ResolvedAt             (0006; nullable)
//	updated_at      -> Finding.UpdatedAt
type FindingsRepository struct {
	db *DB
}

// NewFindingsRepository wires the repo. CLAUDE.md §8.8:
// constructor-based DI; no globals.
func NewFindingsRepository(db *DB) *FindingsRepository {
	return &FindingsRepository{db: db}
}

// InsertFinding inserts a brand-new finding row. The caller MUST
// set every field including ID — see the docstring on
// findings.Repository for the rationale (service-owned identity).
func (r *FindingsRepository) InsertFinding(ctx context.Context, f *findings.Finding) error {
	if f == nil {
		return errors.New("postgres: nil finding")
	}
	evidence := jsonValue(f.Evidence)
	const q = `
		INSERT INTO findings (
			id, organization_id, certificate_id,
			rule_id, rule_version,
			severity, status, title, evidence,
			opened_at, last_seen_at, resolved_at, updated_at
		) VALUES (
			$1, $2, $3,
			$4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13
		)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		f.ID, f.OrganizationID, f.CertificateID,
		f.RuleID, f.RuleVersion,
		string(f.Severity), string(f.Status), f.Title, evidence,
		f.FirstSeenAt, f.LastSeenAt, f.ResolvedAt, f.UpdatedAt,
	); err != nil {
		return fmt.Errorf("postgres: insert finding: %w", err)
	}
	return nil
}

// UpdateFinding writes the supplied state to an existing row
// identified by (id, organization_id). The organization_id is in
// the WHERE clause so a buggy caller cannot update across orgs.
func (r *FindingsRepository) UpdateFinding(ctx context.Context, f *findings.Finding) error {
	if f == nil {
		return errors.New("postgres: nil finding")
	}
	evidence := jsonValue(f.Evidence)
	const q = `
		UPDATE findings
		   SET rule_version = $3,
		       severity     = $4,
		       status       = $5,
		       title        = $6,
		       evidence     = $7,
		       last_seen_at = $8,
		       resolved_at  = $9,
		       updated_at   = $10
		 WHERE id = $1 AND organization_id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q,
		f.ID, f.OrganizationID,
		f.RuleVersion,
		string(f.Severity), string(f.Status), f.Title, evidence,
		f.LastSeenAt, f.ResolvedAt, f.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: update finding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return findings.ErrFindingNotFound
	}
	return nil
}

// GetFinding returns the (org, finding) row or ErrFindingNotFound.
func (r *FindingsRepository) GetFinding(
	ctx context.Context,
	organizationID, findingID string,
) (*findings.Finding, error) {
	const q = `
		SELECT id, organization_id, certificate_id,
		       rule_id, rule_version,
		       severity, status, title, evidence,
		       opened_at, last_seen_at, resolved_at, updated_at
		  FROM findings
		 WHERE id = $1 AND organization_id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, findingID, organizationID)
	f, err := scanFinding(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, findings.ErrFindingNotFound
		}
		return nil, fmt.Errorf("postgres: get finding: %w", err)
	}
	return f, nil
}

// ListAllForOrg returns every finding row for the organization,
// regardless of status. Used by Service.Recompute to compute the
// diff against the freshly-evaluated rule matches. The org
// filter is the only WHERE clause; the result is ordered by id
// for repeatability.
func (r *FindingsRepository) ListAllForOrg(
	ctx context.Context,
	organizationID string,
) ([]findings.Finding, error) {
	const q = `
		SELECT id, organization_id, certificate_id,
		       rule_id, rule_version,
		       severity, status, title, evidence,
		       opened_at, last_seen_at, resolved_at, updated_at
		  FROM findings
		 WHERE organization_id = $1
		 ORDER BY id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list all findings: %w", err)
	}
	defer rows.Close()

	var out []findings.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan finding: %w", err)
		}
		out = append(out, *f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate findings: %w", err)
	}
	return out, nil
}

// ListFindings is the paginated/filtered query backing the
// operator GET /findings endpoint. Filters compose with AND;
// no filter falls back to "all rows for the org".
//
// Ordering: last_seen_at DESC, id ASC. Cursor encodes the same
// tuple; "after" is the strict-less + tiebreaker comparison
// matching the H-010 pattern.
func (r *FindingsRepository) ListFindings(
	ctx context.Context,
	q findings.ListQuery,
) ([]findings.Finding, error) {
	var (
		conditions []string
		args       []any
	)
	args = append(args, q.OrganizationID)
	conditions = append(conditions, "organization_id = $1")

	switch q.Status {
	case findings.StatusFilterOpen:
		conditions = append(conditions, "status = 'open'")
	case findings.StatusFilterResolved:
		conditions = append(conditions, "status = 'resolved'")
	case findings.StatusFilterAll:
		// no filter — both open and resolved.
	}

	if q.Severity != "" {
		args = append(args, string(q.Severity))
		conditions = append(conditions, fmt.Sprintf("severity = $%d", len(args)))
	}
	if q.RuleID != "" {
		args = append(args, q.RuleID)
		conditions = append(conditions, fmt.Sprintf("rule_id = $%d", len(args)))
	}
	if q.CertificateID != "" {
		args = append(args, q.CertificateID)
		conditions = append(conditions, fmt.Sprintf("certificate_id = $%d", len(args)))
	}
	if !q.CursorLastSeenAt.IsZero() {
		args = append(args, q.CursorLastSeenAt)
		atIdx := len(args)
		args = append(args, q.CursorID)
		idIdx := len(args)
		// rows AFTER (cursor.last_seen_at, cursor.id) in
		// (last_seen_at DESC, id ASC) order:
		//   last_seen_at < cursor.last_seen_at
		//   OR (last_seen_at = cursor.last_seen_at AND id > cursor.id)
		conditions = append(conditions, fmt.Sprintf(
			"(last_seen_at < $%d OR (last_seen_at = $%d AND id > $%d))",
			atIdx, atIdx, idIdx,
		))
	}

	args = append(args, q.Limit)
	limitIdx := len(args)

	sql := fmt.Sprintf(`
		SELECT id, organization_id, certificate_id,
		       rule_id, rule_version,
		       severity, status, title, evidence,
		       opened_at, last_seen_at, resolved_at, updated_at
		  FROM findings
		 WHERE %s
		 ORDER BY last_seen_at DESC, id ASC
		 LIMIT $%d`,
		strings.Join(conditions, " AND "), limitIdx,
	)

	rows, err := r.db.querierFor(ctx).Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list findings: %w", err)
	}
	defer rows.Close()

	var out []findings.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan finding: %w", err)
		}
		out = append(out, *f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate findings: %w", err)
	}
	return out, nil
}

// scanFinding parses one row into a *findings.Finding.
func scanFinding(row pgx.Row) (*findings.Finding, error) {
	var (
		f           findings.Finding
		severity    string
		status      string
		evidenceRaw []byte
		resolvedAt  *time.Time
	)
	if err := row.Scan(
		&f.ID, &f.OrganizationID, &f.CertificateID,
		&f.RuleID, &f.RuleVersion,
		&severity, &status, &f.Title, &evidenceRaw,
		&f.FirstSeenAt, &f.LastSeenAt, &resolvedAt, &f.UpdatedAt,
	); err != nil {
		return nil, err
	}
	f.Severity = findings.Severity(severity)
	f.Status = findings.Status(status)
	if len(evidenceRaw) > 0 {
		f.Evidence = json.RawMessage(evidenceRaw)
	}
	f.ResolvedAt = resolvedAt
	return &f, nil
}

// jsonValue normalizes a possibly-nil json.RawMessage to the
// PostgreSQL JSON empty-object literal so the JSONB column
// stays valid JSON in every case (the column was declared
// DEFAULT '{}'::jsonb in 0001 but explicit inserts don't see
// that default unless we pass NULL — and we want to always
// store a real JSON value).
func jsonValue(v json.RawMessage) []byte {
	if len(v) == 0 {
		return []byte("{}")
	}
	return v
}

// CertificateLister implementation lives on
// CertificateInventoryRepository so the findings package can
// pull its narrow read interface from the existing inventory
// storage without the inventory repo growing a findings-
// specific surface.

// ListAllCertificateSummariesForOrg is the
// findings.CertificateLister contract. Returns every cert
// summary for the organization in id ASC order. NO pagination
// — the recompute pass requires a coherent org-wide snapshot.
//
// At v0.1 fleet scale (≤ ~1K certs per org per
// CERTIFICATE_INVENTORY.md §10) this fits comfortably in memory.
// At findings-era scale this becomes a batched scan — see
// HARDENING_BACKLOG.
func (r *CertificateInventoryRepository) ListAllCertificateSummariesForOrg(
	ctx context.Context,
	organizationID string,
) ([]inventory.CertificateSummary, error) {
	const q = `
		SELECT id, fingerprint_sha256, subject, issuer,
		       serial_number_hex, signature_algorithm,
		       public_key_algorithm, public_key_bits,
		       not_before, not_after, is_self_signed, is_ca,
		       first_seen_at, last_seen_at,
		       (SELECT COUNT(*) FROM certificate_observations o
		         WHERE o.organization_id = c.organization_id
		           AND o.certificate_id = c.id) AS observation_count,
		       (SELECT COUNT(*) FROM certificate_observations o
		         WHERE o.organization_id = c.organization_id
		           AND o.certificate_id = c.id
		           AND o.removed_at IS NULL) AS active_observation_count
		  FROM certificates c
		 WHERE organization_id = $1
		 ORDER BY id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list all cert summaries: %w", err)
	}
	defer rows.Close()

	var out []inventory.CertificateSummary
	for rows.Next() {
		var s inventory.CertificateSummary
		if err := rows.Scan(
			&s.ID, &s.FingerprintSHA256, &s.Subject, &s.Issuer,
			&s.SerialNumberHex, &s.SignatureAlg,
			&s.PublicKeyAlg, &s.PublicKeyBits,
			&s.NotBefore, &s.NotAfter, &s.IsSelfSigned, &s.IsCA,
			&s.FirstSeenAt, &s.LastSeenAt,
			&s.ObservationCount, &s.ActiveObservationCount,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan cert summary: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate cert summaries: %w", err)
	}
	return out, nil
}

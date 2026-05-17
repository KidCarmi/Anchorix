package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// ListCertificates returns one page of CertificateSummary rows for
// the H-020 operator list endpoints. The SQL composes a base
// SELECT against `certificates c` with scalar subqueries for the
// two observation counters, plus an EXISTS subquery when AgentID
// and/or CurrentOnly are set.
//
// The ordering is (last_seen_at DESC, id ASC) — last_seen_at
// surfaces recent activity first; id breaks any nanosecond tie
// stably. The cursor compares lexicographically against the same
// tuple (see the WHERE clause).
//
// Filters that translate to fixed SQL fragments (subject ILIKE,
// not_after <, is_ca =, agent EXISTS) are appended into the
// `WHERE` clause by string concatenation against pre-numbered
// placeholders — values are still bound with $N. No values are
// interpolated into SQL text (CLAUDE.md §6.7).
func (r *CertificateInventoryRepository) ListCertificates(
	ctx context.Context,
	q inventory.CertificateListQuery,
) ([]inventory.CertificateSummary, error) {
	var (
		conditions []string
		args       []any
	)

	// $1 is reserved for organization_id below.
	args = append(args, q.OrganizationID)
	conditions = append(conditions, "c.organization_id = $1")

	if q.Search != "" {
		args = append(args, "%"+q.Search+"%")
		idx := len(args)
		conditions = append(conditions, fmt.Sprintf(
			"(c.subject ILIKE $%d OR c.issuer ILIKE $%d OR c.fingerprint_sha256 ILIKE $%d OR c.sans::text ILIKE $%d)",
			idx, idx, idx, idx,
		))
	}
	if q.ExpiringBefore != nil {
		args = append(args, *q.ExpiringBefore)
		conditions = append(conditions, fmt.Sprintf("c.not_after < $%d", len(args)))
	}
	if q.IsCA != nil {
		args = append(args, *q.IsCA)
		conditions = append(conditions, fmt.Sprintf("c.is_ca = $%d", len(args)))
	}

	// EXISTS subquery on certificate_observations covers both the
	// "agent_id filter" and the "current_only filter" cases. When
	// AgentID is set, the subquery requires at least one
	// observation by that agent (current or removed, unless
	// CurrentOnly is also true). When CurrentOnly is true without
	// AgentID, the subquery requires at least one active
	// observation by any agent.
	if q.AgentID != "" || q.CurrentOnly {
		var subConds []string
		subConds = append(subConds,
			"o.organization_id = c.organization_id",
			"o.certificate_id = c.id",
		)
		if q.AgentID != "" {
			args = append(args, q.AgentID)
			subConds = append(subConds, fmt.Sprintf("o.agent_id = $%d", len(args)))
		}
		if q.CurrentOnly {
			subConds = append(subConds, "o.removed_at IS NULL")
		}
		conditions = append(conditions, fmt.Sprintf(
			"EXISTS (SELECT 1 FROM certificate_observations o WHERE %s)",
			strings.Join(subConds, " AND "),
		))
	}

	// Cursor: rows AFTER (cursor.last_seen_at, cursor.id) in
	// (last_seen_at DESC, id ASC) order. "After" means:
	//
	//   last_seen_at < cursor.last_seen_at
	//   OR (last_seen_at = cursor.last_seen_at AND id > cursor.id)
	if !q.CursorLastSeenAt.IsZero() {
		args = append(args, q.CursorLastSeenAt)
		atIdx := len(args)
		args = append(args, q.CursorID)
		idIdx := len(args)
		conditions = append(conditions, fmt.Sprintf(
			"(c.last_seen_at < $%d OR (c.last_seen_at = $%d AND c.id > $%d))",
			atIdx, atIdx, idIdx,
		))
	}

	args = append(args, q.Limit)
	limitIdx := len(args)

	sql := fmt.Sprintf(`
		SELECT c.id, c.fingerprint_sha256, c.subject, c.issuer,
		       c.serial_number_hex, c.signature_algorithm,
		       c.public_key_algorithm, c.public_key_bits,
		       c.not_before, c.not_after, c.is_self_signed, c.is_ca,
		       c.first_seen_at, c.last_seen_at,
		       (SELECT COUNT(*) FROM certificate_observations o
		         WHERE o.organization_id = c.organization_id
		           AND o.certificate_id = c.id) AS observation_count,
		       (SELECT COUNT(*) FROM certificate_observations o
		         WHERE o.organization_id = c.organization_id
		           AND o.certificate_id = c.id
		           AND o.removed_at IS NULL) AS active_observation_count
		  FROM certificates c
		 WHERE %s
		 ORDER BY c.last_seen_at DESC, c.id ASC
		 LIMIT $%d`,
		strings.Join(conditions, " AND "), limitIdx,
	)

	rows, err := r.db.querierFor(ctx).Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list certificates: %w", err)
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
			return nil, fmt.Errorf("postgres: scan certificate summary: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate certificate summaries: %w", err)
	}
	return out, nil
}

// CountObservations returns (total, active) observation counts for
// the (organization_id, certificate_id) pair. The two counts are
// computed in a single SQL round-trip with FILTER aggregation so
// the detail endpoint does not pay two queries for what is
// essentially one scan.
//
// Cross-org / missing certificate_id is not differentiated here —
// both surface as (0, 0). The caller (GetCertificateDetail) calls
// GetCertificate first, which returns ErrCertificateNotFound for
// those cases, so this method never gets reached with a bad id.
func (r *CertificateInventoryRepository) CountObservations(
	ctx context.Context,
	organizationID, certificateID string,
) (int, int, error) {
	const q = `
		SELECT COUNT(*) AS total,
		       COUNT(*) FILTER (WHERE removed_at IS NULL) AS active
		  FROM certificate_observations
		 WHERE organization_id = $1 AND certificate_id = $2`
	var total, active int
	if err := r.db.querierFor(ctx).QueryRow(ctx, q,
		organizationID, certificateID,
	).Scan(&total, &active); err != nil {
		return 0, 0, fmt.Errorf("postgres: count observations: %w", err)
	}
	return total, active, nil
}

// ListObservationsPage returns one page of ObservationListItem
// rows for `GET /certificates/{id}/observations`. The SQL LEFT
// JOINs agent_inventory_snapshots so Hostname is populated when
// the agent has submitted a snapshot, and is "" otherwise.
//
// Ordering: last_seen_at DESC, agent_id ASC, store_location ASC.
// Cursor is the (last_seen_at, agent_id, store_location) tuple.
func (r *CertificateInventoryRepository) ListObservationsPage(
	ctx context.Context,
	q inventory.ObservationListQuery,
) ([]inventory.ObservationListItem, error) {
	var (
		conditions []string
		args       []any
	)
	args = append(args, q.OrganizationID, q.CertificateID)
	conditions = append(conditions,
		"o.organization_id = $1",
		"o.certificate_id = $2",
	)
	if q.CurrentOnly {
		conditions = append(conditions, "o.removed_at IS NULL")
	}
	if !q.CursorLastSeenAt.IsZero() {
		args = append(args, q.CursorLastSeenAt)
		atIdx := len(args)
		args = append(args, q.CursorAgentID)
		agentIdx := len(args)
		args = append(args, q.CursorStoreLocation)
		storeIdx := len(args)
		// "After" in (last_seen_at DESC, agent_id ASC,
		// store_location ASC) order:
		//
		//   last_seen_at < cursor.last_seen_at
		//   OR (last_seen_at = cursor.last_seen_at AND agent_id > cursor.agent_id)
		//   OR (last_seen_at = cursor.last_seen_at AND agent_id = cursor.agent_id
		//       AND store_location > cursor.store_location)
		conditions = append(conditions, fmt.Sprintf(
			"(o.last_seen_at < $%d "+
				"OR (o.last_seen_at = $%d AND o.agent_id > $%d) "+
				"OR (o.last_seen_at = $%d AND o.agent_id = $%d AND o.store_location > $%d))",
			atIdx,
			atIdx, agentIdx,
			atIdx, agentIdx, storeIdx,
		))
	}
	args = append(args, q.Limit)
	limitIdx := len(args)

	sql := fmt.Sprintf(`
		SELECT o.id, o.agent_id,
		       COALESCE(s.hostname, '') AS hostname,
		       o.store_location, o.friendly_name,
		       o.first_seen_at, o.last_seen_at, o.removed_at
		  FROM certificate_observations o
		  LEFT JOIN agent_inventory_snapshots s
		    ON s.organization_id = o.organization_id
		   AND s.agent_id = o.agent_id
		 WHERE %s
		 ORDER BY o.last_seen_at DESC, o.agent_id ASC, o.store_location ASC
		 LIMIT $%d`,
		strings.Join(conditions, " AND "), limitIdx,
	)

	rows, err := r.db.querierFor(ctx).Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list observations page: %w", err)
	}
	defer rows.Close()

	var out []inventory.ObservationListItem
	for rows.Next() {
		var (
			item      inventory.ObservationListItem
			removedAt *time.Time
		)
		if err := rows.Scan(
			&item.ID, &item.AgentID,
			&item.Hostname,
			&item.StoreLocation, &item.FriendlyName,
			&item.FirstSeenAt, &item.LastSeenAt, &removedAt,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan observation row: %w", err)
		}
		item.RemovedAt = removedAt
		if removedAt == nil {
			item.Status = "active"
		} else {
			item.Status = "removed"
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate observations page: %w", err)
	}
	return out, nil
}

// AgentExistsInOrg reports whether an agent row exists for
// (organization_id, agent_id). The query uses the agents primary
// key (organization_id, id) directly. Returns false for both
// cross-org and truly-missing ids — the service collapses both
// into ErrAgentNotFound for enumeration-safe 404 responses.
func (r *CertificateInventoryRepository) AgentExistsInOrg(
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

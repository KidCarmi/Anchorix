package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/agentinventory"
)

// AgentInventorySnapshotRepository implements
// agentinventory.SnapshotRepository against PostgreSQL.
// The agent_inventory_snapshots table is introduced by migration
// 0004 — see backend/migrations/0004_agent_inventory_snapshots.sql.
type AgentInventorySnapshotRepository struct {
	db *DB
}

// NewAgentInventorySnapshotRepository wires the repo. CLAUDE.md
// §8.8: constructor-based DI; no globals.
func NewAgentInventorySnapshotRepository(db *DB) *AgentInventorySnapshotRepository {
	return &AgentInventorySnapshotRepository{db: db}
}

// Upsert inserts the snapshot or replaces the existing row keyed by
// (organization_id, agent_id). All updatable columns are refreshed
// from the supplied Snapshot — the row reflects the agent's
// LATEST report, not a merge of prior reports.
//
// `installed_at` is a pointer: nil writes NULL into the column, a
// non-nil value writes the timestamp. This lets early installers
// that don't know the install time submit inventory without
// inventing a sentinel value.
func (r *AgentInventorySnapshotRepository) Upsert(
	ctx context.Context,
	s *agentinventory.Snapshot,
) error {
	localIPs, err := json.Marshal(s.LocalIPs)
	if err != nil {
		return fmt.Errorf("postgres: marshal local_ips: %w", err)
	}
	var installedAt any
	if s.InstalledAt != nil {
		installedAt = *s.InstalledAt
	}
	const q = `
		INSERT INTO agent_inventory_snapshots (
			organization_id, agent_id, hostname, os_name, os_version,
			agent_version, machine_arch, local_ips, installed_at,
			received_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $10
		)
		ON CONFLICT (organization_id, agent_id) DO UPDATE
		   SET hostname      = EXCLUDED.hostname,
		       os_name       = EXCLUDED.os_name,
		       os_version    = EXCLUDED.os_version,
		       agent_version = EXCLUDED.agent_version,
		       machine_arch  = EXCLUDED.machine_arch,
		       local_ips     = EXCLUDED.local_ips,
		       installed_at  = EXCLUDED.installed_at,
		       received_at   = EXCLUDED.received_at,
		       updated_at    = EXCLUDED.received_at`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		s.OrganizationID, s.AgentID, s.Hostname, s.OSName, s.OSVersion,
		s.AgentVersion, s.MachineArch, localIPs, installedAt,
		s.ReceivedAt,
	); err != nil {
		return fmt.Errorf("postgres: upsert agent inventory snapshot: %w", err)
	}
	return nil
}

// GetByAgentAndOrg returns the current snapshot for the
// (agentID, organizationID) pair. Returns
// agentinventory.ErrSnapshotNotFound when no row exists. The org
// column is part of the WHERE clause so a cross-org id surfaces as
// not-found rather than letting an operator enumerate snapshots in
// neighboring tenants (CLAUDE.md §6 deterministic auth).
func (r *AgentInventorySnapshotRepository) GetByAgentAndOrg(
	ctx context.Context,
	agentID, organizationID string,
) (*agentinventory.Snapshot, error) {
	const q = `
		SELECT organization_id, agent_id, hostname, os_name, os_version,
		       agent_version, machine_arch, local_ips, installed_at,
		       received_at, updated_at
		  FROM agent_inventory_snapshots
		 WHERE agent_id = $1 AND organization_id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, agentID, organizationID)
	snapshot, err := scanAgentInventorySnapshot(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, agentinventory.ErrSnapshotNotFound
		}
		return nil, fmt.Errorf("postgres: get agent inventory snapshot: %w", err)
	}
	return snapshot, nil
}

// ListSummaries returns a page of slim summary rows for the
// organization, ordered by received_at DESC then agent_id ASC. The
// (received_at, agent_id) tuple is the canonical cursor — it is
// stable (agent_id is unique within an org and breaks any nanosecond
// tie on received_at) and indexable.
//
// Cursor semantics: when CursorReceivedAt is the zero value, no
// after-bound is applied (first page). Otherwise the WHERE clause
// filters to rows that come AFTER (CursorReceivedAt, CursorAgentID)
// in the documented sort order. Concretely "after" with
// `received_at DESC, agent_id ASC` means:
//
//	received_at < cursor.received_at
//	OR (received_at = cursor.received_at AND agent_id > cursor.agent_id)
//
// The org filter is in the WHERE clause so cross-org rows never
// surface — there is no application-level filtering downstream.
//
// local_ips_count is computed at SELECT time via jsonb_array_length
// so the slim summary stays a single SQL row per agent without
// pulling the full local_ips array across the wire.
func (r *AgentInventorySnapshotRepository) ListSummaries(
	ctx context.Context,
	q agentinventory.SummaryRepositoryQuery,
) ([]agentinventory.Summary, error) {
	const sql = `
		SELECT agent_id, hostname, os_name, os_version,
		       agent_version, machine_arch,
		       jsonb_array_length(local_ips) AS local_ips_count,
		       installed_at, received_at, updated_at
		  FROM agent_inventory_snapshots
		 WHERE organization_id = $1
		   AND ($2::timestamptz IS NULL
		        OR received_at < $2::timestamptz
		        OR (received_at = $2::timestamptz AND agent_id > $3))
		 ORDER BY received_at DESC, agent_id ASC
		 LIMIT $4`
	// pgx maps Go's time.Time zero value to a non-NULL SQL value;
	// we want NULL semantics for "no cursor", so pass an explicit
	// nil interface when the cursor is unset.
	var cursorAt any
	var cursorAgent any
	if !q.CursorReceivedAt.IsZero() {
		cursorAt = q.CursorReceivedAt
		cursorAgent = q.CursorAgentID
	}
	rows, err := r.db.querierFor(ctx).Query(ctx, sql,
		q.OrganizationID, cursorAt, cursorAgent, q.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: list agent inventory summaries: %w", err)
	}
	defer rows.Close()

	var out []agentinventory.Summary
	for rows.Next() {
		var (
			s             agentinventory.Summary
			installedAt   *time.Time
			localIPsCount int
		)
		if err := rows.Scan(
			&s.AgentID, &s.Hostname, &s.OSName, &s.OSVersion,
			&s.AgentVersion, &s.MachineArch,
			&localIPsCount,
			&installedAt, &s.ReceivedAt, &s.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan agent inventory summary: %w", err)
		}
		s.InstalledAt = installedAt
		s.LocalIPsCount = localIPsCount
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate agent inventory summaries: %w", err)
	}
	return out, nil
}

func scanAgentInventorySnapshot(row pgx.Row) (*agentinventory.Snapshot, error) {
	var (
		s           agentinventory.Snapshot
		localIPsRaw []byte
		installedAt *time.Time
	)
	if err := row.Scan(
		&s.OrganizationID, &s.AgentID, &s.Hostname, &s.OSName, &s.OSVersion,
		&s.AgentVersion, &s.MachineArch, &localIPsRaw, &installedAt,
		&s.ReceivedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	s.InstalledAt = installedAt
	if len(localIPsRaw) > 0 {
		// The column default is '[]'::jsonb so non-empty bytes are
		// always present after a successful insert; an unmarshal
		// error here would mean the DB shape drifted (impossible
		// without a migration). Surface it rather than silently
		// returning an empty list.
		if err := json.Unmarshal(localIPsRaw, &s.LocalIPs); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal local_ips: %w", err)
		}
	}
	if s.LocalIPs == nil {
		s.LocalIPs = []string{}
	}
	return &s, nil
}

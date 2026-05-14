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

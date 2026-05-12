package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/enrollment"
)

// AgentRepository implements enrollment.AgentRepository against
// PostgreSQL. The agents table extends 0001's schema via migration
// 0002 — see backend/migrations/0002_deployment_packages.sql for
// the column additions.
type AgentRepository struct {
	db *DB
}

// NewAgentRepository wires the repo. CLAUDE.md §8.8: constructor-
// based DI; no globals.
func NewAgentRepository(db *DB) *AgentRepository {
	return &AgentRepository{db: db}
}

// Create inserts a new agent row. A unique-violation on
// (organization_id, install_id) is translated into
// enrollment.ErrAgentAlreadyEnrolled so the enrollment service can
// surface a deterministic rejection without exposing the storage
// SQLSTATE to handlers (CLAUDE.md §8.6).
func (r *AgentRepository) Create(
	ctx context.Context,
	a *enrollment.Agent,
	credentialHash []byte,
) error {
	labels, err := json.Marshal(a.Labels)
	if err != nil {
		return fmt.Errorf("postgres: marshal agent labels: %w", err)
	}
	// public_key_fingerprint stays in the schema (0001) but is no
	// longer required for enrollment — mTLS pinning is deferred to
	// Phase 6. We write an empty string into the column so the
	// existing column constraint is satisfied without the v0.1
	// enrollment flow having to invent a fingerprint.
	const q = `
		INSERT INTO agents (
			id, organization_id, hostname, display_name, version, status,
			public_key_fingerprint, enrolled_at, last_seen_at,
			deployment_package_id, machine_fingerprint_hash, install_id,
			group_name, labels, credential_hash, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			NULL, $7, $7,
			$8, $9, $10,
			$11, $12, $13, $7
		)`
	var installID any
	if a.InstallID != "" {
		installID = a.InstallID
	}
	var deploymentID any
	if a.DeploymentPackageID != "" {
		deploymentID = a.DeploymentPackageID
	}
	_, err = r.db.querierFor(ctx).Exec(ctx, q,
		a.ID, a.OrganizationID, a.Hostname, a.DisplayName, a.AgentVersion, string(a.Status),
		a.EnrolledAt,
		deploymentID, a.MachineFingerprintHash, installID,
		a.GroupName, labels, credentialHash,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return enrollment.ErrAgentAlreadyEnrolled
		}
		return fmt.Errorf("postgres: create agent: %w", err)
	}
	return nil
}

// List returns enrolled agents for the organization, most-recently
// enrolled first. The credential_hash column is deliberately NOT
// included in the result — the operator UI never needs it.
func (r *AgentRepository) List(
	ctx context.Context,
	organizationID string,
) ([]enrollment.Agent, error) {
	const q = `
		SELECT id, organization_id, hostname, display_name, version, status,
		       enrolled_at, last_seen_at,
		       deployment_package_id, machine_fingerprint_hash, install_id,
		       group_name, labels, updated_at
		  FROM agents
		 WHERE organization_id = $1
		 ORDER BY enrolled_at DESC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list agents: %w", err)
	}
	defer rows.Close()

	var out []enrollment.Agent
	for rows.Next() {
		agent, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan agent: %w", err)
		}
		out = append(out, *agent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate agents: %w", err)
	}
	return out, nil
}

func scanAgent(row pgx.Row) (*enrollment.Agent, error) {
	var (
		a               enrollment.Agent
		status          string
		deploymentPkgID *string
		installID       *string
		labelsRaw       []byte
		fingerprintHash []byte
		// `version` is the column name in the schema; we expose it
		// as AgentVersion in the domain.
		agentVersion string
	)
	if err := row.Scan(
		&a.ID, &a.OrganizationID, &a.Hostname, &a.DisplayName, &agentVersion, &status,
		&a.EnrolledAt, &a.LastSeenAt,
		&deploymentPkgID, &fingerprintHash, &installID,
		&a.GroupName, &labelsRaw, &a.UpdatedAt,
	); err != nil {
		return nil, err
	}
	a.Status = enrollment.AgentStatus(status)
	a.AgentVersion = agentVersion
	if deploymentPkgID != nil {
		a.DeploymentPackageID = *deploymentPkgID
	}
	a.MachineFingerprintHash = fingerprintHash
	if installID != nil {
		a.InstallID = *installID
	}
	if len(labelsRaw) > 0 {
		_ = json.Unmarshal(labelsRaw, &a.Labels)
	}
	return &a, nil
}

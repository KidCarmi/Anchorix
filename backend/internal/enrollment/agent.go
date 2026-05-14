package enrollment

import (
	"context"
	"time"
)

// AgentStatus is the lifecycle status of an enrolled agent. v0.1
// allows status to be set at enrollment only ("active"); the
// "disabled" / "revoked" transitions are reserved for later phases
// (agent revocation UI).
type AgentStatus string

const (
	AgentStatusActive   AgentStatus = "active"
	AgentStatusDisabled AgentStatus = "disabled"
	AgentStatusRevoked  AgentStatus = "revoked"
)

// Valid reports whether s is one of the recognized AgentStatus
// constants. The set matches the CHECK constraint on agents.status
// in 0001_init.sql.
func (s AgentStatus) Valid() bool {
	switch s {
	case AgentStatusActive, AgentStatusDisabled, AgentStatusRevoked:
		return true
	}
	return false
}

// Agent is an enrolled endpoint. The credential issued at
// enrollment is NOT stored on the struct — only its hash is
// persisted, and the plaintext appears once in the
// EnrollAgentOutput before being forgotten by the control plane.
//
// Time fields:
//   - EnrolledAt is set once at enrollment and never changes.
//     It also serves as the agent's "created at" — an agent comes
//     into existence only via enrollment, so a separate created_at
//     column would carry the same value (CLAUDE.md §8.5 forbids
//     speculative duplication).
//   - LastSeenAt is initialized to EnrolledAt at create time and
//     bumped by the heartbeat endpoint (Phase 3). v0.1 does not
//     yet ship the heartbeat, so today it equals EnrolledAt for
//     every agent.
//   - UpdatedAt is bookkeeping for any future row mutation; for
//     v0.1 it tracks EnrolledAt.
type Agent struct {
	ID                     string
	OrganizationID         string
	Hostname               string
	DisplayName            string
	Status                 AgentStatus
	EnrolledAt             time.Time
	LastSeenAt             time.Time
	DeploymentPackageID    string
	AgentVersion           string
	MachineFingerprintHash []byte
	InstallID              string
	GroupName              string
	Labels                 []string
	UpdatedAt              time.Time
}

// AgentRepository is the storage contract for enrolled agents. The
// concrete implementation lives in internal/storage/postgres; this
// interface is owned by the consumer (CLAUDE.md §8.8).
type AgentRepository interface {
	// Create inserts a new agent row. credentialHash is the SHA-256
	// of the bearer credential issued at enrollment; the plaintext
	// is never passed through this interface.
	//
	// If the agent's InstallID is non-empty and a row with the same
	// (organization_id, install_id) already exists, Create MUST
	// return ErrAgentAlreadyEnrolled. The unique index on
	// (organization_id, install_id) is the storage-layer guarantee
	// that two installers cannot race to create the same logical
	// agent.
	Create(ctx context.Context, a *Agent, credentialHash []byte) error

	// List returns all enrolled agents for the organization. The
	// result is ordered by EnrolledAt DESC so the operator UI
	// shows the most recent enrollment first.
	List(ctx context.Context, organizationID string) ([]Agent, error)

	// FindByCredentialHash looks up an agent by the SHA-256 of the
	// bearer credential it was issued at enrollment. Returns
	// ErrAgentNotFound if no agent matches the hash. The lookup
	// is by hash only — the plaintext credential never touches
	// storage.
	FindByCredentialHash(ctx context.Context, hash []byte) (*Agent, error)

	// UpdateHeartbeat bumps last_seen_at + updated_at and
	// conditionally refreshes agent_version / hostname when the
	// agent reports a non-empty value. A single UPDATE keeps the
	// heartbeat path fast — heartbeats are the hottest write in
	// the agent lifecycle.
	//
	// Returns ErrAgentNotFound if no row matches the
	// (id, organization_id) pair. The org column is part of the
	// WHERE clause for defense in depth even though the caller
	// (the service, invoked by the agent-auth middleware) has
	// already proven the credential belongs to this org.
	UpdateHeartbeat(ctx context.Context, agentID, organizationID, agentVersion, hostname string, at time.Time) error
}

// AuthenticatedAgent is the principal type attached to a request's
// context after a successful agent-credential auth. It is
// deliberately a narrow view of Agent — credential_hash and the
// machine fingerprint are not part of this struct because no
// downstream handler should ever need them. CLAUDE.md §8.4: the
// type expresses domain purpose (this is an agent that has just
// proven its identity), not a database row.
type AuthenticatedAgent struct {
	AgentID             string
	OrganizationID      string
	Status              AgentStatus
	DeploymentPackageID string
	AgentVersion        string
	GroupName           string
	Labels              []string
}

package agentinventory

import (
	"context"
	"errors"
	"time"
)

// Snapshot is the current host-facts report from an agent. There is
// exactly one Snapshot row per (organization_id, agent_id); each
// successful inventory submission REPLACES the row (see
// SnapshotRepository.Upsert).
//
// Field meaning:
//
//   - OrganizationID + AgentID identify the agent the snapshot
//     belongs to. Both ALWAYS come from the authenticated agent
//     principal — never from the request body (CLAUDE.md §6.8
//     default-deny; the HTTP handler is the boundary that enforces
//     this).
//   - Hostname, OSName, OSVersion, AgentVersion, MachineArch are
//     descriptive host facts. They may drift between snapshots; the
//     authoritative identity axis is AgentID.
//   - LocalIPs is the agent-reported list of local interface
//     addresses (IPv4/IPv6 strings). It is purely descriptive — the
//     control plane does not interpret the values in v0.1.
//   - InstalledAt is when the agent service was installed on the
//     host. May be the zero value when the installer did not record
//     it.
//   - ReceivedAt is set server-side on every Upsert (latest server
//     time at write).
//   - UpdatedAt mirrors ReceivedAt; kept as a separate column so
//     future deltas (e.g. an audit-style "this field changed")
//     can distinguish first-write from later-write without
//     reshaping the schema.
type Snapshot struct {
	OrganizationID string
	AgentID        string
	Hostname       string
	OSName         string
	OSVersion      string
	AgentVersion   string
	MachineArch    string
	LocalIPs       []string
	InstalledAt    *time.Time
	ReceivedAt     time.Time
	UpdatedAt      time.Time
}

// SnapshotRepository is the storage contract for agent inventory
// snapshots. The concrete implementation lives in
// internal/storage/postgres; this interface is owned by the
// consumer (CLAUDE.md §8.8).
type SnapshotRepository interface {
	// Upsert writes (or replaces) the snapshot row for
	// (s.OrganizationID, s.AgentID). The caller sets ReceivedAt /
	// UpdatedAt to the desired server time before calling; the
	// repository persists the values as-is.
	//
	// The operation is atomic at the storage layer (single
	// INSERT ... ON CONFLICT). No transaction is required.
	Upsert(ctx context.Context, s *Snapshot) error

	// GetByAgentAndOrg returns the current snapshot for the
	// (organizationID, agentID) pair. Returns ErrSnapshotNotFound
	// when no row exists. The org column is in the WHERE clause so
	// a cross-org id surfaces as "not found" rather than letting an
	// operator enumerate snapshots in neighboring tenants.
	GetByAgentAndOrg(ctx context.Context, agentID, organizationID string) (*Snapshot, error)

	// ListSummaries returns a page of slim Summary rows for the
	// organization, ordered by received_at DESC, agent_id ASC.
	//
	// The repository fetches AT MOST q.Limit rows (the service has
	// already added a +1 sentinel to detect a next page without an
	// extra COUNT). When q.CursorReceivedAt is the zero value, no
	// after-bound is applied (first page). When it is set, the SQL
	// WHERE clause filters to rows strictly after
	// (q.CursorReceivedAt, q.CursorAgentID) in the documented sort
	// order.
	ListSummaries(ctx context.Context, q SummaryRepositoryQuery) ([]Summary, error)
}

// Sentinel errors. Centralized so domain and storage agree on the
// vocabulary (CLAUDE.md §8.1).
var (
	// ErrInvalidSnapshotInput is returned by Service.Submit when the
	// agent-supplied input fails validation (oversize field, too
	// many local_ips, empty agent or organization id). The HTTP
	// layer maps this to 400 bad_request.
	ErrInvalidSnapshotInput = errors.New("agentinventory: invalid snapshot input")

	// ErrSnapshotNotFound is returned by SnapshotRepository.GetByAgentAndOrg
	// when no snapshot exists for the (agent, org) pair. The HTTP
	// layer maps this to 404 not_found on the operator read
	// endpoint.
	ErrSnapshotNotFound = errors.New("agentinventory: snapshot not found")
)

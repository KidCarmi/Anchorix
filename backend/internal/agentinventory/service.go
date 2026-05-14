package agentinventory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
)

// Per-field byte caps enforced by Service.Submit. The values come
// from PR-018: they keep agent-reported strings short enough to fit
// in operator UI columns without truncation, and short enough that
// a hostile or buggy agent cannot store kilobyte-sized blobs in
// snapshot rows. Oversize input is rejected with
// ErrInvalidSnapshotInput; the handler maps that to 400 — there is
// NO silent truncation (CLAUDE.md §6.12 fail closed).
const (
	MaxHostnameLength     = 255
	MaxOSNameLength       = 100
	MaxOSVersionLength    = 100
	MaxAgentVersionLength = 64
	MaxMachineArchLength  = 64

	// MaxLocalIPs caps the number of address strings the agent may
	// report. A workstation with dozens of virtual interfaces is
	// reasonable; thousands is not.
	MaxLocalIPs = 32

	// MaxLocalIPLength caps each individual address string. 64
	// bytes is wider than the longest IPv6 textual form (45 bytes
	// for an embedded-IPv4 form) plus zone-id slack.
	MaxLocalIPLength = 64
)

// SubmitInput is what the HTTP handler passes to Service.Submit
// after a successful agent-bearer auth. The handler MUST set
// AgentID and OrganizationID from the AuthenticatedAgent principal,
// NEVER from the request body — the snapshot endpoint defines
// "whose host is this?" as a function of the credential, not of
// untrusted JSON (CLAUDE.md §6 default-deny).
type SubmitInput struct {
	OrganizationID string
	AgentID        string
	Hostname       string
	OSName         string
	OSVersion      string
	AgentVersion   string
	MachineArch    string
	LocalIPs       []string
	InstalledAt    *time.Time
}

// Service is the agentinventory domain entrypoint. HTTP handlers
// depend on this struct, never on the SnapshotRepository directly
// (CLAUDE.md §8.6, §8.8).
type Service struct {
	repo  SnapshotRepository
	clock clock.Clock
}

// NewService wires the service. Constructor-based DI per CLAUDE.md
// §8.8. Returns a validation error if any dependency is missing —
// never panics (CLAUDE.md §18: no panic-driven business flow).
func NewService(repo SnapshotRepository, clk clock.Clock) (*Service, error) {
	if repo == nil {
		return nil, errors.New("agentinventory.NewService: snapshot repository required")
	}
	if clk == nil {
		return nil, errors.New("agentinventory.NewService: clock required")
	}
	return &Service{repo: repo, clock: clk}, nil
}

// Submit validates the input, derives ReceivedAt / UpdatedAt from
// the injected clock, and UPSERTs the snapshot. Repeated submissions
// from the same agent replace the same row; there is no per-batch
// history.
//
// Audit policy: snapshot submission is operational state sync, like
// heartbeat. Successful Submit calls do NOT emit an audit_events row.
// Failed bearer auth is already audited by the agent-auth middleware
// upstream of this method. See docs/engineering/AGENT_ENROLLMENT.md
// "Heartbeat" for the cardinality rationale that PR-018 reuses.
func (s *Service) Submit(ctx context.Context, in SubmitInput) (*Snapshot, error) {
	snapshot, err := s.buildSnapshot(in)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Upsert(ctx, snapshot); err != nil {
		return nil, fmt.Errorf("agentinventory: upsert snapshot: %w", err)
	}
	return snapshot, nil
}

// GetForAgent returns the current snapshot for an agent within an
// organization. Returns ErrSnapshotNotFound when no snapshot exists
// (e.g. the agent has never submitted inventory).
//
// Org scoping is enforced at the repository's WHERE clause so a
// cross-org id surfaces as ErrSnapshotNotFound, matching the
// not_found-not-forbidden convention used by deployment-package
// revoke (CLAUDE.md §6 — no enumeration via error code).
func (s *Service) GetForAgent(ctx context.Context, agentID, organizationID string) (*Snapshot, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, fmt.Errorf("%w: agent id required", ErrInvalidSnapshotInput)
	}
	if strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("%w: organization id required", ErrInvalidSnapshotInput)
	}
	return s.repo.GetByAgentAndOrg(ctx, agentID, organizationID)
}

// buildSnapshot validates SubmitInput and produces a Snapshot with
// trimmed string fields and a deep-copied LocalIPs slice. The clock
// is consulted once so ReceivedAt and UpdatedAt are identical on a
// fresh write.
func (s *Service) buildSnapshot(in SubmitInput) (*Snapshot, error) {
	if strings.TrimSpace(in.AgentID) == "" {
		return nil, fmt.Errorf("%w: agent id required", ErrInvalidSnapshotInput)
	}
	if strings.TrimSpace(in.OrganizationID) == "" {
		return nil, fmt.Errorf("%w: organization id required", ErrInvalidSnapshotInput)
	}
	hostname, err := validateField("hostname", in.Hostname, MaxHostnameLength)
	if err != nil {
		return nil, err
	}
	osName, err := validateField("os_name", in.OSName, MaxOSNameLength)
	if err != nil {
		return nil, err
	}
	osVersion, err := validateField("os_version", in.OSVersion, MaxOSVersionLength)
	if err != nil {
		return nil, err
	}
	agentVersion, err := validateField("agent_version", in.AgentVersion, MaxAgentVersionLength)
	if err != nil {
		return nil, err
	}
	machineArch, err := validateField("machine_arch", in.MachineArch, MaxMachineArchLength)
	if err != nil {
		return nil, err
	}
	localIPs, err := validateLocalIPs(in.LocalIPs)
	if err != nil {
		return nil, err
	}

	now := s.clock.Now()
	return &Snapshot{
		OrganizationID: strings.TrimSpace(in.OrganizationID),
		AgentID:        strings.TrimSpace(in.AgentID),
		Hostname:       hostname,
		OSName:         osName,
		OSVersion:      osVersion,
		AgentVersion:   agentVersion,
		MachineArch:    machineArch,
		LocalIPs:       localIPs,
		InstalledAt:    in.InstalledAt,
		ReceivedAt:     now,
		UpdatedAt:      now,
	}, nil
}

// validateField trims whitespace and enforces the byte-length cap on
// a single descriptive string field. The cap is measured in BYTES,
// not runes, because the DB columns and the operator UI render the
// raw bytes — a non-ASCII hostname that fits 255 runes but expands
// past 255 bytes is rejected.
func validateField(name, value string, maxBytes int) (string, error) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > maxBytes {
		return "", fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidSnapshotInput, name, maxBytes)
	}
	return trimmed, nil
}

// validateLocalIPs enforces the documented caps on the local_ips
// list. Each entry is trimmed; empty entries (after trim) are
// rejected so the snapshot does not silently store noise. The
// returned slice is a fresh allocation so the service does not
// alias the caller's input.
func validateLocalIPs(in []string) ([]string, error) {
	if len(in) > MaxLocalIPs {
		return nil, fmt.Errorf("%w: local_ips exceeds %d entries", ErrInvalidSnapshotInput, MaxLocalIPs)
	}
	if len(in) == 0 {
		return []string{}, nil
	}
	out := make([]string, 0, len(in))
	for i, raw := range in {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return nil, fmt.Errorf("%w: local_ips[%d] empty", ErrInvalidSnapshotInput, i)
		}
		if len(trimmed) > MaxLocalIPLength {
			return nil, fmt.Errorf("%w: local_ips[%d] exceeds %d bytes", ErrInvalidSnapshotInput, i, MaxLocalIPLength)
		}
		out = append(out, trimmed)
	}
	return out, nil
}

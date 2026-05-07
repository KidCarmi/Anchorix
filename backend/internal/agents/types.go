// Package agents owns agent identity and lifecycle.
package agents

import "time"

// Status is the lifecycle state of an agent.
type Status string

const (
	StatusPendingEnrollment Status = "pending_enrollment"
	StatusActive            Status = "active"
	StatusDisabled          Status = "disabled"
	StatusRevoked           Status = "revoked"
)

// Agent is a registered Windows host running anchorix-agent.
type Agent struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Hostname       string    `json:"hostname"`
	Version        string    `json:"version"`
	Status         Status    `json:"status"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`

	// PublicKeyFingerprint is the SHA-256 of the agent's enrollment public
	// key. It uniquely identifies the agent's cryptographic material and
	// is used to authenticate inbound calls.
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

// EnrollmentToken is a single-use token an operator issues to bootstrap a
// new agent. Tokens are short-lived and never logged (CLAUDE.md §6.5, §6.9).
type EnrollmentToken struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	IssuedBy       string    `json:"issued_by"` // user id
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
}

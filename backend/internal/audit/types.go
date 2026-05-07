// Package audit records immutable audit events for state-changing actions.
//
// Audit events are NOT logs (CLAUDE.md §9). They live in PostgreSQL, are
// insert-only, and survive process restarts and log rotation.
package audit

import "time"

// Event is a single audit record. Once written, an Event is never updated.
type Event struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	OccurredAt     time.Time `json:"occurred_at"`
	Actor          string    `json:"actor"`       // user id, agent id, or "system"
	ActorType      string    `json:"actor_type"`  // user | agent | system
	Action         string    `json:"action"`      // verb_object, e.g. "agent_enrolled"
	TargetType     string    `json:"target_type"` // resource type, e.g. "agent"
	TargetID       string    `json:"target_id"`
	RequestID      string    `json:"request_id,omitempty"`
	Metadata       []byte    `json:"metadata,omitempty"` // JSON-encoded
}

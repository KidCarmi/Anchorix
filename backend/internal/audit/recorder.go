package audit

import "context"

// Recorder is the contract for persisting audit events.
type Recorder interface {
	Record(ctx context.Context, e Event) error
	List(ctx context.Context, q ListQuery) ([]Event, error)
}

// ListQuery captures the supported filters for the audit log view.
type ListQuery struct {
	OrganizationID string
	Actor          string
	Action         string
	TargetType     string
	TargetID       string
	Since          string // RFC3339; empty means no filter
	Limit          int
	Cursor         string
}

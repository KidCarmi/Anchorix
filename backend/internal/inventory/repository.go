package inventory

import "context"

// Repository is the storage contract for the inventory domain. The concrete
// implementation lives in internal/storage/postgres.
type Repository interface {
	UpsertCertificate(ctx context.Context, c *Certificate) (*Certificate, error)
	RecordObservation(ctx context.Context, o *Observation) error
	GetCertificate(ctx context.Context, orgID, id string) (*Certificate, error)
	ListCertificates(ctx context.Context, q ListQuery) ([]*Certificate, error)
}

// ListQuery captures the supported filters for ListCertificates. Adding new
// filters here is intentionally cheap; HTTP handlers translate query params
// into this struct.
type ListQuery struct {
	OrganizationID string
	Search         string
	ExpiringBefore string // RFC3339 timestamp; empty = no filter
	Limit          int
	Cursor         string
}

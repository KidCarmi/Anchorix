package agents

import "context"

// Repository is the persistence contract for the agents domain.
type Repository interface {
	CreateEnrollmentToken(ctx context.Context, t *EnrollmentToken) error
	ConsumeEnrollmentToken(ctx context.Context, tokenHash string) (*EnrollmentToken, error)
	UpsertAgent(ctx context.Context, a *Agent) (*Agent, error)
	GetAgent(ctx context.Context, orgID, id string) (*Agent, error)
	ListAgents(ctx context.Context, orgID string) ([]*Agent, error)
	RecordHeartbeat(ctx context.Context, agentID string) error
}

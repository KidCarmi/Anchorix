// Package transport defines the abstraction over agent ↔ control-plane
// transports. v0.1 ships HTTPS only. Reserving this interface today lets
// us add alternative transports (mTLS-only, message bus, broker-based)
// in future releases without touching domain code.
package transport

import "context"

// Provider is the contract for an agent-facing transport. It is intentionally
// minimal in v0.1; richer methods are added when concrete needs appear.
type Provider interface {
	// Name identifies the transport (e.g. "https").
	Name() string

	// HealthCheck verifies that the transport is configured and ready.
	HealthCheck(ctx context.Context) error
}

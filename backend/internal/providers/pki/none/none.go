// Package none provides a no-op PKI provider used when no backend is
// configured. It is the safe default: introspection only, no writes.
package none

import (
	"context"

	"github.com/kidcarmi/anchorix/backend/internal/providers/pki"
)

// Provider is the introspection-only built-in.
type Provider struct{}

// New returns a new Provider.
func New() *Provider { return &Provider{} }

// Descriptor reports the static identity of this provider.
func (Provider) Descriptor() pki.Descriptor {
	return pki.Descriptor{
		ID:           "none",
		Kind:         "none",
		DisplayName:  "No PKI backend configured",
		Capabilities: nil,
	}
}

// HealthCheck always succeeds; the no-op provider has nothing to verify.
func (Provider) HealthCheck(_ context.Context) error { return nil }

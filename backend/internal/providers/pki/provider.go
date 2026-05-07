// Package pki defines the abstraction over PKI backends.
//
// Per CLAUDE.md §10 (Ops Freedom Rule), every PKI integration sits behind
// this interface. Core domain code MUST NOT import vendor-specific
// packages; only this package's interface is consumed by callers.
//
// In v0.1 the only built-in implementation is "none" (introspection-only).
// Future phases add ADCS, Vault PKI, EJBCA, and Smallstep providers as
// independent subpackages (e.g. internal/providers/pki/adcs).
package pki

import "context"

// Capability describes what a provider can do. The control plane queries
// this to know what UI affordances and APIs to expose for a given provider.
type Capability string

const (
	CapDiscovery    Capability = "discovery"     // can enumerate certs from the CA
	CapIssue        Capability = "issue"         // can issue (out of v0.1 scope)
	CapRevoke       Capability = "revoke"        // can revoke (out of v0.1 scope)
	CapStatusLookup Capability = "status_lookup" // can resolve cert status
)

// Descriptor is the static identity of a registered provider.
type Descriptor struct {
	ID           string       `json:"id"`
	Kind         string       `json:"kind"` // e.g. "adcs", "vault", "smallstep"
	DisplayName  string       `json:"display_name"`
	Capabilities []Capability `json:"capabilities"`
}

// Provider is the abstraction every PKI backend implements.
type Provider interface {
	Descriptor() Descriptor
	HealthCheck(ctx context.Context) error
}

// Registry holds the set of registered providers. v0.1 keeps this in-memory;
// configuration is loaded at startup from the database.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

// Register adds a provider. Duplicate IDs are a programmer error.
func (r *Registry) Register(p Provider) {
	r.providers[p.Descriptor().ID] = p
}

// Get returns a provider by id, or nil if not registered.
func (r *Registry) Get(id string) Provider { return r.providers[id] }

// List returns the registered providers' descriptors. Order is unspecified.
func (r *Registry) List() []Descriptor {
	out := make([]Descriptor, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p.Descriptor())
	}
	return out
}

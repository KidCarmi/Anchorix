package discovery

import "context"

// Stub returns a deterministic, empty inventory. It exists so the agent
// can boot end-to-end on non-Windows dev hosts without enumerating real
// certificate stores. Production code paths must use the Windows
// implementation.
type Stub struct{}

// NewStub returns a new Stub discoverer.
func NewStub() *Stub { return &Stub{} }

// Discover returns no certificates. Returning an empty list (rather than
// a hardcoded fake) keeps test environments honest about what's present.
func (Stub) Discover(_ context.Context) ([]Cert, error) { return []Cert{}, nil }

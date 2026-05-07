//go:build windows

package discovery

import (
	"context"
	"errors"
)

// WindowsDiscoverer enumerates certificates from Windows certificate
// stores. Implementation lands in Phase 3; the type exists today so
// composition wiring can target the final shape.
type WindowsDiscoverer struct {
	Stores []string // e.g. ["LocalMachine\\My", "LocalMachine\\WebHosting"]
}

// NewWindows returns a discoverer configured with the given store names.
func NewWindows(stores []string) *WindowsDiscoverer {
	if len(stores) == 0 {
		stores = []string{`LocalMachine\My`, `LocalMachine\WebHosting`, `CurrentUser\My`}
	}
	return &WindowsDiscoverer{Stores: stores}
}

// Discover enumerates the configured stores and returns non-secret
// metadata. It MUST NOT read private key material.
func (d *WindowsDiscoverer) Discover(_ context.Context) ([]Cert, error) {
	return nil, errors.New("windows discovery not yet implemented (Phase 3)")
}

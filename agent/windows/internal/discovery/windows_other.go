//go:build !windows

package discovery

import (
	"context"
	"errors"
)

// WindowsDiscoverer is unavailable off Windows; this stub exists so
// non-Windows builds compile. Use Stub on Linux/macOS dev hosts.
type WindowsDiscoverer struct {
	Stores []string
}

// NewWindows returns a discoverer that always errors on non-Windows hosts.
func NewWindows(stores []string) *WindowsDiscoverer {
	return &WindowsDiscoverer{Stores: stores}
}

// Discover always returns an error on non-Windows builds.
func (*WindowsDiscoverer) Discover(_ context.Context) ([]Cert, error) {
	return nil, errors.New("windows discovery is only available on GOOS=windows")
}

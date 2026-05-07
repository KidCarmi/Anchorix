// Package discovery enumerates certificate stores and returns non-secret
// metadata. Real Windows enumeration lands in Phase 3; the interface is
// stable today so the rest of the agent can be wired against it.
package discovery

import "context"

// Cert is the agent-side representation of a discovered certificate.
// It carries only public metadata + the public certificate PEM. Private
// key material is NEVER read by the agent (CLAUDE.md §6.2).
type Cert struct {
	StoreLocation     string
	FingerprintSHA256 string
	Subject           string
	Issuer            string
	SerialNumberHex   string
	NotBefore         string // RFC3339
	NotAfter          string // RFC3339
	SANs              []string
	IsCA              bool
	IsSelfSigned      bool
	CertificatePEM    string
}

// Discoverer enumerates certificates from a host. Implementations are
// platform-specific (Windows certstore in production; stub in dev).
type Discoverer interface {
	Discover(ctx context.Context) ([]Cert, error)
}

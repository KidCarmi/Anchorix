// Package inventory owns the certificate domain model and ingestion logic.
//
// Inventory is intentionally storage-agnostic. It depends only on the
// repository interface defined here so that storage backends can change
// without rippling through the domain (CLAUDE.md §5, §10).
package inventory

import "time"

// Certificate is the canonical representation of a discovered certificate.
// It contains only non-secret metadata. Private keys MUST NEVER appear here
// or in any payload that crosses a process or network boundary.
type Certificate struct {
	ID                string    `json:"id"`
	OrganizationID    string    `json:"organization_id"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	SerialNumberHex   string    `json:"serial_number_hex"`
	SignatureAlg      string    `json:"signature_algorithm"`
	PublicKeyAlg      string    `json:"public_key_algorithm"`
	PublicKeyBits     int       `json:"public_key_bits"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	SANs              []string  `json:"sans"`
	KeyUsages         []string  `json:"key_usages"`
	ExtKeyUsages      []string  `json:"ext_key_usages"`
	IsSelfSigned      bool      `json:"is_self_signed"`
	IsCA              bool      `json:"is_ca"`
	FirstSeenAt       time.Time `json:"first_seen_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
}

// Observation is a single (host, store) sighting of a certificate. A single
// Certificate may have many Observations across an estate.
type Observation struct {
	ID            string    `json:"id"`
	CertificateID string    `json:"certificate_id"`
	AgentID       string    `json:"agent_id"`
	Hostname      string    `json:"hostname"`
	StoreLocation string    `json:"store_location"` // e.g. LocalMachine\My
	FriendlyName  string    `json:"friendly_name,omitempty"`
	ObservedAt    time.Time `json:"observed_at"`
}

// IngestPayload is the agent → control-plane payload for a single inventory
// upload. The control plane MUST reject any payload that includes a private
// key field, even one that is empty (CLAUDE.md §6.2).
type IngestPayload struct {
	AgentID      string                 `json:"agent_id"`
	Hostname     string                 `json:"hostname"`
	CollectedAt  time.Time              `json:"collected_at"`
	Certificates []IngestedCertificate  `json:"certificates"`
}

// IngestedCertificate is the wire format for a single discovered certificate.
type IngestedCertificate struct {
	StoreLocation     string    `json:"store_location"`
	FriendlyName      string    `json:"friendly_name,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	SerialNumberHex   string    `json:"serial_number_hex"`
	SignatureAlg      string    `json:"signature_algorithm"`
	PublicKeyAlg      string    `json:"public_key_algorithm"`
	PublicKeyBits     int       `json:"public_key_bits"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	SANs              []string  `json:"sans"`
	KeyUsages         []string  `json:"key_usages"`
	ExtKeyUsages      []string  `json:"ext_key_usages"`
	IsSelfSigned      bool      `json:"is_self_signed"`
	IsCA              bool      `json:"is_ca"`
	// CertificatePEM is the base64-encoded PEM of the public certificate.
	// The control plane parses and verifies fields against this PEM.
	// PRIVATE KEY MATERIAL IS REJECTED.
	CertificatePEM string `json:"certificate_pem"`
}

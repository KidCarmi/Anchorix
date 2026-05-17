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
	// PEM is the public certificate PEM, stored verbatim. Private
	// key material is rejected at the API boundary (CLAUDE.md §6.2,
	// CERTIFICATE_INVENTORY.md §7) before reaching this struct.
	PEM         string    `json:"pem"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// CertificateObservation is a single (agent, store) sighting of a
// certificate. The observation row is the *current* state of one
// (organization_id, certificate_id, agent_id, store_location)
// pair — v0.1 keeps latest state only, with first_seen_at /
// last_seen_at / removed_at carrying the lifecycle bookkeeping.
//
// Field meaning:
//
//   - OrganizationID anchors the row to a single org. The composite
//     FKs in migration 0005 bind both (org, certificate_id) and
//     (org, agent_id) to the same org as the parent rows; cross-org
//     observations cannot exist at the DB level.
//   - CertificateID points at the deduplicated certificates row.
//   - AgentID is the stable identity axis (H-006 design: rebind
//     preserves agent_id, so observations survive reinstalls).
//   - StoreLocation is the host-side store path
//     (e.g. "LocalMachine\\My"). Part of the unique key — the same
//     cert can legitimately appear in multiple stores on the same
//     host with different operational semantics.
//   - FriendlyName is the operator-facing display label the agent
//     reported. Descriptive only, NOT part of the unique key.
//   - FirstSeenAt is the upload's collected_at at the moment this
//     (org, cert, agent, store) was first observed.
//   - LastSeenAt is the upload's collected_at at the most recent
//     observation. Updated on every UPSERT that matches the unique
//     key, subject to the out-of-order guard (older
//     collected_at cannot overwrite newer state).
//   - RemovedAt is non-NULL when the cert was absent from a
//     reconciliation that covered the row's store_location. Cleared
//     back to NULL when the cert reappears in a later batch.
type CertificateObservation struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	CertificateID  string     `json:"certificate_id"`
	AgentID        string     `json:"agent_id"`
	StoreLocation  string     `json:"store_location"`
	FriendlyName   string     `json:"friendly_name,omitempty"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	RemovedAt      *time.Time `json:"removed_at,omitempty"`
}

// IngestionInput is the validated input to Service.Submit. The HTTP
// handler is responsible for:
//
//   - decoding the wire request body and enforcing byte/count caps
//     (per CERTIFICATE_INVENTORY.md §4 size limits) BEFORE calling
//     the service,
//   - populating OrganizationID and AgentID from AgentFromContext
//     (NEVER from the request body — the agent cannot ingest as
//     another agent),
//   - leaving semantic validation (private key detection, PEM
//     parsing, store_coverage / duplicate checks) to the service.
type IngestionInput struct {
	OrganizationID string
	AgentID        string
	CollectedAt    time.Time
	StoreCoverage  []string
	Certificates   []IngestionCertificate
}

// IngestionCertificate is a single agent-reported observation, in
// the post-validation shape Service.Submit consumes. The server
// parses CertificatePEM authoritatively — fingerprint, subject,
// issuer, etc. are NEVER trusted from any wire-side struct.
type IngestionCertificate struct {
	StoreLocation  string
	FriendlyName   string
	CertificatePEM string
}

// IngestionOutput is what Service.Submit returns on success. The
// HTTP handler echoes the counters back to the agent so it can
// log the per-batch acceptance / reconciliation totals without
// having to re-derive them.
type IngestionOutput struct {
	// Accepted is the number of (cert, store) observations
	// successfully upserted (deduplicated by fingerprint at the
	// certificates table; one row per (agent, cert, store) at the
	// observations table).
	Accepted int
	// ReconciledAbsent is the number of pre-existing observations
	// in the declared store_coverage that the batch did NOT
	// include, and that consequently transitioned to removed_at
	// in this submission.
	ReconciledAbsent int
}

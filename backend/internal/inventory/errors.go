package inventory

import "errors"

// Sentinel errors for the certificate-inventory storage layer.
// Callers (the future H-015 ingestion service and H-016 read API)
// use errors.Is to map these to the canonical HTTP envelope.

// ErrCertificateNotFound is returned by Repository.GetCertificate
// when no certificate row matches the (organization_id,
// certificate_id) pair. Cross-org id lookups surface as this
// sentinel — the WHERE clause in the SQL filters on
// organization_id, so a cross-org id is indistinguishable from a
// truly-missing one (CLAUDE.md §6 deterministic auth, no
// enumeration via error code).
var ErrCertificateNotFound = errors.New("inventory: certificate not found")

// ErrAgentNotFound is returned by Service.ListAgentCertificates
// when the (organization_id, agent_id) pair does not match an
// existing agent row. Cross-org and truly-missing both collapse
// to this sentinel for the same enumeration-safety reason as
// ErrCertificateNotFound. HTTP layer maps to 404 not_found.
var ErrAgentNotFound = errors.New("inventory: agent not found")

// ErrInvalidReconciliation is returned by
// Repository.MarkMissingObservationsRemoved when its inputs are
// structurally invalid for reconciliation — currently:
//
//   - empty organizationID or agentID,
//   - empty storeCoverage (per CERTIFICATE_INVENTORY.md §3 / §4,
//     a non-empty store_coverage is required so v0.1 has no
//     "implicit upsert-only / no-reconcile" mode).
//
// The H-015 ingestion service maps this to 400 bad_request before
// it reaches the storage layer, but the repository surfaces the
// sentinel as a defense-in-depth check.
var ErrInvalidReconciliation = errors.New("inventory: invalid reconciliation input")

// ErrInvalidBatch is returned by Service.Submit when an ingestion
// batch fails any of the structural / shape validations the
// service enforces beyond the HTTP handler's byte/count caps:
//
//   - missing organization id or agent id,
//   - empty store_coverage or duplicate entries in it,
//   - cert.store_location not declared in store_coverage,
//   - duplicate (fingerprint, store_location) inside the batch,
//   - duplicate raw PEM bytes inside the batch,
//   - collected_at > now + 24h (clock-skew guard).
//
// HTTP handler maps to 400 bad_request.
var ErrInvalidBatch = errors.New("inventory: invalid certificate batch")

// ErrPrivateKeyMaterial is returned by Service.Submit when any
// certificate_pem in the batch contains a recognized private-key
// marker. Per CLAUDE.md §6.2 and CERTIFICATE_INVENTORY.md §7 the
// ENTIRE batch is rejected — partial accept would let an agent
// probe which markers trigger the reject. HTTP handler maps to
// 400 private_key_rejected.
var ErrPrivateKeyMaterial = errors.New("inventory: private key material rejected")

// ErrInvalidCertificate is returned by Service.Submit when any
// certificate_pem in the batch fails to parse as a single X.509
// CERTIFICATE block. Whole-batch reject for the same reasons as
// ErrPrivateKeyMaterial. HTTP handler maps to 400
// certificate_unparseable.
var ErrInvalidCertificate = errors.New("inventory: certificate failed to parse")

// ErrInternalAudit is returned by Service.Submit when a security-
// significant audit write fails (private-key rejection,
// certificate-unparseable rejection). The audit row is the only
// visible trail for those rejection signals; failing the request
// rather than silently dropping the audit upholds the §9 invariant
// that audits are not optional on security-significant flows. HTTP
// handler maps to 500 internal_error.
var ErrInternalAudit = errors.New("inventory: audit write failed")

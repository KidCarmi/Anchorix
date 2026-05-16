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

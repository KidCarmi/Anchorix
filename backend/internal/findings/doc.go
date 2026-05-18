// Package findings is the certificate findings domain.
//
// Findings are DERIVED STATE — the authoritative inputs are the
// certificates and certificate_observations tables (owned by
// internal/inventory). A findings recompute reads those inputs,
// runs deterministic rules, and upserts rows into the findings
// table. Re-running recompute with unchanged inputs produces
// unchanged outputs (CLAUDE.md §7.6 deterministic behavior).
//
// Boundaries (cross-link CLAUDE.md §8.6):
//
//   - This package OWNS the Finding domain model, rule
//     definitions, and the recompute orchestration.
//   - It DOES NOT own the certificates / observations tables —
//     it reads them via the inventory.Repository interface.
//   - It DOES NOT write the audit_events table directly — it
//     emits via audit.Recorder so audit policy lives in one
//     place.
//   - It DOES NOT execute any HTTP I/O — the httpapi handlers
//     translate the wire shape into Service calls.
//
// Forbidden dependencies:
//
//   - findings -> httpapi (reverse layering)
//   - findings -> storage/postgres (must go through Repository)
//   - findings -> agent/windows
//
// Architectural role:
//
//   - findings.Service is a domain layer (not a transport
//     layer, not a storage layer). It composes the rule
//     evaluation pass with the finding-lifecycle upserts and
//     the audit recording inside one transaction.
//
// Rule philosophy (H-021):
//
//   - Each rule is a small pure function (no I/O, no clock
//     access except via the injected `now` parameter).
//   - Each rule has a stable ID and an integer version. Bumping
//     the version on a rule body change is how a recompute
//     distinguishes "same finding, new rule body" from
//     "different rule".
//   - Severity is statically mapped per rule. v0.1 does NOT
//     compute severity dynamically from cert content (e.g.
//     "weaker RSA = higher severity") — that's a future
//     refinement.
package findings

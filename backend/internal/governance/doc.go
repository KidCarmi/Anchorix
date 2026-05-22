// Package governance owns the derivation half of H-026 trust
// governance: ownership inference and policy resolution.
//
// Boundaries (cross-link CLAUDE.md §8.6):
//
//   - This package OWNS the OwnershipRule / CertificateOwnership /
//     OwnershipMatchExplanation / CertificateOwnershipOverride /
//     PolicyDefinition / PolicyAssignment / PolicyWaiver /
//     GovernanceRecomputeRun domain models and their repository
//     interfaces.
//   - It DOES NOT own the certificates / observations tables;
//     the H-026B engine consumes them through a consumer-owned
//     reader interface (declared next to the engine, not here).
//   - It DOES NOT depend on internal/findings — H-026D's
//     findings enrichment lives as an adapter inside the
//     findings package that calls a small ownership-lookup
//     interface.
//   - It DOES NOT execute any HTTP I/O — the httpapi handlers
//     translate the wire shape into service calls (H-026B+).
//
// Forbidden dependencies:
//
//   - governance -> findings  (consumer-owned interface direction)
//   - governance -> inventory (reads via a consumer-owned interface)
//   - governance -> httpapi   (reverse layering)
//   - governance -> storage/postgres (must go through Repository)
//
// Architectural role: domain layer. H-026A1 ships types +
// repository interfaces + their postgres implementation; the
// engine, scheduler, preview, and HTTP surface land in H-026B
// and later.
//
// The package will grow two subpackages:
//
//   - governance/ownership/ — engine, precedence ladder,
//     explanation snapshot, scheduler. Wired in H-026B.
//   - governance/policy/    — scope-chain resolver, merge logic,
//     waiver lifecycle. Wired in H-026D.
//
// H-026A1 stops short of either; only the shared types and
// repository interfaces live here today.
package governance

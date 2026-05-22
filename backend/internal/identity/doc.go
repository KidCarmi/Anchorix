// Package identity owns the trust-governance vocabulary that
// operators curate: tags, services, service groups, agent
// groups, and their assignment / membership tables.
//
// Identity is the "what / who" half of H-026. It is intentionally
// separate from the governance package (the "derivation" half)
// because identity is operator-curated state with simple CRUD
// semantics; governance derives ownership and policy effect from
// identity + the inventory tables and runs under advisory locks
// with REPEATABLE READ isolation.
//
// Boundaries (cross-link CLAUDE.md §8.6):
//
//   - This package OWNS the Tag / Service / ServiceGroup /
//     AgentGroup domain models and the Repository interface.
//   - It DOES NOT own the certificates / observations tables;
//     it does not import internal/inventory.
//   - It DOES NOT depend on internal/governance — identity is
//     a producer; governance is a consumer. The reverse
//     direction is forbidden.
//   - It DOES NOT execute any HTTP I/O — the httpapi handlers
//     (H-026A2) translate the wire shape into service calls.
//
// Forbidden dependencies:
//
//   - identity -> governance (consumer-owned interface direction)
//   - identity -> httpapi    (reverse layering)
//   - identity -> storage/postgres (must go through Repository)
//
// Architectural role: domain layer. The service layer (H-026A2)
// composes validators (slug rules, service_group cycle
// detection, polymorphic tag_assignment target dispatch) over
// this package's repository interface.
//
// H-026A1 ships the types + repository interface +
// postgres implementation only. No service layer, no HTTP
// handlers, no audit recording — those land in H-026A2 once
// the schema and storage foundation are proven.
package identity

// Package ownership is the H-026B engine: deterministic
// inference of certificate ownership from the operator-curated
// vocabulary in identity (services, tags, agent groups,
// service groups) plus the inventory pipeline's certificates
// and observations.
//
// H-026A3 ships this package as a SKELETON only — no engine
// code lives here yet. The doc.go declares the boundary so
// the H-026B implementation PR can drop the engine, scheduler,
// preview, and explanation snapshot logic into a well-fenced
// directory without re-litigating package layout.
//
// What lands here in H-026B (per
// docs/engineering/H026_TRUST_GOVERNANCE_PLAN.md §11.2):
//
//   - rules.go         — rule type, match predicates
//   - precedence.go    — tier enum, deterministic tiebreaker
//   - engine.go        — streaming pass under
//                        WithTxLockedOwnership(orgID) +
//                        REPEATABLE READ
//   - explanation.go   — winning rule + losing-rules snapshot
//   - service.go       — Recompute / Preview / ApplyOverride
//                        orchestrator
//   - scheduler.go     — sibling of findings.Scheduler;
//                        one goroutine per process, per-org
//                        sweep, ctx-cancel honored
//
// Boundaries (cross-link CLAUDE.md §8.6 + governance plan §2.2):
//
//   - This package OWNS the engine's pure decision functions
//     (decideOwnership, applyTiebreaker) and the orchestration
//     that composes them with the repository writes.
//   - It DOES NOT own the operator-curated vocabulary
//     (services, tags, ...). It reads them through a small
//     consumer-owned reader interface (declared next to the
//     engine in this package, never in identity or governance
//     itself).
//   - It DOES NOT own the storage layer. Repository writes go
//     through governance.OwnershipRepository +
//     governance.GovernanceRecomputeRunsRepository, both of
//     which are interfaces in the parent governance package.
//   - It DOES NOT execute any HTTP I/O — the H-026B handlers
//     translate the wire shape into engine.Service calls.
//
// Forbidden dependencies (binding in this PR; the H-026B
// engine PR must respect them):
//
//   - ownership -> findings       (consumer-owned direction)
//   - ownership -> inventory      (reads via consumer-owned interface)
//   - ownership -> identity       (reads via consumer-owned interface;
//                                  identity is the producer of the
//                                  vocabulary, governance reads it)
//   - ownership -> httpapi        (reverse layering)
//   - ownership -> storage/postgres (must go through the
//                                  governance.* interfaces in the
//                                  parent package)
//
// Allowed dependencies:
//
//   - governance              (parent — types + repository interfaces)
//   - internal/audit          (audit recorder for state changes)
//   - internal/clock          (injected time)
//   - internal/ids            (id minting)
//   - internal/logger         (structured logs)
//   - stdlib only beyond that
//
// Architectural role: domain layer. The H-026B implementation
// PR sized this at < 1500 LOC; the engine is the largest
// single piece of H-026 work and lives here in isolation so
// review attention concentrates on the determinism and
// audit-atomicity invariants.
package ownership

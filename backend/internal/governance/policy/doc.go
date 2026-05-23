// Package policy is the H-026D engine: scope-chain resolution
// of policy assignments + waivers down to a per-certificate
// effective policy, plus the violation pass that emits
// policy_* findings.
//
// H-026A3 ships this package as a SKELETON only — no engine
// code lives here yet. The doc.go declares the boundary so
// the H-026D implementation PR can drop the resolver, the
// merge / intersection logic, and the waiver-lifecycle code
// into a well-fenced directory without re-litigating package
// layout.
//
// What lands here in H-026D (per
// docs/engineering/H026_TRUST_GOVERNANCE_PLAN.md §11.4):
//
//   - definition.go  — typed PolicyRule shapes; JSONB parsing
//                      + validation that the storage layer's
//                      schema_version-fenced JSONB column
//                      relies on.
//   - resolver.go    — walk org -> service group ancestors ->
//                      direct service group -> service ->
//                      certificate; merge effective rules
//                      with intersection-only semantics
//                      (only waivers may loosen).
//   - waiver.go      — active-waiver lookup + expiry sweep
//                      (the recompute pass observes
//                      expires_at <= now and emits
//                      policy_waiver.expired audit rows).
//   - engine.go      — streaming pass that consumes the
//                      resolver and emits policy_* findings
//                      via internal/findings's enrichment
//                      hook.
//   - service.go     — Recompute / Preview orchestration.
//
// Boundaries (cross-link CLAUDE.md §8.6 + governance plan §2.2):
//
//   - This package OWNS the scope-chain walk and the merge
//     rules. Both are deterministic given (assignments,
//     waivers, scope hierarchy, now).
//   - It DOES NOT own the operator-curated vocabulary
//     (services, service groups, ...). It reads them through
//     a consumer-owned reader interface (declared here in
//     H-026D, never in identity or the parent governance
//     package).
//   - It DOES NOT execute findings writes directly. The
//     enrichment hook lives in internal/findings; this
//     package emits a small typed payload that the findings
//     recompute writes alongside the existing finding rows.
//   - It DOES NOT execute any HTTP I/O.
//
// Forbidden dependencies (binding in this PR; the H-026D
// engine PR must respect them):
//
//   - policy -> findings        (consumer-owned direction;
//                                findings consumes a
//                                policy.ViolationFeed-style
//                                interface)
//   - policy -> inventory       (reads via consumer-owned interface)
//   - policy -> identity        (reads via consumer-owned interface)
//   - policy -> httpapi         (reverse layering)
//   - policy -> storage/postgres (must go through the
//                                governance.* interfaces in
//                                the parent package)
//   - policy -> ownership       (the two engines are siblings,
//                                not collaborators; ownership
//                                is a SIGNAL the policy engine
//                                reads through a tiny ownership
//                                lookup interface, but they
//                                don't share state)
//
// Allowed dependencies: same set as ownership/doc.go.
//
// Architectural role: domain layer. The H-026D implementation
// PR sized this at < 1500 LOC alongside a small additive
// migration on findings.
package policy

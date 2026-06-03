// Package explanationretention is the B4 PR-4 maintenance.Job adapter for
// the H-027 explanation-retention prune primitive
// (ownership.Service.PruneExplanationsPage).
//
// It is a THIN adapter: it translates the generic maintenance.Job
// RunPage contract into exactly one call of the dormant prune primitive
// and maps the primitive's result onto maintenance.PageResult. It adds
// NO behavior of its own — no scheduler-state mutation, no audit (the
// primitive owns its audit), no direct repository access, no loop.
//
// It mirrors the sibling overridesweep adapter and, like it, lives in its
// own package (not in internal/governance/maintenance) so the
// maintenance package stays free of any dependency on
// internal/governance/ownership: maintenance owns the generic Job
// contract; this package owns the H-027-specific binding. The scheduler
// tick loop (PR-5+) and the composition root register this Job; nothing
// in PR-4 wires or invokes it in production.
//
// Boundaries (cross-link CLAUDE.md §8.6):
//
//   - This package OWNS the explanation_retention_prune Job adapter and
//     the narrow consumer-owned ExplanationPruner interface.
//   - It depends on internal/governance/maintenance for the Job /
//     PageResult / PageLimits contract, and on
//     internal/governance/ownership ONLY for the prune primitive's
//     result type and the interface the adapter calls. It does NOT
//     import storage/postgres.
//
// Forbidden dependencies:
//
//   - explanationretention -> httpapi          (reverse layering)
//   - explanationretention -> storage/postgres (must go through the
//     ownership Service, which the composition root injects as the pruner)
//   - explanationretention -> the overridesweep sibling adapter (each job
//     is independent)
//
// Architectural role: domain adapter. Constructor DI only (§8.8); no
// global state; no init-time side effects.
package explanationretention

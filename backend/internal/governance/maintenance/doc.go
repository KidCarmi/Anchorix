// Package maintenance is the B4 governance-maintenance scheduler's job
// layer: the Job interface, the immutable JobRegistry, and the bounded
// JobRunner that executes a single due (organization, job) pass.
//
// This package is B4 PR-2 and is DORMANT by construction. It introduces
// NO background execution:
//
//   - no Scheduler.Run tick loop,
//   - no goroutine, no time.Ticker / time.Timer,
//   - no composition-root (serve.go) wiring,
//   - no invocation of the H-027 PruneExplanationsPage or H-029
//     SweepExpiringOverridesPage maintenance primitives (no real Job is
//     registered in this PR; only test fakes exercise the runner).
//
// What it DOES provide is the synchronous machinery a future PR-3+ tick
// loop will call once per due item:
//
//	runner.RunDueJob(ctx, jobState)
//
// which acquires the PR-1 per-(org, job) advisory lock, runs a bounded
// page loop (max pages + max wall-clock per run), and records the
// outcome through the PR-1 SchedulerStateRepository (started / completed
// / partial / failed). The loop never spans a transaction or a lock
// across pages; each Job.RunPage call is self-contained.
//
// Boundaries (cross-link CLAUDE.md §8.6):
//
//   - This package OWNS the Job / PageResult / PageLimits contract, the
//     JobRegistry, and the JobRunner.
//   - It depends on the parent governance package only for the
//     consumer-owned scheduler-state and lock interfaces
//     (SchedulerStateRepository, SchedulerJobLocker, SchedulerJob).
//   - It depends on internal/clock (injected time, CLAUDE.md §8.2) and
//     internal/logger (structured logs, §9).
//
// Forbidden dependencies:
//
//   - maintenance -> httpapi            (reverse layering)
//   - maintenance -> storage/postgres   (must go through governance.* interfaces)
//   - maintenance -> internal/governance/ownership (PR-2 must NOT call the
//     dormant primitives; the real Job adapters land in PR-3/PR-4)
//
// Architectural role: domain layer. Constructor DI only (§8.8); no
// global state; no init-time side effects.
package maintenance

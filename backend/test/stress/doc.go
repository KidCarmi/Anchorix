// Package stress holds heavy-load tests behind a
// `//go:build stress` tag. Tests in this package generate the
// Pilot dataset (1K agents, 5K distinct certs per
// H024_PERFORMANCE_PLAN.md §3) and run it against a real
// PostgreSQL, so they take orders of magnitude longer than the
// integration or perf tiers.
//
// Build tag rationale (H024_PERFORMANCE_PLAN.md §4):
//
//   - The default `go test ./...` and the perf tier's
//     `-tags perf` BOTH exclude this package. Stress runs are
//     opt-in and on-demand: `go test -tags stress -timeout 30m
//     -count=1 ./backend/test/stress/...`.
//   - No nightly workflow ships in H-024A. Operators can run
//     these locally against a beefy postgres; H-024B may
//     promote the suite to a nightly workflow once budgets
//     are measured.
//
// The H-024A scope is the SKELETON: build + persist the Pilot
// fleet, log the durations, sanity-check the row counts. The
// substantive wall-clock budget assertions (per §3) land in
// H-024B once the streaming recompute is the code under test.
package stress

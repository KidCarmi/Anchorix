// Package perf holds performance-regression tests behind a
// `//go:build perf` tag. Tests in this package SKIP unless
// `DATABASE_URL` is set, so they compile cleanly on developer
// machines without postgres but never silently pass.
//
// Build tag rationale (H024_PERFORMANCE_PLAN.md §4):
//
//   - The default `go test ./...` pass excludes this package
//     so PR CI wall-clock does not grow.
//   - `go test -tags perf -count=1 ./backend/test/perf/...`
//     runs the tier on demand. The DATABASE_URL gate matches
//     the integration tier's pattern so the same postgres
//     service container can host both.
//
// The H-024A scope is the test SKELETON: a real harness that
// can be extended by H-024B (and beyond) with query-count
// assertions, paginated-load timing, and the streaming-diff
// coherence checks. The substantive assertions land alongside
// the implementation changes that motivate them; landing the
// skeleton now lets reviewers find their feet before the
// state-machine rewrite ships.
package perf

// Package clock provides a Clock interface so that business logic never
// depends on time.Now() directly. This makes time-sensitive code testable
// and deterministic (CLAUDE.md §8.2).
package clock

import "time"

// Clock returns the current time. Production code uses System; tests use
// a fake clock provided by the test package that needs deterministic time.
type Clock interface {
	Now() time.Time
}

// System is the production clock backed by the OS wall clock. It returns
// UTC times so persisted timestamps are consistent regardless of the host
// timezone.
type System struct{}

// Now returns the current wall-clock time in UTC.
func (System) Now() time.Time { return time.Now().UTC() }

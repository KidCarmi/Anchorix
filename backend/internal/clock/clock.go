// Package clock provides a Clock interface so that business logic never
// depends on time.Now() directly. This makes time-sensitive code testable
// and deterministic (CLAUDE.md §8.2).
package clock

import "time"

// Clock returns the current time. Production code uses Real; tests use Fake.
type Clock interface {
	Now() time.Time
}

// Real is the production clock backed by time.Now().
type Real struct{}

// Now returns the current wall-clock time.
func (Real) Now() time.Time { return time.Now().UTC() }

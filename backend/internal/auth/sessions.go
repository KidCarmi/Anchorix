package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Session is a server-side authentication session.
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	UserAgent string
	RemoteIP  string
}

// IsActive reports whether the session is currently valid given
// `now`. A revoked or expired session is inactive.
func (s *Session) IsActive(now time.Time) bool {
	if s == nil || s.RevokedAt != nil {
		return false
	}
	return now.Before(s.ExpiresAt)
}

// SessionPolicy controls session lifetimes. Immutable after startup
// (CLAUDE.md §8.9). The sliding-session pattern uses a single
// `expires_at` column: each successful auth extends `expires_at` to
// `min(now + Idle, CreatedAt + Absolute)`.
type SessionPolicy struct {
	Idle     time.Duration
	Absolute time.Duration
}

// NewSessionPolicy validates and returns a SessionPolicy. Both
// durations must be positive; absolute must be at least equal to
// idle (CLAUDE.md §8.9: no silent fallback for security-sensitive
// settings).
func NewSessionPolicy(idle, absolute time.Duration) (SessionPolicy, error) {
	if idle <= 0 {
		return SessionPolicy{}, errors.New("auth: session idle lifetime must be positive")
	}
	if absolute <= 0 {
		return SessionPolicy{}, errors.New("auth: session absolute lifetime must be positive")
	}
	if absolute < idle {
		return SessionPolicy{}, fmt.Errorf("auth: absolute (%s) must be >= idle (%s)", absolute, idle)
	}
	return SessionPolicy{Idle: idle, Absolute: absolute}, nil
}

// NextExpiry returns the new ExpiresAt to apply when extending or
// initially issuing a session. created is the session's CreatedAt.
func (p SessionPolicy) NextExpiry(now, created time.Time) time.Time {
	idleDeadline := now.Add(p.Idle)
	absDeadline := created.Add(p.Absolute)
	if idleDeadline.Before(absDeadline) {
		return idleDeadline
	}
	return absDeadline
}

// SessionStore is the persistence contract for sessions. Implemented
// by storage/postgres.SessionsRepository.
type SessionStore interface {
	Create(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	ExtendExpiry(ctx context.Context, id string, newExpiry time.Time) error
	Revoke(ctx context.Context, id string, at time.Time) error
}

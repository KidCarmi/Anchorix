package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordPolicy controls password handling. Constructed once at
// startup from internal/config and passed to the auth service
// (CLAUDE.md §8.8 constructor DI; §8.9 immutable after startup).
type PasswordPolicy struct {
	BcryptCost int
}

// NewPasswordPolicy validates and returns a PasswordPolicy.
// Bounds for cost are enforced here (CLAUDE.md §8.9: validate at
// construction, fail closed).
func NewPasswordPolicy(cost int) (PasswordPolicy, error) {
	if cost < 10 || cost > 14 {
		return PasswordPolicy{}, fmt.Errorf("auth: bcrypt cost %d out of allowed range [10, 14]", cost)
	}
	return PasswordPolicy{BcryptCost: cost}, nil
}

// Hash returns the bcrypt hash of password using p.BcryptCost.
func (p PasswordPolicy) Hash(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("auth: empty password")
	}
	return bcrypt.GenerateFromPassword([]byte(password), p.BcryptCost)
}

// Verify returns nil iff the password matches the stored hash. The
// caller MUST treat any non-nil return as a failed credential check
// — do not distinguish bcrypt-internal errors from a mismatch when
// reporting to clients (CLAUDE.md §6: deterministic auth behavior).
func (PasswordPolicy) Verify(hash []byte, password string) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}

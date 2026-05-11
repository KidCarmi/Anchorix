// Package auth handles operator authentication and session management.
//
// v0.1 ships local password authentication only (bcrypt). SSO (OIDC/SAML)
// is explicitly out of scope per CLAUDE.md §4 and is reserved for v0.x.
//
// Layering (CLAUDE.md §5, §8.6):
//
//	httpapi/handlers → auth.Service → auth.Repository (interface)
//	                                    └── implemented by storage/postgres
//
// This package owns the User / Session / Role types, the password
// hashing policy, the cookie sign/verify primitives, and the login /
// logout / authenticate domain operations. It does NOT know about HTTP
// (no `net/http` imports here) and does NOT know about SQL (no `pgx`
// imports).
package auth

import (
	"context"
	"errors"
	"time"
)

// User is an operator account.
type User struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"display_name"`
	Role           Role       `json:"role"`
	Disabled       bool       `json:"disabled"`
	CreatedAt      time.Time  `json:"created_at"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
}

// Role is a coarse RBAC role. v0.1 ships two roles; finer-grained
// permissions arrive when needed (CLAUDE.md §6.3).
type Role string

const (
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Sentinel errors. Centralized so domain and storage agree on the
// vocabulary (CLAUDE.md §8.1).
var (
	ErrUserNotFound       = errors.New("auth: user not found")
	ErrUserDisabled       = errors.New("auth: user disabled")
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrSessionNotFound    = errors.New("auth: session not found")
	ErrSessionExpired     = errors.New("auth: session expired")
	ErrSessionRevoked     = errors.New("auth: session revoked")
)

// Repository is the persistence contract for users. The concrete
// implementation lives in internal/storage/postgres.
type Repository interface {
	GetUserByEmail(ctx context.Context, email string) (*User, []byte, error) // user + bcrypt hash
	GetUserByID(ctx context.Context, id string) (*User, error)
	UpdateLastLogin(ctx context.Context, userID string, at time.Time) error
	CreateUser(ctx context.Context, u *User, passwordHash []byte) error
}

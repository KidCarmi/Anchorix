// Package auth handles operator authentication and session management.
//
// v0.1 ships local password authentication only (bcrypt). SSO (OIDC/SAML)
// is explicitly out of scope per CLAUDE.md §4 and is reserved for v0.x.
package auth

import (
	"context"
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

// Repository is the persistence contract for users.
type Repository interface {
	GetUserByEmail(ctx context.Context, email string) (*User, []byte, error) // returns user + hashed password
	GetUserByID(ctx context.Context, id string) (*User, error)
	UpdateLastLogin(ctx context.Context, userID string, at time.Time) error
}

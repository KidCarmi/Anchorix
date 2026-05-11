package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
)

// AuthRepository implements auth.Repository against PostgreSQL.
// Holds *DB rather than the pool directly so it can route queries
// through db.querierFor(ctx) and transparently participate in any
// transaction the caller wrapped the operation in.
type AuthRepository struct {
	db *DB
}

// NewAuthRepository wires the repo with the database. CLAUDE.md §8.8:
// constructor-based DI; no globals.
func NewAuthRepository(db *DB) *AuthRepository {
	return &AuthRepository{db: db}
}

// GetUserByEmail returns the user with the given email plus the
// bcrypt password hash. Returns auth.ErrUserNotFound if no row
// matches.
func (r *AuthRepository) GetUserByEmail(ctx context.Context, email string) (*auth.User, []byte, error) {
	const q = `
		SELECT id, organization_id, email, display_name, role, password_hash,
		       disabled, created_at, last_login_at
		  FROM users
		 WHERE email = $1`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, email)
	user, hash, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, auth.ErrUserNotFound
		}
		return nil, nil, fmt.Errorf("postgres: get user by email: %w", err)
	}
	return user, hash, nil
}

// GetUserByID returns the user with the given id. No password hash.
func (r *AuthRepository) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	const q = `
		SELECT id, organization_id, email, display_name, role, password_hash,
		       disabled, created_at, last_login_at
		  FROM users
		 WHERE id = $1`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, id)
	user, _, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrUserNotFound
		}
		return nil, fmt.Errorf("postgres: get user by id: %w", err)
	}
	return user, nil
}

// UpdateLastLogin records when the user last logged in.
func (r *AuthRepository) UpdateLastLogin(ctx context.Context, userID string, at time.Time) error {
	_, err := r.db.querierFor(ctx).Exec(ctx,
		`UPDATE users SET last_login_at = $2 WHERE id = $1`, userID, at)
	if err != nil {
		return fmt.Errorf("postgres: update last_login: %w", err)
	}
	return nil
}

// CreateUser inserts a new user with the given bcrypt hash. Used by
// the `anchorix admin create` command.
func (r *AuthRepository) CreateUser(ctx context.Context, u *auth.User, passwordHash []byte) error {
	const q = `
		INSERT INTO users (id, organization_id, email, display_name, role,
		                   password_hash, disabled, created_at)
		     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.db.querierFor(ctx).Exec(ctx, q,
		u.ID, u.OrganizationID, u.Email, u.DisplayName, string(u.Role),
		passwordHash, u.Disabled, u.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: create user: %w", err)
	}
	return nil
}

// EnsureOrganization upserts an organization row by id. Used by the
// `anchorix admin create` bootstrap path to provision the row that
// the users.organization_id foreign key requires (a pristine DB has
// no organizations seeded). No-op if the row already exists.
func (r *AuthRepository) EnsureOrganization(ctx context.Context, id, name string) error {
	if id == "" || name == "" {
		return fmt.Errorf("postgres: organization id and name required")
	}
	_, err := r.db.querierFor(ctx).Exec(ctx,
		`INSERT INTO organizations (id, name) VALUES ($1, $2)
		 ON CONFLICT (id) DO NOTHING`, id, name)
	if err != nil {
		return fmt.Errorf("postgres: ensure organization: %w", err)
	}
	return nil
}

func scanUser(row pgx.Row) (*auth.User, []byte, error) {
	var (
		u           auth.User
		role        string
		hash        []byte
		lastLoginAt *time.Time
	)
	if err := row.Scan(
		&u.ID, &u.OrganizationID, &u.Email, &u.DisplayName, &role,
		&hash, &u.Disabled, &u.CreatedAt, &lastLoginAt,
	); err != nil {
		return nil, nil, err
	}
	u.Role = auth.Role(role)
	u.LastLoginAt = lastLoginAt
	return &u, hash, nil
}

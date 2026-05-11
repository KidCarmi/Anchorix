package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
)

// AuthRepository implements auth.Repository against PostgreSQL.
type AuthRepository struct {
	pool *pgxpool.Pool
}

// NewAuthRepository wires the repo with a pool from the composition
// root. CLAUDE.md §8.8: constructor-based DI; no globals.
func NewAuthRepository(db *DB) *AuthRepository {
	return &AuthRepository{pool: db.querier()}
}

// GetUserByEmail returns the user with the given email plus the
// bcrypt password hash. Returns auth.ErrUserNotFound if no row
// matches. The caller is responsible for comparing the password
// (the repository never sees plaintext).
func (r *AuthRepository) GetUserByEmail(ctx context.Context, email string) (*auth.User, []byte, error) {
	const q = `
		SELECT id, organization_id, email, display_name, role, password_hash,
		       disabled, created_at, last_login_at
		  FROM users
		 WHERE email = $1`
	row := r.pool.QueryRow(ctx, q, email)
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
	row := r.pool.QueryRow(ctx, q, id)
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
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET last_login_at = $2 WHERE id = $1`, userID, at)
	if err != nil {
		return fmt.Errorf("postgres: update last_login: %w", err)
	}
	return nil
}

// CreateUser inserts a new user with the given bcrypt hash. Used by
// the `anchorix admin create` command. Returns the persisted user.
func (r *AuthRepository) CreateUser(ctx context.Context, u *auth.User, passwordHash []byte) error {
	const q = `
		INSERT INTO users (id, organization_id, email, display_name, role,
		                   password_hash, disabled, created_at)
		     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.pool.Exec(ctx, q,
		u.ID, u.OrganizationID, u.Email, u.DisplayName, string(u.Role),
		passwordHash, u.Disabled, u.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: create user: %w", err)
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

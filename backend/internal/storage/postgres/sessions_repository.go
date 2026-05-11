package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
)

// SessionsRepository implements auth.SessionStore against PostgreSQL.
type SessionsRepository struct {
	db *DB
}

// NewSessionsRepository wires the repo.
func NewSessionsRepository(db *DB) *SessionsRepository {
	return &SessionsRepository{db: db}
}

// Create inserts a new session row.
func (r *SessionsRepository) Create(ctx context.Context, s *auth.Session) error {
	var ip *string
	if s.RemoteIP != "" {
		ip = &s.RemoteIP
	}
	const q = `
		INSERT INTO sessions (id, user_id, created_at, expires_at, user_agent, remote_ip)
		     VALUES ($1, $2, $3, $4, $5, $6::inet)`
	_, err := r.db.querierFor(ctx).Exec(ctx, q,
		s.ID, s.UserID, s.CreatedAt, s.ExpiresAt, s.UserAgent, ip,
	)
	if err != nil {
		return fmt.Errorf("postgres: create session: %w", err)
	}
	return nil
}

// Get returns the session if it exists and has not been revoked.
func (r *SessionsRepository) Get(ctx context.Context, id string) (*auth.Session, error) {
	const q = `
		SELECT id, user_id, created_at, expires_at, revoked_at, user_agent, remote_ip
		  FROM sessions
		 WHERE id = $1`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, id)
	s, err := scanSession(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrSessionNotFound
		}
		return nil, fmt.Errorf("postgres: get session: %w", err)
	}
	if s.RevokedAt != nil {
		return nil, auth.ErrSessionRevoked
	}
	return s, nil
}

// ExtendExpiry sets the session's expires_at to the given time.
func (r *SessionsRepository) ExtendExpiry(ctx context.Context, id string, newExpiry time.Time) error {
	tag, err := r.db.querierFor(ctx).Exec(ctx,
		`UPDATE sessions SET expires_at = $2
		  WHERE id = $1 AND revoked_at IS NULL`, id, newExpiry)
	if err != nil {
		return fmt.Errorf("postgres: extend session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrSessionNotFound
	}
	return nil
}

// Revoke marks the session as revoked. Idempotent.
func (r *SessionsRepository) Revoke(ctx context.Context, id string, at time.Time) error {
	_, err := r.db.querierFor(ctx).Exec(ctx,
		`UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2)
		  WHERE id = $1`, id, at)
	if err != nil {
		return fmt.Errorf("postgres: revoke session: %w", err)
	}
	return nil
}

func scanSession(row pgx.Row) (*auth.Session, error) {
	var (
		s         auth.Session
		revokedAt *time.Time
		ua        *string
		ip        *net.IP
	)
	if err := row.Scan(
		&s.ID, &s.UserID, &s.CreatedAt, &s.ExpiresAt, &revokedAt, &ua, &ip,
	); err != nil {
		return nil, err
	}
	s.RevokedAt = revokedAt
	if ua != nil {
		s.UserAgent = *ua
	}
	if ip != nil {
		s.RemoteIP = ip.String()
	}
	return &s, nil
}

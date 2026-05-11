package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/ids"
)

// Transactor runs fn inside a single transaction. The implementation
// (storage/postgres.DB) binds a tx to the ctx so that repository
// calls made with that ctx automatically participate. The auth
// service uses this to make Login and CreateUser atomic across
// multiple repository writes without leaking pgx.Tx outside the
// storage layer (CLAUDE.md §8.6, §18).
type Transactor interface {
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// Service is the auth domain entrypoint. Handlers depend on this
// struct, never on Repository / SessionStore / Transactor directly
// (CLAUDE.md §8.6, §8.8).
type Service struct {
	users    Repository
	sessions SessionStore
	audit    audit.Recorder
	tx       Transactor
	passwd   PasswordPolicy
	sessPol  SessionPolicy
	clock    clock.Clock
}

// NewService wires the service. Constructor-based DI per CLAUDE.md
// §8.8. Returns a validation error if any dependency is missing —
// never panics (CLAUDE.md §18: no panic-driven business flow).
func NewService(
	users Repository,
	sessions SessionStore,
	auditRec audit.Recorder,
	tx Transactor,
	passwd PasswordPolicy,
	sessPol SessionPolicy,
	clk clock.Clock,
) (*Service, error) {
	switch {
	case users == nil:
		return nil, errors.New("auth.NewService: users repository required")
	case sessions == nil:
		return nil, errors.New("auth.NewService: sessions store required")
	case auditRec == nil:
		return nil, errors.New("auth.NewService: audit recorder required")
	case tx == nil:
		return nil, errors.New("auth.NewService: transactor required")
	case clk == nil:
		return nil, errors.New("auth.NewService: clock required")
	}
	return &Service{
		users:    users,
		sessions: sessions,
		audit:    auditRec,
		tx:       tx,
		passwd:   passwd,
		sessPol:  sessPol,
		clock:    clk,
	}, nil
}

// LoginInput carries the request-side identity of a login attempt.
type LoginInput struct {
	Email     string
	Password  string
	UserAgent string
	RemoteIP  string
	RequestID string
}

// LoginOutput is the successful login result.
type LoginOutput struct {
	User    *User
	Session *Session
}

// Login authenticates the user and creates a new session.
//
// State-changing steps (sessions.Create, users.UpdateLastLogin,
// audit.Record of `auth.login_succeeded`) run inside a single
// transaction. If any one of them fails, none of them persist —
// no half-issued session, no orphan last_login, no
// auditless session creation (CLAUDE.md §18).
//
// Read-only steps (GetUserByEmail, password verify) run outside the
// transaction; they have no rollback semantics. Failed-credential
// attempts emit a `severity:"security"` audit event via the silent
// auditAuthFailure helper.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginOutput, error) {
	user, hash, err := s.users.GetUserByEmail(ctx, in.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.auditAuthFailure(ctx, in, "user_unknown")
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("auth: lookup user: %w", err)
	}
	if user.Disabled {
		s.auditAuthFailure(ctx, in, "user_disabled")
		return nil, ErrInvalidCredentials
	}
	if err := s.passwd.Verify(hash, in.Password); err != nil {
		s.auditAuthFailure(ctx, in, "password_mismatch")
		return nil, ErrInvalidCredentials
	}

	now := s.clock.Now()
	session := &Session{
		ID:        ids.New(),
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: s.sessPol.NextExpiry(now, now),
		UserAgent: in.UserAgent,
		RemoteIP:  in.RemoteIP,
	}

	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.sessions.Create(ctx, session); err != nil {
			return fmt.Errorf("auth: create session: %w", err)
		}
		if err := s.users.UpdateLastLogin(ctx, user.ID, now); err != nil {
			return fmt.Errorf("auth: update last_login: %w", err)
		}
		if err := s.audit.Record(ctx, audit.Event{
			OrganizationID: user.OrganizationID,
			Actor:          user.ID,
			ActorType:      "user",
			Action:         "auth.login_succeeded",
			TargetType:     "session",
			TargetID:       session.ID,
			RequestID:      in.RequestID,
		}); err != nil {
			return fmt.Errorf("auth: record login: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &LoginOutput{User: user, Session: session}, nil
}

// Authenticate resolves a session id to its user, extending the
// expiry as a side effect (sliding-session pattern). Returns one of
// ErrSessionNotFound / ErrSessionExpired / ErrSessionRevoked /
// ErrUserNotFound when the request cannot be authenticated.
//
// The slide is a single UPDATE; no transaction is needed.
func (s *Service) Authenticate(ctx context.Context, sessionID string) (*User, *Session, error) {
	session, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	now := s.clock.Now()
	if !session.IsActive(now) {
		return nil, nil, ErrSessionExpired
	}
	newExpiry := s.sessPol.NextExpiry(now, session.CreatedAt)
	if !newExpiry.Equal(session.ExpiresAt) {
		if err := s.sessions.ExtendExpiry(ctx, session.ID, newExpiry); err != nil {
			return nil, nil, fmt.Errorf("auth: extend session: %w", err)
		}
		session.ExpiresAt = newExpiry
	}
	user, err := s.users.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, err
	}
	if user.Disabled {
		return nil, nil, ErrUserDisabled
	}
	return user, session, nil
}

// Logout revokes the session and audits the action. Both steps run
// in one transaction so a session never reaches "revoked but
// unaudited" state.
func (s *Service) Logout(ctx context.Context, user *User, session *Session, requestID string) error {
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.sessions.Revoke(ctx, session.ID, now); err != nil {
			return fmt.Errorf("auth: revoke session: %w", err)
		}
		return s.audit.Record(ctx, audit.Event{
			OrganizationID: user.OrganizationID,
			Actor:          user.ID,
			ActorType:      "user",
			Action:         "auth.logout",
			TargetType:     "session",
			TargetID:       session.ID,
			RequestID:      requestID,
		})
	})
}

// CreateUser is invoked by `anchorix admin create`. The user insert
// and the `auth.admin_created` audit row are written in a single
// transaction so no user can exist without its creation having been
// audited (CLAUDE.md §9, §18). The plaintext password never leaves
// the call site; only the hash reaches storage (CLAUDE.md §6.9).
func (s *Service) CreateUser(
	ctx context.Context,
	organizationID, email, displayName, plaintextPassword string,
	role Role,
) (*User, error) {
	hash, err := s.passwd.Hash(plaintextPassword)
	if err != nil {
		return nil, fmt.Errorf("auth: hash password: %w", err)
	}
	user := &User{
		ID:             ids.New(),
		OrganizationID: organizationID,
		Email:          email,
		DisplayName:    displayName,
		Role:           role,
		CreatedAt:      s.clock.Now(),
	}
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.users.CreateUser(ctx, user, hash); err != nil {
			return fmt.Errorf("auth: create user: %w", err)
		}
		return s.audit.Record(ctx, audit.Event{
			OrganizationID: organizationID,
			Actor:          "system",
			ActorType:      "system",
			Action:         "auth.admin_created",
			TargetType:     "user",
			TargetID:       user.ID,
		})
	}); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) auditAuthFailure(ctx context.Context, in LoginInput, reason string) {
	// We do not have the organization id on a failed lookup; record
	// "anchorix" as a placeholder organization scope per the audit
	// schema's NOT NULL on organization_id. Once multi-tenant lands,
	// this needs to look up the tenant by email domain or similar.
	metadata := []byte(fmt.Sprintf(`{"reason":%q,"severity":"security"}`, reason))
	_ = s.audit.Record(ctx, audit.Event{
		OrganizationID: "anchorix",
		Actor:          in.Email,
		ActorType:      "user",
		Action:         "auth.login_failed",
		TargetType:     "session",
		TargetID:       "(none)",
		RequestID:      in.RequestID,
		Metadata:       metadata,
	})
}

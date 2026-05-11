// Package middleware holds HTTP middleware used by internal/httpapi.
//
// Single responsibility per file. The session resolver lives here;
// request-id, logging, recovery, and security-header middleware
// stay in internal/httpapi/middleware.go (the older sibling) for now.
package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
)

// ctxKey is the unexported type used to store auth context values.
type ctxKey int

const (
	ctxKeyUser ctxKey = iota
	ctxKeySession
)

// UserFromContext returns the authenticated user attached by
// SessionResolver, or nil if the request is anonymous.
func UserFromContext(ctx context.Context) *auth.User {
	v, _ := ctx.Value(ctxKeyUser).(*auth.User)
	return v
}

// SessionFromContext returns the session attached by SessionResolver.
func SessionFromContext(ctx context.Context) *auth.Session {
	v, _ := ctx.Value(ctxKeySession).(*auth.Session)
	return v
}

// SessionResolver inspects the session cookie, verifies it, and
// attaches the user + session to context when valid. On any failure
// (no cookie, bad signature, expired session, revoked, user
// disabled) it leaves the context anonymous and lets the request
// proceed — RequireAuth is the gate that returns 401.
//
// This split keeps unauthenticated routes (login, /healthz, /readyz)
// trivial while still propagating identity for routes that need it.
func SessionResolver(svc *auth.Service, signer *auth.SignedCookie, cookieName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(cookieName)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			sessionID, err := signer.Verify(c.Value)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			user, session, err := svc.Authenticate(r.Context(), sessionID)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyUser, user)
			ctx = context.WithValue(ctx, ctxKeySession, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuth wraps a handler so it only runs for authenticated
// requests. Anonymous requests get a 401 with the canonical
// envelope (CLAUDE.md §17 envelope is the only shape allowed).
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFromContext(r.Context()) == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MapAuthError translates an auth.* sentinel error into the
// canonical envelope. Returns true if it handled the error.
func MapAuthError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		envelope.WriteError(w, http.StatusUnauthorized,
			"invalid_credentials", "invalid email or password")
		return true
	case errors.Is(err, auth.ErrSessionExpired),
		errors.Is(err, auth.ErrSessionRevoked):
		envelope.WriteError(w, http.StatusUnauthorized,
			"session_expired", "session is no longer valid")
		return true
	case errors.Is(err, auth.ErrSessionNotFound),
		errors.Is(err, auth.ErrUserNotFound),
		errors.Is(err, auth.ErrUserDisabled):
		envelope.WriteError(w, http.StatusUnauthorized,
			"unauthorized", "authentication required")
		return true
	}
	return false
}

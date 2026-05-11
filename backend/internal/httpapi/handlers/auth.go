package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
)

// AuthDeps bundles the dependencies the auth handlers need.
// Constructor-based DI per CLAUDE.md §8.8: handlers are returned by
// these factory functions, never by `init()` or globals.
type AuthDeps struct {
	Service          *auth.Service
	CookieSigner     *auth.SignedCookie
	CookieName       string
	CookieSecure     bool
	IdleLifetime     time.Duration
	AbsoluteLifetime time.Duration
}

// AuthLogin handles POST /api/v1/auth/login.
//
// Body: { "email": "...", "password": "..." }
// On success: 200 + the user profile JSON + Set-Cookie.
// On failure: canonical envelope with one of bad_request /
// invalid_credentials per CLAUDE.md §17.
func AuthLogin(deps AuthDeps) http.HandlerFunc {
	type req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body req
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}
		body.Email = strings.TrimSpace(strings.ToLower(body.Email))
		if body.Email == "" || body.Password == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"email and password are required")
			return
		}

		out, err := deps.Service.Login(r.Context(), auth.LoginInput{
			Email:     body.Email,
			Password:  body.Password,
			UserAgent: r.UserAgent(),
			RemoteIP:  remoteIP(r),
			RequestID: r.Header.Get("X-Request-Id"),
		})
		if err != nil {
			if !middleware.MapAuthError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "login failed")
			}
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     deps.CookieName,
			Value:    deps.CookieSigner.Sign(out.Session.ID),
			Path:     "/",
			HttpOnly: true,
			Secure:   deps.CookieSecure,
			SameSite: http.SameSiteLaxMode,
			Expires:  out.Session.ExpiresAt,
		})
		envelope.WriteJSON(w, http.StatusOK, out.User)
	}
}

// AuthLogout handles POST /api/v1/auth/logout. Requires auth.
func AuthLogout(deps AuthDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		session := middleware.SessionFromContext(r.Context())
		if user == nil || session == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		if err := deps.Service.Logout(r.Context(), user, session, r.Header.Get("X-Request-Id")); err != nil {
			if !middleware.MapAuthError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "logout failed")
			}
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     deps.CookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   deps.CookieSecure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// AuthMe handles GET /api/v1/auth/me. Requires auth.
func AuthMe() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, user)
	}
}

// remoteIP extracts the client IP from r.RemoteAddr.
//
// We deliberately do NOT consult X-Forwarded-For, X-Real-IP, or any
// other client-supplied header. Those are spoofable by any HTTP
// client; trusting them without a trusted-proxy allowlist would let
// callers forge the source IP recorded against their session.
// A trusted-proxy configuration can re-introduce header parsing in
// a future PR — until then RemoteAddr is the only source.
//
// Uses net.SplitHostPort so bracketed IPv6 forms like "[::1]:12345"
// strip the port correctly. The session row's remote_ip column is
// PostgreSQL `inet` and would reject anything that isn't a valid
// address; we return "" so the column is stored NULL when parsing
// fails.
func remoteIP(r *http.Request) string {
	raw := r.RemoteAddr
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		if net.ParseIP(host) != nil {
			return host
		}
	}
	if net.ParseIP(raw) != nil {
		return raw
	}
	return ""
}

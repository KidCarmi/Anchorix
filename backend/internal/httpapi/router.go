package httpapi

import (
	"net/http"

	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/handlers"
	mw "github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// newRouter assembles the API surface. Routes are grouped by resource and
// kept stable under /api/v1; breaking changes require /api/v2 (CLAUDE.md §17).
func newRouter(cfg *config.Config, log *logger.Logger, readiness *Readiness, deps Dependencies) http.Handler {
	mux := http.NewServeMux()

	// Health endpoints sit outside /api/v1 — they are infrastructure, not
	// part of the public REST surface. They must remain unauthenticated.
	mux.HandleFunc("GET /healthz", handlers.Health)
	mux.Handle("GET /readyz", readiness.handler())

	// /api/v1 — versioned REST surface.
	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", apiV1Router(cfg, deps)))

	// Outer chain (applied to every request, including /healthz, /readyz):
	// recovery -> request id -> logging -> security headers.
	return chain(
		mux,
		recoverMiddleware(log),
		requestIDMiddleware(),
		loggingMiddleware(log),
		securityHeadersMiddleware(cfg),
	)
}

func apiV1Router(cfg *config.Config, deps Dependencies) http.Handler {
	mux := http.NewServeMux()

	authDeps := handlers.AuthDeps{
		Service:          deps.AuthService,
		CookieSigner:     deps.CookieSigner,
		CookieName:       cfg.SessionCookieName,
		CookieSecure:     cfg.IsProduction(),
		IdleLifetime:     cfg.SessionIdleLifetime,
		AbsoluteLifetime: cfg.SessionAbsoluteLifetime,
	}
	resolver := mw.SessionResolver(deps.AuthService, deps.CookieSigner, cfg.SessionCookieName)

	// --- auth ---
	// Login is anonymous; the session resolver runs but does not block.
	mux.Handle("POST /auth/login", resolver(handlers.AuthLogin(authDeps)))
	// Logout + /me require an authenticated session.
	mux.Handle("POST /auth/logout", resolver(mw.RequireAuth(handlers.AuthLogout(authDeps))))
	mux.Handle("GET /auth/me", resolver(mw.RequireAuth(handlers.AuthMe())))

	// --- agents ---
	mux.HandleFunc("GET /agents", handlers.AgentsList)
	mux.HandleFunc("GET /agents/{id}", handlers.AgentsGet)
	mux.HandleFunc("POST /agents/enroll", handlers.AgentsEnroll)
	mux.HandleFunc("POST /agents/{id}/heartbeat", handlers.AgentsHeartbeat)
	mux.HandleFunc("POST /agents/{id}/inventory", handlers.AgentsInventory)
	mux.HandleFunc("POST /agents/enrollment-tokens", handlers.AgentsCreateEnrollmentToken)

	// --- certificates ---
	mux.HandleFunc("GET /certificates", handlers.CertificatesList)
	mux.HandleFunc("GET /certificates/{id}", handlers.CertificatesGet)

	// --- findings ---
	mux.HandleFunc("GET /findings", handlers.FindingsList)
	mux.HandleFunc("GET /findings/{id}", handlers.FindingsGet)
	mux.HandleFunc("POST /findings/{id}/acknowledge", handlers.FindingsAcknowledge)
	mux.HandleFunc("POST /findings/{id}/suppress", handlers.FindingsSuppress)

	// --- audit ---
	mux.HandleFunc("GET /audit/events", handlers.AuditList)

	// --- providers ---
	mux.HandleFunc("GET /providers", handlers.ProvidersList)
	mux.HandleFunc("GET /providers/{id}", handlers.ProvidersGet)

	return mux
}

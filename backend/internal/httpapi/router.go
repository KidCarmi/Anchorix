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
		Service:      deps.AuthService,
		CookieSigner: deps.CookieSigner,
		CookieName:   cfg.SessionCookieName,
		// Secure cookie is required whenever TLS is actually in
		// front of the API. The only TLS posture that justifies
		// emitting a non-Secure cookie is disabled_dev — local dev
		// over plain HTTP. Staging and reverse_proxy deployments
		// MUST send Secure (CLAUDE.md §6.4).
		CookieSecure:     cfg.TLSTermination != config.TLSDisabledDev,
		IdleLifetime:     cfg.SessionIdleLifetime,
		AbsoluteLifetime: cfg.SessionAbsoluteLifetime,
	}
	resolver := mw.SessionResolver(deps.AuthService, deps.CookieSigner, cfg.SessionCookieName)

	agentsDeps := handlers.AgentsDeps{Service: deps.EnrollmentService}
	deploymentDeps := handlers.DeploymentPackageDeps{
		Service:       deps.EnrollmentService,
		PublicBaseURL: cfg.PublicBaseURL,
	}

	// --- auth ---
	// Login is anonymous; the session resolver runs but does not block.
	mux.Handle("POST /auth/login", resolver(handlers.AuthLogin(authDeps)))
	// Logout + /me require an authenticated session.
	mux.Handle("POST /auth/logout", resolver(mw.RequireAuth(handlers.AuthLogout(authDeps))))
	mux.Handle("GET /auth/me", resolver(mw.RequireAuth(handlers.AuthMe())))

	// --- deployment packages (admin-only) ---
	mux.Handle("POST /deployment-packages",
		resolver(mw.RequireAdmin(handlers.DeploymentPackagesCreate(deploymentDeps))))
	mux.Handle("POST /deployment-packages/{id}/revoke",
		resolver(mw.RequireAdmin(handlers.DeploymentPackagesRevoke(deploymentDeps))))

	// --- agents ---
	// /agents/* is the operator-facing surface (list, enroll —
	// enroll is anonymous because the bootstrap secret IS the auth).
	// /agent/* (singular) is the AGENT-facing surface, gated by
	// the agent-bearer credential middleware introduced in PR-013's
	// follow-up. Operator session and agent bearer are independent
	// axes — the resolver/RequireAuth combination guards operator
	// endpoints, while RequireAuthenticatedAgent guards agent
	// endpoints. CLAUDE.md §8.6: no mixed identity state.
	//
	// Heartbeat / inventory remain stubs for Phase 3. The legacy
	// POST /agents/enrollment-tokens path is intentionally absent
	// from this router: deployment packages
	// (POST /deployment-packages) replace the concept (see
	// docs/engineering/AGENT_ENROLLMENT.md). Requests to the old
	// path now produce a 404, the same response any other unknown
	// route gets.
	agentAuth := mw.RequireAuthenticatedAgent(deps.EnrollmentService)
	mux.Handle("GET /agents", resolver(mw.RequireAuth(handlers.AgentsList(agentsDeps))))
	mux.HandleFunc("GET /agents/{id}", handlers.AgentsGet)
	mux.Handle("POST /agents/enroll", handlers.AgentsEnroll(agentsDeps))
	// Agent-facing endpoints (/agent/*) all sit behind the
	// bearer-credential middleware. The agent identifies itself
	// via Authorization: Bearer <agent_credential>; the path
	// carries no agent id.
	mux.Handle("GET /agent/me", agentAuth(handlers.AgentMe()))
	mux.Handle("POST /agent/heartbeat", agentAuth(handlers.AgentHeartbeat(agentsDeps)))
	// Inventory remains a 501 stub at the legacy operator-keyed
	// path; Phase 3 will introduce the agent-keyed equivalent
	// (POST /agent/inventory) wrapped behind the same middleware.
	mux.HandleFunc("POST /agents/{id}/inventory", handlers.AgentsInventory)

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

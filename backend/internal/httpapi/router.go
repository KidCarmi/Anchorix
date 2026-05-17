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
	agentInventoryDeps := handlers.AgentInventoryDeps{Service: deps.AgentInventoryService}
	agentCertificatesDeps := handlers.AgentCertificatesDeps{Service: deps.InventoryService}
	certificatesDeps := handlers.CertificatesDeps{Service: deps.InventoryService}
	findingsDeps := handlers.FindingsDeps{Service: deps.FindingsService}

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
	// POST /agent/inventory (PR-018) — agent reports its current
	// machine-inventory snapshot. Operational state sync, like
	// heartbeat: no audit row on success; one snapshot row per
	// (organization_id, agent_id) UPSERTed in place.
	mux.Handle("POST /agent/inventory", agentAuth(handlers.AgentInventorySubmit(agentInventoryDeps)))
	// POST /agent/certificates (H-015) — agent reports a batch of
	// observed certificates. Set-reconciliation per declared
	// store_coverage; private-key material rejected wholesale;
	// transactional with pg_advisory_xact_lock per agent (H-017)
	// so concurrent batches for the same agent serialize.
	mux.Handle("POST /agent/certificates", agentAuth(handlers.AgentCertificatesIngest(agentCertificatesDeps)))
	// GET /agents/{id}/inventory (PR-018) — operator read of the
	// snapshot above. Org-scoped via the session; cross-org id
	// surfaces as 404 not_found.
	mux.Handle("GET /agents/{id}/inventory",
		resolver(mw.RequireAuth(handlers.AgentInventoryGet(agentInventoryDeps))))
	// GET /agent-inventory (H-010) — operator-facing fleet-wide
	// list of current machine-inventory snapshots. Cursor-paginated,
	// org-scoped via the session, slim summary rows only (full
	// snapshot stays on the per-agent GET above). Mounted on the
	// `/agent-inventory` (no `s`) resource so it does not collide
	// with `/agents/{id}/...` path-parameter routes.
	mux.Handle("GET /agent-inventory",
		resolver(mw.RequireAuth(handlers.AgentInventoryList(agentInventoryDeps))))
	// The legacy operator-keyed POST /agents/{id}/inventory stub
	// (a placeholder from the original v0.1 schema proposal) is no
	// longer routed; certificate inventory is a separate Phase 3+
	// concern (internal/inventory) and remains unimplemented.

	// --- certificates (operator read; H-020) ---
	// Org-scoped via the authenticated operator session. Agent
	// bearer credentials are NOT honored on these routes (operator
	// and agent identity remain separate axes per CLAUDE.md §8.6).
	// Cross-org ids surface as 404 not_found — never 403 — so an
	// operator in org A cannot enumerate the presence of resources
	// in org B (CLAUDE.md §6 deterministic auth).
	mux.Handle("GET /certificates",
		resolver(mw.RequireAuth(handlers.CertificatesList(certificatesDeps))))
	mux.Handle("GET /certificates/{id}",
		resolver(mw.RequireAuth(handlers.CertificatesGet(certificatesDeps))))
	mux.Handle("GET /certificates/{id}/observations",
		resolver(mw.RequireAuth(handlers.CertificateObservationsList(certificatesDeps))))
	mux.Handle("GET /agents/{id}/certificates",
		resolver(mw.RequireAuth(handlers.AgentCertificatesList(certificatesDeps))))

	// --- findings (H-021) ---
	// Operator-only. Same auth+org-scoping posture as the
	// certificate read APIs: agent bearer rejected, cross-org
	// ids surface as 404 not_found.
	mux.Handle("POST /findings/recompute",
		resolver(mw.RequireAuth(handlers.FindingsRecompute(findingsDeps))))
	mux.Handle("GET /findings",
		resolver(mw.RequireAuth(handlers.FindingsList(findingsDeps))))
	mux.Handle("GET /findings/{id}",
		resolver(mw.RequireAuth(handlers.FindingsGet(findingsDeps))))
	// Acknowledge / suppress workflow is out of scope for H-021
	// (see CERTIFICATE_FINDINGS.md "Non-goals"); the stubs stay
	// so the route surface remains documented as future work.
	mux.HandleFunc("POST /findings/{id}/acknowledge", handlers.FindingsAcknowledge)
	mux.HandleFunc("POST /findings/{id}/suppress", handlers.FindingsSuppress)

	// --- audit ---
	mux.HandleFunc("GET /audit/events", handlers.AuditList)

	// --- providers ---
	mux.HandleFunc("GET /providers", handlers.ProvidersList)
	mux.HandleFunc("GET /providers/{id}", handlers.ProvidersGet)

	return mux
}

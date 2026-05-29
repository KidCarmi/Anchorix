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
	// H-023 acknowledge / suppress workflow. Both are
	// operator-only POSTs that mutate finding status with a
	// required reason; the audit row is severity:"security".
	mux.Handle("POST /findings/{id}/acknowledge",
		resolver(mw.RequireAuth(handlers.FindingsAcknowledge(findingsDeps))))
	mux.Handle("POST /findings/{id}/suppress",
		resolver(mw.RequireAuth(handlers.FindingsSuppress(findingsDeps))))

	// --- identity / governance vocabulary (H-026A2) ---
	// Operator-only. Routes are registered only when
	// ANCHORIX_GOVERNANCE_API_ENABLED is true and the
	// IdentityService dependency is wired. When the feature
	// gate is off, every path below returns 404 (the routes
	// are not present in the mux).
	//
	// Agent bearer credentials are NOT honored on these
	// routes — the resolver attaches an operator session
	// only, and RequireAuth gates anonymous traffic.
	if deps.IdentityService != nil {
		identityDeps := handlers.IdentityDeps{Service: deps.IdentityService}

		// tags
		mux.Handle("GET /tags", resolver(mw.RequireAuth(handlers.TagsList(identityDeps))))
		mux.Handle("POST /tags", resolver(mw.RequireAuth(handlers.TagsCreate(identityDeps))))
		mux.Handle("GET /tags/{id}", resolver(mw.RequireAuth(handlers.TagsGet(identityDeps))))
		mux.Handle("PATCH /tags/{id}", resolver(mw.RequireAuth(handlers.TagsUpdate(identityDeps))))
		mux.Handle("POST /tags/{id}/disable", resolver(mw.RequireAuth(handlers.TagsDisable(identityDeps))))
		mux.Handle("POST /tags/{id}/enable", resolver(mw.RequireAuth(handlers.TagsEnable(identityDeps))))
		mux.Handle("GET /tags/{id}/assignments", resolver(mw.RequireAuth(handlers.TagAssignmentsList(identityDeps))))
		mux.Handle("POST /tags/{id}/assignments", resolver(mw.RequireAuth(handlers.TagAssignmentsCreate(identityDeps))))
		mux.Handle("DELETE /tags/{id}/assignments", resolver(mw.RequireAuth(handlers.TagAssignmentsDelete(identityDeps))))

		// services
		mux.Handle("GET /services", resolver(mw.RequireAuth(handlers.ServicesList(identityDeps))))
		mux.Handle("POST /services", resolver(mw.RequireAuth(handlers.ServicesCreate(identityDeps))))
		mux.Handle("GET /services/{id}", resolver(mw.RequireAuth(handlers.ServicesGet(identityDeps))))
		mux.Handle("PATCH /services/{id}", resolver(mw.RequireAuth(handlers.ServicesUpdate(identityDeps))))
		mux.Handle("POST /services/{id}/disable", resolver(mw.RequireAuth(handlers.ServicesDisable(identityDeps))))
		mux.Handle("POST /services/{id}/enable", resolver(mw.RequireAuth(handlers.ServicesEnable(identityDeps))))
		mux.Handle("POST /services/{id}/group", resolver(mw.RequireAuth(handlers.ServicesSetGroup(identityDeps))))
		mux.Handle("DELETE /services/{id}/group", resolver(mw.RequireAuth(handlers.ServicesClearGroup(identityDeps))))

		// service groups
		mux.Handle("GET /service-groups", resolver(mw.RequireAuth(handlers.ServiceGroupsList(identityDeps))))
		mux.Handle("POST /service-groups", resolver(mw.RequireAuth(handlers.ServiceGroupsCreate(identityDeps))))
		mux.Handle("GET /service-groups/{id}", resolver(mw.RequireAuth(handlers.ServiceGroupsGet(identityDeps))))
		mux.Handle("POST /service-groups/{id}/parent", resolver(mw.RequireAuth(handlers.ServiceGroupsSetParent(identityDeps))))
		mux.Handle("POST /service-groups/{id}/disable", resolver(mw.RequireAuth(handlers.ServiceGroupsDisable(identityDeps))))

		// agent groups
		mux.Handle("GET /agent-groups", resolver(mw.RequireAuth(handlers.AgentGroupsList(identityDeps))))
		mux.Handle("POST /agent-groups", resolver(mw.RequireAuth(handlers.AgentGroupsCreate(identityDeps))))
		mux.Handle("GET /agent-groups/{id}", resolver(mw.RequireAuth(handlers.AgentGroupsGet(identityDeps))))
		mux.Handle("POST /agent-groups/{id}/disable", resolver(mw.RequireAuth(handlers.AgentGroupsDisable(identityDeps))))
		mux.Handle("GET /agent-groups/{id}/members", resolver(mw.RequireAuth(handlers.AgentGroupsListMembers(identityDeps))))
		mux.Handle("POST /agent-groups/{id}/members", resolver(mw.RequireAuth(handlers.AgentGroupsAddMember(identityDeps))))
		mux.Handle("DELETE /agent-groups/{id}/members", resolver(mw.RequireAuth(handlers.AgentGroupsRemoveMember(identityDeps))))

		// agents-side inverse view of group memberships
		mux.Handle("GET /agents/{id}/groups", resolver(mw.RequireAuth(handlers.AgentsListGroups(identityDeps))))
	}

	// --- ownership engine (H-026B3A) ---
	// Operator-only visibility + recompute trigger. Routes are
	// registered only when ANCHORIX_GOVERNANCE_API_ENABLED is true
	// and the OwnershipService dependency is wired. When the
	// feature gate is off, every path below returns 404. Cross-org
	// ids surface as 404 not_found (CLAUDE.md §6 deterministic
	// auth) — never 403, so the existence of a foreign-org cert /
	// rule cannot be enumerated.
	if deps.OwnershipService != nil {
		ownershipDeps := handlers.OwnershipDeps{
			Service:    deps.OwnershipService,
			StaleAfter: deps.OwnershipStaleAfter,
		}
		mux.Handle("POST /ownership/recompute", resolver(mw.RequireAuth(handlers.OwnershipRecompute(ownershipDeps))))
		mux.Handle("GET /ownership/unowned", resolver(mw.RequireAuth(handlers.OwnershipUnowned(ownershipDeps))))
		mux.Handle("GET /ownership/ambiguous", resolver(mw.RequireAuth(handlers.OwnershipAmbiguous(ownershipDeps))))
		mux.Handle("GET /ownership/stale", resolver(mw.RequireAuth(handlers.OwnershipStale(ownershipDeps))))
		mux.Handle("GET /certificates/{id}/ownership", resolver(mw.RequireAuth(handlers.CertificateOwnershipGet(ownershipDeps))))
		mux.Handle("GET /certificates/{id}/ownership/explanation", resolver(mw.RequireAuth(handlers.CertificateOwnershipExplanation(ownershipDeps))))
		mux.Handle("GET /certificates/{id}/ownership/override", resolver(mw.RequireAuth(handlers.CertificateOwnershipOverrideGet(ownershipDeps))))
		// H-026B3B override mutations. Operator-only; agent bearer not
		// honored. Create/clear write a severity:"security" audit row +
		// re-derive the single target certificate in the same tx under
		// the ownership advisory lock.
		mux.Handle("POST /certificates/{id}/ownership/override", resolver(mw.RequireAuth(handlers.CertificateOwnershipOverrideCreate(ownershipDeps))))
		mux.Handle("DELETE /certificates/{id}/ownership/override", resolver(mw.RequireAuth(handlers.CertificateOwnershipOverrideClear(ownershipDeps))))
		mux.Handle("GET /ownership-rules", resolver(mw.RequireAuth(handlers.OwnershipRulesList(ownershipDeps))))
		mux.Handle("GET /ownership-rules/{id}", resolver(mw.RequireAuth(handlers.OwnershipRulesGet(ownershipDeps))))
		mux.Handle("GET /governance/recompute-runs", resolver(mw.RequireAuth(handlers.GovernanceRecomputeRunsList(ownershipDeps))))
		// H-026B3B rule mutations. Operator-only; agent bearer not
		// honored. Every mutation writes a severity:"security" audit
		// row in the same tx as the state change.
		mux.Handle("POST /ownership-rules", resolver(mw.RequireAuth(handlers.OwnershipRulesCreate(ownershipDeps))))
		mux.Handle("PATCH /ownership-rules/{id}", resolver(mw.RequireAuth(handlers.OwnershipRulesUpdate(ownershipDeps))))
		mux.Handle("POST /ownership-rules/{id}/enable", resolver(mw.RequireAuth(handlers.OwnershipRulesEnable(ownershipDeps))))
		mux.Handle("POST /ownership-rules/{id}/disable", resolver(mw.RequireAuth(handlers.OwnershipRulesDisable(ownershipDeps))))
	}

	// --- audit ---
	mux.HandleFunc("GET /audit/events", handlers.AuditList)

	// --- providers ---
	mux.HandleFunc("GET /providers", handlers.ProvidersList)
	mux.HandleFunc("GET /providers/{id}", handlers.ProvidersGet)

	return mux
}

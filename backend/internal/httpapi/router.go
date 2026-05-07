package httpapi

import (
	"net/http"

	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/handlers"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// newRouter assembles the API surface. Routes are grouped by resource and
// kept stable under /api/v1; breaking changes require /api/v2.
func newRouter(cfg *config.Config, log *logger.Logger, readiness *Readiness) http.Handler {
	mux := http.NewServeMux()

	// Health endpoints sit outside /api/v1 — they are infrastructure, not
	// part of the public REST surface. They must remain unauthenticated.
	//
	// /healthz is a process-only liveness probe and never depends on
	// external resources. /readyz is dependency-aware and fails closed
	// if any registered probe is unhealthy.
	mux.HandleFunc("GET /healthz", handlers.Health)
	mux.Handle("GET /readyz", readiness.handler())

	// /api/v1 — versioned, authenticated REST surface.
	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", apiV1Router()))

	return chain(
		mux,
		recoverMiddleware(log),
		requestIDMiddleware(),
		loggingMiddleware(log),
		securityHeadersMiddleware(cfg),
	)
}

func apiV1Router() http.Handler {
	mux := http.NewServeMux()

	// --- auth ---
	mux.HandleFunc("POST /auth/login", handlers.AuthLogin)
	mux.HandleFunc("POST /auth/logout", handlers.AuthLogout)
	mux.HandleFunc("GET /auth/me", handlers.AuthMe)

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

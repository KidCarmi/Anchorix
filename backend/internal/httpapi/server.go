// Package httpapi exposes the REST API over HTTP.
//
// httpapi is the only package allowed to import net/http handlers; domain
// modules expose plain Go interfaces that handlers translate into HTTP
// requests/responses (CLAUDE.md §5).
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/agentinventory"
	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/enrollment"
	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// Dependencies bundles the runtime dependencies the HTTP layer needs.
// The composition root in cmd/anchorix constructs one of these and
// passes it to NewServer (CLAUDE.md §8.8 constructor DI).
type Dependencies struct {
	AuthService           *auth.Service
	CookieSigner          *auth.SignedCookie
	EnrollmentService     *enrollment.Service
	AgentInventoryService *agentinventory.Service
	InventoryService      *inventory.Service
	FindingsService       *findings.Service

	// IdentityService is the H-026A2 trust-governance vocabulary
	// service (tags, services, service groups, agent groups,
	// memberships). May be nil when ANCHORIX_GOVERNANCE_API_ENABLED
	// is false — in that case the router skips registering the
	// identity routes and they return 404.
	IdentityService *identity.Service

	// OwnershipService is the H-026B3A ownership engine surface
	// (recompute trigger + operator visibility views). May be nil
	// when ANCHORIX_GOVERNANCE_API_ENABLED is false — in that case
	// the router does not register any ownership routes.
	OwnershipService *ownership.Service

	// OwnershipStaleAfter is the threshold used by
	// `GET /ownership/stale` when no `?older_than=` override is
	// supplied. Comes from ANCHORIX_OWNERSHIP_STALE_THRESHOLD.
	OwnershipStaleAfter time.Duration
}

// Server owns the HTTP listener and graceful shutdown lifecycle.
type Server struct {
	cfg       *config.Config
	log       *logger.Logger
	deps      Dependencies
	srv       *http.Server
	readiness *Readiness
}

// NewServer wires the router and middleware. It does not start listening.
//
// Callers (the composition root) may register readiness probes on the
// returned server's Readiness() before invoking Run, so that probes
// reflecting real runtime dependencies (e.g. a database ping) are in
// place from the first request /readyz serves.
func NewServer(cfg *config.Config, log *logger.Logger, deps Dependencies) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	if log == nil {
		return nil, errors.New("nil logger")
	}
	if deps.AuthService == nil || deps.CookieSigner == nil || deps.EnrollmentService == nil || deps.AgentInventoryService == nil || deps.InventoryService == nil || deps.FindingsService == nil {
		return nil, errors.New("httpapi: incomplete Dependencies (AuthService + CookieSigner + EnrollmentService + AgentInventoryService + InventoryService + FindingsService required)")
	}
	// IdentityService is OPTIONAL — controlled by the H-026A2
	// ANCHORIX_GOVERNANCE_API_ENABLED feature gate. When nil,
	// the router skips registering the identity routes.
	readiness := NewReadiness()
	router := newRouter(cfg, log, readiness, deps)
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return &Server{cfg: cfg, log: log, deps: deps, srv: srv, readiness: readiness}, nil
}

// Readiness exposes the server's probe registry so the composition root
// can register dependency probes before Run is called.
func (s *Server) Readiness() *Readiness { return s.readiness }

// Handler returns the assembled HTTP handler. Used by integration
// tests that drive the server via httptest without binding a port.
// Not part of any production code path.
func (s *Server) Handler() http.Handler { return s.srv.Handler }

// Run starts listening and blocks until the context is cancelled.
// On cancellation it performs a graceful shutdown with a fixed timeout.
func (s *Server) Run(ctx context.Context) error {
	errs := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("listen: %w", err)
			return
		}
		errs <- nil
	}()

	select {
	case <-ctx.Done():
		s.log.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-errs:
		return err
	}
}

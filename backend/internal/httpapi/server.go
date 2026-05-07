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

	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// Server owns the HTTP listener and graceful shutdown lifecycle.
type Server struct {
	cfg       *config.Config
	log       *logger.Logger
	srv       *http.Server
	readiness *Readiness
}

// NewServer wires the router and middleware. It does not start listening.
//
// Callers (the composition root) may register readiness probes on the
// returned server's Readiness() before invoking Run, so that probes
// reflecting real runtime dependencies (e.g. a database ping) are in
// place from the first request /readyz serves.
func NewServer(cfg *config.Config, log *logger.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	if log == nil {
		return nil, errors.New("nil logger")
	}
	readiness := NewReadiness()
	router := newRouter(cfg, log, readiness)
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return &Server{cfg: cfg, log: log, srv: srv, readiness: readiness}, nil
}

// Readiness exposes the server's probe registry so the composition root
// can register dependency probes before Run is called.
func (s *Server) Readiness() *Readiness { return s.readiness }

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

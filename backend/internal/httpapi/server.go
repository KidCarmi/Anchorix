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
	cfg *config.Config
	log *logger.Logger
	srv *http.Server
}

// NewServer wires the router and middleware. It does not start listening.
func NewServer(cfg *config.Config, log *logger.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	if log == nil {
		return nil, errors.New("nil logger")
	}
	router := newRouter(cfg, log)
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return &Server{cfg: cfg, log: log, srv: srv}, nil
}

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

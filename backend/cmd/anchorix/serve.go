package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// cmdServe starts the control plane: opens the DB pool, verifies the
// schema, wires the auth domain, registers the postgres readiness
// probe, and runs the HTTP server with graceful shutdown.
//
// CLAUDE.md §8.7: this composition root contains no business logic —
// just dependency wiring. CLAUDE.md §8.8: every dependency is
// constructor-injected; no globals.
func cmdServe(ctx context.Context, cfg *config.Config, log *logger.Logger) error {
	if cfg.TLSTermination == config.TLSDisabledDev {
		log.Warn("starting with TLS disabled (development only)",
			"hint", "set ANCHORIX_TLS_TERMINATION=process or reverse_proxy in production")
	}

	// Storage layer.
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer db.Close()

	// CLAUDE.md §16: no auto-mutate at runtime. We require the schema
	// to already be at the expected version; the operator runs
	// `anchorix migrate up` to advance it.
	migrations, err := postgres.LoadEmbeddedMigrations()
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	if err := db.EnsureSchema(ctx, migrations); err != nil {
		return fmt.Errorf("schema check: %w", err)
	}

	// Domain wiring.
	usersRepo := postgres.NewAuthRepository(db)
	sessionsRepo := postgres.NewSessionsRepository(db)
	auditRecorder := postgres.NewAuditRecorder(db, clock.System{})

	passwd, err := auth.NewPasswordPolicy(cfg.BcryptCost)
	if err != nil {
		return fmt.Errorf("password policy: %w", err)
	}
	sessPol, err := auth.NewSessionPolicy(cfg.SessionIdleLifetime, cfg.SessionAbsoluteLifetime)
	if err != nil {
		return fmt.Errorf("session policy: %w", err)
	}
	signer, err := auth.NewSignedCookie(cfg.SessionKey)
	if err != nil {
		return fmt.Errorf("signed cookie: %w", err)
	}
	authService, err := auth.NewService(usersRepo, sessionsRepo, auditRecorder, db, passwd, sessPol, clock.System{})
	if err != nil {
		return fmt.Errorf("auth service: %w", err)
	}

	// HTTP layer.
	srv, err := httpapi.NewServer(cfg, log, httpapi.Dependencies{
		AuthService:  authService,
		CookieSigner: signer,
	})
	if err != nil {
		return fmt.Errorf("init server: %w", err)
	}
	// Real DB readiness — /readyz now fails closed when postgres is
	// unreachable (CLAUDE.md §18).
	srv.Readiness().Register("postgres", db.Ping)

	log.Info("starting control plane",
		"addr", cfg.HTTPAddr,
		"env", cfg.Env,
		"tls_termination", cfg.TLSTermination,
	)
	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("serve: %w", err)
	}
	log.Info("shutdown complete")
	return nil
}

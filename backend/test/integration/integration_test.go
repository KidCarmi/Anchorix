//go:build integration

// Package integration holds tests that require a real PostgreSQL.
// CI runs them via the postgres service container in
// .github/workflows/ci.yml; locally:
//
//	go test -tags integration ./test/integration/...
//
// The default `go test ./...` skips this package thanks to the
// build tag, so the inner-loop unit run stays network-free.
package integration

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// testDB opens a pool against DATABASE_URL. Skips the test if the
// env var isn't set (so the package compiles on dev machines without
// postgres but doesn't accidentally pass).
func testDB(t *testing.T) *postgres.DB {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := postgres.Open(ctx, url)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// freshDatabase runs `migrate up` and truncates the domain tables so
// each test starts from a known state. Migrations are idempotent
// (CLAUDE.md §16) so this is safe to call from many tests in the
// same process.
func freshDatabase(t *testing.T, db *postgres.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	migrations, err := postgres.LoadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("LoadEmbeddedMigrations: %v", err)
	}
	if _, err := db.MigrateUp(ctx, migrations); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	err = db.WithTx(ctx, func(tx pgx.Tx) error {
		stmts := []string{
			"DELETE FROM sessions",
			"DELETE FROM agent_enrollment_tokens",
			"DELETE FROM audit_events",
			"DELETE FROM users",
			"DELETE FROM organizations",
			`INSERT INTO organizations (id, name) VALUES ('anchorix', 'Anchorix')`,
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// testServer wires the same dependencies as cmd/anchorix serve but
// against httptest, so handler tests can hit the real router without
// binding a TCP port. Returns the server (Close on cleanup) and the
// auth service for tests that exercise the domain directly.
func testServer(t *testing.T, db *postgres.DB) (*httptest.Server, *auth.Service) {
	t.Helper()
	cfg := testConfig(t)
	log := logger.New("error", config.EnvDevelopment)

	usersRepo := postgres.NewAuthRepository(db)
	sessionsRepo := postgres.NewSessionsRepository(db)
	auditRecorder := postgres.NewAuditRecorder(db, clock.System{})

	passwd, err := auth.NewPasswordPolicy(cfg.BcryptCost)
	if err != nil {
		t.Fatalf("password policy: %v", err)
	}
	sessPol, err := auth.NewSessionPolicy(cfg.SessionIdleLifetime, cfg.SessionAbsoluteLifetime)
	if err != nil {
		t.Fatalf("session policy: %v", err)
	}
	signer, err := auth.NewSignedCookie(cfg.SessionKey)
	if err != nil {
		t.Fatalf("signed cookie: %v", err)
	}
	svc := auth.NewService(usersRepo, sessionsRepo, auditRecorder, passwd, sessPol, clock.System{})

	srv, err := httpapi.NewServer(cfg, log, httpapi.Dependencies{
		AuthService:  svc,
		CookieSigner: signer,
	})
	if err != nil {
		t.Fatalf("httpapi.NewServer: %v", err)
	}
	srv.Readiness().Register("postgres", db.Ping)

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, svc
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Env:                     config.EnvDevelopment,
		LogLevel:                "error",
		HTTPAddr:                "127.0.0.1:0",
		PublicBaseURL:           "http://localhost:0",
		SessionKey:              []byte(strings.Repeat("k", 32)),
		SessionCookieName:       "anchorix_session",
		SessionIdleLifetime:     8 * time.Hour,
		SessionAbsoluteLifetime: 24 * time.Hour,
		BcryptCost:              10, // cheapest for speed
		TLSTermination:          config.TLSDisabledDev,
		DatabaseURL:             os.Getenv("DATABASE_URL"),
	}
}

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
	"crypto/rand"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/agentinventory"
	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/enrollment"
	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
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
	err = db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		stmts := []string{
			"DELETE FROM sessions",
			"DELETE FROM agent_enrollment_tokens",
			// certificate_observations cascades off both agents
			// (composite FK on org+agent_id ON DELETE CASCADE) and
			// certificates (composite FK on org+certificate_id ON
			// DELETE CASCADE) per migration 0005, so the explicit
			// DELETE is belt-and-braces. The composite FK on the
			// org column is RESTRICT, so we MUST clear observations
			// and certificates before organizations regardless.
			// findings has composite FK to certificates with
			// ON DELETE CASCADE; deleting findings first is
			// belt-and-braces against a partial-cascade bug.
			"DELETE FROM findings",
			// H-026A1 governance tables (migrations 0009/0010/0011).
			// Order matters: derived-state tables before their
			// reference targets, partial-unique-protected tables in
			// their natural dependency order. The composite FKs are
			// mostly ON DELETE RESTRICT, so the explicit per-table
			// DELETEs are required to bring an org back to a clean
			// state between integration runs.
			"DELETE FROM governance_recompute_runs",
			"DELETE FROM policy_waivers",
			"DELETE FROM policy_assignments",
			"DELETE FROM policy_definitions",
			"DELETE FROM certificate_ownership",
			"DELETE FROM ownership_match_explanations",
			"DELETE FROM certificate_ownership_overrides",
			"DELETE FROM ownership_rules",
			"DELETE FROM agent_group_memberships",
			"DELETE FROM agent_groups",
			"DELETE FROM service_group_memberships",
			"DELETE FROM tag_assignments",
			"DELETE FROM tags",
			"DELETE FROM services",
			// service_groups has a self-referencing FK
			// (parent_id) with ON DELETE RESTRICT. Within a
			// single multi-row DELETE FROM the row-deletion
			// order is undefined, so a parent row can be
			// processed before its children — RESTRICT fires
			// and the whole statement aborts. NULLing out
			// parent_id first guarantees no row references
			// another at delete-time. The two-statement
			// approach is safe regardless of PG's heap-scan
			// order. (Switching parent_id to ON DELETE CASCADE
			// would silently orphan operator-curated
			// hierarchies on accidental service-group delete,
			// which is exactly what RESTRICT exists to
			// prevent — the cleanup pays this small cost
			// instead.)
			"UPDATE service_groups SET parent_id = NULL",
			"DELETE FROM service_groups",
			"DELETE FROM certificate_observations",
			"DELETE FROM certificates",
			// agents must go before deployment_packages because of the
			// FK from agents.deployment_package_id (added in 0002).
			"DELETE FROM agents",
			"DELETE FROM deployment_packages",
			// audit_events has BEFORE UPDATE/DELETE FOR EACH ROW
			// triggers that enforce the §9 / §16 append-only invariant
			// in production. TRUNCATE does not fire those row-level
			// triggers, so it is the only safe way to reset audit
			// rows between tests without weakening the production
			// guarantee or granting tests trigger-bypass privileges.
			"TRUNCATE TABLE audit_events",
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
//
// Delegates to testServerWithOptions with the identity service
// enabled — the common case for integration tests.
func testServer(t *testing.T, db *postgres.DB) (*httptest.Server, *auth.Service) {
	return testServerWithOptions(t, db, testServerOpts{IdentityEnabled: true})
}

// testServerOpts toggles dependency wiring at construction
// time. Today's only knob is IdentityEnabled, which mirrors
// the production ANCHORIX_GOVERNANCE_API_ENABLED feature gate:
// when false, the identity service is NOT constructed and the
// router skips registering the H-026A2 routes. Used by the
// feature-gate regression test (TestFeatureGateOffReturns404).
type testServerOpts struct {
	IdentityEnabled bool
}

// testServerWithOptions is the parameterized variant of
// testServer. Tests that need a non-default dependency set
// (the feature-gate-off test, future opt-in features) call
// this directly; everything else goes through testServer.
func testServerWithOptions(t *testing.T, db *postgres.DB, opts testServerOpts) (*httptest.Server, *auth.Service) {
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
	svc, err := auth.NewService(usersRepo, sessionsRepo, auditRecorder, db, passwd, sessPol, clock.System{})
	if err != nil {
		t.Fatalf("auth.NewService: %v", err)
	}

	deploymentRepo := postgres.NewDeploymentPackageRepository(db)
	agentsRepo := postgres.NewAgentRepository(db)
	enrollSvc, err := enrollment.NewService(
		deploymentRepo, agentsRepo, auditRecorder, db, clock.System{}, rand.Reader,
	)
	if err != nil {
		t.Fatalf("enrollment.NewService: %v", err)
	}

	inventoryRepo := postgres.NewAgentInventorySnapshotRepository(db)
	inventorySvc, err := agentinventory.NewService(inventoryRepo, clock.System{})
	if err != nil {
		t.Fatalf("agentinventory.NewService: %v", err)
	}

	certRepo := postgres.NewCertificateInventoryRepository(db)
	certSvc, err := inventory.NewService(certRepo, db, auditRecorder, clock.System{})
	if err != nil {
		t.Fatalf("inventory.NewService: %v", err)
	}

	findingsRepo := postgres.NewFindingsRepository(db)
	findingsSvc, err := findings.NewService(
		findingsRepo, certRepo, db, auditRecorder, clock.System{}, findings.DefaultRules(),
	)
	if err != nil {
		t.Fatalf("findings.NewService: %v", err)
	}

	// H-026A2 identity service. Wired when opts.IdentityEnabled
	// is true. The production composition root gates this on
	// ANCHORIX_GOVERNANCE_API_ENABLED; setting IdentityEnabled
	// to false from a test mirrors the gate-off behavior so the
	// route-not-registered path can be exercised.
	var identitySvc *identity.Service
	if opts.IdentityEnabled {
		identityRepo := postgres.NewIdentityRepository(db)
		targetResolver := postgres.NewIdentityTargetResolver(db)
		identitySvc, err = identity.NewService(
			identityRepo, db, auditRecorder, targetResolver, clock.System{},
		)
		if err != nil {
			t.Fatalf("identity.NewService: %v", err)
		}
	}

	srv, err := httpapi.NewServer(cfg, log, httpapi.Dependencies{
		AuthService:           svc,
		CookieSigner:          signer,
		EnrollmentService:     enrollSvc,
		AgentInventoryService: inventorySvc,
		InventoryService:      certSvc,
		FindingsService:       findingsSvc,
		IdentityService:       identitySvc,
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

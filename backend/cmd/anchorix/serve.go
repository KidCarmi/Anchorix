package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/kidcarmi/anchorix/backend/internal/agentinventory"
	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/enrollment"
	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
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

	deploymentPackagesRepo := postgres.NewDeploymentPackageRepository(db)
	agentsRepo := postgres.NewAgentRepository(db)
	enrollmentService, err := enrollment.NewService(
		deploymentPackagesRepo, agentsRepo, auditRecorder, db, clock.System{}, rand.Reader,
	)
	if err != nil {
		return fmt.Errorf("enrollment service: %w", err)
	}

	agentInventoryRepo := postgres.NewAgentInventorySnapshotRepository(db)
	agentInventoryService, err := agentinventory.NewService(agentInventoryRepo, clock.System{})
	if err != nil {
		return fmt.Errorf("agent inventory service: %w", err)
	}

	certInventoryRepo := postgres.NewCertificateInventoryRepository(db)
	inventoryService, err := inventory.NewService(certInventoryRepo, db, auditRecorder, clock.System{})
	if err != nil {
		return fmt.Errorf("inventory service: %w", err)
	}

	findingsRepo := postgres.NewFindingsRepository(db)
	findingsService, err := findings.NewService(
		findingsRepo, certInventoryRepo, db, auditRecorder, clock.System{}, findings.DefaultRules(),
	)
	if err != nil {
		return fmt.Errorf("findings service: %w", err)
	}

	// H-022: background recompute scheduler. Owns a single
	// long-running goroutine started below; ctx cancellation
	// stops the loop. The scheduler is constructed even when
	// disabled (Run becomes a no-op) so the wiring is stable.
	organizationsRepo := postgres.NewOrganizationsRepository(db)
	findingsScheduler, err := findings.NewScheduler(
		findingsService,
		organizationsRepo,
		log,
		clock.System{},
		findings.SchedulerConfig{
			Enabled:  cfg.FindingsSchedulerEnabled,
			Interval: cfg.FindingsSchedulerInterval,
		},
	)
	if err != nil {
		return fmt.Errorf("findings scheduler: %w", err)
	}

	// H-026A2: identity/governance vocabulary service. Wired
	// only when ANCHORIX_GOVERNANCE_API_ENABLED is true so the
	// feature gate is a true off-switch — routes are not
	// registered when disabled.
	var identityService *identity.Service
	if cfg.GovernanceAPIEnabled {
		identityRepo := postgres.NewIdentityRepository(db)
		targetResolver := postgres.NewIdentityTargetResolver(db)
		identityService, err = identity.NewService(
			identityRepo, db, auditRecorder, targetResolver, clock.System{},
		)
		if err != nil {
			return fmt.Errorf("identity service: %w", err)
		}
	}

	// H-026A3: governance repository aggregate. The H-026B
	// ownership engine and the H-026D policy engine each take
	// one *governance.Repo argument instead of three separate
	// interfaces, so the engine constructors slot in here
	// without re-shaping the composition root. Constructed
	// unconditionally because the engines haven't landed yet
	// (the value is intentionally unused for the duration of
	// this PR — the `_ = governanceRepo` suppresses the
	// "declared and not used" check). The first engine PR
	// (H-026B) drops the suppression and passes the aggregate
	// to ownership.NewService.
	//
	// Validating the aggregate at construction means a future
	// partially-wired Repo fails closed at startup rather than
	// on the first recompute.
	//
	// Construction here is inert: the three postgres.NewXxx
	// constructors only stash the *DB pointer — no queries, no
	// goroutines — so building the aggregate unconditionally
	// (outside the GovernanceAPIEnabled gate above) has zero
	// runtime cost and starts nothing. H-026B MUST gate the
	// engine + scheduler it constructs from this aggregate
	// behind a feature flag (GovernanceAPIEnabled or a
	// dedicated ANCHORIX_OWNERSHIP_ENGINE_ENABLED) so a
	// governance-disabled deployment does not spin up a
	// recompute loop. Do NOT wire the scheduler immediately
	// after this block without that gate.
	governanceRepo := &governance.Repo{
		Ownership:     postgres.NewOwnershipRepository(db),
		Policy:        postgres.NewPolicyRepository(db),
		RecomputeRuns: postgres.NewGovernanceRecomputeRunsRepository(db),
	}
	if err := governanceRepo.Validate(); err != nil {
		return fmt.Errorf("governance repo: %w", err)
	}

	// H-026B3A: ownership engine. Constructed only when
	// ANCHORIX_GOVERNANCE_API_ENABLED is true so the feature gate
	// is a true off-switch — when disabled, ownershipService is
	// nil and the router does not register any /ownership/*,
	// /certificates/{id}/ownership/*, /ownership-rules, or
	// /governance/recompute-runs routes. The scheduler is NOT
	// constructed here (B4 work).
	var ownershipService *ownership.Service
	if cfg.GovernanceAPIEnabled {
		ruleTargetResolver := postgres.NewOwnershipRuleTargetResolver(db)
		ownershipService, err = ownership.NewService(
			governanceRepo, db, auditRecorder, clock.System{}, ruleTargetResolver,
			ownership.ServiceConfig{BulkAuditThreshold: cfg.OwnershipBulkAuditThreshold},
		)
		if err != nil {
			return fmt.Errorf("ownership service: %w", err)
		}
	}

	// HTTP layer.
	srv, err := httpapi.NewServer(cfg, log, httpapi.Dependencies{
		AuthService:           authService,
		CookieSigner:          signer,
		EnrollmentService:     enrollmentService,
		AgentInventoryService: agentInventoryService,
		InventoryService:      inventoryService,
		FindingsService:       findingsService,
		IdentityService:       identityService,
		OwnershipService:      ownershipService,
		OwnershipStaleAfter:   cfg.OwnershipStaleThreshold,
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

	// Start the H-022 findings scheduler. Runs in a goroutine
	// owned by this composition root; ctx cancellation
	// propagates to its loop and any in-flight recompute (the
	// DB transaction sees ctx done and rolls back). The
	// scheduler's Run returns nil on graceful shutdown.
	schedDone := make(chan struct{})
	go func() {
		defer close(schedDone)
		if err := findingsScheduler.Run(ctx); err != nil {
			log.Error("findings scheduler exited with error", "err", err.Error())
		}
	}()

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("serve: %w", err)
	}
	// Wait for the scheduler goroutine to drain before
	// returning so the deferred db.Close() doesn't race a
	// recompute tx still mid-rollback.
	<-schedDone
	log.Info("shutdown complete")
	return nil
}

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// cmdAdmin dispatches `anchorix admin <subcommand>`. There is NO
// default admin account and NO default password; the first operator
// must be created explicitly via this command (CLAUDE.md §6.5).
func cmdAdmin(ctx context.Context, cfg *config.Config, log *logger.Logger, rest []string) error {
	if len(rest) == 0 {
		return errors.New("usage: anchorix admin create --email <email> --password <pw> [--display-name <name>] [--organization <id>]")
	}
	switch rest[0] {
	case "create":
		return cmdAdminCreate(ctx, cfg, log, rest[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", rest[0])
	}
}

// cmdAdminCreate creates a single operator account. The password
// MUST be supplied by the caller — there is no auto-generate path.
// Operators are expected to use a secure shell pattern such as
//
//	read -srp 'Password: ' PW && \
//	  anchorix admin create --email ops@example.com --password "$PW" && \
//	  unset PW
//
// or
//
//	anchorix admin create --email ops@example.com --password "$(openssl rand -base64 24)"
//
// We deliberately do not print the password to stdout under any
// circumstance: CLAUDE.md §6.9 forbids secret values in logs and
// makes the same prohibition apply to the bootstrap path.
func cmdAdminCreate(ctx context.Context, cfg *config.Config, log *logger.Logger, args []string) error {
	fs := flag.NewFlagSet("admin create", flag.ContinueOnError)
	email := fs.String("email", "", "operator email (required)")
	displayName := fs.String("display-name", "", "display name (defaults to email local part)")
	password := fs.String("password", "", "password (required; supply via stdin/shell so it does not appear in shell history)")
	orgID := fs.String("organization", "anchorix", "organization id (default: anchorix)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*email = strings.TrimSpace(strings.ToLower(*email))
	if *email == "" {
		return errors.New("admin create: --email is required")
	}
	if *password == "" {
		return errors.New("admin create: --password is required (no default, no auto-generate; see docs/BOOTSTRAP.md)")
	}
	if *displayName == "" {
		if at := strings.IndexByte(*email, '@'); at > 0 {
			*displayName = (*email)[:at]
		} else {
			*displayName = *email
		}
	}

	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("admin create: open postgres: %w", err)
	}
	defer db.Close()

	usersRepo := postgres.NewAuthRepository(db)
	sessionsRepo := postgres.NewSessionsRepository(db)
	auditRecorder := postgres.NewAuditRecorder(db, clock.System{})

	passwd, err := auth.NewPasswordPolicy(cfg.BcryptCost)
	if err != nil {
		return fmt.Errorf("admin create: password policy: %w", err)
	}
	sessPol, err := auth.NewSessionPolicy(cfg.SessionIdleLifetime, cfg.SessionAbsoluteLifetime)
	if err != nil {
		return fmt.Errorf("admin create: session policy: %w", err)
	}
	svc := auth.NewService(usersRepo, sessionsRepo, auditRecorder, passwd, sessPol, clock.System{})

	// Bootstrap: provision the organization row before creating the
	// user. The users.organization_id foreign key requires it, and a
	// pristine DB has no organizations seeded (CLAUDE.md §16 — no
	// runtime auto-mutate, so we ensure it explicitly here). Idempotent.
	if err := usersRepo.EnsureOrganization(ctx, *orgID, *orgID); err != nil {
		return fmt.Errorf("admin create: %w", err)
	}

	user, err := svc.CreateUser(ctx, *orgID, *email, *displayName, *password, auth.RoleAdmin)
	if err != nil {
		return fmt.Errorf("admin create: %w", err)
	}

	log.Info("admin created", "user_id", user.ID, "email", user.Email)
	fmt.Printf("created admin user %s (id=%s)\n", user.Email, user.ID)
	return nil
}

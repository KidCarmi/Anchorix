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
		return errors.New("usage: anchorix admin create --email <email> [--display-name <name>] [--password <pw>]")
	}
	switch rest[0] {
	case "create":
		return cmdAdminCreate(ctx, cfg, log, rest[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", rest[0])
	}
}

func cmdAdminCreate(ctx context.Context, cfg *config.Config, log *logger.Logger, args []string) error {
	fs := flag.NewFlagSet("admin create", flag.ContinueOnError)
	email := fs.String("email", "", "operator email (required)")
	displayName := fs.String("display-name", "", "display name (defaults to email local part)")
	password := fs.String("password", "", "password (if omitted, a strong random password is generated and printed once)")
	orgID := fs.String("organization", "anchorix", "organization id (default: anchorix)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*email = strings.TrimSpace(strings.ToLower(*email))
	if *email == "" {
		return errors.New("admin create: --email is required")
	}
	if *displayName == "" {
		if at := strings.IndexByte(*email, '@'); at > 0 {
			*displayName = (*email)[:at]
		} else {
			*displayName = *email
		}
	}

	plaintext := *password
	generated := false
	if plaintext == "" {
		pw, err := auth.GenerateRandomPassword(24)
		if err != nil {
			return fmt.Errorf("admin create: generate password: %w", err)
		}
		plaintext = pw
		generated = true
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

	user, err := svc.CreateUser(ctx, *orgID, *email, *displayName, plaintext, auth.RoleAdmin)
	if err != nil {
		return fmt.Errorf("admin create: %w", err)
	}

	log.Info("admin created", "user_id", user.ID, "email", user.Email)
	fmt.Printf("created admin user %s (id=%s)\n", user.Email, user.ID)
	if generated {
		// CLAUDE.md §6.9: print to stdout once, never to the structured
		// logger. Operator captures it from terminal output.
		fmt.Printf("generated password (capture now, will not be shown again):\n  %s\n", plaintext)
	}
	return nil
}

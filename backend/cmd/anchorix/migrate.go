package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// cmdMigrate handles `anchorix migrate {up|status}`. Migrations are
// embedded into the binary at build time; the runner is explicit and
// deterministic (CLAUDE.md §16).
func cmdMigrate(ctx context.Context, cfg *config.Config, log *logger.Logger, rest []string) error {
	if len(rest) == 0 {
		return errors.New("usage: anchorix migrate [up|status]")
	}
	migrations, err := postgres.LoadEmbeddedMigrations()
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer db.Close()

	switch rest[0] {
	case "up":
		applied, err := db.MigrateUp(ctx, migrations)
		if err != nil {
			return fmt.Errorf("migrate up: %w", err)
		}
		log.Info("migrate up complete", "applied", applied)
		fmt.Printf("applied %d migration(s)\n", applied)
		return nil
	case "status":
		st, err := db.Status(ctx, migrations)
		if err != nil {
			return fmt.Errorf("migrate status: %w", err)
		}
		fmt.Printf("binary version: %d\n", st.BinaryVersion)
		fmt.Printf("db version:     %d\n", st.DBVersion)
		switch {
		case st.DBVersion == st.BinaryVersion:
			fmt.Println("status:         up to date")
		case st.DBVersion < st.BinaryVersion:
			fmt.Printf("status:         %d migration(s) pending — run `anchorix migrate up`\n",
				st.BinaryVersion-st.DBVersion)
		default:
			fmt.Println("status:         DB ahead of binary; redeploy or reconcile")
		}
		return nil
	default:
		return fmt.Errorf("unknown migrate subcommand %q (want up|status)", rest[0])
	}
}

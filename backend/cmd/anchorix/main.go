// Package main is the composition root for the Anchorix control plane.
//
// All wiring of dependencies happens here. Subcommands keep the entrypoint
// small and explicit:
//
//	anchorix serve           — run the HTTP API
//	anchorix migrate up      — apply pending DB migrations
//	anchorix migrate status  — print binary vs DB migration versions
//	anchorix admin create    — create an operator account (no defaults)
//	anchorix healthcheck     — used by container HEALTHCHECK; calls /readyz
//	anchorix version         — print build version
//
// Per CLAUDE.md, this binary is the only deployable for the control plane.
// main.go is the composition root only — no business logic lives here
// (§8.7). Each subcommand body lives in its own sibling file.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "anchorix: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	cmd, rest := args[0], args[1:]

	// Commands that don't need config — and MUST work without env
	// (e.g. someone running `anchorix version` to confirm what's
	// installed). Loading config here would force ANCHORIX_SESSION_KEY
	// and DATABASE_URL to be set just to print a version string.
	switch cmd {
	case "version":
		fmt.Println("anchorix v0.1.0-dev")
		return nil
	case "-h", "--help", "help":
		return usageError()
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := logger.New(cfg.LogLevel, cfg.Env)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch cmd {
	case "serve":
		return cmdServe(ctx, cfg, log)
	case "migrate":
		return cmdMigrate(ctx, cfg, log, rest)
	case "admin":
		return cmdAdmin(ctx, cfg, log, rest)
	case "healthcheck":
		return cmdHealthcheck(ctx, cfg)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usageError() error {
	return errors.New("usage: anchorix [serve|migrate|admin|healthcheck|version]")
}

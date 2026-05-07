// Package main is the composition root for the Anchorix control plane.
//
// All wiring of dependencies happens here. Subcommands keep the entrypoint
// small and explicit:
//
//	anchorix serve       — run the HTTP API
//	anchorix migrate up  — apply pending DB migrations
//	anchorix healthcheck — used by container HEALTHCHECK
//
// Per CLAUDE.md, this binary is the only deployable for the control plane.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi"
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
	case "healthcheck":
		return cmdHealthcheck(ctx, cfg)
	case "version":
		fmt.Println("anchorix v0.1.0-dev")
		return nil
	case "-h", "--help", "help":
		return usageError()
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func cmdServe(ctx context.Context, cfg *config.Config, log *logger.Logger) error {
	srv, err := httpapi.NewServer(cfg, log)
	if err != nil {
		return fmt.Errorf("init server: %w", err)
	}
	log.Info("starting control plane", "addr", cfg.HTTPAddr, "env", cfg.Env)
	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("serve: %w", err)
	}
	log.Info("shutdown complete")
	return nil
}

func cmdMigrate(ctx context.Context, cfg *config.Config, log *logger.Logger, rest []string) error {
	if len(rest) == 0 {
		return errors.New("usage: anchorix migrate [up|status]")
	}
	// Real implementation lands in Phase 1. Stub keeps the surface stable.
	log.Info("migrate command invoked", "subcommand", rest[0])
	_ = ctx
	_ = cfg
	return errors.New("migrations not yet implemented (Phase 1)")
}

func cmdHealthcheck(ctx context.Context, cfg *config.Config) error {
	// Lightweight in-process check used by the container HEALTHCHECK.
	// Phase 1 will wire this to ping the HTTP server's /readyz endpoint.
	_ = ctx
	_ = cfg
	return nil
}

func usageError() error {
	return errors.New("usage: anchorix [serve|migrate|healthcheck|version]")
}

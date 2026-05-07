// Package main is the Anchorix Windows agent entrypoint.
//
// The agent is a small, single-binary Windows service. It is platform-
// neutral here; OS-specific code lives behind build-tagged files in
// internal/discovery and internal/service.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kidcarmi/anchorix/agent/windows/internal/config"
	"github.com/kidcarmi/anchorix/agent/windows/internal/logger"
	"github.com/kidcarmi/anchorix/agent/windows/internal/service"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "anchorix-agent: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "run"
	if len(args) > 0 {
		cmd = args[0]
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := logger.New(cfg.LogLevel)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch cmd {
	case "run":
		return service.Run(ctx, cfg, log)
	case "version":
		fmt.Println("anchorix-agent v0.1.0-dev")
		return nil
	case "install", "uninstall":
		// Windows service install/uninstall lands in Phase 6. Reserve the
		// commands so the operator-facing UX stays stable.
		return errors.New("service install/uninstall not yet implemented (Phase 6)")
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

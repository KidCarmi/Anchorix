// Package main is the composition root for the Anchorix control plane.
//
// All wiring of dependencies happens here. Subcommands keep the entrypoint
// small and explicit:
//
//	anchorix serve         — run the HTTP API
//	anchorix migrate up    — apply pending DB migrations
//	anchorix admin create  — create the first operator account (no defaults)
//	anchorix healthcheck   — used by container HEALTHCHECK; calls /readyz
//	anchorix version       — print build version
//
// Per CLAUDE.md, this binary is the only deployable for the control plane.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	case "admin":
		return cmdAdmin(ctx, cfg, log, rest)
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
	// Phase 1 will register a Postgres ping probe here, e.g.:
	//
	//   srv.Readiness().Register("postgres", db.Ping)
	//
	// Until storage is wired, /readyz reports ready with no probes —
	// a known, intentional state documented in docs/api/REST_API.md.

	if cfg.TLSTermination == config.TLSDisabledDev {
		log.Warn("starting with TLS disabled (development only)",
			"hint", "set ANCHORIX_TLS_TERMINATION=process or reverse_proxy in production")
	}

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

func cmdMigrate(ctx context.Context, cfg *config.Config, log *logger.Logger, rest []string) error {
	if len(rest) == 0 {
		return errors.New("usage: anchorix migrate [up|status]")
	}
	log.Info("migrate command invoked", "subcommand", rest[0])
	_ = ctx
	_ = cfg
	return errors.New("migrations not yet implemented (Phase 1)")
}

// cmdAdmin handles `anchorix admin <subcommand>`. The intended bootstrap
// path is `admin create` — there is NO default admin account and NO
// default password. The first operator must be created explicitly via
// this command (CLAUDE.md §6.5, §6.12).
func cmdAdmin(ctx context.Context, cfg *config.Config, log *logger.Logger, rest []string) error {
	if len(rest) == 0 {
		return errors.New("usage: anchorix admin create --email <email> [--display-name <name>]")
	}
	switch rest[0] {
	case "create":
		// Implementation lands in Phase 1 alongside the auth package.
		// Behavior contract (binding):
		//   - require --email; reject duplicates
		//   - if --password is omitted, generate a strong random password,
		//     print it ONCE to stdout, and never log it
		//   - bcrypt-hash before insert; never store plaintext
		//   - record an audit event of type "admin_created"
		log.Info("admin create invoked", "args", rest[1:])
		_ = ctx
		_ = cfg
		return errors.New("admin create not yet implemented (Phase 1) — see docs/BOOTSTRAP.md")
	default:
		return fmt.Errorf("unknown admin subcommand %q", rest[0])
	}
}

// cmdHealthcheck is the container HEALTHCHECK entrypoint. It performs a
// short HTTP GET against the local /readyz so that container health
// reflects real readiness (CLAUDE.md §7.5). Distroless images do not
// ship curl/wget, so this check stays in-process intentionally.
func cmdHealthcheck(ctx context.Context, cfg *config.Config) error {
	host, port, err := net.SplitHostPort(cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("parse ANCHORIX_HTTP_ADDR: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + "/readyz"

	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("readyz: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("readyz returned HTTP %d", res.StatusCode)
	}
	return nil
}

func usageError() error {
	return errors.New("usage: anchorix [serve|migrate|admin|healthcheck|version]")
}

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/config"
)

// cmdHealthcheck is the container HEALTHCHECK entrypoint. It performs
// a short HTTP GET against the local /readyz so container health
// reflects real readiness (CLAUDE.md §18 readiness probe semantics).
// Distroless images don't ship curl/wget, so this stays in-process.
//
// Uses a named http.Client with an explicit timeout per CLAUDE.md
// §8.11. http.DefaultClient is forbidden in feature code.
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
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("readyz: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("readyz returned HTTP %d", res.StatusCode)
	}
	return nil
}

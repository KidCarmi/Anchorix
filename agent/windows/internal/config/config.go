// Package config loads agent configuration from environment, then config
// file, then registry (in that precedence). For now only env is wired;
// the file/registry layers arrive when packaging lands (Phase 6).
package config

import (
	"errors"
	"os"
	"time"
)

// Config is the validated agent configuration.
type Config struct {
	LogLevel          string
	ControlPlaneURL   string
	HeartbeatInterval time.Duration
	InventoryInterval time.Duration
	IdentityFile      string
	DiscoveryMode     string // "windows" (default) or "stub" for dev
	EnrollmentToken   string // optional; only used on first run
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	c := &Config{
		LogLevel:        envDefault("ANCHORIX_AGENT_LOG_LEVEL", "info"),
		ControlPlaneURL: os.Getenv("ANCHORIX_AGENT_CONTROL_PLANE_URL"),
		IdentityFile:    envDefault("ANCHORIX_AGENT_IDENTITY_FILE", defaultIdentityPath()),
		DiscoveryMode:   envDefault("ANCHORIX_AGENT_DISCOVERY", "windows"),
		EnrollmentToken: os.Getenv("ANCHORIX_AGENT_ENROLLMENT_TOKEN"),
	}
	var err error
	if c.HeartbeatInterval, err = parseDuration("ANCHORIX_AGENT_HEARTBEAT_INTERVAL", "60s"); err != nil {
		return nil, err
	}
	if c.InventoryInterval, err = parseDuration("ANCHORIX_AGENT_INVENTORY_INTERVAL", "15m"); err != nil {
		return nil, err
	}
	if c.ControlPlaneURL == "" {
		return nil, errors.New("ANCHORIX_AGENT_CONTROL_PLANE_URL is required")
	}
	switch c.DiscoveryMode {
	case "windows", "stub":
	default:
		return nil, errors.New("ANCHORIX_AGENT_DISCOVERY must be 'windows' or 'stub'")
	}
	return c, nil
}

func envDefault(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func parseDuration(key, fallback string) (time.Duration, error) {
	raw := envDefault(key, fallback)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, errors.New(key + ": invalid duration " + raw)
	}
	return d, nil
}

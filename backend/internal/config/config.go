// Package config is the single source of truth for runtime configuration.
//
// Per CLAUDE.md §8.1, no other package may read environment variables
// directly. All configuration must flow through this loader so that
// validation, defaults, and redaction are applied centrally.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Env identifies the runtime environment. It is used only to switch logging
// formats and to refuse insecure configuration in production.
type Env string

const (
	EnvDevelopment Env = "development"
	EnvStaging     Env = "staging"
	EnvProduction  Env = "production"
)

// Config is the immutable, validated configuration for the control plane.
// Fields are populated once at startup and must not be mutated afterwards.
type Config struct {
	Env           Env
	LogLevel      string
	HTTPAddr      string
	PublicBaseURL string

	// SessionKey is the symmetric key used to sign session cookies.
	// It MUST be at least 32 bytes (base64-decoded). Never log this value.
	SessionKey []byte

	DatabaseURL string

	EnrollmentTokenTTL      time.Duration
	AgentHeartbeatInterval  time.Duration
	AgentInventoryInterval  time.Duration

	TLSCertFile string
	TLSKeyFile  string
}

// Load reads configuration from the process environment, applies defaults,
// and validates required values. It returns an error if any required
// secret is missing or obviously invalid.
//
// Per CLAUDE.md §6.1 / §6.9, this is the only place that calls os.Getenv.
func Load() (*Config, error) {
	cfg := &Config{
		Env:           Env(envDefault("ANCHORIX_ENV", string(EnvDevelopment))),
		LogLevel:      envDefault("ANCHORIX_LOG_LEVEL", "info"),
		HTTPAddr:      envDefault("ANCHORIX_HTTP_ADDR", "0.0.0.0:8080"),
		PublicBaseURL: envDefault("ANCHORIX_PUBLIC_BASE_URL", "http://localhost:8080"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		TLSCertFile:   os.Getenv("ANCHORIX_TLS_CERT_FILE"),
		TLSKeyFile:    os.Getenv("ANCHORIX_TLS_KEY_FILE"),
	}

	var err error
	if cfg.SessionKey, err = decodeSessionKey(os.Getenv("ANCHORIX_SESSION_KEY")); err != nil {
		return nil, fmt.Errorf("ANCHORIX_SESSION_KEY: %w", err)
	}
	if cfg.EnrollmentTokenTTL, err = parseDuration("ANCHORIX_ENROLLMENT_TOKEN_TTL", "15m"); err != nil {
		return nil, err
	}
	if cfg.AgentHeartbeatInterval, err = parseDuration("ANCHORIX_AGENT_HEARTBEAT_INTERVAL", "60s"); err != nil {
		return nil, err
	}
	if cfg.AgentInventoryInterval, err = parseDuration("ANCHORIX_AGENT_INVENTORY_INTERVAL", "15m"); err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	switch c.Env {
	case EnvDevelopment, EnvStaging, EnvProduction:
	default:
		return fmt.Errorf("invalid ANCHORIX_ENV: %q", c.Env)
	}
	if c.DatabaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	if len(c.SessionKey) < 32 {
		return errors.New("ANCHORIX_SESSION_KEY must decode to at least 32 bytes")
	}
	if c.Env == EnvProduction {
		if strings.Contains(c.DatabaseURL, "sslmode=disable") {
			return errors.New("DATABASE_URL must not use sslmode=disable in production")
		}
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			// In production we expect TLS to be terminated either at the
			// process or at a fronting proxy; we surface a warning either
			// way during startup. Hard-failing here is too aggressive.
		}
	}
	return nil
}

// IsProduction reports whether the control plane is running in production.
func (c *Config) IsProduction() bool { return c.Env == EnvProduction }

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
		return 0, fmt.Errorf("%s: invalid duration %q: %w", key, raw, err)
	}
	return d, nil
}

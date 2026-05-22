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
	"strconv"
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

// TLSTermination tells the control plane how TLS is handled in front of it.
// The empty value is invalid in production; in development it falls back to
// TLSDisabledDev with a startup warning.
type TLSTermination string

const (
	// TLSProcess: the control plane process terminates TLS itself using
	// ANCHORIX_TLS_CERT_FILE / ANCHORIX_TLS_KEY_FILE.
	TLSProcess TLSTermination = "process"
	// TLSReverseProxy: a TLS-terminating reverse proxy sits in front of
	// the control plane. The process speaks plain HTTP on its bind address.
	TLSReverseProxy TLSTermination = "reverse_proxy"
	// TLSDisabledDev: plain HTTP, never allowed in production.
	TLSDisabledDev TLSTermination = "disabled_dev"
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

	// SessionCookieName is the cookie name used for the session id.
	// Defaults to "anchorix_session" — change with care because
	// existing browsers will retain the old name's cookie.
	SessionCookieName string

	// SessionIdleLifetime — sliding window. Each authenticated
	// request extends ExpiresAt to min(now + Idle, created + Absolute).
	SessionIdleLifetime time.Duration

	// SessionAbsoluteLifetime — hard cap from session creation.
	SessionAbsoluteLifetime time.Duration

	// BcryptCost is the cost factor used by the password policy.
	// Bounds [10, 14] are enforced at config-load time.
	BcryptCost int

	DatabaseURL string

	EnrollmentTokenTTL     time.Duration
	AgentHeartbeatInterval time.Duration
	AgentInventoryInterval time.Duration

	// FindingsScheduler — H-022 background recompute loop.
	// Defaults: enabled=true, interval=6h. Operators can
	// disable for CI / staged rollouts via the env var below.
	// Validation requires interval >= 30s when enabled; see
	// internal/findings.MinSchedulerInterval.
	FindingsSchedulerEnabled  bool
	FindingsSchedulerInterval time.Duration

	// GovernanceAPIEnabled controls whether the H-026A2
	// identity / governance operator API is routed.
	// Defaults true; an operator can flip it off without code
	// rollback if the read/write paths cause production
	// trouble. When false, every /api/v1/(tags|services|
	// service-groups|agent-groups){,/...} route returns 404
	// from the router (the routes are not registered).
	//
	// The feature gate is API-only — the schema is always
	// present (it's append-only per CLAUDE.md §16). Repository
	// reads from other packages (none today, the H-026B engine
	// later) are not affected by this flag.
	GovernanceAPIEnabled bool

	TLSTermination TLSTermination
	TLSCertFile    string
	TLSKeyFile     string
}

// Load reads configuration from the process environment, applies defaults,
// and validates required values. It returns an error if any required
// secret is missing or obviously invalid.
//
// Per CLAUDE.md §6.1 / §6.9, this is the only place that calls os.Getenv.
func Load() (*Config, error) {
	cfg := &Config{
		Env:               Env(envDefault("ANCHORIX_ENV", string(EnvDevelopment))),
		LogLevel:          envDefault("ANCHORIX_LOG_LEVEL", "info"),
		HTTPAddr:          envDefault("ANCHORIX_HTTP_ADDR", "0.0.0.0:8080"),
		PublicBaseURL:     envDefault("ANCHORIX_PUBLIC_BASE_URL", "http://localhost:8080"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		SessionCookieName: envDefault("ANCHORIX_SESSION_COOKIE_NAME", "anchorix_session"),
		TLSTermination:    TLSTermination(strings.TrimSpace(os.Getenv("ANCHORIX_TLS_TERMINATION"))),
		TLSCertFile:       os.Getenv("ANCHORIX_TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("ANCHORIX_TLS_KEY_FILE"),
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
	if cfg.FindingsSchedulerEnabled, err = parseBool("ANCHORIX_FINDINGS_SCHEDULER_ENABLED", true); err != nil {
		return nil, err
	}
	if cfg.FindingsSchedulerInterval, err = parseDuration("ANCHORIX_FINDINGS_SCHEDULER_INTERVAL", "6h"); err != nil {
		return nil, err
	}
	if cfg.GovernanceAPIEnabled, err = parseBool("ANCHORIX_GOVERNANCE_API_ENABLED", true); err != nil {
		return nil, err
	}
	if cfg.SessionIdleLifetime, err = parseDuration("ANCHORIX_SESSION_IDLE_LIFETIME", "8h"); err != nil {
		return nil, err
	}
	if cfg.SessionAbsoluteLifetime, err = parseDuration("ANCHORIX_SESSION_ABSOLUTE_LIFETIME", "24h"); err != nil {
		return nil, err
	}
	if cfg.BcryptCost, err = parseInt("ANCHORIX_BCRYPT_COST", 12); err != nil {
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
	if c.SessionCookieName == "" {
		return errors.New("ANCHORIX_SESSION_COOKIE_NAME must not be empty")
	}
	if c.SessionIdleLifetime <= 0 {
		return errors.New("ANCHORIX_SESSION_IDLE_LIFETIME must be positive")
	}
	if c.SessionAbsoluteLifetime <= 0 {
		return errors.New("ANCHORIX_SESSION_ABSOLUTE_LIFETIME must be positive")
	}
	if c.SessionAbsoluteLifetime < c.SessionIdleLifetime {
		return fmt.Errorf("ANCHORIX_SESSION_ABSOLUTE_LIFETIME (%s) must be >= ANCHORIX_SESSION_IDLE_LIFETIME (%s)",
			c.SessionAbsoluteLifetime, c.SessionIdleLifetime)
	}
	if c.BcryptCost < 10 || c.BcryptCost > 14 {
		return fmt.Errorf("ANCHORIX_BCRYPT_COST=%d out of range [10, 14]", c.BcryptCost)
	}
	if err := c.validateTLS(); err != nil {
		return err
	}
	if c.IsProduction() && strings.Contains(c.DatabaseURL, "sslmode=disable") {
		return errors.New("DATABASE_URL must not use sslmode=disable in production")
	}
	if err := c.validateFindingsScheduler(); err != nil {
		return err
	}
	return nil
}

// validateFindingsScheduler enforces H-022 interval bounds at
// process startup so a misconfigured deployment fails closed
// before the scheduler is constructed. Mirrors
// findings.ValidateSchedulerConfig but lives in config to keep
// the env-var error message close to the variable name.
func (c *Config) validateFindingsScheduler() error {
	if !c.FindingsSchedulerEnabled {
		return nil
	}
	const minInterval = 30 * time.Second
	if c.FindingsSchedulerInterval <= 0 {
		return errors.New("ANCHORIX_FINDINGS_SCHEDULER_INTERVAL must be positive")
	}
	if c.FindingsSchedulerInterval < minInterval {
		return fmt.Errorf(
			"ANCHORIX_FINDINGS_SCHEDULER_INTERVAL=%s below minimum %s",
			c.FindingsSchedulerInterval, minInterval,
		)
	}
	return nil
}

// validateTLS enforces the TLS posture rules.
//
// Production must be explicit (process or reverse_proxy). Development
// defaults to disabled_dev for ergonomics, but a misconfigured production
// deployment must fail closed at startup (CLAUDE.md §6.12).
func (c *Config) validateTLS() error {
	switch c.TLSTermination {
	case TLSProcess:
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return errors.New("ANCHORIX_TLS_TERMINATION=process requires ANCHORIX_TLS_CERT_FILE and ANCHORIX_TLS_KEY_FILE")
		}
	case TLSReverseProxy:
		// Operator's reverse proxy is responsible for TLS. Nothing else
		// to validate here. Defining this mode explicitly is the point.
	case TLSDisabledDev:
		if c.IsProduction() {
			return errors.New("ANCHORIX_TLS_TERMINATION=disabled_dev is forbidden in production")
		}
	case "":
		if c.IsProduction() {
			return errors.New("ANCHORIX_TLS_TERMINATION must be set in production (process|reverse_proxy)")
		}
		c.TLSTermination = TLSDisabledDev
	default:
		return fmt.Errorf("invalid ANCHORIX_TLS_TERMINATION: %q (allowed: process|reverse_proxy|disabled_dev)", c.TLSTermination)
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

func parseInt(key string, fallback int) (int, error) {
	raw := envDefault(key, "")
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q: %w", key, raw, err)
	}
	return v, nil
}

// parseBool accepts the canonical Go truthy/falsy strings
// (`true`/`false`/`1`/`0`/`t`/`f`/`yes`/`no` per
// strconv.ParseBool) and falls back to the supplied default
// when the env var is unset.
func parseBool(key string, fallback bool) (bool, error) {
	raw := envDefault(key, "")
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: invalid boolean %q: %w", key, raw, err)
	}
	return v, nil
}

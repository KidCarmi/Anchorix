package config

import (
	"strings"
	"testing"
)

// PR-002 added bcrypt cost, session idle/absolute lifetimes, and the
// session cookie name. These tests cover the new validation paths.

func TestLoadBcryptCostDefault(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BcryptCost != 12 {
		t.Fatalf("default bcrypt cost = %d, want 12", cfg.BcryptCost)
	}
}

func TestLoadBcryptCostOutOfRange(t *testing.T) {
	for _, v := range []string{"9", "15"} {
		t.Run(v, func(t *testing.T) {
			baseEnv(t, EnvDevelopment)
			t.Setenv("ANCHORIX_BCRYPT_COST", v)
			if _, err := Load(); err == nil {
				t.Fatalf("Load: want error for cost=%s", v)
			}
		})
	}
}

func TestLoadBcryptCostInRange(t *testing.T) {
	for _, v := range []string{"10", "12", "14"} {
		t.Run(v, func(t *testing.T) {
			baseEnv(t, EnvDevelopment)
			t.Setenv("ANCHORIX_BCRYPT_COST", v)
			if _, err := Load(); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
	}
}

func TestLoadSessionLifetimesDefault(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SessionIdleLifetime <= 0 {
		t.Fatalf("idle lifetime not positive: %s", cfg.SessionIdleLifetime)
	}
	if cfg.SessionAbsoluteLifetime <= 0 {
		t.Fatalf("absolute lifetime not positive: %s", cfg.SessionAbsoluteLifetime)
	}
	if cfg.SessionAbsoluteLifetime < cfg.SessionIdleLifetime {
		t.Fatalf("absolute (%s) < idle (%s)", cfg.SessionAbsoluteLifetime, cfg.SessionIdleLifetime)
	}
	// Documented defaults.
	if cfg.SessionIdleLifetime.String() != "8h0m0s" {
		t.Fatalf("idle default = %s, want 8h0m0s", cfg.SessionIdleLifetime)
	}
	if cfg.SessionAbsoluteLifetime.String() != "24h0m0s" {
		t.Fatalf("absolute default = %s, want 24h0m0s", cfg.SessionAbsoluteLifetime)
	}
}

func TestLoadSessionAbsoluteLessThanIdleRejected(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	t.Setenv("ANCHORIX_SESSION_IDLE_LIFETIME", "1h")
	t.Setenv("ANCHORIX_SESSION_ABSOLUTE_LIFETIME", "30m")
	_, err := Load()
	if err == nil {
		t.Fatal("Load: want error when absolute < idle")
	}
	if !strings.Contains(err.Error(), "ANCHORIX_SESSION_ABSOLUTE_LIFETIME") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCookieNameDefault(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SessionCookieName != "anchorix_session" {
		t.Fatalf("cookie name default = %q, want anchorix_session", cfg.SessionCookieName)
	}
}

func TestLoadCookieNameOverridden(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	t.Setenv("ANCHORIX_SESSION_COOKIE_NAME", "my_session")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SessionCookieName != "my_session" {
		t.Fatalf("cookie name = %q, want my_session", cfg.SessionCookieName)
	}
}

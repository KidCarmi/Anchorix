package config

import (
	"strings"
	"testing"
)

// validKey is a base64 string that decodes to >= 32 bytes — the minimum
// the loader accepts for ANCHORIX_SESSION_KEY.
var validKey = strings.Repeat("A", 44) // 44 base64 chars → 33 bytes

// baseEnv returns a minimal valid environment for tests. Individual cases
// override fields by calling t.Setenv after applying these.
func baseEnv(t *testing.T, env Env) {
	t.Helper()
	t.Setenv("ANCHORIX_ENV", string(env))
	t.Setenv("ANCHORIX_LOG_LEVEL", "info")
	t.Setenv("ANCHORIX_HTTP_ADDR", "127.0.0.1:8080")
	t.Setenv("ANCHORIX_PUBLIC_BASE_URL", "http://localhost:8080")
	t.Setenv("ANCHORIX_SESSION_KEY", validKey)
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/anchorix?sslmode=require")
	// Clear TLS so each test sets exactly what it needs.
	t.Setenv("ANCHORIX_TLS_TERMINATION", "")
	t.Setenv("ANCHORIX_TLS_CERT_FILE", "")
	t.Setenv("ANCHORIX_TLS_KEY_FILE", "")
}

func TestLoadDevDefaultsTLSToDisabledDev(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TLSTermination != TLSDisabledDev {
		t.Fatalf("dev default TLS termination = %q, want %q", cfg.TLSTermination, TLSDisabledDev)
	}
}

func TestLoadProductionRequiresExplicitTLS(t *testing.T) {
	baseEnv(t, EnvProduction)
	_, err := Load()
	if err == nil {
		t.Fatal("Load: want error for production with unset TLS termination")
	}
	if !strings.Contains(err.Error(), "ANCHORIX_TLS_TERMINATION") {
		t.Fatalf("error should mention ANCHORIX_TLS_TERMINATION, got: %v", err)
	}
}

func TestLoadProductionRejectsDisabledDev(t *testing.T) {
	baseEnv(t, EnvProduction)
	t.Setenv("ANCHORIX_TLS_TERMINATION", string(TLSDisabledDev))
	_, err := Load()
	if err == nil {
		t.Fatal("Load: want error for production + disabled_dev")
	}
	if !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadProductionProcessTLSRequiresFiles(t *testing.T) {
	baseEnv(t, EnvProduction)
	t.Setenv("ANCHORIX_TLS_TERMINATION", string(TLSProcess))
	// Files intentionally not set.
	_, err := Load()
	if err == nil {
		t.Fatal("Load: want error when process TLS has no cert/key files")
	}
	if !strings.Contains(err.Error(), "ANCHORIX_TLS_CERT_FILE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadProductionProcessTLSWithFilesPasses(t *testing.T) {
	baseEnv(t, EnvProduction)
	t.Setenv("ANCHORIX_TLS_TERMINATION", string(TLSProcess))
	t.Setenv("ANCHORIX_TLS_CERT_FILE", "/etc/anchorix/server.crt")
	t.Setenv("ANCHORIX_TLS_KEY_FILE", "/etc/anchorix/server.key")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TLSTermination != TLSProcess {
		t.Fatalf("TLS termination = %q, want %q", cfg.TLSTermination, TLSProcess)
	}
}

func TestLoadProductionReverseProxyPasses(t *testing.T) {
	baseEnv(t, EnvProduction)
	t.Setenv("ANCHORIX_TLS_TERMINATION", string(TLSReverseProxy))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TLSTermination != TLSReverseProxy {
		t.Fatalf("TLS termination = %q, want %q", cfg.TLSTermination, TLSReverseProxy)
	}
}

func TestLoadRejectsUnknownTLSTermination(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	t.Setenv("ANCHORIX_TLS_TERMINATION", "yolo")
	_, err := Load()
	if err == nil {
		t.Fatal("Load: want error for unknown TLS termination value")
	}
	if !strings.Contains(err.Error(), "invalid ANCHORIX_TLS_TERMINATION") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsShortSessionKey(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	t.Setenv("ANCHORIX_SESSION_KEY", "short")
	_, err := Load()
	if err == nil {
		t.Fatal("Load: want error for short session key")
	}
}

func TestLoadRejectsProductionInsecureDB(t *testing.T) {
	baseEnv(t, EnvProduction)
	t.Setenv("ANCHORIX_TLS_TERMINATION", string(TLSReverseProxy))
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/anchorix?sslmode=disable")
	_, err := Load()
	if err == nil {
		t.Fatal("Load: want error for sslmode=disable in production")
	}
	if !strings.Contains(err.Error(), "sslmode=disable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsMissingDatabaseURL(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	t.Setenv("DATABASE_URL", "")
	_, err := Load()
	if err == nil {
		t.Fatal("Load: want error for missing DATABASE_URL")
	}
}

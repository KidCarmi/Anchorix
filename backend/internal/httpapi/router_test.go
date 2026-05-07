package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// testRouter wires a handler exactly the way Server does, but without
// binding a TCP socket. Tests inject probes and exercise routes via
// httptest.
func testRouter(t *testing.T, register func(*Readiness)) http.Handler {
	t.Helper()
	cfg := &config.Config{Env: config.EnvDevelopment}
	log := logger.New("error", config.EnvDevelopment)
	r := NewReadiness()
	if register != nil {
		register(r)
	}
	return newRouter(cfg, log, r)
}

func TestHealthzAlwaysOK(t *testing.T) {
	h := testRouter(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("unexpected content-type: %q", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body status = %q, want ok", body["status"])
	}
}

func TestReadyzWithNoProbesIsReady(t *testing.T) {
	h := testRouter(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ready" {
		t.Fatalf("body status = %v, want ready", body["status"])
	}
}

func TestReadyzWithPassingProbeIsReady(t *testing.T) {
	h := testRouter(t, func(r *Readiness) {
		r.Register("dummy", func(_ context.Context) error { return nil })
	})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200", rec.Code)
	}
}

func TestReadyzFailsClosedOnFailingProbe(t *testing.T) {
	h := testRouter(t, func(r *Readiness) {
		r.Register("postgres", func(_ context.Context) error { return errors.New("connection refused") })
	})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "unready" {
		t.Fatalf("body status = %v, want unready", body["status"])
	}
	checks, ok := body["checks"].(map[string]any)
	if !ok {
		t.Fatalf("checks missing in %v", body)
	}
	pg, ok := checks["postgres"].(string)
	if !ok || !strings.HasPrefix(pg, "error:") {
		t.Fatalf("postgres check should report error, got %v", checks["postgres"])
	}
}

func TestReadyzMixedProbesFailClosed(t *testing.T) {
	// One healthy + one unhealthy probe must produce an unready response.
	h := testRouter(t, func(r *Readiness) {
		r.Register("a", func(_ context.Context) error { return nil })
		r.Register("b", func(_ context.Context) error { return errors.New("down") })
	})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestNotImplementedRouteEnvelope guarantees the stable error response
// shape that clients rely on:  { "error": { "code": ..., "message": ... } }.
// Every handler that returns notImplemented must produce this shape; this
// test catches regressions in the helper or the router wiring.
func TestNotImplementedRouteEnvelope(t *testing.T) {
	h := testRouter(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "not_implemented" {
		t.Fatalf("error.code = %q, want not_implemented", body.Error.Code)
	}
	if body.Error.Message == "" {
		t.Fatal("error.message must be non-empty")
	}
}

func TestUnknownRouteIs404(t *testing.T) {
	h := testRouter(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/does-not-exist", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRequestIDHeaderRoundtrip(t *testing.T) {
	h := testRouter(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("X-Request-Id missing from response")
	}
}

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kidcarmi/anchorix/backend/internal/agentinventory"
	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/config"
	"github.com/kidcarmi/anchorix/backend/internal/enrollment"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// testRouter wires a handler exactly the way Server does, but without
// binding a TCP socket. Tests inject probes and exercise routes via
// httptest.
//
// The auth.Service it constructs has a nil Repository / SessionStore —
// fine for the existing /healthz, /readyz, envelope and 404 tests
// which don't exercise auth. Tests that exercise the login flow live
// in backend/test/integration/ and stand up real postgres.
func testRouter(t *testing.T, register func(*Readiness)) http.Handler {
	t.Helper()
	cfg := &config.Config{
		Env:                     config.EnvDevelopment,
		SessionCookieName:       "anchorix_session",
		SessionIdleLifetime:     8 * 60 * 60_000_000_000,
		SessionAbsoluteLifetime: 24 * 60 * 60_000_000_000,
		BcryptCost:              10,
	}
	log := logger.New("error", config.EnvDevelopment)
	r := NewReadiness()
	if register != nil {
		register(r)
	}
	signer, err := auth.NewSignedCookie(bytes.Repeat([]byte("A"), 32))
	if err != nil {
		t.Fatalf("NewSignedCookie: %v", err)
	}
	deps := Dependencies{
		AuthService:           &auth.Service{},
		CookieSigner:          signer,
		EnrollmentService:     &enrollment.Service{},
		AgentInventoryService: &agentinventory.Service{},
		InventoryService:      &inventory.Service{},
	}
	return newRouter(cfg, log, r, deps)
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
// Every handler that still returns notImplemented must produce this
// shape; this test catches regressions in the helper or the router
// wiring. We exercise a still-stub route (GET /findings) so the
// test stays valid as more handlers gain real implementations.
// GET /agents became real in PR-013; GET /certificates became
// real in H-020.
func TestNotImplementedRouteEnvelope(t *testing.T) {
	h := testRouter(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
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

// TestAuthLoginBadRequest exercises the new auth login handler's
// input validation: an empty body must produce a bad_request envelope.
// We do NOT exercise the success path here — that requires a real
// postgres and lives in backend/test/integration/.
func TestAuthLoginBadRequest(t *testing.T) {
	h := testRouter(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "bad_request" {
		t.Fatalf("error.code = %q, want bad_request", body.Error.Code)
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

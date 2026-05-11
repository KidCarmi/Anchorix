//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestReadyzReportsPostgresProbe asserts that with a healthy postgres
// pool registered as a readiness probe, /readyz returns 200 + the
// probe's "ok" state. (The fail-closed path is harder to exercise
// in an integration test without disrupting the shared service
// container; the unit test in internal/httpapi covers that contract.)
func TestReadyzReportsPostgresProbe(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	srv, _ := testServer(t, db)

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/readyz status = %d; body=%s", resp.StatusCode, body)
	}
	var out struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Status != "ready" {
		t.Fatalf("status = %q; want ready", out.Status)
	}
	if out.Checks["postgres"] != "ok" {
		t.Fatalf("postgres check = %q; want ok", out.Checks["postgres"])
	}
}

// TestHealthzAlwaysOK confirms the process-only liveness check still
// answers regardless of dependency state.
func TestHealthzAlwaysOK(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d; want 200", resp.StatusCode)
	}
}

// Package handlers contains thin HTTP adapters. Handlers MUST NOT contain
// business logic — they translate HTTP into domain calls and back. Domain
// behavior lives in internal/{inventory,risks,agents,audit,...}.
package handlers

import (
	"encoding/json"
	"net/http"
)

// Health is the liveness probe. It must never depend on external resources.
func Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Ready is the readiness probe. It will gain a DB ping in Phase 1.
func Ready(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

// notImplemented returns a stable 501 payload for endpoints that exist in the
// API surface but whose implementation lands in a later roadmap phase.
func notImplemented(w http.ResponseWriter) {
	writeError(w, http.StatusNotImplemented, "not_implemented",
		"endpoint defined in v0.1 contract but not yet implemented")
}

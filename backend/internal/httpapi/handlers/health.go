// Package handlers contains thin HTTP adapters. Handlers MUST NOT contain
// business logic — they translate HTTP into domain calls and back. Domain
// behavior lives in internal/{inventory,risks,agents,audit,...}.
//
// Every response — success or error — flows through
// internal/httpapi/envelope so the wire shape stays canonical. There is
// no second copy of the JSON envelope code in this package.
package handlers

import (
	"net/http"

	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
)

// Health is the process liveness probe. It MUST NOT depend on external
// resources — it answers "is this process running and able to serve HTTP?"
// only. Readiness (dependency health) is served by /readyz, which is
// wired in internal/httpapi to the Readiness probe registry.
func Health(w http.ResponseWriter, _ *http.Request) {
	envelope.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// notImplemented returns the canonical 501 envelope for endpoints that
// exist in the v0.1 API contract but whose implementation lands in a
// later roadmap phase. Centralizing this keeps every stub handler's
// response shape identical.
func notImplemented(w http.ResponseWriter) {
	envelope.WriteError(w, http.StatusNotImplemented, "not_implemented",
		"endpoint defined in v0.1 contract but not yet implemented")
}

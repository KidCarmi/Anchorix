// Package envelope is the single canonical implementation of the
// Anchorix HTTP response envelope. Every JSON response — success or
// error — produced by the control plane MUST go through this package
// so the wire format documented in docs/api/REST_API.md stays stable.
//
// The contract is intentionally tiny:
//
//	WriteJSON(w, status, body)        — success / data responses
//	WriteError(w, status, code, msg)  — { "error": { "code", "message" } }
//
// Handlers and infrastructure code (e.g. /readyz) both depend on this
// package. There is no second copy to "keep in sync".
package envelope

import (
	"encoding/json"
	"net/http"
)

// contentType is the canonical response Content-Type. Defined as a
// package-level constant so any future change is one-line and global.
const contentType = "application/json; charset=utf-8"

// WriteJSON serializes body as JSON and writes it with the given status.
// It sets Content-Type before WriteHeader so middleware that inspects
// headers (e.g. compression) sees the correct value.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// WriteError emits the canonical error envelope:
//
//	{ "error": { "code": "...", "message": "..." } }
//
// Clients (the React SPA and agents) rely on this shape; handlers MUST
// NOT construct their own error JSON. Centralizing it here means
// regressions show up as test failures in router_test.go.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, errorEnvelope{
		Error: errorDetail{Code: code, Message: message},
	})
}

type errorEnvelope struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

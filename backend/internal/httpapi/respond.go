package httpapi

import (
	"encoding/json"
	"net/http"
)

// writeJSON is the package-internal JSON response helper. The handlers
// subpackage has its own copy with the same shape; both must keep the
// `error: { code, message }` envelope stable so clients can rely on it.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

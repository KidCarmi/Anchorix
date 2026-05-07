package logger

import (
	"log/slog"
	"strings"
)

// sensitiveFields are field keys whose values must never be written to logs.
// Centralizing this list satisfies CLAUDE.md §6.9.
var sensitiveFields = map[string]struct{}{
	"password":         {},
	"passphrase":       {},
	"secret":           {},
	"token":            {},
	"access_token":     {},
	"refresh_token":    {},
	"session_key":      {},
	"authorization":    {},
	"cookie":           {},
	"set-cookie":       {},
	"private_key":      {},
	"enrollment_token": {},
	"api_key":          {},
}

// redactAttr replaces sensitive attribute values with a fixed marker.
// The marker is intentionally non-empty so that operators can grep logs
// and detect that a sensitive field was emitted (and from where).
func redactAttr(_ []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	if _, hit := sensitiveFields[key]; hit {
		return slog.String(a.Key, "[REDACTED]")
	}
	// Heuristic: any key suffixed with _token / _secret / _password.
	for _, suffix := range []string{"_token", "_secret", "_password", "_key"} {
		if strings.HasSuffix(key, suffix) && key != "request_id" {
			return slog.String(a.Key, "[REDACTED]")
		}
	}
	return a
}

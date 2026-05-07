package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kidcarmi/anchorix/backend/internal/config"
)

// captureLogger returns a Logger whose output goes to buf so we can
// inspect what made it through redaction.
func captureLogger(buf *bytes.Buffer) *Logger {
	return newWithWriter("info", config.EnvProduction, buf)
}

func TestRedactKnownSensitiveFields(t *testing.T) {
	for _, key := range []string{
		"password", "passphrase", "secret", "token",
		"access_token", "refresh_token", "session_key",
		"authorization", "cookie", "set-cookie",
		"private_key", "enrollment_token", "api_key",
	} {
		t.Run(key, func(t *testing.T) {
			var buf bytes.Buffer
			log := captureLogger(&buf)
			log.Info("event", key, "supersecret-value")

			out := buf.String()
			if strings.Contains(out, "supersecret-value") {
				t.Fatalf("sensitive value leaked for key %q: %s", key, out)
			}
			if !strings.Contains(out, "[REDACTED]") {
				t.Fatalf("expected [REDACTED] marker for key %q: %s", key, out)
			}
		})
	}
}

func TestRedactKeySuffixHeuristic(t *testing.T) {
	// Keys not in the explicit list still get redacted if they end in a
	// known suffix.
	for _, key := range []string{
		"agent_token", "csrf_token", "bootstrap_token",
		"shared_secret", "user_password", "encryption_key",
	} {
		t.Run(key, func(t *testing.T) {
			var buf bytes.Buffer
			log := captureLogger(&buf)
			log.Info("event", key, "leaky-value")

			out := buf.String()
			if strings.Contains(out, "leaky-value") {
				t.Fatalf("sensitive value leaked for key %q: %s", key, out)
			}
		})
	}
}

func TestRedactDoesNotEatRequestID(t *testing.T) {
	// request_id ends in _id, not a sensitive suffix, but historically
	// redactors have over-matched. Make sure it survives.
	var buf bytes.Buffer
	log := captureLogger(&buf)
	log.Info("http_request", "request_id", "abc-123")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["request_id"] != "abc-123" {
		t.Fatalf("request_id was unexpectedly modified: %v", got["request_id"])
	}
}

func TestNonSensitiveFieldsSurvive(t *testing.T) {
	var buf bytes.Buffer
	log := captureLogger(&buf)
	log.Info("event", "hostname", "ws-001", "count", 42)

	out := buf.String()
	if !strings.Contains(out, "ws-001") {
		t.Fatalf("non-sensitive value redacted unexpectedly: %s", out)
	}
}

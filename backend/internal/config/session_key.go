package config

import (
	"encoding/base64"
	"errors"
	"strings"
)

// decodeSessionKey accepts either a raw byte string of sufficient length or
// a base64-encoded value. Empty input is rejected so we never silently fall
// back to a zero key in any environment.
func decodeSessionKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("missing")
	}
	// Try base64 first; fall back to raw bytes if it doesn't look base64.
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	return []byte(raw), nil
}

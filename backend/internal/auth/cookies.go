package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// SignedCookie wraps a session id with an HMAC-SHA256 signature
// derived from cfg.SessionKey. The on-the-wire form is
//
//	<base64url(session_id_bytes)>.<base64url(hmac)>
//
// Both halves use URL-safe base64 without padding. The session id
// is opaque (an `internal/ids` value); server-side lookup confirms
// it actually exists. The HMAC is a defense-in-depth check that
// blocks tampered cookies without paying a DB round-trip.
type SignedCookie struct {
	key []byte
}

// ErrInvalidCookie is returned by Verify when the cookie is
// malformed or its signature does not match. The caller MUST treat
// this as "no session present" — do not distinguish further.
var ErrInvalidCookie = errors.New("auth: invalid session cookie")

// NewSignedCookie returns a signer using key (>= 32 bytes).
func NewSignedCookie(key []byte) (*SignedCookie, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("auth: cookie key must be >= 32 bytes, got %d", len(key))
	}
	// Copy the key so the caller can wipe their slice without
	// affecting future verifications.
	cp := make([]byte, len(key))
	copy(cp, key)
	return &SignedCookie{key: cp}, nil
}

// Sign produces the on-the-wire cookie value for the given session
// id.
func (s *SignedCookie) Sign(sessionID string) string {
	enc := base64.RawURLEncoding
	encID := enc.EncodeToString([]byte(sessionID))
	mac := s.mac([]byte(sessionID))
	return encID + "." + enc.EncodeToString(mac)
}

// Verify parses a cookie value and returns the session id if the
// signature matches. Constant-time compare avoids timing leaks.
//
// Uses RawURLEncoding.Strict() so encodings with non-zero trailing
// padding bits (a form of canonicality bypass) are rejected at the
// decode step instead of producing the same decoded bytes as the
// canonical form.
func (s *SignedCookie) Verify(value string) (string, error) {
	enc := base64.RawURLEncoding.Strict()
	dot := strings.IndexByte(value, '.')
	if dot <= 0 || dot == len(value)-1 {
		return "", ErrInvalidCookie
	}
	idBytes, err := enc.DecodeString(value[:dot])
	if err != nil {
		return "", ErrInvalidCookie
	}
	gotMAC, err := enc.DecodeString(value[dot+1:])
	if err != nil {
		return "", ErrInvalidCookie
	}
	wantMAC := s.mac(idBytes)
	if subtle.ConstantTimeCompare(gotMAC, wantMAC) != 1 {
		return "", ErrInvalidCookie
	}
	return string(idBytes), nil
}

func (s *SignedCookie) mac(payload []byte) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write(payload)
	return h.Sum(nil)
}

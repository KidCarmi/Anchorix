package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestSignedCookieRoundTrip(t *testing.T) {
	signer, err := NewSignedCookie(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewSignedCookie: %v", err)
	}
	const sid = "session-12345"
	cookie := signer.Sign(sid)
	got, err := signer.Verify(cookie)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != sid {
		t.Fatalf("session id = %q, want %q", got, sid)
	}
}

func TestSignedCookieRejectsTamperedID(t *testing.T) {
	signer, err := NewSignedCookie(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewSignedCookie: %v", err)
	}
	cookie := signer.Sign("session-12345")
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed cookie: %q", cookie)
	}
	// Tamper at position 0 — the first base64 char encodes the high
	// 6 bits of byte 0, with no padding bits. Any change there
	// necessarily produces different decoded bytes.
	orig := parts[0][0]
	alt := byte('A')
	if orig == 'A' {
		alt = 'B'
	}
	tampered := string(alt) + parts[0][1:] + "." + parts[1]
	if _, err := signer.Verify(tampered); err == nil {
		t.Fatal("Verify: tampered cookie was accepted")
	}
}

func TestSignedCookieRejectsTamperedMAC(t *testing.T) {
	signer, err := NewSignedCookie(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewSignedCookie: %v", err)
	}
	cookie := signer.Sign("abc")
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed cookie: %q", cookie)
	}
	// Tamper at position 0 of the MAC base64 — same reasoning as
	// TestSignedCookieRejectsTamperedID.
	orig := parts[1][0]
	alt := byte('A')
	if orig == 'A' {
		alt = 'B'
	}
	tampered := parts[0] + "." + string(alt) + parts[1][1:]
	if _, err := signer.Verify(tampered); err == nil {
		t.Fatal("Verify: tampered MAC was accepted")
	}
}

func TestSignedCookieRejectsMalformed(t *testing.T) {
	signer, err := NewSignedCookie(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewSignedCookie: %v", err)
	}
	for _, v := range []string{"", ".", "novalue.", ".nomac", "no-dot", "abc.@!@"} {
		t.Run(v, func(t *testing.T) {
			if _, err := signer.Verify(v); err == nil {
				t.Fatalf("Verify(%q) succeeded; want error", v)
			}
		})
	}
}

func TestSignedCookieDifferentKeysProduceDifferentSignatures(t *testing.T) {
	s1, _ := NewSignedCookie(bytes.Repeat([]byte("a"), 32))
	s2, _ := NewSignedCookie(bytes.Repeat([]byte("b"), 32))
	c1 := s1.Sign("x")
	c2 := s2.Sign("x")
	if c1 == c2 {
		t.Fatal("different keys produced identical signed cookies")
	}
	if _, err := s2.Verify(c1); err == nil {
		t.Fatal("s2 accepted s1's cookie")
	}
}

func TestNewSignedCookieRejectsShortKey(t *testing.T) {
	if _, err := NewSignedCookie(bytes.Repeat([]byte("k"), 16)); err == nil {
		t.Fatal("NewSignedCookie: short key was accepted")
	}
}

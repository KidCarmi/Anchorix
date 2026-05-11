package auth

import (
	"testing"
	"time"
)

func TestNewSessionPolicyValidation(t *testing.T) {
	cases := []struct {
		name           string
		idle, absolute time.Duration
		wantErr        bool
	}{
		{"valid 8h/24h", 8 * time.Hour, 24 * time.Hour, false},
		{"valid idle equals absolute", time.Hour, time.Hour, false},
		{"zero idle", 0, time.Hour, true},
		{"zero absolute", time.Hour, 0, true},
		{"negative idle", -time.Hour, time.Hour, true},
		{"absolute less than idle", 2 * time.Hour, time.Hour, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSessionPolicy(tc.idle, tc.absolute)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSessionPolicyNextExpiry(t *testing.T) {
	p, err := NewSessionPolicy(8*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSessionPolicy: %v", err)
	}
	created := time.Date(2026, 5, 9, 10, 0, 0, 0, time.UTC)

	// At creation time the idle deadline (created + 8h) is the binding one.
	if got := p.NextExpiry(created, created); !got.Equal(created.Add(8 * time.Hour)) {
		t.Fatalf("at t=0: got %s, want %s", got, created.Add(8*time.Hour))
	}

	// 17h after creation: idle deadline = 17h + 8h = 25h after creation,
	// absolute = 24h after creation. Absolute wins; expiry is capped.
	now := created.Add(17 * time.Hour)
	want := created.Add(24 * time.Hour)
	if got := p.NextExpiry(now, created); !got.Equal(want) {
		t.Fatalf("absolute cap: got %s, want %s", got, want)
	}

	// Before the absolute cap kicks in, idle wins.
	now = created.Add(time.Hour)
	want = now.Add(8 * time.Hour)
	if got := p.NextExpiry(now, created); !got.Equal(want) {
		t.Fatalf("idle slide: got %s, want %s", got, want)
	}
}

func TestSessionIsActive(t *testing.T) {
	now := time.Date(2026, 5, 9, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		s    *Session
		want bool
	}{
		{"nil", nil, false},
		{"active", &Session{ExpiresAt: now.Add(time.Hour)}, true},
		{"expired", &Session{ExpiresAt: now.Add(-time.Hour)}, false},
		{"revoked", func() *Session {
			r := now.Add(-time.Minute)
			return &Session{ExpiresAt: now.Add(time.Hour), RevokedAt: &r}
		}(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.IsActive(now); got != tc.want {
				t.Fatalf("IsActive = %v, want %v", got, tc.want)
			}
		})
	}
}

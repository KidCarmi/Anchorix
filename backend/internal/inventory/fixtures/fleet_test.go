package fixtures

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// TestSmallv01BuildIsStructurallyDeterministic pins the
// package-level determinism contract: two `(seed, cfg, now)`
// triples that match produce STRUCTURALLY equal fleets. Row
// counts, IDs, and rule-bucket assignments must match. PEM
// bytes (and SHA-256 fingerprints) differ across runs because
// key material reads from crypto/rand by design — the fixture
// docs spell out the rationale; this test enforces what the
// fixture actually guarantees.
func TestSmallv01BuildIsStructurallyDeterministic(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	cfg := Smallv01()

	a, err := NewFleetBuilder(42, cfg, now).Build()
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	b, err := NewFleetBuilder(42, cfg, now).Build()
	if err != nil {
		t.Fatalf("build B: %v", err)
	}
	if got, want := len(a.Agents), len(b.Agents); got != want {
		t.Fatalf("agent count: A=%d B=%d", got, want)
	}
	if got, want := len(a.Certificates), len(b.Certificates); got != want {
		t.Fatalf("cert count: A=%d B=%d", got, want)
	}
	if got, want := len(a.Observations), len(b.Observations); got != want {
		t.Fatalf("observation count: A=%d B=%d", got, want)
	}
	// IDs are derived from a seeded math/rand source that the
	// crypto-randomness path does not touch, so they MUST match
	// byte-for-byte across runs. If they ever stop matching,
	// nondeterminism has crept into the ID source — a
	// regression worth catching early.
	for i := range a.Agents {
		if a.Agents[i].ID != b.Agents[i].ID {
			t.Fatalf("agents[%d].ID differs across runs: A=%q B=%q",
				i, a.Agents[i].ID, b.Agents[i].ID)
		}
	}
	for i := range a.Certificates {
		if a.Certificates[i].ID != b.Certificates[i].ID {
			t.Errorf("certs[%d].ID differs across runs: A=%q B=%q",
				i, a.Certificates[i].ID, b.Certificates[i].ID)
		}
	}
	// Rule-bucket assignment must match — the bucket choice is
	// driven by `planCertShapes` (no crypto randomness), so
	// observable cert attributes that gate the rules must be
	// equal across runs.
	for i := range a.Certificates {
		ca, cb := a.Certificates[i], b.Certificates[i]
		if ca.NotAfter != cb.NotAfter || ca.NotBefore != cb.NotBefore {
			t.Errorf("certs[%d] validity window differs across runs", i)
		}
		if ca.SignatureAlg != cb.SignatureAlg {
			t.Errorf("certs[%d].SignatureAlg differs: A=%q B=%q",
				i, ca.SignatureAlg, cb.SignatureAlg)
		}
		if ca.PublicKeyBits != cb.PublicKeyBits {
			t.Errorf("certs[%d].PublicKeyBits differs: A=%d B=%d",
				i, ca.PublicKeyBits, cb.PublicKeyBits)
		}
		if ca.IsSelfSigned != cb.IsSelfSigned {
			t.Errorf("certs[%d].IsSelfSigned differs across runs", i)
		}
	}
}

// TestSmallv01CardinalitiesMatchPreset is the regression
// guardrail for the FleetConfig math. If a future tweak to
// `planCertShapes` silently changes the bucket-sum convention,
// this test catches it before the perf-regression assertions
// downstream do.
func TestSmallv01CardinalitiesMatchPreset(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	cfg := Smallv01()
	fleet, err := NewFleetBuilder(1, cfg, now).Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(fleet.Agents) != cfg.AgentCount {
		t.Errorf("agents = %d, want %d", len(fleet.Agents), cfg.AgentCount)
	}
	if len(fleet.Certificates) != cfg.CertCount {
		t.Errorf("certs = %d, want %d", len(fleet.Certificates), cfg.CertCount)
	}
	// Observations: every agent observes between 1 and
	// `CertsPerAgent * StoresPerAgent` rows. Lower bound is
	// loose because tail-cert overlap can shorten the picks
	// map; the upper bound is the cap the builder enforces.
	wantMin := cfg.AgentCount
	wantMax := cfg.AgentCount * cfg.CertsPerAgent * cfg.StoresPerAgent
	if got := len(fleet.Observations); got < wantMin || got > wantMax {
		t.Errorf("observations = %d, want in [%d, %d]", got, wantMin, wantMax)
	}
}

// TestGeneratedPEMParses confirms every cert byte in the
// fixture round-trips through `crypto/x509.ParseCertificate`.
// The ingestion service's parser will reject anything that
// fails this check, so the fixture's contract is "every PEM
// is real X.509".
func TestGeneratedPEMParses(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	fleet, err := NewFleetBuilder(7, Smallv01(), now).Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for i, c := range fleet.Certificates {
		block, _ := pem.Decode([]byte(c.PEM))
		if block == nil {
			t.Fatalf("cert[%d]: pem.Decode returned nil block", i)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatalf("cert[%d]: parse: %v", i, err)
		}
	}
}

// TestRuleDistributionShape is a sanity check on the bucket
// math: each non-zero ratio in the preset must produce at
// least one rule-matching cert when applied to a small
// fixture. Catches regressions where a future refactor zeros
// out a bucket (e.g. by misordering append calls in
// `planCertShapes`).
func TestRuleDistributionShape(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	cfg := Smallv01()
	fleet, err := NewFleetBuilder(11, cfg, now).Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var expired, expiringSoon, weakKey, weakSig, selfSigned, longLived int
	for _, c := range fleet.Certificates {
		switch {
		case c.NotAfter.Before(now):
			expired++
		case c.NotAfter.After(now) && c.NotAfter.Before(now.Add(31*24*time.Hour)):
			expiringSoon++
		case c.PublicKeyBits < 2048:
			weakKey++
		case c.SignatureAlg == "SHA1-RSA" || c.SignatureAlg == "MD5-RSA":
			weakSig++
		case c.IsSelfSigned && !c.IsCA:
			selfSigned++
		case c.NotAfter.Sub(c.NotBefore) > 398*24*time.Hour:
			longLived++
		}
	}
	// At Smallv01 ratios all six buckets should have at least
	// one match; allow zero for buckets whose ratio rounds
	// floor() to zero (CertCount * 0.05 = 3 for the v0.1
	// preset, so all rounded buckets fire).
	for name, n := range map[string]int{
		"expired":      expired,
		"expiringSoon": expiringSoon,
		"weakKey":      weakKey,
		"weakSig":      weakSig,
		"selfSigned":   selfSigned,
		"longLived":    longLived,
	} {
		if n == 0 {
			t.Errorf("bucket %s = 0, want >= 1 in Smallv01", name)
		}
	}
}

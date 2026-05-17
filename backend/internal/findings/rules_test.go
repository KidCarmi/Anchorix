package findings

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// fixedNow is the deterministic clock anchor used by every
// boundary test below. Wall-clock-free.
var fixedNow = time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)

// healthyCert is the baseline summary all rules should NOT
// match. Each rule's tests start from this baseline and mutate
// the one field they care about.
func healthyCert() inventory.CertificateSummary {
	return inventory.CertificateSummary{
		ID:                "healthy-cert",
		FingerprintSHA256: "abc123",
		Subject:           "CN=ok.example",
		Issuer:            "CN=Issuer",
		SerialNumberHex:   "01",
		SignatureAlg:      "SHA256-RSA",
		PublicKeyAlg:      "RSA",
		PublicKeyBits:     2048,
		NotBefore:         fixedNow.Add(-30 * 24 * time.Hour),
		NotAfter:          fixedNow.Add(180 * 24 * time.Hour), // outside expiring-soon window
		IsSelfSigned:      false,
		IsCA:              false,
	}
}

// --- certificate_expired ------------------------------------------

func TestRuleCertificateExpired_MatchesPastNotAfter(t *testing.T) {
	cert := healthyCert()
	cert.NotAfter = fixedNow.Add(-1 * time.Second)
	m := ruleCertificateExpired{}.Evaluate(&cert, fixedNow)
	if m == nil {
		t.Fatal("rule did not match a clearly-expired cert")
	}
}

func TestRuleCertificateExpired_DoesNotMatchExactBoundary(t *testing.T) {
	// not_after == now is NOT yet expired — the interval is
	// half-open at the upper bound. A separate test pins this
	// because the implementation uses `now.After(NotAfter)` not
	// `now.Equal(NotAfter)`.
	cert := healthyCert()
	cert.NotAfter = fixedNow
	if m := (ruleCertificateExpired{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("expected no match at exact-now boundary; got %+v", m)
	}
}

func TestRuleCertificateExpired_DoesNotMatchFuture(t *testing.T) {
	cert := healthyCert()
	if m := (ruleCertificateExpired{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("expected no match for future cert; got %+v", m)
	}
}

// --- certificate_expiring_soon -------------------------------------

func TestRuleCertificateExpiringSoon_MatchesWithinWindow(t *testing.T) {
	cert := healthyCert()
	cert.NotAfter = fixedNow.Add(7 * 24 * time.Hour) // 7 days, inside 30-day window
	m := ruleCertificateExpiringSoon{}.Evaluate(&cert, fixedNow)
	if m == nil {
		t.Fatal("rule did not match a cert 7 days from expiry")
	}
}

func TestRuleCertificateExpiringSoon_MatchesExactWindowBoundary(t *testing.T) {
	// not_after == now + 30 days is INSIDE the window. The
	// implementation uses strictly-greater-than for the
	// out-of-window check, so the 30-day boundary matches.
	cert := healthyCert()
	cert.NotAfter = fixedNow.Add(expiringSoonWindow)
	m := ruleCertificateExpiringSoon{}.Evaluate(&cert, fixedNow)
	if m == nil {
		t.Fatal("expected match at exact 30-day boundary")
	}
}

func TestRuleCertificateExpiringSoon_DoesNotMatchOutsideWindow(t *testing.T) {
	cert := healthyCert()
	cert.NotAfter = fixedNow.Add(expiringSoonWindow + time.Hour)
	if m := (ruleCertificateExpiringSoon{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("expected no match outside 30-day window; got %+v", m)
	}
}

func TestRuleCertificateExpiringSoon_DoesNotMatchAlreadyExpired(t *testing.T) {
	// An already-expired cert is owned by the expired rule, not
	// the expiring-soon rule. The two rules are intentionally
	// non-overlapping.
	cert := healthyCert()
	cert.NotAfter = fixedNow.Add(-1 * time.Hour)
	if m := (ruleCertificateExpiringSoon{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("expected no match for already-expired cert; got %+v", m)
	}
}

func TestRuleCertificateExpiringSoon_DoesNotMatchExactBoundaryExpired(t *testing.T) {
	// not_after == now is at the expired/expiring boundary.
	// The expiring-soon rule must NOT match (cert.NotAfter.After(now)
	// is false), leaving the expired rule to also NOT match (its
	// boundary is `now.After(NotAfter)` which is also false at
	// equality). Together this means a cert with not_after exactly
	// equal to now produces ZERO findings; a 1-second-later
	// recompute fires certificate_expired.
	cert := healthyCert()
	cert.NotAfter = fixedNow
	if m := (ruleCertificateExpiringSoon{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("expected no match at exact-now boundary; got %+v", m)
	}
}

// --- weak_signature_algorithm --------------------------------------

func TestRuleWeakSignatureAlgorithm_MatchesSHA1(t *testing.T) {
	cases := []string{"SHA1-RSA", "SHA1WithRSA", "ecdsa-sha1", "sha1-RSA"}
	for _, s := range cases {
		cert := healthyCert()
		cert.SignatureAlg = s
		m := ruleWeakSignatureAlgorithm{}.Evaluate(&cert, fixedNow)
		if m == nil {
			t.Errorf("expected match for SignatureAlg=%q", s)
			continue
		}
		var ev weakSigEvidence
		if err := json.Unmarshal(m.Evidence, &ev); err != nil {
			t.Errorf("evidence unmarshal: %v", err)
			continue
		}
		if ev.WeakHash != "SHA1" {
			t.Errorf("SignatureAlg=%q: weak_hash=%q, want SHA1", s, ev.WeakHash)
		}
	}
}

func TestRuleWeakSignatureAlgorithm_MatchesMD5(t *testing.T) {
	cert := healthyCert()
	cert.SignatureAlg = "MD5-RSA"
	m := ruleWeakSignatureAlgorithm{}.Evaluate(&cert, fixedNow)
	if m == nil {
		t.Fatal("expected match for MD5 signature")
	}
	var ev weakSigEvidence
	_ = json.Unmarshal(m.Evidence, &ev)
	if ev.WeakHash != "MD5" {
		t.Errorf("weak_hash = %q, want MD5", ev.WeakHash)
	}
}

func TestRuleWeakSignatureAlgorithm_DoesNotMatchStrongHashes(t *testing.T) {
	for _, s := range []string{"SHA256-RSA", "SHA384-RSA", "SHA512-ECDSA", "Ed25519"} {
		cert := healthyCert()
		cert.SignatureAlg = s
		if m := (ruleWeakSignatureAlgorithm{}).Evaluate(&cert, fixedNow); m != nil {
			t.Errorf("unexpected match for strong SignatureAlg=%q", s)
		}
	}
}

// --- weak_rsa_key --------------------------------------------------

func TestRuleWeakRSAKey_MatchesBelowThreshold(t *testing.T) {
	for _, bits := range []int{512, 1024, 1536, 2047} {
		cert := healthyCert()
		cert.PublicKeyBits = bits
		m := ruleWeakRSAKey{}.Evaluate(&cert, fixedNow)
		if m == nil {
			t.Errorf("expected match for RSA %d", bits)
		}
	}
}

func TestRuleWeakRSAKey_DoesNotMatchAtThreshold(t *testing.T) {
	// Exact 2048 is NOT weak (rule uses strict <).
	cert := healthyCert()
	cert.PublicKeyBits = 2048
	if m := (ruleWeakRSAKey{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("unexpected match for RSA 2048; got %+v", m)
	}
}

func TestRuleWeakRSAKey_DoesNotMatchECDSA(t *testing.T) {
	// Non-RSA keys are out of scope — even a tiny ECDSA curve
	// must NOT trigger this rule (a future rule would handle it).
	cert := healthyCert()
	cert.PublicKeyAlg = "ECDSA"
	cert.PublicKeyBits = 256
	if m := (ruleWeakRSAKey{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("unexpected match for ECDSA 256; got %+v", m)
	}
}

// --- self_signed_leaf ----------------------------------------------

func TestRuleSelfSignedLeaf_MatchesSelfSignedLeaf(t *testing.T) {
	cert := healthyCert()
	cert.IsSelfSigned = true
	cert.IsCA = false
	m := ruleSelfSignedLeaf{}.Evaluate(&cert, fixedNow)
	if m == nil {
		t.Fatal("expected match for self-signed leaf")
	}
}

func TestRuleSelfSignedLeaf_DoesNotMatchSelfSignedCA(t *testing.T) {
	// Self-signed CAs are operationally normal (they ARE roots).
	cert := healthyCert()
	cert.IsSelfSigned = true
	cert.IsCA = true
	if m := (ruleSelfSignedLeaf{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("unexpected match for self-signed CA")
	}
}

func TestRuleSelfSignedLeaf_DoesNotMatchSignedLeaf(t *testing.T) {
	cert := healthyCert()
	cert.IsSelfSigned = false
	cert.IsCA = false
	if m := (ruleSelfSignedLeaf{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("unexpected match for properly-signed leaf")
	}
}

// --- long_lived_certificate ----------------------------------------

func TestRuleLongLivedCertificate_MatchesLongLivedLeaf(t *testing.T) {
	cert := healthyCert()
	cert.NotBefore = fixedNow.Add(-200 * 24 * time.Hour)
	cert.NotAfter = fixedNow.Add(400 * 24 * time.Hour)
	m := ruleLongLivedCertificate{}.Evaluate(&cert, fixedNow)
	if m == nil {
		t.Fatal("expected match for 600-day validity leaf")
	}
}

func TestRuleLongLivedCertificate_DoesNotMatchAtThreshold(t *testing.T) {
	// Exactly 398 days is NOT long-lived (rule uses strict >).
	cert := healthyCert()
	cert.NotBefore = fixedNow
	cert.NotAfter = fixedNow.Add(longLivedThreshold)
	if m := (ruleLongLivedCertificate{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("unexpected match at 398-day boundary")
	}
}

func TestRuleLongLivedCertificate_DoesNotMatchCA(t *testing.T) {
	// CAs are scoped out — they legitimately have long lifetimes.
	cert := healthyCert()
	cert.IsCA = true
	cert.NotBefore = fixedNow.Add(-365 * 24 * time.Hour)
	cert.NotAfter = fixedNow.Add(10 * 365 * 24 * time.Hour) // 10 years
	if m := (ruleLongLivedCertificate{}).Evaluate(&cert, fixedNow); m != nil {
		t.Errorf("unexpected match for long-lived CA")
	}
}

// --- whole healthy cert ---------------------------------------------

func TestAllRules_HealthyCertProducesNoFindings(t *testing.T) {
	cert := healthyCert()
	for _, rule := range DefaultRules() {
		if m := rule.Evaluate(&cert, fixedNow); m != nil {
			t.Errorf("rule %s unexpectedly matched the healthy cert; evidence=%s",
				rule.ID(), string(m.Evidence))
		}
	}
}

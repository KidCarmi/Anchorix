package findings

import (
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// Rule IDs for the v0.1 deterministic rule set. Stable strings —
// renaming any of these is a breaking change that would orphan
// existing operator filters and saved views.
const (
	RuleCertificateExpired      = "certificate_expired"
	RuleCertificateExpiringSoon = "certificate_expiring_soon"
	RuleWeakSignatureAlgorithm  = "weak_signature_algorithm"
	RuleWeakRSAKey              = "weak_rsa_key"
	RuleSelfSignedLeaf          = "self_signed_leaf"
	RuleLongLivedCertificate    = "long_lived_certificate"
)

// expiringSoonWindow is the threshold "≤ N days until expiry" the
// certificate_expiring_soon rule fires under. 30 days mirrors
// the standard renewal-warning window most operators expect.
const expiringSoonWindow = 30 * 24 * time.Hour

// weakRSAThresholdBits is the lower bound for RSA key size below
// which keys are considered weak. 2048 is the modern minimum
// per NIST SP 800-57 and most public-CA baseline requirements.
const weakRSAThresholdBits = 2048

// longLivedThreshold is the upper bound for leaf cert lifetime
// above which the long_lived_certificate rule fires. 398 days
// mirrors the public-CA Baseline Requirements maximum for
// publicly-trusted leaf certs since 2020. Internal-PKI shops
// frequently issue longer-lived leaves; the rule surfaces them
// as low/medium-severity informational findings, not as
// errors.
const longLivedThreshold = 398 * 24 * time.Hour

// DefaultRules returns the registered v0.1 rule set in
// deterministic order. The composition root passes this slice
// (or a subset) to NewService.
func DefaultRules() []Rule {
	return []Rule{
		ruleCertificateExpired{},
		ruleCertificateExpiringSoon{},
		ruleWeakSignatureAlgorithm{},
		ruleWeakRSAKey{},
		ruleSelfSignedLeaf{},
		ruleLongLivedCertificate{},
	}
}

// --- certificate_expired -------------------------------------------

type ruleCertificateExpired struct{}

func (ruleCertificateExpired) ID() string         { return RuleCertificateExpired }
func (ruleCertificateExpired) Version() int       { return 1 }
func (ruleCertificateExpired) Severity() Severity { return SeverityHigh }
func (ruleCertificateExpired) Title() string      { return "Certificate has expired" }

// Evaluate matches when the certificate's not_after has passed
// `now`. Boundary: a cert whose not_after equals `now` exactly
// is NOT yet expired (interval is half-open at the upper bound).
type certExpiredEvidence struct {
	NotAfter   time.Time `json:"not_after"`
	ExpiredFor string    `json:"expired_for"`
}

func (ruleCertificateExpired) Evaluate(cert *inventory.CertificateSummary, now time.Time) *RuleMatch {
	if !now.After(cert.NotAfter) {
		return nil
	}
	return &RuleMatch{
		Evidence: mustMarshalEvidence(certExpiredEvidence{
			NotAfter:   cert.NotAfter.UTC(),
			ExpiredFor: now.Sub(cert.NotAfter).Truncate(time.Second).String(),
		}),
	}
}

// --- certificate_expiring_soon -------------------------------------

type ruleCertificateExpiringSoon struct{}

func (ruleCertificateExpiringSoon) ID() string         { return RuleCertificateExpiringSoon }
func (ruleCertificateExpiringSoon) Version() int       { return 1 }
func (ruleCertificateExpiringSoon) Severity() Severity { return SeverityMedium }
func (ruleCertificateExpiringSoon) Title() string      { return "Certificate is expiring soon" }

// Evaluate matches when not_after is in the window [now, now + 30d].
// Boundary: cert with not_after exactly equal to `now` is treated
// as "expired" (caught by certificate_expired); a cert whose
// not_after is exactly `now + 30 days` IS in the expiring-soon
// window. The two rules are intentionally non-overlapping.
type certExpiringSoonEvidence struct {
	NotAfter   time.Time `json:"not_after"`
	ExpiresIn  string    `json:"expires_in"`
	WindowDays int       `json:"window_days"`
}

func (ruleCertificateExpiringSoon) Evaluate(cert *inventory.CertificateSummary, now time.Time) *RuleMatch {
	if !cert.NotAfter.After(now) {
		// Already expired — owned by the expired rule.
		return nil
	}
	if cert.NotAfter.Sub(now) > expiringSoonWindow {
		return nil
	}
	return &RuleMatch{
		Evidence: mustMarshalEvidence(certExpiringSoonEvidence{
			NotAfter:   cert.NotAfter.UTC(),
			ExpiresIn:  cert.NotAfter.Sub(now).Truncate(time.Second).String(),
			WindowDays: int(expiringSoonWindow / (24 * time.Hour)),
		}),
	}
}

// --- weak_signature_algorithm --------------------------------------

type ruleWeakSignatureAlgorithm struct{}

func (ruleWeakSignatureAlgorithm) ID() string         { return RuleWeakSignatureAlgorithm }
func (ruleWeakSignatureAlgorithm) Version() int       { return 1 }
func (ruleWeakSignatureAlgorithm) Severity() Severity { return SeverityHigh }
func (ruleWeakSignatureAlgorithm) Title() string {
	return "Certificate uses a weak signature algorithm"
}

// Evaluate matches when the signature algorithm name contains
// "MD5" or "SHA1" (case-insensitive). The Go crypto/x509 package
// formats SignatureAlgorithm strings like "MD5-RSA",
// "SHA1-ECDSA", "SHA1-WithRSA" — a substring check is more
// future-proof than a fixed enum and matches the format the
// inventory parser produces (parse.go uses
// cert.SignatureAlgorithm.String()).
type weakSigEvidence struct {
	SignatureAlgorithm string `json:"signature_algorithm"`
	WeakHash           string `json:"weak_hash"`
}

func (ruleWeakSignatureAlgorithm) Evaluate(cert *inventory.CertificateSummary, now time.Time) *RuleMatch {
	upper := strings.ToUpper(cert.SignatureAlg)
	switch {
	case strings.Contains(upper, "MD5"):
		return &RuleMatch{
			Evidence: mustMarshalEvidence(weakSigEvidence{
				SignatureAlgorithm: cert.SignatureAlg,
				WeakHash:           "MD5",
			}),
		}
	case strings.Contains(upper, "SHA1"):
		return &RuleMatch{
			Evidence: mustMarshalEvidence(weakSigEvidence{
				SignatureAlgorithm: cert.SignatureAlg,
				WeakHash:           "SHA1",
			}),
		}
	}
	return nil
}

// --- weak_rsa_key --------------------------------------------------

type ruleWeakRSAKey struct{}

func (ruleWeakRSAKey) ID() string         { return RuleWeakRSAKey }
func (ruleWeakRSAKey) Version() int       { return 1 }
func (ruleWeakRSAKey) Severity() Severity { return SeverityHigh }
func (ruleWeakRSAKey) Title() string      { return "RSA key below 2048 bits" }

// Evaluate matches when public_key_algorithm is RSA AND key size
// is below 2048 bits. Non-RSA keys (ECDSA, Ed25519, etc.) are
// not in scope for this rule — their own minimums live in
// future findings (out of scope for v0.1).
//
// Boundary: a cert with exactly 2048-bit RSA does NOT match;
// the rule fires only on strict-less-than.
type weakRSAEvidence struct {
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	PublicKeyBits      int    `json:"public_key_bits"`
	ThresholdBits      int    `json:"threshold_bits"`
}

func (ruleWeakRSAKey) Evaluate(cert *inventory.CertificateSummary, now time.Time) *RuleMatch {
	if !strings.EqualFold(cert.PublicKeyAlg, "RSA") {
		return nil
	}
	if cert.PublicKeyBits >= weakRSAThresholdBits {
		return nil
	}
	return &RuleMatch{
		Evidence: mustMarshalEvidence(weakRSAEvidence{
			PublicKeyAlgorithm: cert.PublicKeyAlg,
			PublicKeyBits:      cert.PublicKeyBits,
			ThresholdBits:      weakRSAThresholdBits,
		}),
	}
}

// --- self_signed_leaf ----------------------------------------------

type ruleSelfSignedLeaf struct{}

func (ruleSelfSignedLeaf) ID() string         { return RuleSelfSignedLeaf }
func (ruleSelfSignedLeaf) Version() int       { return 1 }
func (ruleSelfSignedLeaf) Severity() Severity { return SeverityMedium }
func (ruleSelfSignedLeaf) Title() string      { return "Self-signed leaf certificate" }

// Evaluate matches when the cert is self-signed AND not a CA.
// Self-signed CAs are operationally normal (they ARE roots);
// self-signed leaves are an operational smell.
type selfSignedLeafEvidence struct {
	Subject string `json:"subject"`
}

func (ruleSelfSignedLeaf) Evaluate(cert *inventory.CertificateSummary, now time.Time) *RuleMatch {
	if !cert.IsSelfSigned {
		return nil
	}
	if cert.IsCA {
		return nil
	}
	return &RuleMatch{
		Evidence: mustMarshalEvidence(selfSignedLeafEvidence{
			Subject: cert.Subject,
		}),
	}
}

// --- long_lived_certificate ----------------------------------------

type ruleLongLivedCertificate struct{}

func (ruleLongLivedCertificate) ID() string         { return RuleLongLivedCertificate }
func (ruleLongLivedCertificate) Version() int       { return 1 }
func (ruleLongLivedCertificate) Severity() Severity { return SeverityLow }
func (ruleLongLivedCertificate) Title() string      { return "Long-lived leaf certificate" }

// Evaluate matches when the cert is a LEAF (not CA) and its
// validity window (not_after - not_before) exceeds 398 days.
// The 398-day threshold mirrors the public-CA Baseline
// Requirements cap. Long-lived CAs are normal — the rule scopes
// to leaves only.
type longLivedEvidence struct {
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	ValidityDays  int       `json:"validity_days"`
	ThresholdDays int       `json:"threshold_days"`
}

func (ruleLongLivedCertificate) Evaluate(cert *inventory.CertificateSummary, now time.Time) *RuleMatch {
	if cert.IsCA {
		return nil
	}
	validity := cert.NotAfter.Sub(cert.NotBefore)
	if validity <= longLivedThreshold {
		return nil
	}
	return &RuleMatch{
		Evidence: mustMarshalEvidence(longLivedEvidence{
			NotBefore:     cert.NotBefore.UTC(),
			NotAfter:      cert.NotAfter.UTC(),
			ValidityDays:  int(validity / (24 * time.Hour)),
			ThresholdDays: int(longLivedThreshold / (24 * time.Hour)),
		}),
	}
}

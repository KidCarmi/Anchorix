package fixtures

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// certShape carries the parameters one generated cert needs.
// Fields not relevant to a particular cert (e.g., ExpiredAge
// when the cert is "clean") are zero.
type certShape struct {
	// Subject is the canonical name in the certificate
	// subject (and issuer, when SelfSigned).
	Subject string
	// SerialIndex is a monotonic integer rolled into the
	// serial number. Combined with the per-Fleet seed it
	// guarantees unique fingerprints across the run.
	SerialIndex int
	// KeyBits selects the RSA key size. 1024 produces a
	// `weak_rsa_key` rule hit; 2048+ does not.
	KeyBits int
	// SignatureAlg selects the cert signature algorithm.
	// Use x509.MD5WithRSA or x509.SHA1WithRSA to produce
	// `weak_signature_algorithm` hits; SHA256WithRSA is the
	// clean default.
	SignatureAlg x509.SignatureAlgorithm
	// NotBefore / NotAfter define the validity window.
	NotBefore time.Time
	NotAfter  time.Time
	// SelfSigned controls whether the cert is its own
	// issuer (matches `self_signed_leaf` when NOT IsCA).
	SelfSigned bool
	// IsCA marks the cert as a CA in BasicConstraints. Used
	// in concert with SelfSigned to model self-signed roots
	// vs. self-signed leafs.
	IsCA bool
}

// certPEM is the materialized output of cert generation. The
// `Fingerprint` is the SHA-256 of the DER bytes, matching the
// fingerprint policy the ingestion service uses; callers can
// pair the PEM with the fingerprint without re-parsing.
type certPEM struct {
	PEM         string
	Fingerprint string
	Subject     string
	NotBefore   time.Time
	NotAfter    time.Time
}

// keyPool caches RSA keys by bit-size so generating thousands
// of certs does not pay thousands of key-gen costs.
//
// Key material is sourced from `crypto/rand.Reader`, NOT from
// the seeded `math/rand` sources the rest of the fixture uses
// for structural determinism. The fixture's reproducibility
// contract is about row counts, IDs, rule-bucket assignment,
// and observation removed/active flags — not about
// byte-identical PEM bytes. Using crypto/rand here keeps
// CodeQL's `go/insecure-randomness` clean while costing
// nothing the perf/stress tier's assertions actually need.
//
// 1024-bit RSA is intentional for the `weak_rsa_key` rule
// fixture bucket and is suppressed for this single file via
// `.github/codeql/codeql-config.yml`. The rule under test is
// "flag certs with key bits below 2048"; the fixture has to
// produce inputs that fire it.
type keyPool struct {
	keys map[int][]*rsa.PrivateKey
}

func newKeyPool() *keyPool {
	return &keyPool{keys: make(map[int][]*rsa.PrivateKey)}
}

// at returns the i-th key for the given bit-size, generating
// fresh keys as needed. Capping the pool at `poolSize` per
// bit-size keeps memory bounded; the generator reuses keys
// modulo poolSize, which is fine for the fixture (each cert
// has a unique serial / subject so the fingerprint stays
// unique even when the underlying key repeats).
const keyPoolSize = 32

func (p *keyPool) at(bits, i int) (*rsa.PrivateKey, error) {
	if i < 0 {
		i = -i
	}
	idx := i % keyPoolSize
	for len(p.keys[bits]) <= idx {
		k, err := rsa.GenerateKey(cryptorand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("fixtures: rsa.GenerateKey(%d): %w", bits, err)
		}
		p.keys[bits] = append(p.keys[bits], k)
	}
	return p.keys[bits][idx], nil
}

// generateCertificate produces one real, parseable X.509
// certificate as PEM bytes. The signing key comes from the
// pool; the resulting fingerprint is unique because the
// (subject, serial, validity, key) combination is unique per
// shape. Both the key generation and the cert signing read
// from `crypto/rand.Reader` — see `keyPool` for the rationale.
func generateCertificate(pool *keyPool, shape certShape) (*certPEM, error) {
	sigAlg := shape.SignatureAlg
	if sigAlg == x509.UnknownSignatureAlgorithm {
		sigAlg = x509.SHA256WithRSA
	}
	keyBits := shape.KeyBits
	if keyBits == 0 {
		keyBits = 2048
	}

	signingKey, err := pool.at(keyBits, shape.SerialIndex)
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(int64(shape.SerialIndex) + 1),
		Subject:      pkix.Name{CommonName: shape.Subject},
		NotBefore:    shape.NotBefore,
		NotAfter:     shape.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// ExtKeyUsage ServerAuth matches what real Windows
		// host identity certs typically carry. The
		// findings rule set does not gate on this; setting
		// it keeps the certs realistic for any future rule
		// that does.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{shape.Subject},
		SignatureAlgorithm:    sigAlg,
		IsCA:                  shape.IsCA,
		BasicConstraintsValid: true,
	}

	// Self-signed: issuer == subject, signed by own key.
	// CA-style root: same shape with IsCA=true. Non-self-signed
	// leafs share a fixture-internal "issuing CA" by reusing
	// the next key in the pool as the signer; the issuing CA
	// is implicit (we don't store the CA cert itself — the
	// findings rules in v0.1 don't care about chain validity).
	parent := &tmpl
	signerKey := signingKey
	if !shape.SelfSigned {
		// Use a stable distinct subject for the issuer so
		// the issuer string differs from the subject (so
		// the `is_self_signed` heuristic on subject==issuer
		// stays honest). The actual issuer key is the same
		// pooled key shifted by one — keeps generation
		// cheap and the cert valid X.509.
		issuerSubject := "CN=Anchorix Fixture Issuing CA"
		issuerTmpl := tmpl
		issuerTmpl.Subject = pkix.Name{CommonName: issuerSubject}
		issuerTmpl.IsCA = true
		issuerTmpl.BasicConstraintsValid = true
		parent = &issuerTmpl
		// Pick a different key for the issuer to avoid the
		// subject==issuer-but-different-key collision the
		// `is_self_signed` rule warns about.
		signerKey, err = pool.at(keyBits, shape.SerialIndex+keyPoolSize/2)
		if err != nil {
			return nil, err
		}
	}

	der, err := x509.CreateCertificate(cryptorand.Reader, &tmpl, parent, &signingKey.PublicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("fixtures: x509.CreateCertificate(%q): %w", shape.Subject, err)
	}

	// Round-trip through the parser to confirm the bytes are
	// what the ingestion service will accept. Reject early on
	// any mismatch so a fixture bug fails the test
	// deterministically rather than corrupting downstream
	// assertions.
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("fixtures: parse generated cert: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parsed.Raw})

	return &certPEM{
		PEM:         string(pemBytes),
		Fingerprint: sha256Hex(parsed.Raw),
		Subject:     parsed.Subject.CommonName,
		NotBefore:   parsed.NotBefore,
		NotAfter:    parsed.NotAfter,
	}, nil
}

// sha256Hex returns the hex-encoded SHA-256 of the input.
// Matches the fingerprint encoding the ingestion service
// stores in `certificates.fingerprint_sha256`, so a fixture
// cert's reported fingerprint round-trips byte-identically
// through ingestion.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

package fixtures

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"math/rand"
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
// of certs does not pay thousands of key-gen costs. Keys are
// generated with the seeded reader, so the same `(seed, bits,
// index)` always yields the same key.
type keyPool struct {
	src  io.Reader
	keys map[int][]*rsa.PrivateKey
}

func newKeyPool(src io.Reader) *keyPool {
	return &keyPool{src: src, keys: make(map[int][]*rsa.PrivateKey)}
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
		k, err := rsa.GenerateKey(p.src, bits)
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
// shape.
func generateCertificate(pool *keyPool, src io.Reader, shape certShape) (*certPEM, error) {
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

	der, err := x509.CreateCertificate(src, &tmpl, parent, &signingKey.PublicKey, signerKey)
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

// deterministicReader adapts a seeded math/rand source into an
// io.Reader so crypto/x509 and crypto/rsa can consume it.
// *rand.Rand already implements Read(p) (n, error), so the
// type itself is the adapter; we just give it a named
// constructor for readability.
func deterministicReader(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
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

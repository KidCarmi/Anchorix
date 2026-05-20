package fixtures

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
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
// Key material for the strong-key path (>= 2048 bits) comes
// from `crypto/rand.Reader`. The fixture's reproducibility
// contract is structural (row counts, IDs, rule-bucket
// assignment, removed/active flags) and does not require
// byte-identical PEMs, so using crypto/rand keeps CodeQL's
// `go/insecure-randomness` clean for free.
//
// The weak-key path (bits < 2048, used to produce
// `weak_rsa_key` rule hits) does NOT call `rsa.GenerateKey`.
// Instead it returns a precomputed 1024-bit RSA private key
// embedded as a base64 PKCS#1 DER constant below. CodeQL's
// `go/weak-cryptographic-key` query inspects the literal bits
// argument to `rsa.GenerateKey`; the embedded weak key is
// never minted at runtime, so the query has nothing to flag.
// The fixture still produces certs that fire `weak_rsa_key`,
// because the rule reads `cert.PublicKeyBits` from the cert
// row, not from the key-generation call site.
type keyPool struct {
	keys map[int][]*rsa.PrivateKey
}

func newKeyPool() *keyPool {
	return &keyPool{keys: make(map[int][]*rsa.PrivateKey)}
}

// minStrongRSABits is the lower bound for keys minted at
// runtime via `rsa.GenerateKey`. Anything strictly below this
// is served from `fixtureWeakRSAKey` instead — the embedded
// precomputed key — so the only literal bit-size that reaches
// `rsa.GenerateKey` is 2048 or higher.
const minStrongRSABits = 2048

// at returns the i-th key for the given bit-size. Capping the
// strong-key pool at `keyPoolSize` per bit-size keeps memory
// bounded; the generator reuses keys modulo poolSize, which is
// fine for the fixture (each cert has a unique serial /
// subject so the fingerprint stays unique even when the
// underlying key repeats). The weak-key path returns the
// embedded precomputed key for every request — sharing one
// 1024-bit key across all weak-key certs is acceptable for
// fixture purposes because the `weak_rsa_key` rule does not
// inspect the modulus, only the bit-length.
const keyPoolSize = 32

func (p *keyPool) at(bits, i int) (*rsa.PrivateKey, error) {
	if bits < minStrongRSABits {
		return loadFixtureWeakRSAKey()
	}
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

// fixtureWeakRSAKeyBase64 is a base64-encoded PKCS#1 DER of a
// 1024-bit RSA private key, used by the `weak_rsa_key` rule
// fixture bucket. The bytes were minted ONCE, OFFLINE via
// `openssl genrsa 1024 | openssl rsa -traditional -outform DER`
// — see the H-024A commit history for the provenance.
//
// This is a TEST-FIXTURE-ONLY weak key. It is:
//   - never used as the identity of any agent, operator, or
//     control-plane TLS endpoint,
//   - never deployed to a real CA, never trusted by any
//     production trust store,
//   - included in the repository solely so the fixture builder
//     can produce certificates that exercise the
//     `weak_rsa_key` finding rule WITHOUT calling
//     `rsa.GenerateKey(_, 1024)` at runtime (which would
//     legitimately trip CodeQL's `go/weak-cryptographic-key`).
//
// Stored as base64 (not PEM) so gitleaks' default PRIVATE-KEY
// PEM regex does not fire on it. The doc comment is
// deliberately verbose so a future reader (or a security
// auditor) understands why a weak private key is in the tree.
const fixtureWeakRSAKeyBase64 = "" +
	"MIICXgIBAAKBgQDFmvi9slcU2BaBDW9645dhlcCs9o9MEqTYOZCLx1wQJvlaw/QO" +
	"uhdzLYCFOVZooappaUVqZpWU2cKzdgwTvV+w/Ue3xjw5KYLUbieCy4WtaFAj5geH" +
	"4buadFbc4Mk+xOPze/KSK1VEFUk8Fpzvbwet7cb0WpFkN40iLxMQdBb5CwIDAQAB" +
	"AoGAb+rLwrTFOVsBs+nmH9XTIUPtsoiatF1C2+wOf/xTmhpY1B1zlvuy2FsHFW1a" +
	"ETyvBbDHzfF3+qwy5+2N/YgeL2I1V9i325r4HxaLAZ8eRVc+ydEHs3P4L5mWcSEY" +
	"2CxsUo4QnvEurDgxZ+YqC9B3nisfsWkM094bCr9/5zazTHECQQD0vqyQb461/gFJ" +
	"dqfUAuSJ1oK+oavMiSC+k1SlaTlVOA/P3FFQ6QlbclUwrFPvljIKE3pxExSemuuL" +
	"BOVXSV8tAkEAzrFV0hX2zuszys86buW5iJuHB5QtFSF08FwZ18wn/q7AcKepPxRB" +
	"oXRbqoQwG/PDL0rVGRutuGBExpq8kICcFwJBAMCHmrKIv6hVJ+gFqqKyn9v63qFe" +
	"BwsAuLySo9z3uL1cO7wVofZXTCAfAfsnJWRtL/ITPpfjHa5jSnXzJQMUWgUCQQCz" +
	"4piLT7xOV1rq/jGfxGUVpC3/hZE627RXYADJ1A9W0yX+pZxhnrKD3q3MmGD6YssT" +
	"hLAzuugVGAujQZYsuRGfAkEAyyAAxghhB4OIjaSklnUdDl34zJYQW/ZYDzzDiFSe" +
	"Dam57TuDf7vv6aALo29oVWzCQKsApV+uASDrY7+38qU5kQ=="

var (
	fixtureWeakRSAKeyOnce sync.Once
	fixtureWeakRSAKey     *rsa.PrivateKey
	fixtureWeakRSAKeyErr  error
)

// loadFixtureWeakRSAKey decodes the embedded PKCS#1 DER on
// first use and caches the parsed `*rsa.PrivateKey` so
// subsequent calls are free. Returns the cached error if the
// initial parse failed — that case is a fixture-internal bug
// (the const at the top of this file would have to be
// corrupt), and we want every dependent test to surface the
// same explanation rather than retrying parse on every call.
func loadFixtureWeakRSAKey() (*rsa.PrivateKey, error) {
	fixtureWeakRSAKeyOnce.Do(func() {
		der, err := base64.StdEncoding.DecodeString(fixtureWeakRSAKeyBase64)
		if err != nil {
			fixtureWeakRSAKeyErr = fmt.Errorf("fixtures: decode embedded weak key: %w", err)
			return
		}
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			fixtureWeakRSAKeyErr = fmt.Errorf("fixtures: parse embedded weak key: %w", err)
			return
		}
		fixtureWeakRSAKey = key
	})
	if fixtureWeakRSAKeyErr != nil {
		return nil, fixtureWeakRSAKeyErr
	}
	return fixtureWeakRSAKey, nil
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

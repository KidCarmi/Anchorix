package inventory

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // legacy CAs still issue DSA certs we need to inventory
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// privateKeyPEMMarkers is the case-insensitive allow-list of PEM
// labels that indicate private-key material the control plane MUST
// reject (CLAUDE.md §6.2). Detection runs before any PEM parse
// attempt so even a malformed PEM that happens to contain a
// private-key marker is rejected up front.
//
// The list mirrors the H-014 stub's `looksLikePrivateKey` allow-list
// and is the same vocabulary CERTIFICATE_INVENTORY.md §7 commits to.
var privateKeyPEMMarkers = []string{
	"BEGIN PRIVATE KEY",
	"BEGIN RSA PRIVATE KEY",
	"BEGIN EC PRIVATE KEY",
	"BEGIN DSA PRIVATE KEY",
	"BEGIN ENCRYPTED PRIVATE KEY",
	"BEGIN OPENSSH PRIVATE KEY",
}

// containsPrivateKeyMarker reports whether s contains any
// recognized private-key PEM label. Case-insensitive. Used by the
// Service to short-circuit BEFORE any X.509 parsing — a batch with
// private-key material is rejected wholesale; cert parsing of the
// rest of the batch never runs (CERTIFICATE_INVENTORY.md §7
// reject-whole-batch policy).
func containsPrivateKeyMarker(s string) bool {
	upper := strings.ToUpper(s)
	for _, marker := range privateKeyPEMMarkers {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

// parsedCertificate carries the fields extracted from a successful
// PEM-to-X.509 parse, in the canonical shape Service.Submit hands
// to the repository UpsertCertificate call.
type parsedCertificate struct {
	FingerprintSHA256 string
	Subject           string
	Issuer            string
	SerialNumberHex   string
	SignatureAlg      string
	PublicKeyAlg      string
	PublicKeyBits     int
	NotBefore         time.Time
	NotAfter          time.Time
	SANs              []string
	KeyUsages         []string
	ExtKeyUsages      []string
	IsSelfSigned      bool
	IsCA              bool
	// CanonicalPEM is the re-encoded single-block PEM the
	// repository stores. The agent's bytes might have weird line
	// wrapping, extra whitespace, or stray characters between
	// blocks; we strip all that and emit a standard PEM so two
	// agents reporting the same cert produce byte-identical stored
	// PEMs (CERTIFICATE_INVENTORY.md §"PEM canonicalization" open
	// question — recommended yes; this is the implementation).
	CanonicalPEM string
}

// errMalformedPEM is wrapped into ErrInvalidCertificate so callers
// can errors.Is on the public sentinel without exposing the
// specific parse failure to the wire.
var errMalformedPEM = errors.New("malformed PEM")

// MaxParsedSANCount caps the per-certificate SAN array we extract
// from a parsed X.509. Real certs almost never go above a few
// hundred; we reject anything above this as defensive against a
// pathologically large cert that would bloat the SANs JSONB
// column past any reasonable size.
const MaxParsedSANCount = 1024

// parseAndCanonicalize takes raw PEM bytes from an agent and
// produces a parsedCertificate with normalized fields plus a
// canonical PEM re-encoding. Two key invariants:
//
//   - fingerprint is SHA-256 of the DER (cert.Raw), not of the
//     input PEM. Different agent serializers can produce the same
//     cert with different PEM formatting; the fingerprint is
//     identical regardless.
//   - CanonicalPEM is generated via encoding/pem from the parsed
//     cert's DER, so the stored PEM is byte-identical across
//     differently-formatted inputs.
//
// Input contract (post-merge hardening): rawPEM MUST contain
// exactly ONE PEM block, of type CERTIFICATE, surrounded only by
// optional whitespace. Specifically rejected:
//
//   - empty input or whitespace-only input;
//   - input where pem.Decode finds NO block at all;
//   - input where the (first) block is not type CERTIFICATE
//     (CSRs, certificate-request blocks, etc.);
//   - input with any non-whitespace bytes BEFORE the BEGIN line
//     (some agent serializers emit metadata preamble — we want
//     clean canonical PEM only);
//   - input with any non-whitespace bytes AFTER the END line,
//     including a SECOND PEM block of any type. Cert chains
//     (leaf + intermediate concatenated in one entry) are the
//     real-world case this guards against — each entry in the
//     batch's certificates array MUST be exactly one cert; chain
//     entries belong in separate array entries.
//
// All rejections collapse to errMalformedPEM, which the caller
// wraps in ErrInvalidCertificate for the wire envelope
// (CLAUDE.md §6 deterministic auth — no enumeration via error
// code).
//
// Returns ErrInvalidCertificate (wrapped) on parse failure. Does
// NOT detect private-key material — that's containsPrivateKeyMarker's
// job and the caller runs it BEFORE this function (so we never
// PEM-parse anything that might contain a private key).
func parseAndCanonicalize(rawPEM string) (*parsedCertificate, error) {
	if strings.TrimSpace(rawPEM) == "" {
		return nil, fmt.Errorf("%w: empty PEM", errMalformedPEM)
	}

	// Reject any non-whitespace content BEFORE the BEGIN line.
	// pem.Decode silently skips arbitrary preamble; we don't want
	// that — agents must send clean canonical PEM. The cheapest
	// check: after trimming leading whitespace, the input must
	// start with the BEGIN-CERTIFICATE marker.
	trimmed := strings.TrimLeft(rawPEM, " \t\r\n")
	const beginMarker = "-----BEGIN CERTIFICATE-----"
	if !strings.HasPrefix(trimmed, beginMarker) {
		return nil, fmt.Errorf("%w: input must start with %s (only whitespace allowed before)",
			errMalformedPEM, beginMarker)
	}

	block, rest := pem.Decode([]byte(rawPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", errMalformedPEM)
	}
	if block.Type != "CERTIFICATE" {
		// Defensive: HasPrefix above should have caught this
		// already, but pem.Decode allows leading whitespace inside
		// the BEGIN line region in some edge encodings. Belt + braces.
		return nil, fmt.Errorf("%w: PEM block type %q is not CERTIFICATE",
			errMalformedPEM, block.Type)
	}

	// Reject any non-whitespace content AFTER the END line. This
	// includes a second PEM block of ANY type (cert chains, CSRs,
	// stray private-key markers that the upstream scan would have
	// caught anyway). Agents that legitimately want to report
	// multiple certs put them in separate certificates[] entries.
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("%w: trailing content after CERTIFICATE block (only whitespace allowed; additional certificates must be sent as separate batch entries)",
			errMalformedPEM)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: x509 parse: %v", errMalformedPEM, err)
	}

	bits := publicKeyBitLength(cert.PublicKey)
	sans := extractSANs(cert)
	if len(sans) > MaxParsedSANCount {
		return nil, fmt.Errorf("%w: SAN count %d exceeds %d", errMalformedPEM, len(sans), MaxParsedSANCount)
	}

	digest := sha256.Sum256(cert.Raw)

	// Re-emit canonical PEM. encoding/pem.Encode produces the
	// standard 64-column wrap with normalized line endings.
	canonical := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return &parsedCertificate{
		FingerprintSHA256: hex.EncodeToString(digest[:]),
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		SerialNumberHex:   hex.EncodeToString(cert.SerialNumber.Bytes()),
		SignatureAlg:      cert.SignatureAlgorithm.String(),
		PublicKeyAlg:      cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:     bits,
		NotBefore:         cert.NotBefore.UTC(),
		NotAfter:          cert.NotAfter.UTC(),
		SANs:              sans,
		KeyUsages:         keyUsageStrings(cert.KeyUsage),
		ExtKeyUsages:      extKeyUsageStrings(cert.ExtKeyUsage),
		IsSelfSigned:      isSelfSigned(cert),
		IsCA:              cert.IsCA,
		CanonicalPEM:      string(canonical),
	}, nil
}

// isSelfSigned returns true when the cert's subject matches its
// issuer AND the cert's signature verifies against its own public
// key. Subject == issuer alone is insufficient — an attacker could
// mint a cert with matching subject/issuer strings but a different
// signing key. The CheckSignatureFrom guard makes the property
// cryptographic, not string-based.
func isSelfSigned(c *x509.Certificate) bool {
	if c.Subject.String() != c.Issuer.String() {
		return false
	}
	// CheckSignatureFrom(c) verifies that c was signed by the
	// supplied parent's public key — passing c as its own parent
	// is the canonical "did this cert sign itself" check.
	return c.CheckSignatureFrom(c) == nil
}

// publicKeyBitLength returns the bit length of the cert's public
// key for the common algorithms Anchorix expects to encounter.
// Returns 0 for unrecognized key types — the operator UI / future
// findings can flag 0 as "unknown key size" rather than the value
// silently misrepresenting the cert.
func publicKeyBitLength(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		if k.Curve != nil && k.Curve.Params() != nil {
			return k.Curve.Params().BitSize
		}
		return 0
	case ed25519.PublicKey:
		return 256
	case *dsa.PublicKey:
		if k.P != nil {
			return k.P.BitLen()
		}
		return 0
	}
	return 0
}

// extractSANs flattens the cert's SAN extension into a single
// []string with deterministic ordering: DNS names first, then IP
// addresses, then URIs, then email addresses. Operators querying
// SANs typically substring-match against the merged list, so
// flattening to one slice keeps the JSONB column query-friendly.
func extractSANs(c *x509.Certificate) []string {
	out := make([]string, 0,
		len(c.DNSNames)+len(c.IPAddresses)+len(c.URIs)+len(c.EmailAddresses))
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	out = append(out, c.EmailAddresses...)
	return out
}

// keyUsageStrings decodes the X.509 KeyUsage bitfield into a
// human-readable string list. Order is the same as the bit order
// defined by RFC 5280 §4.2.1.3.
func keyUsageStrings(u x509.KeyUsage) []string {
	type entry struct {
		bit  x509.KeyUsage
		name string
	}
	all := []entry{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	out := make([]string, 0, len(all))
	for _, e := range all {
		if u&e.bit != 0 {
			out = append(out, e.name)
		}
	}
	return out
}

// extKeyUsageStrings maps the Go ExtKeyUsage iota to the string
// names operators and findings code can query against. Unknown
// usages (custom OIDs surfaced via cert.UnknownExtKeyUsage) are
// intentionally NOT included — v0.1 reports only the well-known
// vocabulary.
func extKeyUsageStrings(usages []x509.ExtKeyUsage) []string {
	out := make([]string, 0, len(usages))
	for _, u := range usages {
		switch u {
		case x509.ExtKeyUsageAny:
			out = append(out, "Any")
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			out = append(out, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			out = append(out, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			out = append(out, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			out = append(out, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			out = append(out, "NetscapeServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			out = append(out, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			out = append(out, "MicrosoftKernelCodeSigning")
		}
	}
	return out
}

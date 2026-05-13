package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// bearerTokenBytes is the entropy of a freshly minted bootstrap
// secret or agent credential. 256 bits is more than enough — at
// this entropy any brute-force attack is bounded by the SHA-256
// preimage cost (≈2^256 work) rather than by the search space
// itself.
const bearerTokenBytes = 32

// generateBearerToken returns a new high-entropy bearer token and
// its SHA-256 hash. The caller is responsible for returning the
// plaintext to the requester exactly once and persisting only the
// hash. The plaintext is base64-url (unpadded, strict alphabet) so
// it round-trips cleanly through HTTP JSON and Windows installer
// configuration without escaping.
//
// Bcrypt is deliberately NOT used: bcrypt is calibrated to slow
// brute-force attacks against low-entropy passwords. A 256-bit
// random token has no brute-force surface — SHA-256 is sufficient
// and avoids burning CPU on every enrollment.
func generateBearerToken(rng io.Reader) (plaintext string, hash []byte, err error) {
	if rng == nil {
		rng = rand.Reader
	}
	buf := make([]byte, bearerTokenBytes)
	if _, err := io.ReadFull(rng, buf); err != nil {
		return "", nil, fmt.Errorf("enrollment: read random: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plaintext))
	return plaintext, sum[:], nil
}

// hashBearerToken returns the SHA-256 of plaintext. Used at the
// enrollment HTTP boundary to look up a deployment package by its
// stored bootstrap_secret_hash — the lookup never has to materialize
// the plaintext on the storage side.
func hashBearerToken(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

// hashFingerprint is a thin alias around SHA-256 used for the
// optional installer-supplied machine fingerprint. Kept separate
// from hashBearerToken so a future change to fingerprint hashing
// (e.g. domain-separated HKDF) does not silently affect bearer-token
// verification.
func hashFingerprint(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

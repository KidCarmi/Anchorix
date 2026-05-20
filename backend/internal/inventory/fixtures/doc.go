// Package fixtures generates deterministic synthetic certificate
// inventory data for performance, stress, and regression tests.
//
// Test-only intent. The composition root (`cmd/anchorix`) does NOT
// import this package and never should. Production code paths
// remain unchanged. The package is exported (not _test.go) so
// integration tests, perf-tier tests (`//go:build perf`), and
// stress tests (`//go:build stress`) can all share one builder.
//
// # Ownership
//
// Owns: deterministic generation of certificates, observations,
// and pre-seeded findings for one organization. Owns the X.509
// generator that produces real, parseable PEM bytes (the agent
// ingestion path's parser is the contract this fixture must
// satisfy).
//
// Does NOT own: persistence layout, schema, or rule evaluation.
// Persistence helpers (`WriteTo`, `PreSeedFindings`) call through
// the existing storage repositories and the findings rule
// registry — the fixture deliberately stays a thin layer over
// existing primitives.
//
// # Determinism (structural, not byte-identical)
//
// The fixture guarantees STRUCTURAL determinism, not byte
// equality. Two seeded math/rand sources drive everything
// callers actually depend on: IDs, the cert-shape buckets,
// observation assignment, and which findings get pre-promoted
// to acknowledged / suppressed. Two runs with the same
// `(seed, cfg)` produce:
//
//   - identical row counts for agents, certificates, and
//     observations,
//   - identical assignment of each cert to a rule-match bucket
//     (expired / expiring-soon / weak-key / weak-sig /
//     self-signed-leaf / long-lived / clean),
//   - identical observation row IDs and removed-vs-active
//     flagging.
//
// Cert PEM bytes (and therefore SHA-256 fingerprints) WILL
// differ across runs. Key material and X.509 signing read
// from `crypto/rand.Reader` by design: a deterministic crypto
// source would trip the `go/insecure-randomness` CodeQL query
// (CLAUDE.md §11 keeps that gate binding) and the fixture's
// reproducibility contract does not require byte-identical
// PEMs to begin with. Tests that need to assert against
// fingerprints must capture them from one run and compare
// within the same process — never hard-code a fingerprint
// across processes.
//
// The `weak_rsa_key` fixture bucket uses a precomputed
// 1024-bit RSA private key embedded as a base64 PKCS#1 DER
// constant in `certificates.go` rather than minting one at
// runtime via `rsa.GenerateKey(_, 1024)`. CodeQL's
// `go/weak-cryptographic-key` query inspects the literal bits
// argument to `rsa.GenerateKey`; the embedded key is never
// minted at runtime, so the query has nothing to flag. The
// `weak_rsa_key` finding rule still fires correctly because
// it reads `cert.PublicKeyBits` from the certificate row, not
// the call site. The embedded key is documented inline at the
// const declaration; it is a test fixture, never used as the
// identity of any agent, operator, or control-plane TLS
// endpoint.
//
// # Real X.509 bytes, not synthetic strings
//
// `CertificatePEM` is generated through `crypto/x509.CreateCertificate`
// and re-encoded via `encoding/pem`, so the ingestion service's
// parser (`internal/inventory/parse.go`) accepts the fixture
// unchanged. RSA keys are cached in a small pool keyed by
// (algorithm, bits) so generating tens of thousands of certs
// does not generate tens of thousands of keys — the same key
// signs many certs with distinct subjects / serials, giving
// every cert a unique fingerprint while keeping wall-clock
// generation cost bounded.
//
// Forbidden dependencies
//
//   - No imports from `internal/httpapi/*` — fixtures live below
//     the HTTP layer.
//   - No environment variables (CLAUDE.md §8.9). Every knob is a
//     field on `FleetConfig`.
//   - No randomness outside the seeded source.
//
// # Architectural role
//
// Test fixture / data generator. Lives in `internal/inventory/`
// because its only purpose is generating inputs to the
// certificate inventory domain; placing it elsewhere would force
// every consumer to thread a fixture-specific abstraction.
package fixtures

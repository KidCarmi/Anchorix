package fixtures

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/ids"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// certSummaryFromRow lifts a fixture certRow into the
// inventory.CertificateSummary shape the findings rule registry
// consumes. Observation counts are left at zero — the rules in
// v0.1 do not gate on them, and the pre-seed flow does not need
// to model fleet-wide cardinality for the rule pass.
func certSummaryFromRow(c certRow) inventory.CertificateSummary {
	return inventory.CertificateSummary{
		ID:                c.ID,
		FingerprintSHA256: c.Fingerprint,
		Subject:           c.Subject,
		Issuer:            c.Issuer,
		SerialNumberHex:   c.SerialNumberHex,
		SignatureAlg:      c.SignatureAlg,
		PublicKeyAlg:      c.PublicKeyAlg,
		PublicKeyBits:     c.PublicKeyBits,
		NotBefore:         c.NotBefore,
		NotAfter:          c.NotAfter,
		IsSelfSigned:      c.IsSelfSigned,
		IsCA:              c.IsCA,
	}
}

// agentRow is the seeded representation of one synthetic agent.
// Mirrors the production `agents` table shape just closely
// enough for the fixture writer to insert rows directly —
// fixtures bypass the enrollment HTTP flow for speed, exactly
// like the integration suite's `seedAgent` helper does.
type agentRow struct {
	ID       string
	Hostname string
}

// observationRow is one (agent, cert, store) sighting. Mirrors
// the production `certificate_observations` table shape. The
// builder may set RemovedAt to model the "cert disappeared"
// lineage; nil means active.
type observationRow struct {
	ID            string
	AgentID       string
	CertID        string
	StoreLocation string
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	RemovedAt     *time.Time
}

// certRow is one cert ready for persistence. Carries the
// pre-generated PEM, fingerprint, and rule-relevant metadata
// (signature algorithm, key bits, self-signed flag, validity
// window). Mirrors the production `certificates` row shape;
// fields the rules don't read (SANs, key_usages, etc.) carry
// minimal defaults that the parser accepts.
type certRow struct {
	ID              string
	Fingerprint     string
	Subject         string
	Issuer          string
	SerialNumberHex string
	SignatureAlg    string
	PublicKeyAlg    string
	PublicKeyBits   int
	NotBefore       time.Time
	NotAfter        time.Time
	IsSelfSigned    bool
	IsCA            bool
	PEM             string
}

// Fleet is the immutable, in-memory build product. Callers
// inspect or persist; they never mutate. Two runs of
// `NewFleetBuilder(seed, cfg, now).Build()` produce
// structurally equal Fleets for the same `(seed, cfg, now)`:
// same row counts, same rule-bucket assignment per cert,
// same observation IDs and removed flags. PEM bytes differ
// because key material reads from crypto/rand by design —
// see the package doc.
type Fleet struct {
	Config       FleetConfig
	BuilderNow   time.Time
	Agents       []agentRow
	Certificates []certRow
	Observations []observationRow
}

// FleetBuilder is the constructor entry point. `NewFleetBuilder`
// fixes the seed (the determinism contract) and the config;
// `Build` does the work. The builder type itself is small —
// most of the logic is in `Build` so the package surface stays
// shallow.
type FleetBuilder struct {
	seed int64
	cfg  FleetConfig
	now  time.Time
}

// NewFleetBuilder constructs a builder anchored at `now`. Pass
// the wall-clock anchor explicitly so fixture-driven tests are
// not at the mercy of CI clock drift; production code injects
// `clock.Clock` for the same reason (CLAUDE.md §8.2).
func NewFleetBuilder(seed int64, cfg FleetConfig, now time.Time) *FleetBuilder {
	return &FleetBuilder{seed: seed, cfg: cfg, now: now}
}

// Build materializes the fleet in memory. Returns an error
// only if the underlying cert-generation step fails (a
// fixture-internal bug, not a config-input bug). Cardinality
// math is documented inline so a future tweak to one ratio
// surfaces as a deterministic test failure rather than a
// silent change.
func (b *FleetBuilder) Build() (*Fleet, error) {
	if err := validateConfig(b.cfg); err != nil {
		return nil, err
	}

	// Two seeded math/rand sources drive the parts of the
	// fixture that are required to be reproducible:
	// `shapeSrc` decides which agent observes which cert and
	// which observations are flagged removed; `idSrc` mints
	// row ids. The third axis — key material and X.509
	// signing — deliberately reads from crypto/rand
	// (see `keyPool`), so the fixture's PEM bytes vary across
	// runs but its structural shape does not. The seed
	// offsets (+1, +2) are preserved from the pre-refactor
	// shape so a caller running the same seed before and
	// after the swap sees the same IDs.
	shapeSrc := rand.New(rand.NewSource(b.seed + 1))
	idSrc := rand.New(rand.NewSource(b.seed + 2))

	pool := newKeyPool()

	// Phase 1: agents.
	agents := make([]agentRow, b.cfg.AgentCount)
	for i := range agents {
		agents[i] = agentRow{
			ID:       stableID(idSrc),
			Hostname: fmt.Sprintf("host-%05d.fixture.example", i),
		}
	}

	// Phase 2: cert shapes — decide which rules each cert will
	// fire BEFORE generating the X.509 bytes. The shape ratios
	// from FleetConfig are mutually exclusive across the
	// "weakness" axes so a cert lands in exactly one bucket.
	shapes := planCertShapes(b.cfg, b.now)

	// Phase 3: generate the X.509 bytes for each shape.
	certs := make([]certRow, len(shapes))
	for i, s := range shapes {
		pemOut, err := generateCertificate(pool, s)
		if err != nil {
			return nil, fmt.Errorf("fixtures: generate cert %d: %w", i, err)
		}
		certs[i] = certRow{
			ID:              stableID(idSrc),
			Fingerprint:     pemOut.Fingerprint,
			Subject:         "CN=" + s.Subject,
			Issuer:          issuerStringFor(s),
			SerialNumberHex: fmt.Sprintf("%x", s.SerialIndex+1),
			SignatureAlg:    sigAlgString(s.SignatureAlg),
			PublicKeyAlg:    "RSA",
			PublicKeyBits:   keyBitsOrDefault(s.KeyBits),
			NotBefore:       pemOut.NotBefore,
			NotAfter:        pemOut.NotAfter,
			IsSelfSigned:    s.SelfSigned,
			IsCA:            s.IsCA,
			PEM:             pemOut.PEM,
		}
	}

	// Phase 4: observations. Each agent observes
	// `CertsPerAgent` distinct certs. Picks are deterministic
	// for the seed: the first `SharedCertRatio * CertCount`
	// certs are the "shared pool" every agent draws from with
	// high probability; the rest are tail certs, each owned by
	// roughly one agent.
	observations := planObservations(b.cfg, b.now, agents, certs, shapeSrc, idSrc)

	return &Fleet{
		Config:       b.cfg,
		BuilderNow:   b.now,
		Agents:       agents,
		Certificates: certs,
		Observations: observations,
	}, nil
}

// validateConfig fails closed on shapes that would silently
// produce surprising fixtures (e.g. ratios outside [0, 1] or
// counts that go negative). Returning an error at Build time
// keeps the test that built the fixture in the failing stack
// frame, instead of producing a malformed Fleet downstream.
func validateConfig(cfg FleetConfig) error {
	if cfg.OrganizationID == "" {
		return errors.New("fixtures: OrganizationID required")
	}
	if cfg.AgentCount <= 0 {
		return errors.New("fixtures: AgentCount must be > 0")
	}
	if cfg.CertCount <= 0 {
		return errors.New("fixtures: CertCount must be > 0")
	}
	if cfg.StoresPerAgent <= 0 {
		return errors.New("fixtures: StoresPerAgent must be > 0")
	}
	if cfg.CertsPerAgent <= 0 {
		return errors.New("fixtures: CertsPerAgent must be > 0")
	}
	for _, r := range []struct {
		name string
		val  float64
	}{
		{"SharedCertRatio", cfg.SharedCertRatio},
		{"ExpiredRatio", cfg.ExpiredRatio},
		{"ExpiringSoonRatio", cfg.ExpiringSoonRatio},
		{"WeakKeyRatio", cfg.WeakKeyRatio},
		{"WeakSigRatio", cfg.WeakSigRatio},
		{"SelfSignedLeafRatio", cfg.SelfSignedLeafRatio},
		{"LongLivedRatio", cfg.LongLivedRatio},
		{"RemovedObsRatio", cfg.RemovedObsRatio},
		{"AcknowledgedRatio", cfg.AcknowledgedRatio},
		{"SuppressedRatio", cfg.SuppressedRatio},
	} {
		if r.val < 0 || r.val > 1 {
			return fmt.Errorf("fixtures: %s = %f must be in [0, 1]", r.name, r.val)
		}
	}
	return nil
}

// planCertShapes decides each cert's rule profile up front.
// Buckets are mutually exclusive in this order: expired,
// expiring-soon, weak-key, weak-sig, self-signed-leaf,
// long-lived, clean. A cert that falls inside multiple ratios
// is assigned to the first matching bucket so the final
// distribution is the sum of `floor(ratio * CertCount)` plus a
// "clean" remainder.
func planCertShapes(cfg FleetConfig, now time.Time) []certShape {
	n := cfg.CertCount
	expired := int(float64(n) * cfg.ExpiredRatio)
	expiringSoon := int(float64(n) * cfg.ExpiringSoonRatio)
	weakKey := int(float64(n) * cfg.WeakKeyRatio)
	weakSig := int(float64(n) * cfg.WeakSigRatio)
	selfSignedLeaf := int(float64(n) * cfg.SelfSignedLeafRatio)
	longLived := int(float64(n) * cfg.LongLivedRatio)

	shapes := make([]certShape, 0, n)
	i := 0
	add := func(s certShape) {
		s.SerialIndex = i
		s.Subject = fmt.Sprintf("cert-%05d.fixture.example", i)
		shapes = append(shapes, s)
		i++
	}

	// Expired: NotAfter strictly in the past.
	for k := 0; k < expired; k++ {
		add(certShape{
			NotBefore:    now.Add(-2 * 365 * 24 * time.Hour),
			NotAfter:     now.Add(-30 * 24 * time.Hour),
			SignatureAlg: x509.SHA256WithRSA,
		})
	}
	// Expiring soon: NotAfter in (now, now + 30d].
	for k := 0; k < expiringSoon; k++ {
		add(certShape{
			NotBefore:    now.Add(-180 * 24 * time.Hour),
			NotAfter:     now.Add(15 * 24 * time.Hour),
			SignatureAlg: x509.SHA256WithRSA,
		})
	}
	// Weak key: 1024-bit RSA. Validity is comfortably future
	// so the expired / expiring-soon rules do not also fire on
	// these certs (the fixture aims for one rule per shape).
	for k := 0; k < weakKey; k++ {
		add(certShape{
			KeyBits:      1024,
			NotBefore:    now.Add(-30 * 24 * time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			SignatureAlg: x509.SHA256WithRSA,
		})
	}
	// Weak signature algorithm: SHA1WithRSA. SHA-1 is in the
	// rule's match list (case-insensitive substring on "SHA1").
	for k := 0; k < weakSig; k++ {
		add(certShape{
			NotBefore:    now.Add(-30 * 24 * time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			SignatureAlg: x509.SHA1WithRSA,
		})
	}
	// Self-signed leaf: subject == issuer, NOT IsCA.
	for k := 0; k < selfSignedLeaf; k++ {
		add(certShape{
			NotBefore:    now.Add(-30 * 24 * time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			SignatureAlg: x509.SHA256WithRSA,
			SelfSigned:   true,
			IsCA:         false,
		})
	}
	// Long-lived leaf: (NotAfter - NotBefore) > 398d. The rule
	// uses strict-greater so a cert at exactly 398 days does
	// NOT fire — pick 500 days to land squarely in the match.
	for k := 0; k < longLived; k++ {
		add(certShape{
			NotBefore:    now.Add(-30 * 24 * time.Hour),
			NotAfter:     now.Add(500 * 24 * time.Hour),
			SignatureAlg: x509.SHA256WithRSA,
		})
	}
	// Clean certs fill the remainder. 365-day leaf, 2048-bit
	// RSA, SHA-256.
	for i < n {
		add(certShape{
			NotBefore:    now.Add(-30 * 24 * time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			SignatureAlg: x509.SHA256WithRSA,
		})
	}
	return shapes
}

// planObservations assigns certs to agents and decides which
// observations are marked removed. Determinism is preserved
// because every choice draws from the seeded `shapeSrc` and
// `idSrc` in a fixed order.
func planObservations(
	cfg FleetConfig,
	now time.Time,
	agents []agentRow,
	certs []certRow,
	shapeSrc, idSrc *rand.Rand,
) []observationRow {
	// Stores are a small fixed set drawn from the v0.1
	// CERTIFICATE_INVENTORY.md vocabulary. We pick the first
	// StoresPerAgent entries to keep deterministic behavior.
	stores := []string{
		`LocalMachine\My`,
		`LocalMachine\WebHosting`,
		`LocalMachine\Root`,
		`LocalMachine\CA`,
		`CurrentUser\My`,
	}
	if cfg.StoresPerAgent < len(stores) {
		stores = stores[:cfg.StoresPerAgent]
	}

	// Shared pool: the first `SharedCertRatio * CertCount`
	// certs. Tail: the rest.
	sharedCount := int(float64(len(certs)) * cfg.SharedCertRatio)
	if sharedCount > len(certs) {
		sharedCount = len(certs)
	}

	observations := make([]observationRow, 0, len(agents)*cfg.CertsPerAgent)
	for ai, agent := range agents {
		// Each agent picks CertsPerAgent distinct certs:
		// `CertsPerAgent / 2 + 1` from the shared pool (random
		// indices), plus the remainder from the tail biased
		// toward this agent's index so the tail is spread.
		picks := make(map[int]struct{}, cfg.CertsPerAgent)

		// Shared picks.
		sharedPicks := cfg.CertsPerAgent / 2
		if sharedPicks > sharedCount {
			sharedPicks = sharedCount
		}
		for len(picks) < sharedPicks && sharedCount > 0 {
			picks[shapeSrc.Intn(sharedCount)] = struct{}{}
		}

		// Tail picks. A round-robin starting at the agent's
		// index ensures the tail is fully covered when
		// AgentCount * (CertsPerAgent - sharedPicks) >=
		// (CertCount - sharedCount); otherwise the unpicked
		// tail simply does not appear in observations, which
		// is realistic.
		tailNeeded := cfg.CertsPerAgent - len(picks)
		tailStart := ai
		for k := 0; k < tailNeeded && len(picks) < cfg.CertsPerAgent; k++ {
			tailIdx := sharedCount + ((tailStart + k) % maxInt(1, len(certs)-sharedCount))
			if tailIdx >= len(certs) {
				continue
			}
			picks[tailIdx] = struct{}{}
		}

		// For each picked cert, the agent observes it in a
		// deterministic subset of the configured stores. Sort
		// the picked cert indices before iterating — Go map
		// iteration order is intentionally randomized, and the
		// loop body below consumes from `idSrc` (observation
		// ID minting) and `shapeSrc` (removed-vs-active
		// assignment). Without sorting, two `Build()` calls
		// with the same `(seed, cfg, now)` allocate the same
		// IDs and removed flags but to DIFFERENT picked certs,
		// silently breaking the structural-determinism
		// contract this fixture's doc.go advertises.
		pickedIdx := make([]int, 0, len(picks))
		for certIdx := range picks {
			pickedIdx = append(pickedIdx, certIdx)
		}
		sort.Ints(pickedIdx)
		for _, certIdx := range pickedIdx {
			cert := certs[certIdx]
			storesForCert := stores
			if len(stores) > 1 {
				// Cap stores per (agent, cert) so the
				// observation count does not blow up
				// quadratically. Use one or two stores per
				// observation pair, picked by `(ai+certIdx)
				// % len(stores)`.
				start := (ai + certIdx) % len(stores)
				count := 1
				if (ai+certIdx)%4 == 0 {
					count = 2
				}
				if start+count > len(stores) {
					count = len(stores) - start
				}
				storesForCert = stores[start : start+count]
			}

			for _, store := range storesForCert {
				obs := observationRow{
					ID:            stableID(idSrc),
					AgentID:       agent.ID,
					CertID:        cert.ID,
					StoreLocation: store,
					FirstSeenAt:   now.Add(-7 * 24 * time.Hour),
					LastSeenAt:    now,
				}
				// Mark a deterministic subset as removed.
				// `shapeSrc.Float64() < ratio` keeps the
				// distribution close to the target ratio at
				// any fleet size.
				if cfg.RemovedObsRatio > 0 && shapeSrc.Float64() < cfg.RemovedObsRatio {
					removedAt := now.Add(-24 * time.Hour)
					obs.RemovedAt = &removedAt
				}
				observations = append(observations, obs)
			}
		}
	}
	return observations
}

// stableID returns a 32-hex id derived from the seeded RNG
// rather than `ids.New()` (which uses crypto/rand and would
// reintroduce nondeterminism). Matches the production id
// shape so downstream rows look indistinguishable from
// real-world data.
func stableID(src *rand.Rand) string {
	var buf [16]byte
	_, _ = src.Read(buf[:])
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 32)
	for i, b := range buf {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0x0f]
	}
	return string(out)
}

// Various small string helpers — kept package-private so
// callers do not have to learn the fixture's vocabulary.

func issuerStringFor(s certShape) string {
	if s.SelfSigned {
		return "CN=" + s.Subject
	}
	return "CN=Anchorix Fixture Issuing CA"
}

func sigAlgString(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.SHA1WithRSA:
		return "SHA1-RSA"
	case x509.MD5WithRSA:
		return "MD5-RSA"
	case x509.SHA256WithRSA, x509.UnknownSignatureAlgorithm:
		return "SHA256-RSA"
	case x509.SHA384WithRSA:
		return "SHA384-RSA"
	case x509.SHA512WithRSA:
		return "SHA512-RSA"
	default:
		return alg.String()
	}
}

func keyBitsOrDefault(b int) int {
	if b == 0 {
		return 2048
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// WriteTo persists the fleet to a real PostgreSQL database
// via direct SQL. Bypasses the ingestion service intentionally
// — fixtures are meant to seed the table state quickly, not
// to exercise the ingestion code path. `freshDatabase` (in
// the integration test suite) should run beforehand so the
// caller is writing into a known-empty schema.
//
// Honors the composition root's invariants the same way the
// integration suite's `seedAgent` helper does: agents share
// the supplied OrganizationID, observations carry the
// composite (org, cert_id) and (org, agent_id) FK pairs from
// migration 0005, and removed observations get their
// `removed_at` set.
//
// Returns the first error encountered; partial inserts roll
// back via the surrounding transaction.
func (f *Fleet) WriteTo(ctx context.Context, db *postgres.DB) error {
	return db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		// Agents.
		for _, a := range f.Agents {
			_, err := tx.Exec(ctx,
				`INSERT INTO agents
					(id, organization_id, hostname, version, status, enrolled_at, last_seen_at)
				 VALUES ($1, $2, $3, '', 'active', now(), now())`,
				a.ID, f.Config.OrganizationID, a.Hostname,
			)
			if err != nil {
				return fmt.Errorf("fixtures: insert agent %s: %w", a.ID, err)
			}
		}

		// Certificates.
		for _, c := range f.Certificates {
			sans, _ := json.Marshal([]string{})
			keyUsages, _ := json.Marshal([]string{"DigitalSignature"})
			extKeyUsages, _ := json.Marshal([]string{"ServerAuth"})
			_, err := tx.Exec(ctx,
				`INSERT INTO certificates (
					id, organization_id, fingerprint_sha256, subject, issuer,
					serial_number_hex, signature_algorithm, public_key_algorithm,
					public_key_bits, not_before, not_after, sans, key_usages,
					ext_key_usages, is_self_signed, is_ca, pem,
					first_seen_at, last_seen_at
				) VALUES (
					$1, $2, $3, $4, $5,
					$6, $7, $8,
					$9, $10, $11, $12, $13,
					$14, $15, $16, $17,
					$18, $18
				)`,
				c.ID, f.Config.OrganizationID, c.Fingerprint, c.Subject, c.Issuer,
				c.SerialNumberHex, c.SignatureAlg, c.PublicKeyAlg,
				c.PublicKeyBits, c.NotBefore, c.NotAfter, sans, keyUsages,
				extKeyUsages, c.IsSelfSigned, c.IsCA, c.PEM,
				f.BuilderNow,
			)
			if err != nil {
				return fmt.Errorf("fixtures: insert certificate %s: %w", c.ID, err)
			}
		}

		// Observations.
		for _, o := range f.Observations {
			_, err := tx.Exec(ctx,
				`INSERT INTO certificate_observations (
					id, organization_id, certificate_id, agent_id,
					store_location, friendly_name,
					first_seen_at, last_seen_at, removed_at
				) VALUES ($1, $2, $3, $4, $5, '', $6, $7, $8)`,
				o.ID, f.Config.OrganizationID, o.CertID, o.AgentID,
				o.StoreLocation,
				o.FirstSeenAt, o.LastSeenAt, o.RemovedAt,
			)
			if err != nil {
				return fmt.Errorf("fixtures: insert observation %s: %w", o.ID, err)
			}
		}
		return nil
	})
}

// PreSeedFindings runs the supplied rule set against the
// fleet's certificate rows and inserts the resulting open
// findings, then promotes deterministic subsets to
// `acknowledged` / `suppressed` per the FleetConfig ratios.
//
// Bypasses `findings.Service.Recompute` intentionally — the
// goal is a steady-state findings table the recompute under
// test will diff against, not to exercise the recompute path
// itself.
//
// Rule version is taken from the live rule registry so future
// version bumps round-trip correctly. The override metadata
// columns get fixture-supplied values that the H-023
// production paths would also emit
// (`status_reason` non-empty, `status_actor` populated,
// `status_changed_at` set; `suppress_expires_at` set for the
// permanent-suppression subset only).
//
// Returns the count of findings inserted and the count of
// rows promoted to each override state, so the caller can
// sanity-check the seeded distribution.
func (f *Fleet) PreSeedFindings(
	ctx context.Context,
	db *postgres.DB,
	rules []findings.Rule,
) (inserted, acknowledged, suppressed int, err error) {
	if db == nil {
		return 0, 0, 0, errors.New("fixtures: PreSeedFindings requires a non-nil *postgres.DB")
	}
	if len(rules) == 0 {
		return 0, 0, 0, errors.New("fixtures: PreSeedFindings requires at least one rule")
	}

	// Evaluate the rule set against in-memory cert summaries
	// derived from the fleet's certRow slice. Mirrors the
	// production rule input shape (inventory.CertificateSummary).
	matches := make([]preSeedMatch, 0)
	for _, c := range f.Certificates {
		summary := certSummaryFromRow(c)
		for _, rule := range rules {
			m := rule.Evaluate(&summary, f.BuilderNow)
			if m == nil {
				continue
			}
			matches = append(matches, preSeedMatch{
				cert:     c,
				rule:     rule,
				evidence: m.Evidence,
			})
		}
	}

	ackTarget := int(float64(len(matches)) * f.Config.AcknowledgedRatio)
	supTarget := int(float64(len(matches)) * f.Config.SuppressedRatio)

	err = db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		for i, m := range matches {
			id := ids.New()
			status := string(findings.StatusOpen)
			var reason, actor *string
			var changedAt, expiresAt, resolvedAt *time.Time

			switch {
			case i < ackTarget:
				status = string(findings.StatusAcknowledged)
				r := "fixture: pre-seeded acknowledged"
				a := "fixture"
				ch := f.BuilderNow.Add(-1 * time.Hour)
				reason, actor, changedAt = &r, &a, &ch
				acknowledged++
			case i < ackTarget+supTarget:
				status = string(findings.StatusSuppressed)
				r := "fixture: pre-seeded suppressed"
				a := "fixture"
				ch := f.BuilderNow.Add(-1 * time.Hour)
				exp := f.BuilderNow.Add(30 * 24 * time.Hour)
				reason, actor, changedAt, expiresAt = &r, &a, &ch, &exp
				suppressed++
			}

			ev := m.evidence
			if len(ev) == 0 {
				ev = json.RawMessage(`{}`)
			}
			_, execErr := tx.Exec(ctx,
				`INSERT INTO findings (
					id, organization_id, certificate_id,
					rule_id, rule_version,
					severity, status, title, evidence,
					opened_at, last_seen_at, resolved_at, updated_at,
					status_reason, status_actor, status_changed_at, suppress_expires_at
				) VALUES (
					$1, $2, $3,
					$4, $5,
					$6, $7, $8, $9,
					$10, $11, $12, $13,
					$14, $15, $16, $17
				)`,
				id, f.Config.OrganizationID, m.cert.ID,
				m.rule.ID(), m.rule.Version(),
				string(m.rule.Severity()), status, m.rule.Title(), []byte(ev),
				f.BuilderNow, f.BuilderNow, resolvedAt, f.BuilderNow,
				reason, actor, changedAt, expiresAt,
			)
			if execErr != nil {
				return fmt.Errorf("fixtures: insert finding %s: %w", id, execErr)
			}
			inserted++
		}
		return nil
	})
	return inserted, acknowledged, suppressed, err
}

type preSeedMatch struct {
	cert     certRow
	rule     findings.Rule
	evidence json.RawMessage
}

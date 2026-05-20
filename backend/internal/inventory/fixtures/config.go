package fixtures

// FleetConfig parameterizes the synthetic-fleet builder. Every
// knob is explicit (CLAUDE.md §8.9 forbids env-driven test
// shape). The ratios are applied to CertCount; counts inside
// `Build` are computed via floor truncation so the same
// (seed, cfg) always yields identical cardinalities.
//
// Source of truth for the preset values:
// docs/engineering/H024_PERFORMANCE_PLAN.md §5.1.
type FleetConfig struct {
	// OrganizationID is the org every generated row binds to.
	// One org per fleet — multi-org generation is not in scope
	// (CLAUDE.md §4 keeps multi-tenancy out of v0.1).
	OrganizationID string

	// AgentCount is the number of agent rows the fleet seeds.
	// Each agent is a stable identity; observations attach via
	// (organization_id, agent_id).
	AgentCount int

	// CertCount is the number of distinct certificate rows the
	// fleet seeds — the cardinality of the certificates table
	// after build. Distinct = unique fingerprint.
	CertCount int

	// StoresPerAgent is the number of store_locations each
	// agent observes from. Drives the observations-table
	// cardinality; with SharedCertRatio and CertsPerAgent, the
	// observation count is roughly
	// `AgentCount * CertsPerAgent`, modulated by which certs
	// each agent sees.
	StoresPerAgent int

	// CertsPerAgent is the average number of distinct certs
	// each agent observes. Combined with SharedCertRatio, this
	// drives the observation count and the cert-sharing
	// distribution.
	CertsPerAgent int

	// SharedCertRatio is the fraction of certs (in [0, 1])
	// observed by more than one agent — the realistic case for
	// Windows roots / SCCM-distributed internal-CA leafs. The
	// remaining `1 - SharedCertRatio` certs are observed by
	// exactly one agent each (a "tail" of host-unique certs).
	SharedCertRatio float64

	// ExpiredRatio is the fraction of certs (in [0, 1]) whose
	// NotAfter is in the past relative to BuilderNow. Drives
	// `certificate_expired` rule hits.
	ExpiredRatio float64

	// ExpiringSoonRatio is the fraction with NotAfter in
	// (BuilderNow, BuilderNow + 30d]. Drives
	// `certificate_expiring_soon` rule hits.
	ExpiringSoonRatio float64

	// WeakKeyRatio is the fraction of certs generated with an
	// RSA key below 2048 bits. Drives `weak_rsa_key`.
	WeakKeyRatio float64

	// WeakSigRatio is the fraction of certs whose signature
	// algorithm is MD5 or SHA1 with RSA. Drives
	// `weak_signature_algorithm`.
	WeakSigRatio float64

	// SelfSignedLeafRatio is the fraction of certs that are
	// self-signed leafs (subject == issuer, NOT IsCA). Drives
	// `self_signed_leaf`.
	SelfSignedLeafRatio float64

	// LongLivedRatio is the fraction of leaf certs whose
	// (NotAfter - NotBefore) exceeds 398 days. Drives
	// `long_lived_certificate`.
	LongLivedRatio float64

	// RemovedObsRatio is the fraction of observations whose
	// removed_at is set to a value in the past. Models the
	// "cert disappeared from this agent's store" lineage.
	RemovedObsRatio float64

	// AcknowledgedRatio is the fraction of open findings the
	// PreSeedFindings step promotes to status=acknowledged.
	// Only relevant when callers ask for pre-seeded findings.
	AcknowledgedRatio float64

	// SuppressedRatio is the fraction of open findings the
	// PreSeedFindings step promotes to status=suppressed.
	// Suppression expiries are randomized within
	// SuppressExpiryWindow.
	SuppressedRatio float64
}

// Smallv01 is the preset used by the perf-tier tests that join
// the in-CI path (`//go:build perf`). The dataset is tiny so
// the CI runner can build, persist, and exercise it in
// milliseconds without inflating PR wall-clock.
//
// Cardinality lines up with the v0.1 column of
// H024_PERFORMANCE_PLAN.md §5.1 but at the low end so the
// total observation count stays in the low thousands.
func Smallv01() FleetConfig {
	return FleetConfig{
		OrganizationID:      "anchorix",
		AgentCount:          10,
		CertCount:           60,
		StoresPerAgent:      3,
		CertsPerAgent:       20,
		SharedCertRatio:     0.50,
		ExpiredRatio:        0.05,
		ExpiringSoonRatio:   0.10,
		WeakKeyRatio:        0.05,
		WeakSigRatio:        0.05,
		SelfSignedLeafRatio: 0.05,
		LongLivedRatio:      0.05,
		RemovedObsRatio:     0.05,
		AcknowledgedRatio:   0.10,
		SuppressedRatio:     0.10,
	}
}

// Pilot is the preset used by the stress tier
// (`//go:build stress`). Sized against the pilot column of
// H024_PERFORMANCE_PLAN.md §3 (1K agents, 5K distinct certs).
// Generating real X.509 bytes for ~5K certs takes a few seconds
// thanks to the key-pool reuse; the persistence step is the
// dominant cost. Stress tests typically run this once per
// invocation and reuse the seeded DB across sub-tests.
func Pilot() FleetConfig {
	return FleetConfig{
		OrganizationID:      "anchorix",
		AgentCount:          1000,
		CertCount:           5000,
		StoresPerAgent:      5,
		CertsPerAgent:       100,
		SharedCertRatio:     0.70,
		ExpiredRatio:        0.05,
		ExpiringSoonRatio:   0.10,
		WeakKeyRatio:        0.02,
		WeakSigRatio:        0.02,
		SelfSignedLeafRatio: 0.05,
		LongLivedRatio:      0.05,
		RemovedObsRatio:     0.10,
		AcknowledgedRatio:   0.05,
		SuppressedRatio:     0.05,
	}
}

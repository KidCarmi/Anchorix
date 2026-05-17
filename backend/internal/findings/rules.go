package findings

import (
	"encoding/json"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// Rule evaluates one certificate and decides whether the rule
// matches. Rules MUST be pure: no I/O, no clock access except
// via the injected `now`. The same (cert, now) pair always
// produces the same RuleMatch / nil decision (CLAUDE.md §7.6).
//
// ID is the stable rule key used in finding rows (matches the
// finding's `rule_id` column). Operators filter by it.
// Renaming a rule's ID is a breaking change and requires a
// separate compatibility plan; bumping Version() does NOT
// require renaming.
//
// Version is an integer bumped when the rule body changes
// meaningfully (different match logic, different evidence
// shape). Service.Recompute persists rule_version on the
// finding row so re-evaluating with an updated rule body
// records the new version on the existing finding.
//
// Severity is statically declared per rule. v0.1 does NOT
// compute severity from cert content (e.g. "weaker RSA means
// higher severity") — flat mapping per the H-021 brief.
//
// Title is the operator-facing one-liner stored on the finding
// row. Kept short and rule-specific (not "Certificate issue
// found" — that's the dashboard's job to compose).
type Rule interface {
	ID() string
	Version() int
	Severity() Severity
	Title() string
	Evaluate(cert *inventory.CertificateSummary, now time.Time) *RuleMatch
}

// RuleMatch is what Rule.Evaluate returns when a certificate
// triggers the rule. nil means "no match, no finding".
//
// Evidence is a JSON-encoded payload that gets stored on the
// finding row. Schemas are per-rule and documented in the rule
// implementation; the consumer (operator UI, future findings
// API) treats Evidence as opaque JSON. Keep it small —
// metadata about WHY the rule matched, not a redundant copy of
// the cert.
type RuleMatch struct {
	Evidence json.RawMessage
}

// mustMarshalEvidence is a small helper for rules whose evidence
// shape is fixed at compile time. A marshalling failure on a
// statically-shaped struct is a programmer error, not a runtime
// condition the operator can fix — collapse it to a panic at
// initialization rather than threading errors through every
// rule.
func mustMarshalEvidence(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		// Never reachable for fixed-shape structs. A test failure
		// here means a rule's evidence struct has a non-JSON-
		// serializable field; fix the rule.
		panic("findings: rule produced non-JSON-encodable evidence: " + err.Error())
	}
	return raw
}

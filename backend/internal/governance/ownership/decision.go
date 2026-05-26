package ownership

import (
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// maxLosingRules bounds the losing_rules snapshot (governance plan
// §3.10 / §6). The K highest-precedence non-winning matched rules are
// kept; the rest are dropped. The cap keeps the JSONB column bounded.
const maxLosingRules = 8

// ownershipDecision is the pure result of evaluating one certificate
// against the rule set + any active override. It carries everything
// the recompute needs to persist the certificate_ownership row and
// build the explanation snapshot; it performs no I/O.
type ownershipDecision struct {
	decision      governance.Decision
	serviceID     *string
	winningRuleID *string
	overrideID    *string
	confidence    governance.Confidence
	losing        []losingRuleInfo
}

// losingRuleInfo is one non-winning matched rule, with the reason it
// lost. Ordered deterministically by the engine walk order.
type losingRuleInfo struct {
	ruleID   string
	name     string
	tier     governance.PrecedenceTier
	priority int
	reason   string
}

// decideOwnership is the deterministic core: given a certificate's
// signals, an optional active override, the compiled rule set (already
// in engine walk order), and the recompute clock, it returns the
// ownership decision. Pure — no I/O, no clock reads beyond the passed
// `now`, no map iteration affecting output.
//
// Precedence (governance plan §4):
//
//  1. An active, non-expired override wins outright (tier "explicit").
//  2. Otherwise the first rule (in walk order) whose predicate matches
//     is the candidate winner.
//  3. Ambiguity is detected on the (priority, created_at) PREFIX
//     within the winner's tier — id is excluded from the tie test
//     because it is unique and would make ambiguity unreachable. If
//     two+ matched rules in the winner's tier share its priority AND
//     created_at, the decision is `ambiguous`; the winner is still the
//     lowest-id rule (operations stay deterministic) but the ambiguous
//     flag is not cleared.
//  4. No match → `unowned`.
func decideOwnership(
	sig governance.CertificateSignals,
	override *governance.CertificateOwnershipOverride,
	rules []compiledRule,
	now time.Time,
) ownershipDecision {
	if overrideActive(override, now) {
		svc := override.ServiceID
		id := override.ID
		return ownershipDecision{
			decision:   governance.DecisionOverridden,
			serviceID:  &svc,
			overrideID: &id,
			confidence: governance.ConfidenceHigh,
		}
	}

	var matched []compiledRule
	for _, cr := range rules {
		if cr.matches(sig) {
			matched = append(matched, cr)
		}
	}
	if len(matched) == 0 {
		return ownershipDecision{decision: governance.DecisionUnowned, confidence: governance.ConfidenceLow}
	}

	winner := matched[0]
	// Count matched rules tied with the winner on the
	// (tier, priority, created_at) prefix — NOT id.
	tied := 0
	for _, m := range matched {
		if m.rule.PrecedenceTier == winner.rule.PrecedenceTier &&
			m.rule.Priority == winner.rule.Priority &&
			m.rule.CreatedAt.Equal(winner.rule.CreatedAt) {
			tied++
		}
	}
	decision := governance.DecisionMatched
	if tied > 1 {
		decision = governance.DecisionAmbiguous
	}

	svc := winner.rule.ServiceID
	wr := winner.rule.ID
	return ownershipDecision{
		decision:      decision,
		serviceID:     &svc,
		winningRuleID: &wr,
		confidence:    confidenceForTier(winner.rule.PrecedenceTier),
		losing:        buildLosing(matched, winner),
	}
}

// overrideActive reports whether an override should win for this
// evaluation: present, uncleared (the caller only passes uncleared
// rows), and not expired. An override with expires_at <= now is
// treated as absent so the cert re-derives from rules.
func overrideActive(o *governance.CertificateOwnershipOverride, now time.Time) bool {
	if o == nil {
		return false
	}
	return o.ExpiresAt == nil || o.ExpiresAt.After(now)
}

// buildLosing renders the non-winning matched rules (in the engine
// walk order they already arrive in) into bounded, reasoned
// losing-rule entries. Deterministic: input is sorted, output is a
// truncated prefix.
func buildLosing(matched []compiledRule, winner compiledRule) []losingRuleInfo {
	if len(matched) <= 1 {
		return nil
	}
	out := make([]losingRuleInfo, 0, len(matched)-1)
	for _, m := range matched[1:] {
		out = append(out, losingRuleInfo{
			ruleID:   m.rule.ID,
			name:     m.rule.Name,
			tier:     m.rule.PrecedenceTier,
			priority: m.rule.Priority,
			reason:   reasonNotChosen(m.rule, winner.rule),
		})
		if len(out) == maxLosingRules {
			break
		}
	}
	return out
}

// reasonNotChosen returns a closed-enum string explaining why losing
// rule l lost to winner w. The branches mirror the decision ladder so
// the explanation is reconstructable without re-running the engine.
func reasonNotChosen(l, w governance.OwnershipRule) string {
	switch {
	case l.PrecedenceTier != w.PrecedenceTier:
		return "lower precedence than " + string(w.PrecedenceTier)
	case l.Priority != w.Priority:
		return "same tier, lower priority than winner"
	case !l.CreatedAt.Equal(w.CreatedAt):
		return "same tier, same priority, later created_at than winner"
	default:
		return "tied with winner; tiebreaker on id"
	}
}

package ownership

import (
	"fmt"
	"strings"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// Rule field bounds. Names + descriptions are operator-facing free
// text; the caps keep a single rule row bounded and mirror the
// identity-package limits (maxDisplayNameLen / maxDescriptionLen).
const (
	maxRuleNameLen        = 200
	maxRuleDescriptionLen = 1000
	maxRuleMatchValueLen  = 1024 // same ceiling as maxRegexPatternLen
	minRulePriority       = 0
	maxRulePriority       = 1_000_000
)

// tierForKind is the canonical match_kind → precedence_tier mapping.
// A rule's tier is DERIVED from its match_kind, not chosen
// independently: the §4.2 ladder assigns each kind to exactly one
// tier. The validator uses this both to reject a tier that disagrees
// with the kind and to fill the tier when the caller omits it.
//
// `explicit` and `service_member` are intentionally ABSENT: explicit
// is the override path (not an operator rule), and service_member is
// the reserved tier. No operator-creatable match_kind maps to either,
// so any attempt to create one is rejected.
var tierForKind = map[governance.MatchKind]governance.PrecedenceTier{
	governance.MatchAgentGroup:    governance.PrecedenceAgentGroup,
	governance.MatchSANGlob:       governance.PrecedenceSANPattern,
	governance.MatchSANRegex:      governance.PrecedenceSANPattern,
	governance.MatchSubjectCNGlob: governance.PrecedenceSubjectPattern,
	governance.MatchTag:           governance.PrecedenceTag,
	governance.MatchIssuerDN:      governance.PrecedenceIssuerStore,
	governance.MatchStoreLocation: governance.PrecedenceIssuerStore,
	governance.MatchFallback:      governance.PrecedenceFallback,
}

// validatedRuleShape is the result of validating the identity-shaping
// fields of a create request: the canonical tier for the kind and a
// flag for whether the match_value names an agent group (so the
// caller knows to run the agent-group existence check).
type validatedRuleShape struct {
	tier                 governance.PrecedenceTier
	matchValueIsAgentGrp bool
}

// validateRuleKindAndTier validates the match_kind, derives the
// canonical tier, and — when the caller supplied a tier — rejects a
// tier that disagrees with the kind. service_member is rejected with
// the dedicated sentinel; any other unknown/explicit tier or unknown
// kind is ErrInvalidRule.
//
// This is the single chokepoint the engine's compileRules trusts: a
// rule that passes here can never carry service_member, explicit, an
// unknown tier, or a tier inconsistent with its kind.
func validateRuleKindAndTier(kind governance.MatchKind, suppliedTier governance.PrecedenceTier) (governance.PrecedenceTier, error) {
	if suppliedTier == governance.PrecedenceServiceMember {
		return "", fmt.Errorf("%w: precedence_tier", ErrServiceMemberReserved)
	}
	canonical, ok := tierForKind[kind]
	if !ok {
		return "", fmt.Errorf("%w: unknown match_kind %q", ErrInvalidRule, kind)
	}
	// A supplied tier must match the kind's canonical tier exactly.
	// Empty (unset) is accepted and filled with the canonical tier.
	if suppliedTier != "" && suppliedTier != canonical {
		return "", fmt.Errorf("%w: precedence_tier %q does not match match_kind %q (expected %q)",
			ErrInvalidRule, suppliedTier, kind, canonical)
	}
	return canonical, nil
}

// validateMatchValue validates the match_value for a given kind:
//   - fallback: must be empty (the rule matches every cert).
//   - san_regex: must compile as RE2 and be within the size cap.
//   - san_glob / subject_cn_glob / agent_group / issuer_dn /
//     store_location / tag: must be non-empty and within the cap.
//
// It returns whether the value names an agent group so the caller
// runs the existence check. Regex compilation reuses the engine's
// compileRegex (same RE2 + size-cap behavior the recompute enforces),
// so a value accepted here can never become an inert compile failure
// at recompute time.
func validateMatchValue(kind governance.MatchKind, value string) (isAgentGroup bool, err error) {
	if kind == governance.MatchFallback {
		if value != "" {
			return false, fmt.Errorf("%w: fallback rule match_value must be empty", ErrInvalidRule)
		}
		return false, nil
	}
	if strings.TrimSpace(value) == "" {
		return false, fmt.Errorf("%w: match_value required for match_kind %q", ErrInvalidRule, kind)
	}
	if len(value) > maxRuleMatchValueLen {
		return false, fmt.Errorf("%w: match_value length %d exceeds cap %d", ErrInvalidRule, len(value), maxRuleMatchValueLen)
	}
	if kind == governance.MatchSANRegex {
		if re, reason := compileRegex(value); re == nil {
			return false, fmt.Errorf("%w: %s", ErrInvalidRule, reason)
		}
	}
	return kind == governance.MatchAgentGroup, nil
}

// validateRuleName / validateRuleDescription apply the operator-facing
// free-text bounds.
func validateRuleName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: name required", ErrInvalidRule)
	}
	if len(name) > maxRuleNameLen {
		return fmt.Errorf("%w: name length %d exceeds cap %d", ErrInvalidRule, len(name), maxRuleNameLen)
	}
	return nil
}

func validateRuleDescription(desc string) error {
	if len(desc) > maxRuleDescriptionLen {
		return fmt.Errorf("%w: description length %d exceeds cap %d", ErrInvalidRule, len(desc), maxRuleDescriptionLen)
	}
	return nil
}

func validateRulePriority(priority int) error {
	if priority < minRulePriority || priority > maxRulePriority {
		return fmt.Errorf("%w: priority %d out of range [%d,%d]", ErrInvalidRule, priority, minRulePriority, maxRulePriority)
	}
	return nil
}

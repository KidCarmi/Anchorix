package ownership

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// maxRegexPatternLen caps operator-supplied san_regex patterns. Go's
// regexp is RE2 (linear time, no catastrophic backtracking), so the
// risk is not backtracking but oversized / over-alternated patterns
// inflating compile cost and program size. A pattern beyond this cap
// is treated as a compile failure (inert + audited), never evaluated.
const maxRegexPatternLen = 1024

// ruleCompileFailure records a rule whose predicate could not be
// compiled (an over-length or invalid san_regex). The rule is treated
// as never-matching for the pass (fail closed); the failure is
// surfaced as an ownership.rule_compile_failed audit row and in the
// governance.recomputed metadata.
type ruleCompileFailure struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

// compiledRule is an ownership rule with its match predicate prepared
// once per recompute pass. Glob and regex kinds carry a compiled
// *regexp.Regexp; the tag kind carries the parsed key/value; the
// remaining kinds match directly off rule.MatchValue.
type compiledRule struct {
	rule       governance.OwnershipRule
	ordinal    int
	re         *regexp.Regexp // san_glob, san_regex, subject_cn_glob
	tagKey     string         // tag
	tagValue   string         // tag
	tagHasVal  bool           // tag: false = match any value for the key
	compileErr bool           // true = inert (never matches)
}

// compileRules validates and compiles every enabled rule, returning
// the compiled set sorted into the deterministic engine walk order
// (tier ordinal, priority, created_at, id) plus the list of
// compile failures.
//
// Structural drift fails the whole pass loudly: an unrecognized
// precedence_tier or match_kind returns an error (ErrUnknownPrecedenceTier
// / ErrUnknownMatchKind) so the recompute rolls back rather than
// evaluating an undefined rule. A bad san_regex is NOT fatal — it is
// recorded as a compile failure and its rule is marked inert
// (fail closed: it can never grant ownership).
func compileRules(rules []governance.OwnershipRule) ([]compiledRule, []ruleCompileFailure, error) {
	compiled := make([]compiledRule, 0, len(rules))
	var failures []ruleCompileFailure
	for _, r := range rules {
		// service_member is a RESERVED tier in H-026B (governance plan
		// §5.4 / OQ-1): no operator rule may carry it yet. The B3
		// rule-create validator rejects it at creation; here — defense
		// in depth — the engine treats any service_member rule that
		// reached the DB (the migration 0010 CHECK still permits the
		// value) as INERT: skipped from the compiled set so it can
		// never win. Fail closed, no abort, no audit spam.
		if r.PrecedenceTier == governance.PrecedenceServiceMember {
			continue
		}
		ord, ok := ordinalOf(r.PrecedenceTier)
		if !ok {
			return nil, nil, fmt.Errorf("%w: rule %s tier %q", ErrUnknownPrecedenceTier, r.ID, r.PrecedenceTier)
		}
		cr := compiledRule{rule: r, ordinal: ord}
		switch r.MatchKind {
		case governance.MatchFallback,
			governance.MatchAgentGroup,
			governance.MatchIssuerDN,
			governance.MatchStoreLocation:
			// Direct value comparison; nothing to compile.
		case governance.MatchSANGlob, governance.MatchSubjectCNGlob:
			cr.re = compileGlob(r.MatchValue)
		case governance.MatchSANRegex:
			re, reason := compileRegex(r.MatchValue)
			if re == nil {
				cr.compileErr = true
				failures = append(failures, ruleCompileFailure{RuleID: r.ID, Reason: reason})
			}
			cr.re = re
		case governance.MatchTag:
			cr.tagKey, cr.tagValue, cr.tagHasVal = parseTagMatch(r.MatchValue)
		default:
			return nil, nil, fmt.Errorf("%w: rule %s kind %q", ErrUnknownMatchKind, r.ID, r.MatchKind)
		}
		compiled = append(compiled, cr)
	}

	// Deterministic engine walk order. SliceStable so equal keys keep
	// input order, but the (ordinal, priority, created_at, id) key is
	// a total order so the result is fully deterministic regardless.
	sort.SliceStable(compiled, func(i, j int) bool {
		a, b := compiled[i].rule, compiled[j].rule
		if compiled[i].ordinal != compiled[j].ordinal {
			return compiled[i].ordinal < compiled[j].ordinal
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.ID < b.ID
	})
	return compiled, failures, nil
}

// matches reports whether the rule's predicate is satisfied by the
// certificate's signals. A rule with a compile error never matches.
func (cr compiledRule) matches(sig governance.CertificateSignals) bool {
	if cr.compileErr {
		return false
	}
	switch cr.rule.MatchKind {
	case governance.MatchFallback:
		return true
	case governance.MatchSANGlob, governance.MatchSANRegex:
		for _, san := range sig.SANs {
			if cr.re.MatchString(san) {
				return true
			}
		}
		return false
	case governance.MatchSubjectCNGlob:
		cn := parseCN(sig.Subject)
		return cn != "" && cr.re.MatchString(cn)
	case governance.MatchAgentGroup:
		return containsString(sig.ObservingAgentGroupIDs, cr.rule.MatchValue)
	case governance.MatchIssuerDN:
		return sig.Issuer == cr.rule.MatchValue
	case governance.MatchStoreLocation:
		return containsString(sig.StoreLocations, cr.rule.MatchValue)
	case governance.MatchTag:
		return matchesTag(sig.CertTags, cr) || matchesTag(sig.AgentTags, cr)
	default:
		// Unreachable: compileRules rejects unknown kinds.
		return false
	}
}

func matchesTag(tags []governance.TagPair, cr compiledRule) bool {
	for _, t := range tags {
		if t.Key == cr.tagKey && (!cr.tagHasVal || t.Value == cr.tagValue) {
			return true
		}
	}
	return false
}

func containsString(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

// compileGlob converts a hostname-style glob (`*` = any run, `?` =
// single char) into an anchored, case-insensitive RE2. DNS names are
// case-insensitive, so glob matching is too. Glob compilation cannot
// fail — every produced pattern is valid RE2.
func compileGlob(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// compileRegex compiles an operator-supplied san_regex. Returns
// (nil, reason) on an over-length or invalid pattern so the caller
// marks the rule inert. The pattern is matched unanchored, honoring
// the operator's own anchors — their choice, deterministic per RE2.
func compileRegex(pattern string) (*regexp.Regexp, string) {
	if len(pattern) > maxRegexPatternLen {
		return nil, fmt.Sprintf("pattern length %d exceeds cap %d", len(pattern), maxRegexPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, "invalid regex: " + err.Error()
	}
	return re, ""
}

// parseTagMatch splits a tag match_value of the form "key:value" into
// its parts. With no colon the whole string is the key and any value
// matches; "key:" matches only the empty value for that key.
func parseTagMatch(matchValue string) (key, value string, hasValue bool) {
	if i := strings.IndexByte(matchValue, ':'); i >= 0 {
		return matchValue[:i], matchValue[i+1:], true
	}
	return matchValue, "", false
}

// parseCN extracts the first CN= component value from a subject DN.
// Attribute types are case-insensitive; the value is returned
// verbatim. v0.x does not unescape RFC 4514 sequences — hostnames in
// CNs do not need it. Returns "" when no CN component is present.
func parseCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if len(part) >= 3 && strings.EqualFold(part[:3], "CN=") {
			return part[3:]
		}
	}
	return ""
}

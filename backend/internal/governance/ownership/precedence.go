package ownership

import "github.com/kidcarmi/anchorix/backend/internal/governance"

// tierOrdinal is the §4.2 precedence ladder as integer ranks. Lower
// rank = higher precedence. This is the single source of truth for
// engine ordering — the engine sorts compiled rules by this ordinal
// (then priority, created_at, id), so it does NOT depend on the SQL
// ORDER BY in ListOwnershipRulesForEngine (that CASE map is
// belt-and-suspenders). A tier value not in this map is structural
// drift and aborts the pass via ErrUnknownPrecedenceTier.
var tierOrdinal = map[governance.PrecedenceTier]int{
	governance.PrecedenceExplicit:       1,
	governance.PrecedenceServiceMember:  2,
	governance.PrecedenceAgentGroup:     3,
	governance.PrecedenceSANPattern:     4,
	governance.PrecedenceSubjectPattern: 5,
	governance.PrecedenceTag:            6,
	governance.PrecedenceIssuerStore:    7,
	governance.PrecedenceFallback:       8,
}

// ordinalOf returns the ladder rank for a tier and whether it is
// recognized.
func ordinalOf(t governance.PrecedenceTier) (int, bool) {
	o, ok := tierOrdinal[t]
	return o, ok
}

// confidenceForTier maps a winning tier to the coarse confidence
// label (governance plan §3.8 / §4.2): explicit + service_member are
// high; agent_group / san_pattern / subject_pattern / tag are medium;
// issuer_store / fallback are low. An unrecognized tier never reaches
// here — compilation rejects it — so the default is unreachable and
// returns low (fail-closed: least confident).
func confidenceForTier(t governance.PrecedenceTier) governance.Confidence {
	switch t {
	case governance.PrecedenceExplicit, governance.PrecedenceServiceMember:
		return governance.ConfidenceHigh
	case governance.PrecedenceAgentGroup, governance.PrecedenceSANPattern,
		governance.PrecedenceSubjectPattern, governance.PrecedenceTag:
		return governance.ConfidenceMedium
	default:
		return governance.ConfidenceLow
	}
}

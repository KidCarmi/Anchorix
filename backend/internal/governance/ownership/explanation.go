package ownership

import (
	"encoding/json"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// engineVersion stamps every explanation row and the
// governance.recomputed audit metadata. Bump it when the decision
// logic or the ladder changes so old explanations render
// unambiguously and the first post-bump recompute re-evaluates every
// cert (governance plan OQ-6).
const engineVersion = 1

// losingRuleJSON is the on-disk shape of one losing-rule entry in
// ownership_match_explanations.losing_rules.
type losingRuleJSON struct {
	RuleID          string                    `json:"rule_id"`
	Name            string                    `json:"name"`
	Tier            governance.PrecedenceTier `json:"tier"`
	Priority        int                       `json:"priority"`
	ReasonNotChosen string                    `json:"reason_not_chosen"`
}

// signalsSeenJSON is the on-disk shape of
// ownership_match_explanations.signals_seen. It is the explainability
// surface: an operator can reconstruct the engine's inputs without
// re-running it. Every slice is coalesced to a non-nil value so the
// JSON is `[]` not `null` — deterministic bytes.
type signalsSeenJSON struct {
	SubjectCN      string               `json:"subject_cn"`
	SANs           []string             `json:"sans"`
	Issuer         string               `json:"issuer"`
	StoreLocations []string             `json:"store_locations"`
	AgentIDs       []string             `json:"agent_ids"`
	AgentGroupIDs  []string             `json:"agent_group_ids"`
	CertTags       []governance.TagPair `json:"cert_tags"`
	AgentTags      []governance.TagPair `json:"agent_tags"`
}

// buildLosingRulesJSON marshals the decision's losing rules. The
// input is already in deterministic engine walk order, so the bytes
// are stable across runs. An empty set marshals to `[]`.
func buildLosingRulesJSON(losing []losingRuleInfo) json.RawMessage {
	arr := make([]losingRuleJSON, 0, len(losing))
	for _, l := range losing {
		arr = append(arr, losingRuleJSON{
			RuleID:          l.ruleID,
			Name:            l.name,
			Tier:            l.tier,
			Priority:        l.priority,
			ReasonNotChosen: l.reason,
		})
	}
	b, err := json.Marshal(arr)
	if err != nil {
		// arr is composed only of strings/ints; marshal cannot fail.
		return json.RawMessage("[]")
	}
	return b
}

// buildSignalsSeenJSON marshals the certificate's signals. Slices
// arrive already DISTINCT and sorted from the storage read, so the
// output is deterministic; nil slices are coalesced to empty so the
// bytes never contain `null`.
func buildSignalsSeenJSON(sig governance.CertificateSignals) json.RawMessage {
	s := signalsSeenJSON{
		SubjectCN:      parseCN(sig.Subject),
		SANs:           coalesceStrings(sig.SANs),
		Issuer:         sig.Issuer,
		StoreLocations: coalesceStrings(sig.StoreLocations),
		AgentIDs:       coalesceStrings(sig.ObservingAgentIDs),
		AgentGroupIDs:  coalesceStrings(sig.ObservingAgentGroupIDs),
		CertTags:       coalesceTags(sig.CertTags),
		AgentTags:      coalesceTags(sig.AgentTags),
	}
	b, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

func coalesceStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func coalesceTags(t []governance.TagPair) []governance.TagPair {
	if t == nil {
		return []governance.TagPair{}
	}
	return t
}

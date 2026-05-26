package ownership

import (
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

var baseTime = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

func rule(id string, tier governance.PrecedenceTier, kind governance.MatchKind, val string, prio int, created time.Time) governance.OwnershipRule {
	return governance.OwnershipRule{
		ID:             id,
		OrganizationID: "anchorix",
		Name:           id,
		ServiceID:      "svc-" + id,
		PrecedenceTier: tier,
		Priority:       prio,
		MatchKind:      kind,
		MatchValue:     val,
		Enabled:        true,
		CreatedAt:      created,
		UpdatedAt:      created,
		CreatedBy:      "tester",
	}
}

func mustCompile(t *testing.T, rules ...governance.OwnershipRule) []compiledRule {
	t.Helper()
	c, _, err := compileRules(rules)
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}
	return c
}

func sigWithSAN(sans ...string) governance.CertificateSignals {
	return governance.CertificateSignals{CertificateID: "c1", Subject: "CN=x", Issuer: "CN=ca", SANs: sans}
}

func TestDecideUnownedWhenNoRules(t *testing.T) {
	d := decideOwnership(sigWithSAN("a.example"), nil, nil, baseTime)
	if d.decision != governance.DecisionUnowned || d.serviceID != nil || d.confidence != governance.ConfidenceLow {
		t.Fatalf("got %+v; want unowned/low/nil", d)
	}
}

func TestDecideUnownedWhenNoMatch(t *testing.T) {
	rules := mustCompile(t, rule("r1", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.other", 100, baseTime))
	d := decideOwnership(sigWithSAN("a.example"), nil, rules, baseTime)
	if d.decision != governance.DecisionUnowned {
		t.Fatalf("got %s; want unowned", d.decision)
	}
}

func TestDecideFallbackMatches(t *testing.T) {
	rules := mustCompile(t, rule("rfb", governance.PrecedenceFallback, governance.MatchFallback, "", 1, baseTime))
	d := decideOwnership(sigWithSAN("a.example"), nil, rules, baseTime)
	if d.decision != governance.DecisionMatched || *d.serviceID != "svc-rfb" || d.confidence != governance.ConfidenceLow {
		t.Fatalf("got %+v; want matched/svc-rfb/low", d)
	}
}

func TestDecideFirstMatchWinsAcrossTiers(t *testing.T) {
	// fallback (tier 8) + san_pattern (tier 4) both match; san wins.
	rules := mustCompile(t,
		rule("rfb", governance.PrecedenceFallback, governance.MatchFallback, "", 1, baseTime),
		rule("rsan", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime),
	)
	d := decideOwnership(sigWithSAN("a.example"), nil, rules, baseTime)
	if d.decision != governance.DecisionMatched || *d.winningRuleID != "rsan" || d.confidence != governance.ConfidenceMedium {
		t.Fatalf("got %+v; want matched/rsan/medium", d)
	}
	if len(d.losing) != 1 || d.losing[0].ruleID != "rfb" || d.losing[0].reason != "lower precedence than san_pattern" {
		t.Fatalf("losing = %+v", d.losing)
	}
}

func TestDecideTiebreakerPriority(t *testing.T) {
	rules := mustCompile(t,
		rule("rlo", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 200, baseTime),
		rule("rhi", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime),
	)
	d := decideOwnership(sigWithSAN("a.example"), nil, rules, baseTime)
	if d.decision != governance.DecisionMatched || *d.winningRuleID != "rhi" {
		t.Fatalf("got %+v; want matched/rhi (lower priority wins)", d)
	}
	if d.losing[0].reason != "same tier, lower priority than winner" {
		t.Fatalf("loser reason = %q", d.losing[0].reason)
	}
}

func TestDecideTiebreakerCreatedAt(t *testing.T) {
	rules := mustCompile(t,
		rule("rlate", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime.Add(time.Minute)),
		rule("rearly", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime),
	)
	d := decideOwnership(sigWithSAN("a.example"), nil, rules, baseTime)
	if *d.winningRuleID != "rearly" || d.decision != governance.DecisionMatched {
		t.Fatalf("got %+v; want matched/rearly (earlier created_at wins)", d)
	}
	if d.losing[0].reason != "same tier, same priority, later created_at than winner" {
		t.Fatalf("loser reason = %q", d.losing[0].reason)
	}
}

func TestDecideAmbiguousOnPriorityCreatedAtTie(t *testing.T) {
	// Same tier, same priority, same created_at, differ only by id →
	// ambiguous; winner is the lowest id; id does NOT clear ambiguity.
	rules := mustCompile(t,
		rule("rb", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime),
		rule("ra", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime),
	)
	d := decideOwnership(sigWithSAN("a.example"), nil, rules, baseTime)
	if d.decision != governance.DecisionAmbiguous {
		t.Fatalf("got %s; want ambiguous", d.decision)
	}
	if *d.winningRuleID != "ra" {
		t.Fatalf("winner = %s; want ra (lowest id)", *d.winningRuleID)
	}
	if len(d.losing) != 1 || d.losing[0].ruleID != "rb" || d.losing[0].reason != "tied with winner; tiebreaker on id" {
		t.Fatalf("losing = %+v", d.losing)
	}
}

func TestDecideOverrideWins(t *testing.T) {
	rules := mustCompile(t, rule("rsan", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime))
	ov := &governance.CertificateOwnershipOverride{ID: "ovr1", CertificateID: "c1", ServiceID: "svc-pinned"}
	d := decideOwnership(sigWithSAN("a.example"), ov, rules, baseTime)
	if d.decision != governance.DecisionOverridden || *d.serviceID != "svc-pinned" || *d.overrideID != "ovr1" {
		t.Fatalf("got %+v; want overridden/svc-pinned/ovr1", d)
	}
	if d.winningRuleID != nil || d.confidence != governance.ConfidenceHigh || len(d.losing) != 0 {
		t.Fatalf("override decision should have nil winning rule, high confidence, no losing: %+v", d)
	}
}

func TestDecideExpiredOverrideIgnored(t *testing.T) {
	rules := mustCompile(t, rule("rsan", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime))
	past := baseTime.Add(-time.Hour)
	ov := &governance.CertificateOwnershipOverride{ID: "ovr1", CertificateID: "c1", ServiceID: "svc-pinned", ExpiresAt: &past}
	d := decideOwnership(sigWithSAN("a.example"), ov, rules, baseTime)
	if d.decision != governance.DecisionMatched || *d.winningRuleID != "rsan" {
		t.Fatalf("expired override must be ignored; got %+v", d)
	}
}

func TestDecideNonExpiringOverrideWins(t *testing.T) {
	ov := &governance.CertificateOwnershipOverride{ID: "ovr1", CertificateID: "c1", ServiceID: "svc-pinned", ExpiresAt: nil}
	d := decideOwnership(sigWithSAN("a.example"), ov, nil, baseTime)
	if d.decision != governance.DecisionOverridden {
		t.Fatalf("nil-expiry override must win; got %s", d.decision)
	}
}

func TestDecideConfidenceByTier(t *testing.T) {
	cases := []struct {
		tier governance.PrecedenceTier
		kind governance.MatchKind
		want governance.Confidence
	}{
		{governance.PrecedenceAgentGroup, governance.MatchAgentGroup, governance.ConfidenceMedium},
		{governance.PrecedenceIssuerStore, governance.MatchIssuerDN, governance.ConfidenceLow},
		{governance.PrecedenceFallback, governance.MatchFallback, governance.ConfidenceLow},
	}
	for _, c := range cases {
		var sig governance.CertificateSignals
		switch c.kind {
		case governance.MatchAgentGroup:
			sig = governance.CertificateSignals{CertificateID: "c1", ObservingAgentGroupIDs: []string{"g1"}}
		case governance.MatchIssuerDN:
			sig = governance.CertificateSignals{CertificateID: "c1", Issuer: "CN=ca"}
		default:
			sig = governance.CertificateSignals{CertificateID: "c1"}
		}
		val := ""
		switch c.kind {
		case governance.MatchAgentGroup:
			val = "g1"
		case governance.MatchIssuerDN:
			val = "CN=ca"
		}
		rules := mustCompile(t, rule("r", c.tier, c.kind, val, 100, baseTime))
		d := decideOwnership(sig, nil, rules, baseTime)
		if d.decision != governance.DecisionMatched || d.confidence != c.want {
			t.Fatalf("tier %s: got decision=%s confidence=%s; want matched/%s", c.tier, d.decision, d.confidence, c.want)
		}
	}
}

func TestDecideLosingRulesBoundedAndOrdered(t *testing.T) {
	// 12 matching san rules at increasing priority: winner = lowest
	// priority; losing capped at 8 in ascending priority order.
	var rs []governance.OwnershipRule
	for i := 0; i < 12; i++ {
		rs = append(rs, rule("r"+string(rune('a'+i)), governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100+i, baseTime))
	}
	rules := mustCompile(t, rs...)
	d := decideOwnership(sigWithSAN("a.example"), nil, rules, baseTime)
	if len(d.losing) != maxLosingRules {
		t.Fatalf("losing len = %d; want %d", len(d.losing), maxLosingRules)
	}
	for i := 1; i < len(d.losing); i++ {
		if d.losing[i-1].priority > d.losing[i].priority {
			t.Fatalf("losing not ascending by priority: %+v", d.losing)
		}
	}
}

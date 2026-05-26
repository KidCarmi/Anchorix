package ownership

import (
	"errors"
	"strings"
	"testing"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

func TestCompileRulesUnknownTierFailsLoud(t *testing.T) {
	_, _, err := compileRules([]governance.OwnershipRule{
		rule("r1", governance.PrecedenceTier("bogus_tier"), governance.MatchFallback, "", 1, baseTime),
	})
	if !errors.Is(err, ErrUnknownPrecedenceTier) {
		t.Fatalf("got %v; want ErrUnknownPrecedenceTier", err)
	}
}

func TestCompileRulesUnknownKindFailsLoud(t *testing.T) {
	_, _, err := compileRules([]governance.OwnershipRule{
		rule("r1", governance.PrecedenceSANPattern, governance.MatchKind("bogus_kind"), "x", 1, baseTime),
	})
	if !errors.Is(err, ErrUnknownMatchKind) {
		t.Fatalf("got %v; want ErrUnknownMatchKind", err)
	}
}

func TestCompileRulesRegexFailureIsInertNotFatal(t *testing.T) {
	compiled, failures, err := compileRules([]governance.OwnershipRule{
		rule("rbad", governance.PrecedenceSANPattern, governance.MatchSANRegex, "[", 100, baseTime),
		rule("rgood", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 200, baseTime),
	})
	if err != nil {
		t.Fatalf("regex failure must NOT abort the pass: %v", err)
	}
	if len(failures) != 1 || failures[0].RuleID != "rbad" {
		t.Fatalf("failures = %+v; want one for rbad", failures)
	}
	// The bad rule is inert (never matches); the good rule still wins.
	d := decideOwnership(sigWithSAN("a.example"), nil, compiled, baseTime)
	if d.decision != governance.DecisionMatched || *d.winningRuleID != "rgood" {
		t.Fatalf("inert bad regex should not match; got %+v", d)
	}
}

func TestCompileRulesRegexOverLengthIsInert(t *testing.T) {
	long := strings.Repeat("a", maxRegexPatternLen+1)
	_, failures, err := compileRules([]governance.OwnershipRule{
		rule("rlong", governance.PrecedenceSANPattern, governance.MatchSANRegex, long, 100, baseTime),
	})
	if err != nil {
		t.Fatalf("over-length regex must not abort: %v", err)
	}
	if len(failures) != 1 || !strings.Contains(failures[0].Reason, "length") {
		t.Fatalf("failures = %+v; want one length failure", failures)
	}
}

func TestCompileRulesSortsToLadderOrder(t *testing.T) {
	// Inserted out of order; expect (tier ordinal, priority,
	// created_at, id).
	compiled, _, err := compileRules([]governance.OwnershipRule{
		rule("rfb", governance.PrecedenceFallback, governance.MatchFallback, "", 1, baseTime),
		rule("rsanB", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime),
		rule("rsanA", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime),
		rule("ragent", governance.PrecedenceAgentGroup, governance.MatchAgentGroup, "g", 100, baseTime),
	})
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}
	got := []string{compiled[0].rule.ID, compiled[1].rule.ID, compiled[2].rule.ID, compiled[3].rule.ID}
	want := []string{"ragent", "rsanA", "rsanB", "rfb"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v; want %v", got, want)
		}
	}
}

func TestGlobMatchCaseInsensitiveAnchored(t *testing.T) {
	re := compileGlob("*.corp.example")
	if !re.MatchString("a.CORP.example") {
		t.Fatalf("glob should match case-insensitively")
	}
	if re.MatchString("a.corp.other") {
		t.Fatalf("glob should be anchored; must not match different suffix")
	}
	if re.MatchString("prefix-a.corp.example.evil.com") {
		t.Fatalf("glob anchored at end; must not match trailing junk")
	}
}

func TestSubjectCNGlobMatch(t *testing.T) {
	rules := mustCompile(t, rule("rcn", governance.PrecedenceSubjectPattern, governance.MatchSubjectCNGlob, "billing-*.corp.example", 100, baseTime))
	sig := governance.CertificateSignals{CertificateID: "c1", Subject: "CN=billing-01.corp.example,OU=Web"}
	d := decideOwnership(sig, nil, rules, baseTime)
	if d.decision != governance.DecisionMatched || *d.winningRuleID != "rcn" {
		t.Fatalf("subject CN glob should match; got %+v", d)
	}
}

func TestParseCN(t *testing.T) {
	cases := map[string]string{
		"CN=foo.example":          "foo.example",
		"CN=foo.example,OU=X,O=Y": "foo.example",
		"OU=X,CN=bar.example":     "bar.example",
		"cn=lower.example":        "lower.example",
		"O=NoCommonName":          "",
		"":                        "",
	}
	for subj, want := range cases {
		if got := parseCN(subj); got != want {
			t.Fatalf("parseCN(%q) = %q; want %q", subj, got, want)
		}
	}
}

func TestParseTagMatch(t *testing.T) {
	k, v, has := parseTagMatch("env:prod")
	if k != "env" || v != "prod" || !has {
		t.Fatalf("env:prod → %q/%q/%v", k, v, has)
	}
	k, v, has = parseTagMatch("env")
	if k != "env" || v != "" || has {
		t.Fatalf("env → %q/%q/%v (want any-value)", k, v, has)
	}
	k, v, has = parseTagMatch("env:")
	if k != "env" || v != "" || !has {
		t.Fatalf("env: → %q/%q/%v (want empty-value match)", k, v, has)
	}
}

func TestTagAgentGroupIssuerStorePredicates(t *testing.T) {
	sig := governance.CertificateSignals{
		CertificateID:          "c1",
		Issuer:                 "CN=Internal CA",
		StoreLocations:         []string{"LocalMachine\\WebHosting"},
		ObservingAgentGroupIDs: []string{"grp-web"},
		CertTags:               []governance.TagPair{{Key: "env", Value: "prod"}},
		AgentTags:              []governance.TagPair{{Key: "tier", Value: "web"}},
	}
	check := func(kind governance.MatchKind, tier governance.PrecedenceTier, val string, wantMatch bool) {
		t.Helper()
		rules := mustCompile(t, rule("r", tier, kind, val, 100, baseTime))
		d := decideOwnership(sig, nil, rules, baseTime)
		matched := d.decision == governance.DecisionMatched
		if matched != wantMatch {
			t.Fatalf("kind=%s val=%q matched=%v; want %v", kind, val, matched, wantMatch)
		}
	}
	check(governance.MatchTag, governance.PrecedenceTag, "env:prod", true)
	check(governance.MatchTag, governance.PrecedenceTag, "tier", true) // agent tag, any value
	check(governance.MatchTag, governance.PrecedenceTag, "env:dev", false)
	check(governance.MatchAgentGroup, governance.PrecedenceAgentGroup, "grp-web", true)
	check(governance.MatchAgentGroup, governance.PrecedenceAgentGroup, "grp-other", false)
	check(governance.MatchIssuerDN, governance.PrecedenceIssuerStore, "CN=Internal CA", true)
	check(governance.MatchIssuerDN, governance.PrecedenceIssuerStore, "CN=Other CA", false)
	check(governance.MatchStoreLocation, governance.PrecedenceIssuerStore, "LocalMachine\\WebHosting", true)
	check(governance.MatchStoreLocation, governance.PrecedenceIssuerStore, "LocalMachine\\My", false)
}

func TestExplanationDeterminism(t *testing.T) {
	rules := mustCompile(t,
		rule("rfb", governance.PrecedenceFallback, governance.MatchFallback, "", 1, baseTime),
		rule("rsan", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.example", 100, baseTime),
	)
	sig := governance.CertificateSignals{
		CertificateID:  "c1",
		Subject:        "CN=a.example",
		Issuer:         "CN=ca",
		SANs:           []string{"a.example", "b.example"},
		StoreLocations: []string{"S1"},
		CertTags:       []governance.TagPair{{Key: "env", Value: "prod"}},
	}
	d := decideOwnership(sig, nil, rules, baseTime)
	// Byte-identical across repeated builds → deterministic.
	l1, l2 := buildLosingRulesJSON(d.losing), buildLosingRulesJSON(d.losing)
	s1, s2 := buildSignalsSeenJSON(sig), buildSignalsSeenJSON(sig)
	if string(l1) != string(l2) || string(s1) != string(s2) {
		t.Fatalf("explanation JSON not deterministic")
	}
	if !strings.Contains(string(s1), `"subject_cn":"a.example"`) {
		t.Fatalf("signals_seen missing parsed subject_cn: %s", s1)
	}
	if strings.Contains(string(s1), "null") {
		t.Fatalf("signals_seen must coalesce nil slices to []: %s", s1)
	}
}

package ownership

import (
	"errors"
	"strings"
	"testing"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

func TestValidateRuleKindAndTier(t *testing.T) {
	cases := []struct {
		name      string
		kind      governance.MatchKind
		supplied  governance.PrecedenceTier
		wantTier  governance.PrecedenceTier
		wantErrIs error
	}{
		{"san_glob derives san_pattern", governance.MatchSANGlob, "", governance.PrecedenceSANPattern, nil},
		{"agent_group derives agent_group", governance.MatchAgentGroup, "", governance.PrecedenceAgentGroup, nil},
		{"fallback derives fallback", governance.MatchFallback, "", governance.PrecedenceFallback, nil},
		{"issuer_dn derives issuer_store", governance.MatchIssuerDN, "", governance.PrecedenceIssuerStore, nil},
		{"store_location derives issuer_store", governance.MatchStoreLocation, "", governance.PrecedenceIssuerStore, nil},
		{"tag derives tag", governance.MatchTag, "", governance.PrecedenceTag, nil},
		{"subject derives subject_pattern", governance.MatchSubjectCNGlob, "", governance.PrecedenceSubjectPattern, nil},
		{"matching supplied tier accepted", governance.MatchSANGlob, governance.PrecedenceSANPattern, governance.PrecedenceSANPattern, nil},
		{"service_member tier rejected", governance.MatchSANGlob, governance.PrecedenceServiceMember, "", ErrServiceMemberReserved},
		{"explicit tier mismatch rejected", governance.MatchSANGlob, governance.PrecedenceExplicit, "", ErrInvalidRule},
		{"mismatched tier rejected", governance.MatchSANGlob, governance.PrecedenceTag, "", ErrInvalidRule},
		{"unknown kind rejected", governance.MatchKind("bogus"), "", "", ErrInvalidRule},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tier, err := validateRuleKindAndTier(c.kind, c.supplied)
			if c.wantErrIs != nil {
				if !errors.Is(err, c.wantErrIs) {
					t.Fatalf("err = %v; want errors.Is %v", err, c.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tier != c.wantTier {
				t.Fatalf("tier = %q; want %q", tier, c.wantTier)
			}
		})
	}
}

func TestValidateMatchValue(t *testing.T) {
	t.Run("fallback must be empty", func(t *testing.T) {
		if _, err := validateMatchValue(governance.MatchFallback, ""); err != nil {
			t.Fatalf("empty fallback value: %v", err)
		}
		if _, err := validateMatchValue(governance.MatchFallback, "x"); !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("non-empty fallback value err = %v; want ErrInvalidRule", err)
		}
	})
	t.Run("non-fallback requires value", func(t *testing.T) {
		if _, err := validateMatchValue(governance.MatchSANGlob, "  "); !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("blank value err = %v; want ErrInvalidRule", err)
		}
	})
	t.Run("oversized value rejected", func(t *testing.T) {
		big := strings.Repeat("a", maxRuleMatchValueLen+1)
		if _, err := validateMatchValue(governance.MatchSANGlob, big); !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("oversized value err = %v; want ErrInvalidRule", err)
		}
	})
	t.Run("invalid regex rejected", func(t *testing.T) {
		if _, err := validateMatchValue(governance.MatchSANRegex, "["); !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("invalid regex err = %v; want ErrInvalidRule", err)
		}
	})
	t.Run("oversized regex rejected", func(t *testing.T) {
		big := strings.Repeat("a", maxRegexPatternLen+1)
		if _, err := validateMatchValue(governance.MatchSANRegex, big); !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("oversized regex err = %v; want ErrInvalidRule", err)
		}
	})
	t.Run("valid regex accepted", func(t *testing.T) {
		if _, err := validateMatchValue(governance.MatchSANRegex, `^.*\.example$`); err != nil {
			t.Fatalf("valid regex: %v", err)
		}
	})
	t.Run("agent_group flagged", func(t *testing.T) {
		isAG, err := validateMatchValue(governance.MatchAgentGroup, "grp-1")
		if err != nil || !isAG {
			t.Fatalf("agent_group value: isAG=%v err=%v; want true/nil", isAG, err)
		}
	})
	t.Run("non-agent-group not flagged", func(t *testing.T) {
		isAG, err := validateMatchValue(governance.MatchSANGlob, "*.example")
		if err != nil || isAG {
			t.Fatalf("san value: isAG=%v err=%v; want false/nil", isAG, err)
		}
	})
}

func TestValidateRuleNameDescriptionPriority(t *testing.T) {
	if err := validateRuleName(""); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("empty name err = %v; want ErrInvalidRule", err)
	}
	if err := validateRuleName(strings.Repeat("n", maxRuleNameLen+1)); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("oversized name err = %v; want ErrInvalidRule", err)
	}
	if err := validateRuleName("billing-san"); err != nil {
		t.Fatalf("valid name: %v", err)
	}
	if err := validateRuleDescription(strings.Repeat("d", maxRuleDescriptionLen+1)); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("oversized description err = %v; want ErrInvalidRule", err)
	}
	if err := validateRulePriority(-1); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("negative priority err = %v; want ErrInvalidRule", err)
	}
	if err := validateRulePriority(maxRulePriority + 1); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("over-max priority err = %v; want ErrInvalidRule", err)
	}
	if err := validateRulePriority(100); err != nil {
		t.Fatalf("valid priority: %v", err)
	}
}

// TestTierForKindNeverProducesReservedTiers guards the canonical map:
// no operator-creatable kind may map to explicit or service_member.
func TestTierForKindNeverProducesReservedTiers(t *testing.T) {
	for kind, tier := range tierForKind {
		if tier == governance.PrecedenceExplicit || tier == governance.PrecedenceServiceMember {
			t.Fatalf("kind %q maps to reserved tier %q", kind, tier)
		}
	}
}

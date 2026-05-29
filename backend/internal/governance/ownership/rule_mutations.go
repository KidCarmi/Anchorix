package ownership

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/ids"
)

// H-026B3B ownership-rule mutations. Each mutation:
//
//   - validates input (pure, fail-closed) BEFORE touching the DB;
//   - validates rule targets via the bounded resolver (active service;
//     active agent group for agent_group rules) — no fleet scans;
//   - writes the repo row and the severity:"security" audit event in
//     ONE transaction (WithTx), so an audit failure rolls the mutation
//     back: exactly-once audit on success, none on failure;
//   - is org-scoped on every read and write; cross-org ids collapse to
//     ErrOwnershipRuleNotFound (→ 404), never a cross-org mutation.
//
// Identity-shaping fields (name, match_kind, service_id, tier) are
// immutable after creation (A1 design): UpdateRule mutates only
// priority / match_value / description. Changing identity is a
// disable + recreate.

// CreateRuleInput is the validated input to CreateRule. Tier is
// optional: when empty it is derived from MatchKind's canonical tier.
type CreateRuleInput struct {
	OrganizationID string
	ActorUserID    string
	Name           string
	Description    string
	ServiceID      string
	MatchKind      governance.MatchKind
	PrecedenceTier governance.PrecedenceTier // optional; derived from kind when empty
	MatchValue     string
	Priority       int
}

// UpdateRuleInput is the validated input to UpdateRule. The mutable
// fields are pointers so an omitted field (nil) is preserved from the
// stored row, distinguishing "not supplied" from an explicit value —
// a PATCH of {"description":"x"} must not blank match_value or reset
// priority to 0. MatchValue is re-validated against the rule's
// (immutable) MatchKind.
type UpdateRuleInput struct {
	OrganizationID string
	ActorUserID    string
	RuleID         string
	Description    *string
	MatchValue     *string
	Priority       *int
}

// ruleAuditEventNow builds the severity:"security" audit.Event for a
// rule mutation. Every governance state change carries
// severity:"security" per CLAUDE.md §9; the marshal of a map of
// documented scalar types cannot fail in practice.
func (s *Service) ruleAuditEventNow(orgID, actor, action, ruleID string, now time.Time, extra map[string]any) audit.Event {
	combined := make(map[string]any, len(extra)+1)
	combined["severity"] = "security"
	for k, v := range extra {
		combined[k] = v
	}
	md, _ := json.Marshal(combined)
	return audit.Event{
		OrganizationID: orgID,
		OccurredAt:     now,
		Actor:          actor,
		ActorType:      "user",
		Action:         action,
		TargetType:     "ownership_rule",
		TargetID:       ruleID,
		Metadata:       md,
	}
}

// CreateRule validates + persists a new ownership rule and emits
// ownership.rule_created (severity:"security"). Rejects:
// service_member tier, unknown/ mismatched tier+kind, invalid or
// oversized regex, empty/oversized name|match_value, out-of-range
// priority, nonexistent target service, and (for agent_group rules)
// nonexistent agent group. Duplicate (org,name) → ErrOwnershipRuleAlreadyExists.
func (s *Service) CreateRule(ctx context.Context, in CreateRuleInput) (*governance.OwnershipRule, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.ServiceID = strings.TrimSpace(in.ServiceID)
	if err := requireRuleOrgActor(in.OrganizationID, in.ActorUserID); err != nil {
		return nil, err
	}
	if err := validateRuleName(in.Name); err != nil {
		return nil, err
	}
	if err := validateRuleDescription(in.Description); err != nil {
		return nil, err
	}
	if err := validateRulePriority(in.Priority); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.ServiceID) == "" {
		return nil, fmt.Errorf("%w: service_id required", ErrInvalidRule)
	}
	tier, err := validateRuleKindAndTier(in.MatchKind, in.PrecedenceTier)
	if err != nil {
		return nil, err
	}
	isAgentGroup, err := validateMatchValue(in.MatchKind, in.MatchValue)
	if err != nil {
		return nil, err
	}

	// Target existence (bounded single-row lookups). The target
	// service must be active; an agent_group rule's value must name an
	// active agent group.
	ok, err := s.resolver.ActiveServiceExists(ctx, in.OrganizationID, in.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("ownership: resolve service: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: service_id %q", ErrRuleServiceNotFound, in.ServiceID)
	}
	if isAgentGroup {
		ok, err := s.resolver.ActiveAgentGroupExists(ctx, in.OrganizationID, in.MatchValue)
		if err != nil {
			return nil, fmt.Errorf("ownership: resolve agent group: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("%w: agent_group %q", ErrRuleTargetNotFound, in.MatchValue)
		}
	}

	now := s.clock.Now()
	rule := &governance.OwnershipRule{
		ID:             ids.New(),
		OrganizationID: in.OrganizationID,
		Name:           in.Name,
		Description:    in.Description,
		ServiceID:      in.ServiceID,
		PrecedenceTier: tier,
		Priority:       in.Priority,
		MatchKind:      in.MatchKind,
		MatchValue:     in.MatchValue,
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      in.ActorUserID,
	}
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.Ownership.CreateOwnershipRule(ctx, rule); err != nil {
			return err // includes ErrOwnershipRuleAlreadyExists (typed conflict)
		}
		return s.recordRuleAudit(ctx, s.ruleAuditEventNow(in.OrganizationID, in.ActorUserID, "ownership.rule_created", rule.ID, now, map[string]any{
			"name":            rule.Name,
			"service_id":      rule.ServiceID,
			"precedence_tier": string(rule.PrecedenceTier),
			"match_kind":      string(rule.MatchKind),
			"priority":        rule.Priority,
		}))
	}); err != nil {
		return nil, err
	}
	return rule, nil
}

// UpdateRule mutates the operator-editable fields (priority,
// match_value, description) of an existing rule and emits
// ownership.rule_updated. match_value is re-validated against the
// rule's immutable match_kind; an agent_group rule's new value must
// still name an active agent group. Cross-org / missing id →
// ErrOwnershipRuleNotFound.
func (s *Service) UpdateRule(ctx context.Context, in UpdateRuleInput) (*governance.OwnershipRule, error) {
	in.RuleID = strings.TrimSpace(in.RuleID)
	if err := requireRuleOrgActor(in.OrganizationID, in.ActorUserID); err != nil {
		return nil, err
	}
	if in.RuleID == "" {
		return nil, fmt.Errorf("%w: rule id required", ErrInvalidRule)
	}

	// Load the existing rule to learn its immutable match_kind, to
	// produce a clean 404 for a cross-org / missing id before any
	// write, and to MERGE omitted PATCH fields: a nil field is
	// preserved from the stored row, so PATCH {"description":"x"} does
	// not blank match_value or reset priority to 0.
	existing, err := s.repo.Ownership.GetOwnershipRule(ctx, in.OrganizationID, in.RuleID)
	if err != nil {
		return nil, err // ErrOwnershipRuleNotFound on miss / cross-org
	}

	description := existing.Description
	if in.Description != nil {
		description = strings.TrimSpace(*in.Description)
	}
	matchValue := existing.MatchValue
	if in.MatchValue != nil {
		matchValue = *in.MatchValue
	}
	priority := existing.Priority
	if in.Priority != nil {
		priority = *in.Priority
	}

	if err := validateRuleDescription(description); err != nil {
		return nil, err
	}
	if err := validateRulePriority(priority); err != nil {
		return nil, err
	}
	isAgentGroup, err := validateMatchValue(existing.MatchKind, matchValue)
	if err != nil {
		return nil, err
	}
	if isAgentGroup {
		ok, err := s.resolver.ActiveAgentGroupExists(ctx, in.OrganizationID, matchValue)
		if err != nil {
			return nil, fmt.Errorf("ownership: resolve agent group: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("%w: agent_group %q", ErrRuleTargetNotFound, matchValue)
		}
	}

	now := s.clock.Now()
	var updated *governance.OwnershipRule
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.Ownership.UpdateOwnershipRuleMutable(ctx, in.OrganizationID, in.RuleID, priority, matchValue, description); err != nil {
			return err
		}
		got, err := s.repo.Ownership.GetOwnershipRule(ctx, in.OrganizationID, in.RuleID)
		if err != nil {
			return err
		}
		updated = got
		return s.recordRuleAudit(ctx, s.ruleAuditEventNow(in.OrganizationID, in.ActorUserID, "ownership.rule_updated", in.RuleID, now, map[string]any{
			"priority": priority,
		}))
	}); err != nil {
		return nil, err
	}
	return updated, nil
}

// EnableRule restores enabled=true (idempotent) and emits
// ownership.rule_enabled.
func (s *Service) EnableRule(ctx context.Context, organizationID, actorUserID, ruleID string) (*governance.OwnershipRule, error) {
	return s.setRuleEnabled(ctx, organizationID, actorUserID, ruleID, true)
}

// DisableRule stamps disabled_at + enabled=false (idempotent) and
// emits ownership.rule_disabled. A disabled rule is excluded from the
// engine's next recompute.
func (s *Service) DisableRule(ctx context.Context, organizationID, actorUserID, ruleID string) (*governance.OwnershipRule, error) {
	return s.setRuleEnabled(ctx, organizationID, actorUserID, ruleID, false)
}

func (s *Service) setRuleEnabled(ctx context.Context, organizationID, actorUserID, ruleID string, enable bool) (*governance.OwnershipRule, error) {
	ruleID = strings.TrimSpace(ruleID)
	if err := requireRuleOrgActor(organizationID, actorUserID); err != nil {
		return nil, err
	}
	if ruleID == "" {
		return nil, fmt.Errorf("%w: rule id required", ErrInvalidRule)
	}
	// Preflight existence so a cross-org / missing id is a clean 404
	// before we open the tx (the repo enable/disable returns
	// ErrOwnershipRuleNotFound too, but checking first keeps the audit
	// row from being attempted for a nonexistent target).
	if _, err := s.repo.Ownership.GetOwnershipRule(ctx, organizationID, ruleID); err != nil {
		return nil, err
	}

	now := s.clock.Now()
	action := "ownership.rule_disabled"
	if enable {
		action = "ownership.rule_enabled"
	}
	var updated *governance.OwnershipRule
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if enable {
			err = s.repo.Ownership.EnableOwnershipRule(ctx, organizationID, ruleID)
		} else {
			err = s.repo.Ownership.DisableOwnershipRule(ctx, organizationID, ruleID)
		}
		if err != nil {
			return err
		}
		got, err := s.repo.Ownership.GetOwnershipRule(ctx, organizationID, ruleID)
		if err != nil {
			return err
		}
		updated = got
		return s.recordRuleAudit(ctx, s.ruleAuditEventNow(organizationID, actorUserID, action, ruleID, now, nil))
	}); err != nil {
		return nil, err
	}
	return updated, nil
}

// --- shared helpers ---------------------------------------------------

func requireRuleOrgActor(orgID, actor string) error {
	if strings.TrimSpace(orgID) == "" {
		return fmt.Errorf("%w: organization id required", ErrInvalidRule)
	}
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor user id required", ErrInvalidRule)
	}
	return nil
}

func (s *Service) recordRuleAudit(ctx context.Context, e audit.Event) error {
	if err := s.audit.Record(ctx, e); err != nil {
		return fmt.Errorf("ownership: record rule audit: %w", err)
	}
	return nil
}

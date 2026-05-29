package governance

import (
	"context"
	"time"
)

// OwnershipRepository is the storage contract for the
// ownership half of governance. The concrete implementation
// lives in internal/storage/postgres; this interface is owned
// by the consumer (CLAUDE.md §8.8).
//
// H-026A1 ships the minimum surface needed to prove storage
// correctness. The H-026B engine composes higher-level methods
// (paginated cert load, snapshot recompute) on top.
type OwnershipRepository interface {
	// ----- ownership rules -----

	CreateOwnershipRule(ctx context.Context, r *OwnershipRule) error
	GetOwnershipRule(ctx context.Context, organizationID, ruleID string) (*OwnershipRule, error)

	// ListOwnershipRules returns every rule in the organization
	// ordered by id ASC. When enabledOnly is true, disabled
	// rules are excluded.
	//
	// The order is `id ASC` — operator-facing stable pagination.
	// This is **deliberately NOT** the engine walk order, which
	// is `(precedence_tier, priority, created_at, id)`. The
	// engine's read path will live in
	// internal/governance/ownership/ (H-026B) and use the
	// partial index `ownership_rules_org_enabled_walk_idx` from
	// migration 0010 directly via a separate repository method
	// — H-026B must add that method, not reuse this one. The
	// distinction matters because the engine's determinism
	// guarantee (governance plan §4.4) depends on the tier /
	// priority / created_at tiebreaker; calling this method
	// would walk rules in id order, which is non-deterministic
	// w.r.t. the precedence ladder.
	ListOwnershipRules(ctx context.Context, organizationID string, enabledOnly bool) ([]OwnershipRule, error)

	// ListOwnershipRulesByService returns every rule pointing at
	// serviceID, regardless of enabled / disabled state.
	ListOwnershipRulesByService(ctx context.Context, organizationID, serviceID string) ([]OwnershipRule, error)

	// ListOwnershipRulesPaged is the cursor-paged variant of
	// ListOwnershipRules, used by the H-026B3A operator
	// /ownership-rules view. Ordered by id ASC for repeatable
	// pagination. The enabledFilter is tri-state: nil returns all
	// rules, a pointer to true returns only enabled, and a pointer
	// to false returns only disabled.
	ListOwnershipRulesPaged(
		ctx context.Context,
		organizationID, cursorRuleID string,
		pageSize int,
		enabledFilter *bool,
	) ([]OwnershipRule, error)

	// ListOwnershipRulesForEngine returns the org's ENABLED rules in
	// the engine's deterministic walk order:
	// (precedence_tier ladder ordinal ASC, priority ASC,
	// created_at ASC, id ASC). The tier ordinal is the §4.2 ladder
	// (explicit=1 … fallback=8), NOT the lexical text order — the
	// implementation CASE-maps the tier so a tier rename cannot
	// silently reorder the ladder (H026B plan §3.2). This is the read
	// the H-026B engine walks; it is deliberately distinct from
	// ListOwnershipRules (id ASC, operator pagination), which the
	// engine MUST NOT use.
	ListOwnershipRulesForEngine(ctx context.Context, organizationID string) ([]OwnershipRule, error)

	// UpdateOwnershipRuleMutable updates the operator-editable
	// fields (priority, match_value, description).
	// Identity-shaping fields (precedence_tier, match_kind,
	// service_id, name) require a delete + recreate per
	// design — H-026A1 doesn't expose those changes.
	UpdateOwnershipRuleMutable(
		ctx context.Context,
		organizationID, ruleID string,
		priority int,
		matchValue, description string,
	) error

	// DisableOwnershipRule stamps disabled_at and clears the
	// enabled flag. Idempotent.
	DisableOwnershipRule(ctx context.Context, organizationID, ruleID string) error

	// EnableOwnershipRule restores enabled=true and clears
	// disabled_at. Idempotent.
	EnableOwnershipRule(ctx context.Context, organizationID, ruleID string) error

	// ----- certificate ownership (derived) -----

	// UpsertCertificateOwnership writes the cert's current
	// ownership state. INSERT on first call, UPDATE on
	// subsequent calls for the same (org, cert) pair.
	UpsertCertificateOwnership(ctx context.Context, o *CertificateOwnership) error

	// GetCertificateOwnership returns the current row.
	// ErrCertificateOwnershipNotFound when the engine has not
	// yet derived ownership for the cert.
	GetCertificateOwnership(ctx context.Context, organizationID, certificateID string) (*CertificateOwnership, error)

	// ListCertificateOwnershipByService returns every cert
	// currently owned by serviceID, ordered by certificate_id
	// ASC.
	ListCertificateOwnershipByService(
		ctx context.Context,
		organizationID, serviceID string,
	) ([]CertificateOwnership, error)

	// ListCertificateOwnershipByDecision returns every cert
	// currently classified `decision`, ordered by certificate_id
	// ASC. Used by the unowned-triage operator view.
	ListCertificateOwnershipByDecision(
		ctx context.Context,
		organizationID string,
		decision Decision,
	) ([]CertificateOwnership, error)

	// ListCertificateOwnershipByDecisionPaged is the cursor-paged
	// variant of ListCertificateOwnershipByDecision, used by the
	// H-026B3A operator views /ownership/unowned and /ownership/ambiguous
	// where the result set can exceed the in-memory budget on a
	// large fleet.
	ListCertificateOwnershipByDecisionPaged(
		ctx context.Context,
		organizationID string,
		decision Decision,
		cursorCertID string,
		pageSize int,
	) ([]CertificateOwnership, error)

	// ListCertificateOwnershipPaged returns one page of the org's
	// current ownership rows whose certificate_id is strictly greater
	// than cursorCertID, ordered by certificate_id ASC, capped at
	// pageSize. The empty cursor starts from the beginning. The
	// H-026B recompute pages this in lockstep with
	// ListCertificateSignalsPaged (both keyed by certificate_id ASC)
	// so the streaming diff never holds the whole fleet in memory.
	ListCertificateOwnershipPaged(
		ctx context.Context,
		organizationID, cursorCertID string,
		pageSize int,
	) ([]CertificateOwnership, error)

	// ListCertificateOwnershipStale returns one page of ownership
	// rows whose last_evaluated_at is strictly before olderThan,
	// ordered by certificate_id ASC, paged by cursorCertID, capped at
	// limit. Backs GET /ownership/stale; the staleness threshold is a
	// config knob, not a stored column (H026B plan §4.5).
	ListCertificateOwnershipStale(
		ctx context.Context,
		organizationID string,
		olderThan time.Time,
		cursorCertID string,
		limit int,
	) ([]CertificateOwnership, error)

	// ----- overrides -----

	CreateOwnershipOverride(ctx context.Context, o *CertificateOwnershipOverride) error
	GetOwnershipOverride(ctx context.Context, organizationID, overrideID string) (*CertificateOwnershipOverride, error)

	// GetActiveOwnershipOverride returns the unique active
	// override for the cert, or nil if none exists. (Not an
	// error — "no active override" is a normal state.)
	GetActiveOwnershipOverride(
		ctx context.Context,
		organizationID, certificateID string,
	) (*CertificateOwnershipOverride, error)

	// ClearOwnershipOverride writes (cleared_at, cleared_by,
	// cleared_reason). Returns ErrOwnershipOverrideNotFound on
	// miss.
	ClearOwnershipOverride(
		ctx context.Context,
		organizationID, overrideID, clearedBy, clearedReason string,
		clearedAt time.Time,
	) error

	// ListActiveOwnershipOverridesPaged returns one page of the org's
	// ACTIVE (cleared_at IS NULL) overrides whose certificate_id is
	// strictly greater than cursorCertID, ordered by certificate_id
	// ASC, capped at pageSize. The active partial-unique index
	// guarantees one active override per cert, so certificate_id is a
	// valid unique cursor. The H-026B recompute uses this to apply
	// tier-1 (explicit) ownership without a per-cert override lookup.
	ListActiveOwnershipOverridesPaged(
		ctx context.Context,
		organizationID, cursorCertID string,
		pageSize int,
	) ([]CertificateOwnershipOverride, error)

	// ListOverridesExpiringBy returns every ACTIVE override in the org
	// whose expires_at is non-NULL and <= now, ordered by
	// certificate_id ASC. The H-026B recompute auto-clears these in
	// the same pass. The expired set is small at fleet scale, so this
	// is unpaged by design.
	ListOverridesExpiringBy(
		ctx context.Context,
		organizationID string,
		now time.Time,
	) ([]CertificateOwnershipOverride, error)

	// ----- engine signal reads -----

	// ListCertificateSignalsPaged returns one page of per-certificate
	// ownership signals whose certificate_id is strictly greater than
	// cursorCertID, ordered by certificate_id ASC, capped at pageSize.
	// The empty cursor starts from the beginning.
	//
	// The implementation MUST page by the certificates table and
	// gather each cert's observation / agent-group / tag signal sets
	// via per-certificate LATERAL sub-aggregates (or an equivalent
	// bounded per-cert strategy). It MUST NOT use a fleet-wide GROUP
	// BY across certificates × observations × memberships ×
	// tag_assignments — that materializes the whole fleet and defeats
	// paging (binding requirement, H026B plan §3.1). The engine makes
	// ZERO per-cert follow-up queries: every signal it needs is on the
	// returned CertificateSignals.
	ListCertificateSignalsPaged(
		ctx context.Context,
		organizationID, cursorCertID string,
		pageSize int,
	) ([]CertificateSignals, error)

	// ----- explanations -----

	CreateOwnershipExplanation(ctx context.Context, e *OwnershipMatchExplanation) error
	GetOwnershipExplanation(ctx context.Context, organizationID, explanationID string) (*OwnershipMatchExplanation, error)

	// ListOwnershipExplanationsForCertificate returns the
	// per-cert explanation timeline ordered by decided_at DESC.
	// limit caps the response — pass 0 for all.
	ListOwnershipExplanationsForCertificate(
		ctx context.Context,
		organizationID, certificateID string,
		limit int,
	) ([]OwnershipMatchExplanation, error)

	// ListOwnershipExplanationsForCertificatePaged is the cursor-paged
	// variant. Ordering is `(decided_at DESC, id ASC)`; the cursor is
	// the (decided_at, id) of the LAST row of the previous page.
	// A cursor with a zero-value time and empty id is the "from the
	// beginning" sentinel and yields the unfiltered first page.
	ListOwnershipExplanationsForCertificatePaged(
		ctx context.Context,
		organizationID, certificateID string,
		cursorDecidedAt time.Time,
		cursorExplanationID string,
		limit int,
	) ([]OwnershipMatchExplanation, error)
}

// PolicyRepository is the storage contract for the policy
// half of governance.
type PolicyRepository interface {
	// ----- policy definitions -----

	CreatePolicyDefinition(ctx context.Context, d *PolicyDefinition) error
	GetPolicyDefinition(ctx context.Context, organizationID, definitionID string) (*PolicyDefinition, error)

	// GetLatestPolicyDefinitionBySlug returns the highest
	// (slug, version) row for the slug. Returns
	// ErrPolicyDefinitionNotFound when the slug is unknown.
	GetLatestPolicyDefinitionBySlug(
		ctx context.Context,
		organizationID, slug string,
	) (*PolicyDefinition, error)

	// ListPolicyDefinitions returns every (slug, version) row
	// in the organization ordered by (slug ASC, version DESC).
	// When activeOnly is true, disabled rows are excluded.
	ListPolicyDefinitions(ctx context.Context, organizationID string, activeOnly bool) ([]PolicyDefinition, error)

	DisablePolicyDefinition(ctx context.Context, organizationID, definitionID string) error

	// ----- policy assignments -----

	CreatePolicyAssignment(ctx context.Context, a *PolicyAssignment) error
	GetPolicyAssignment(ctx context.Context, organizationID, assignmentID string) (*PolicyAssignment, error)

	// ClearPolicyAssignment writes (cleared_at, cleared_by).
	// Returns ErrPolicyAssignmentNotFound on miss.
	ClearPolicyAssignment(
		ctx context.Context,
		organizationID, assignmentID, clearedBy string,
		clearedAt time.Time,
	) error

	// ListActivePolicyAssignmentsForScope returns every active
	// assignment whose (scope_kind, scope_id) matches, ordered
	// by assigned_at ASC, id ASC.
	ListActivePolicyAssignmentsForScope(
		ctx context.Context,
		organizationID string,
		scopeKind PolicyScopeKind,
		scopeID string,
	) ([]PolicyAssignment, error)

	// ListActivePolicyAssignmentsForDefinition returns every
	// active assignment of the definition.
	ListActivePolicyAssignmentsForDefinition(
		ctx context.Context,
		organizationID, definitionID string,
	) ([]PolicyAssignment, error)

	// ----- policy waivers -----

	CreatePolicyWaiver(ctx context.Context, w *PolicyWaiver) error
	GetPolicyWaiver(ctx context.Context, organizationID, waiverID string) (*PolicyWaiver, error)

	// ClearPolicyWaiver writes (cleared_at, cleared_by).
	// Returns ErrPolicyWaiverNotFound on miss.
	ClearPolicyWaiver(
		ctx context.Context,
		organizationID, waiverID, clearedBy string,
		clearedAt time.Time,
	) error

	// ListActivePolicyWaiversForScope returns every active
	// waiver whose (scope_kind, scope_id) matches, ordered by
	// granted_at ASC, id ASC.
	ListActivePolicyWaiversForScope(
		ctx context.Context,
		organizationID string,
		scopeKind PolicyScopeKind,
		scopeID string,
	) ([]PolicyWaiver, error)

	// ListActivePolicyWaiversForDefinition returns every active
	// waiver attached to the definition.
	ListActivePolicyWaiversForDefinition(
		ctx context.Context,
		organizationID, definitionID string,
	) ([]PolicyWaiver, error)
}

// GovernanceRecomputeRunsRepository is the storage contract for
// the per-pass operational record table. Kept on its own
// interface because the H-026B engine and the H-026D engine
// both write to it; neither imports the other.
type GovernanceRecomputeRunsRepository interface {
	// StartRecomputeRun INSERTs a new row with the supplied
	// identity and start metadata. Succeeded / FinishedAt /
	// ErrorClass / counters are populated by FinishRecomputeRun
	// at the end of the pass.
	StartRecomputeRun(ctx context.Context, r *GovernanceRecomputeRun) error

	// FinishRecomputeRun updates the row with the final
	// counters + outcome.
	FinishRecomputeRun(ctx context.Context, r *GovernanceRecomputeRun) error

	// GetRecomputeRun fetches one row by id within an
	// organization.
	GetRecomputeRun(ctx context.Context, organizationID, runID string) (*GovernanceRecomputeRun, error)

	// ListRecentRecomputeRuns returns the most recent runs for
	// (organizationID, kind) ordered by started_at DESC,
	// capped at limit (limit=0 means default).
	ListRecentRecomputeRuns(
		ctx context.Context,
		organizationID string,
		kind RecomputeKind,
		limit int,
	) ([]GovernanceRecomputeRun, error)
}

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

	// GetCertificateOwnershipByCertificateIDs returns the prior-ownership
	// rows for the given cert ids in one org as a map keyed on
	// certificate_id. Empty / nil certIDs returns an empty map without a
	// DB round-trip. Foreign-org cert ids do not match (the WHERE binds
	// organization_id). An id with no certificate_ownership row is
	// silently absent from the result map — the caller treats it as
	// "first-run for that cert", matching the recompute's existing
	// no-prior-ownership semantic.
	//
	// The H-030 recompute set-lookup primitive: the recompute paginates
	// signals, collects each page's cert ids, and calls this method to
	// load matching prior ownership in one bounded round-trip. Memory
	// and per-iteration cost are bounded by len(certIDs) ≤ one signal
	// page. The query is index-aligned with the certificate_ownership
	// PK (organization_id, certificate_id) — no new index needed, no
	// fleet-wide scan reachable. Implementations MAY apply a defensive
	// upper bound on the batch size to fail closed on a caller bug.
	GetCertificateOwnershipByCertificateIDs(
		ctx context.Context,
		organizationID string,
		certIDs []string,
	) (map[string]CertificateOwnership, error)

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

	// ListExpiringOverridesPaged returns one page of ACTIVE overrides
	// (cleared_at IS NULL) whose expires_at is non-NULL and <= now,
	// keyed by certificate_id > cursorCertID, ordered certificate_id
	// ASC, capped at pageSize. The empty cursor starts from the
	// beginning. It is the H-029 paged read primitive a future B4
	// scheduler / manual operator sweep will drive (design:
	// docs/governance/H-029-expiring-override-sweep-pagination-design.md).
	//
	// The page is index-aligned with the partial-unique active-override
	// index (`certificate_ownership_overrides_active_idx
	// (organization_id, certificate_id) WHERE cleared_at IS NULL`) so a
	// bounded forward walk over expiring overrides never fleet-scans.
	// pageSize is bounded at the repository level until a service layer
	// owns clamping: pageSize <= 0 falls back to a documented default,
	// pageSize > the documented maximum is clamped. Read-only — no lock
	// required.
	ListExpiringOverridesPaged(
		ctx context.Context,
		organizationID string,
		now time.Time,
		cursorCertID string,
		pageSize int,
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

	// GetCertificateSignals returns the signal bundle for ONE
	// certificate via a bounded PK lookup (never a fleet scan), or
	// (nil, nil) when no cert row matches in the org. Used by the
	// H-026B3B single-cert override re-derivation.
	GetCertificateSignals(
		ctx context.Context,
		organizationID, certificateID string,
	) (*CertificateSignals, error)

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

	// ListCertificateIDsWithExplanationsPaged returns one page of the
	// DISTINCT certificate_ids that have explanation history in the org,
	// whose certificate_id is strictly greater than cursorCertID, ordered
	// certificate_id ASC, capped at pageSize. The empty cursor starts
	// from the beginning. It is the H-027 retention prune's outer walk.
	//
	// It MUST be backed by the (organization_id, certificate_id, ...)
	// index prefix and MUST NOT fleet-scan. Pruning non-current
	// explanations never removes a certificate from this list — the
	// FK-pinned current explanation always survives — so the
	// certificate_id cursor is stable and complete across prune passes.
	ListCertificateIDsWithExplanationsPaged(
		ctx context.Context,
		organizationID, cursorCertID string,
		pageSize int,
	) ([]string, error)

	// ListPrunableExplanationIDs returns a BOUNDED batch of explanation
	// ids eligible for retention pruning for ONE certificate, implementing
	// the same rule as ownership.SelectExplanationsToPrune but pushed into
	// SQL so a churny certificate with deep history never triggers an
	// unbounded read inside the prune transaction. An id is returned iff:
	//
	//   - its decided_at is strictly older than olderThan (the cutoff), AND
	//   - it is NOT among the latest keepN by (decided_at DESC, id ASC), AND
	//   - it is NOT the certificate's current (FK-pinned) explanation.
	//
	// Results are ordered oldest-first (decided_at ASC, id DESC) and
	// capped at limit, so repeated passes make deterministic forward
	// progress and a deep cert drains across passes (idempotent). Both
	// the latest-N subquery (LIMIT keepN) and the outer result (LIMIT
	// limit) are bounded; the statement never scans a cert's full
	// history. Org- and cert-scoped throughout.
	ListPrunableExplanationIDs(
		ctx context.Context,
		organizationID, certificateID string,
		olderThan time.Time,
		keepN, limit int,
	) ([]string, error)

	// DeleteOwnershipExplanationsForCertificate deletes the given
	// explanation ids for ONE certificate in the org. The DELETE is org-
	// AND cert-scoped and additionally guards against ever removing the
	// certificate's CURRENT (FK-pinned) explanation via a NOT EXISTS
	// check on certificate_ownership.explanation_id — belt-and-suspenders
	// with the ON DELETE RESTRICT FK and the caller's selection
	// exclusion. A zero-id slice or a no-match set is a safe no-op
	// returning 0. Returns the number of rows actually deleted.
	DeleteOwnershipExplanationsForCertificate(
		ctx context.Context,
		organizationID, certificateID string,
		explanationIDs []string,
	) (int64, error)
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

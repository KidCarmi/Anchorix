package ownership

import (
	"context"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// Read-side methods on Service. These are thin facades over
// governance.OwnershipRepository + GovernanceRecomputeRunsRepository
// so the H-026B3A HTTP handlers depend on a single domain interface
// (ownership.Service) and never reach around to storage directly
// (CLAUDE.md §8.6). Every method is org-scoped on its first
// parameter; the handler layer derives the organization id from the
// authenticated session.

// GetCertificateOwnership returns the current derived-state row for
// one cert, or governance.ErrCertificateOwnershipNotFound when the
// engine has not yet evaluated it (no recompute has run, or the cert
// was added after the most recent pass).
func (s *Service) GetCertificateOwnership(ctx context.Context, organizationID, certificateID string) (*governance.CertificateOwnership, error) {
	return s.repo.Ownership.GetCertificateOwnership(ctx, organizationID, certificateID)
}

// ListCertificateOwnershipByDecisionPaged drives the
// /ownership/unowned and /ownership/ambiguous operator views.
func (s *Service) ListCertificateOwnershipByDecisionPaged(
	ctx context.Context,
	organizationID string,
	decision governance.Decision,
	cursorCertID string,
	limit int,
) ([]governance.CertificateOwnership, error) {
	return s.repo.Ownership.ListCertificateOwnershipByDecisionPaged(ctx, organizationID, decision, cursorCertID, limit)
}

// ListCertificateOwnershipStale drives /ownership/stale. The
// olderThan threshold is computed by the caller from
// ANCHORIX_OWNERSHIP_STALE_THRESHOLD (or the request's `?older_than=`
// override) so the engine package stays free of env reads.
func (s *Service) ListCertificateOwnershipStale(
	ctx context.Context,
	organizationID string,
	olderThan time.Time,
	cursorCertID string,
	limit int,
) ([]governance.CertificateOwnership, error) {
	return s.repo.Ownership.ListCertificateOwnershipStale(ctx, organizationID, olderThan, cursorCertID, limit)
}

// GetActiveOwnershipOverride returns the unique active override for
// the cert (or nil when none is active — "no active override" is a
// valid state, not an error).
func (s *Service) GetActiveOwnershipOverride(ctx context.Context, organizationID, certificateID string) (*governance.CertificateOwnershipOverride, error) {
	return s.repo.Ownership.GetActiveOwnershipOverride(ctx, organizationID, certificateID)
}

// GetOwnershipRule returns one rule by id (or
// governance.ErrOwnershipRuleNotFound).
func (s *Service) GetOwnershipRule(ctx context.Context, organizationID, ruleID string) (*governance.OwnershipRule, error) {
	return s.repo.Ownership.GetOwnershipRule(ctx, organizationID, ruleID)
}

// ListOwnershipRulesPaged drives the /ownership-rules operator view.
// Ordered by id ASC for repeatable pagination — distinct from the
// engine walk order (compileRules sorts by ladder ordinal).
func (s *Service) ListOwnershipRulesPaged(
	ctx context.Context,
	organizationID, cursorRuleID string,
	limit int,
	enabledOnly bool,
) ([]governance.OwnershipRule, error) {
	return s.repo.Ownership.ListOwnershipRulesPaged(ctx, organizationID, cursorRuleID, limit, enabledOnly)
}

// ListOwnershipExplanationsForCertificate returns the per-cert
// explanation timeline (decided_at DESC). limit caps the response;
// pass 0 for all rows. Per-cert cardinality is bounded — the engine
// only writes a new explanation on a real transition.
func (s *Service) ListOwnershipExplanationsForCertificate(
	ctx context.Context,
	organizationID, certificateID string,
	limit int,
) ([]governance.OwnershipMatchExplanation, error) {
	return s.repo.Ownership.ListOwnershipExplanationsForCertificate(ctx, organizationID, certificateID, limit)
}

// ListRecentRecomputeRuns drives /governance/recompute-runs.
func (s *Service) ListRecentRecomputeRuns(
	ctx context.Context,
	organizationID string,
	kind governance.RecomputeKind,
	limit int,
) ([]governance.GovernanceRecomputeRun, error) {
	return s.repo.RecomputeRuns.ListRecentRecomputeRuns(ctx, organizationID, kind, limit)
}

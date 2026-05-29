package ownership

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
)

const (
	// DefaultExplanationPrunePageSize is the number of certificates a
	// single prune page walks when the caller passes pageSize <= 0. It
	// mirrors the recompute streaming page size: large enough that
	// round-trips don't dominate, small enough that one page's working
	// set stays bounded.
	DefaultExplanationPrunePageSize = 500
	// maxExplanationPrunePageSize caps a single page so a caller cannot
	// request an unbounded transaction. A larger request is clamped
	// down, not rejected.
	maxExplanationPrunePageSize = 1000
	// defaultExplanationPrunePerCertLimit caps how many explanation rows
	// a single page may delete for ONE certificate, so a churny cert with
	// deep history cannot turn a page into an unbounded read/delete. The
	// remainder is reclaimed on subsequent passes (idempotent, eventually
	// consistent). Overridable in tests via SetPrunePerCertLimitForTest.
	defaultExplanationPrunePerCertLimit = 256
)

// ExplanationPruneResult summarizes one bounded prune page. The caller
// (a future scheduler or manual trigger — not this phase) loops pages
// by passing NextCursor back as cursorCertID until Done is true.
type ExplanationPruneResult struct {
	OrganizationID string
	// StartCursor is the cursorCertID this page began after.
	StartCursor string
	// NextCursor is the last certificate_id examined on this page; pass
	// it as the next call's cursorCertID. Unchanged from StartCursor on
	// an empty terminal page.
	NextCursor string
	// CertsScanned is the number of certificates examined this page.
	CertsScanned int
	// DeletedCount is the number of explanation rows deleted this page.
	DeletedCount int
	// Done is true when the page returned fewer certificates than the
	// page size, i.e. the org's certificate walk is complete.
	Done bool
}

// PruneExplanationsPage prunes one BOUNDED page of an organization's
// ownership_match_explanations history under the H-027 hybrid retention
// policy. It is a dormant primitive: no scheduler, background loop, or
// HTTP endpoint invokes it in this phase.
//
// One call == one page == one transaction holding the per-org ownership
// advisory lock (WithTxLockedOwnership), so the prune serializes with
// recompute / override mutations for that org and never holds the lock
// across a full-org cleanup. Within the page it walks the org's
// certificate_ids that have explanation history (certificate_id ASC,
// exclusive of cursorCertID), and for each cert:
//
//   - selects up to prunePerCertLimit candidate ids via the bounded
//     ListPrunableExplanationIDs SQL primitive (oldest-first; older than
//     cutoff; not in the latest-N keep set; not the FK-pinned current);
//   - deletes them with an org+cert scope AND a NOT EXISTS guard against
//     the current explanation.
//
// SelectExplanationsToPrune (PR-1) remains the canonical, unit-tested
// SPEC of the rule; the SQL primitive implements the same rule, bounded.
// A deep-history cert drains across passes (idempotent, eventually
// consistent) instead of doing an unbounded read in one transaction.
//
// A single rollup governance.explanation_pruned audit row (severity
// "security") is written in the SAME transaction, but ONLY when the
// page actually deleted rows — a no-op page changes no state, so it
// emits no audit (CLAUDE.md §6.6). An audit failure rolls the whole
// page's deletes back (atomicity).
//
// Fails closed: empty organization id is rejected, and a degenerate
// retention policy (KeepN < 1 or MaxAge <= 0) returns an error rather
// than risk over-deletion. pageSize <= 0 falls back to the default;
// an oversized request is clamped to maxExplanationPrunePageSize.
func (s *Service) PruneExplanationsPage(ctx context.Context, organizationID, actorUserID, cursorCertID string, pageSize int) (*ExplanationPruneResult, error) {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil, fmt.Errorf("ownership: organization id required")
	}
	policy := s.retention
	if policy.KeepN < 1 || policy.MaxAge <= 0 {
		return nil, fmt.Errorf("ownership: invalid retention policy (keep_n=%d max_age=%s)", policy.KeepN, policy.MaxAge)
	}
	if pageSize <= 0 {
		pageSize = DefaultExplanationPrunePageSize
	}
	if pageSize > maxExplanationPrunePageSize {
		pageSize = maxExplanationPrunePageSize
	}

	actor, actorKind := strings.TrimSpace(actorUserID), "user"
	if actor == "" {
		actor, actorKind = "system", "system"
	}
	now := s.clock.Now()

	result := &ExplanationPruneResult{
		OrganizationID: organizationID,
		StartCursor:    cursorCertID,
		NextCursor:     cursorCertID,
	}
	err := s.tx.WithTxLockedOwnership(ctx, organizationID, func(txCtx context.Context) error {
		certIDs, err := s.repo.Ownership.ListCertificateIDsWithExplanationsPaged(txCtx, organizationID, cursorCertID, pageSize)
		if err != nil {
			return fmt.Errorf("ownership: list certs with explanations: %w", err)
		}
		result.CertsScanned = len(certIDs)
		result.Done = len(certIDs) < pageSize
		for _, certID := range certIDs {
			deleted, err := s.pruneCertificateExplanations(txCtx, organizationID, certID, policy, now)
			if err != nil {
				return err
			}
			result.DeletedCount += deleted
			result.NextCursor = certID
		}
		if result.DeletedCount > 0 {
			return s.emitExplanationPruned(txCtx, organizationID, actor, actorKind, now, result, policy)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// pruneCertificateExplanations prunes one certificate's eligible
// explanation rows and returns how many were deleted.
//
// Eligibility (the same rule as the pure SelectExplanationsToPrune
// spec — not current, beyond latest-N by decided_at DESC/id ASC, older
// than the cutoff) is evaluated by a BOUNDED SQL primitive that returns
// at most prunePerCertLimit candidate ids, oldest-first. This keeps the
// per-cert read bounded for a deep-history cert: the latest-N keep set
// and the candidate batch are both LIMIT-capped, and any remainder is
// reclaimed on a later pass. The DELETE re-applies the org+cert+current
// guard so the FK-pinned current explanation can never be removed.
func (s *Service) pruneCertificateExplanations(ctx context.Context, organizationID, certificateID string, policy RetentionPolicy, now time.Time) (int, error) {
	cutoff := now.Add(-policy.MaxAge)
	prune, err := s.repo.Ownership.ListPrunableExplanationIDs(ctx, organizationID, certificateID, cutoff, policy.KeepN, s.prunePerCertLimit())
	if err != nil {
		return 0, fmt.Errorf("ownership: select prunable explanations: %w", err)
	}
	if len(prune) == 0 {
		return 0, nil
	}
	deleted, err := s.repo.Ownership.DeleteOwnershipExplanationsForCertificate(ctx, organizationID, certificateID, prune)
	if err != nil {
		return 0, fmt.Errorf("ownership: delete explanations: %w", err)
	}
	return int(deleted), nil
}

// prunePerCertLimit is the per-certificate candidate cap for one page,
// honoring the test override when set.
func (s *Service) prunePerCertLimit() int {
	if s.prunePerCertOverride > 0 {
		return s.prunePerCertOverride
	}
	return defaultExplanationPrunePerCertLimit
}

// explanationPrunedMetadata is the governance.explanation_pruned rollup
// audit shape: one row per prune page that deleted something.
type explanationPrunedMetadata struct {
	Severity       string `json:"severity"`
	OrganizationID string `json:"organization_id"`
	DeletedCount   int    `json:"deleted_count"`
	CertsScanned   int    `json:"certs_scanned"`
	KeepN          int    `json:"keep_n"`
	MaxAge         string `json:"max_age"`
	Cursor         string `json:"cursor"`
	NextCursor     string `json:"next_cursor"`
}

func (s *Service) emitExplanationPruned(ctx context.Context, organizationID, actor, actorKind string, now time.Time, result *ExplanationPruneResult, policy RetentionPolicy) error {
	md, _ := json.Marshal(explanationPrunedMetadata{
		Severity:       "security",
		OrganizationID: organizationID,
		DeletedCount:   result.DeletedCount,
		CertsScanned:   result.CertsScanned,
		KeepN:          policy.KeepN,
		MaxAge:         policy.MaxAge.String(),
		Cursor:         result.StartCursor,
		NextCursor:     result.NextCursor,
	})
	if err := s.audit.Record(ctx, audit.Event{
		OrganizationID: organizationID,
		OccurredAt:     now,
		Actor:          actor,
		ActorType:      actorKind,
		Action:         "governance.explanation_pruned",
		TargetType:     "organization",
		TargetID:       organizationID,
		Metadata:       md,
	}); err != nil {
		return fmt.Errorf("ownership: record explanation prune audit: %w", err)
	}
	return nil
}

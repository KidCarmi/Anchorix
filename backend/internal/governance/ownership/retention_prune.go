package ownership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
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
//   - loads its explanation timeline (decided_at DESC, id ASC);
//   - resolves its current (FK-pinned) explanation id;
//   - selects prunable rows via SelectExplanationsToPrune (not current,
//     beyond latest-N, older than MaxAge);
//   - deletes them with an org+cert scope AND a NOT EXISTS guard against
//     the current explanation.
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
// explanation rows and returns how many were deleted. It short-circuits
// before any delete when the timeline is already within latest-N or the
// selector finds nothing eligible.
func (s *Service) pruneCertificateExplanations(ctx context.Context, organizationID, certificateID string, policy RetentionPolicy, now time.Time) (int, error) {
	timeline, err := s.repo.Ownership.ListOwnershipExplanationsForCertificate(ctx, organizationID, certificateID, 0)
	if err != nil {
		return 0, fmt.Errorf("ownership: load explanation timeline: %w", err)
	}
	if len(timeline) <= policy.KeepN {
		return 0, nil
	}
	currentID, err := s.currentExplanationID(ctx, organizationID, certificateID)
	if err != nil {
		return 0, err
	}
	records := make([]ExplanationRecord, 0, len(timeline))
	for _, e := range timeline {
		records = append(records, ExplanationRecord{ID: e.ID, DecidedAt: e.DecidedAt})
	}
	prune := SelectExplanationsToPrune(records, currentID, policy, now)
	if len(prune) == 0 {
		return 0, nil
	}
	deleted, err := s.repo.Ownership.DeleteOwnershipExplanationsForCertificate(ctx, organizationID, certificateID, prune)
	if err != nil {
		return 0, fmt.Errorf("ownership: delete explanations: %w", err)
	}
	return int(deleted), nil
}

// currentExplanationID returns the certificate's FK-pinned current
// explanation id, or "" when the cert has no ownership row yet (a state
// that should not arise once decided, handled defensively — latest-N
// still protects the recent rows in that case).
func (s *Service) currentExplanationID(ctx context.Context, organizationID, certificateID string) (string, error) {
	own, err := s.repo.Ownership.GetCertificateOwnership(ctx, organizationID, certificateID)
	if err != nil {
		if errors.Is(err, governance.ErrCertificateOwnershipNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("ownership: load current ownership: %w", err)
	}
	return own.ExplanationID, nil
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

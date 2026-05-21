package findings

import (
	"context"
	"fmt"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/ids"
)

// diffOp is the action the per-(cert, rule) decision asks the
// orchestration layer to perform on the findings table. Both
// the legacy load-all path and the H-024B streaming path
// consume the same decision outputs, which is what makes their
// final table state byte-identical for the same input.
type diffOp int

const (
	diffOpNoChange diffOp = iota
	diffOpInsert
	diffOpUpdate
)

// counterBucket is the recompute counter the orchestration
// layer should bump after applying a transition. Mutually
// exclusive — every transition lands in exactly one bucket.
// Matches the four fields on RecomputeResult.
type counterBucket int

const (
	counterOpened counterBucket = iota
	counterUpdated
	counterResolved
	counterUnchanged
)

// matchKey is the identity tuple for a finding within an org:
// `(certificate_id, rule_id)`. The third axis (organization_id)
// is constant across one Recompute call, so we don't include
// it. Matches the
// `UNIQUE (organization_id, certificate_id, rule_id)`
// constraint on the findings table.
type matchKey struct {
	certID string
	ruleID string
}

// matchEntry pairs the matching Rule with the RuleMatch
// payload it produced. The rule is needed for severity, title,
// version, and id; the match carries the evidence JSON.
type matchEntry struct {
	rule  Rule
	match *RuleMatch
}

// decideMatchTransition is the H-023 state-machine kernel for
// the "rule MATCHES on this cert" case. Pure function of its
// inputs — no I/O, no service state, no mutation of `prior`.
// Returns the finding row to write, the op the caller should
// perform, and the counter bucket to bump.
//
// `prior` may be nil (no existing finding for this
// (cert, rule) key). All other parameters are required. The
// returned *Finding is a fresh struct; callers MUST NOT assume
// pointer identity with `prior` (the helper copies on the
// update branches so the streaming and load-all paths get the
// same behaviour without sharing memory).
//
// Behaviour matrix (preserved from H-021 + H-023, see
// CERTIFICATE_FINDINGS.md §5 and §8):
//
//	prior == nil               → INSERT new open finding; bucket = opened
//	prior.Status == open       → UPDATE rule-derived fields; bucket = updated
//	prior.Status == resolved   → UPDATE to open (reopen); bucket = opened
//	prior.Status == ack'd      → UPDATE rule-derived, preserve override; bucket = updated
//	prior.Status == suppressed:
//	   expired (now >= expiry) → UPDATE to open, clear override; bucket = opened
//	   permanent / not expired → UPDATE rule-derived, preserve override; bucket = updated
//	prior.Status == other      → ErrUnsupportedFindingStatus (fail loudly)
func decideMatchTransition(
	prior *Finding,
	organizationID, certID string,
	rule Rule,
	match *RuleMatch,
	now time.Time,
) (*Finding, diffOp, counterBucket, error) {
	if prior == nil {
		// First-time observation of this (cert, rule): mint
		// the new row in `open`. ID is service-owned per
		// the H-021 contract.
		return &Finding{
			ID:             ids.New(),
			OrganizationID: organizationID,
			CertificateID:  certID,
			RuleID:         rule.ID(),
			RuleVersion:    rule.Version(),
			Severity:       rule.Severity(),
			Status:         StatusOpen,
			Title:          rule.Title(),
			Evidence:       match.Evidence,
			FirstSeenAt:    now,
			LastSeenAt:     now,
			ResolvedAt:     nil,
			UpdatedAt:      now,
		}, diffOpInsert, counterOpened, nil
	}

	// Defensive copy so the caller's `prior` pointer is not
	// mutated. The streaming path passes pointers into a
	// freshly-read page slice; the load-all path passes
	// pointers into a long-lived map. Mutating either via a
	// shared reference would create cross-path divergence the
	// byte-identical equivalence test could not protect
	// against.
	next := *prior

	switch prior.Status {
	case StatusOpen:
		next.LastSeenAt = now
		next.UpdatedAt = now
		next.Severity = rule.Severity()
		next.Title = rule.Title()
		next.RuleVersion = rule.Version()
		next.Evidence = match.Evidence
		return &next, diffOpUpdate, counterUpdated, nil

	case StatusResolved:
		// resolved → reopen. `FirstSeenAt` is intentionally
		// NOT touched — it preserves the original detection
		// moment across resolve / reopen cycles (CERTIFICATE_FINDINGS.md §5).
		next.Status = StatusOpen
		next.LastSeenAt = now
		next.UpdatedAt = now
		next.ResolvedAt = nil
		next.Severity = rule.Severity()
		next.Title = rule.Title()
		next.RuleVersion = rule.Version()
		next.Evidence = match.Evidence
		return &next, diffOpUpdate, counterOpened, nil

	case StatusAcknowledged:
		// acknowledged + rule still matches: stay
		// acknowledged. Bump rule-derived fields; PRESERVE
		// override metadata (status_reason, status_actor,
		// status_changed_at).
		next.LastSeenAt = now
		next.UpdatedAt = now
		next.Severity = rule.Severity()
		next.Title = rule.Title()
		next.RuleVersion = rule.Version()
		next.Evidence = match.Evidence
		return &next, diffOpUpdate, counterUpdated, nil

	case StatusSuppressed:
		// `now` is the recompute's anchor — compare against
		// SuppressExpiresAt strictly (>=) so a suppression
		// that expires EXACTLY at `now` is considered
		// expired and the finding reopens.
		if prior.SuppressExpiresAt != nil && !now.Before(*prior.SuppressExpiresAt) {
			// Suppression expired: reopen to `open` and
			// clear override metadata. Audit history
			// remains in audit_events.
			next.Status = StatusOpen
			next.LastSeenAt = now
			next.UpdatedAt = now
			next.ResolvedAt = nil
			next.Severity = rule.Severity()
			next.Title = rule.Title()
			next.RuleVersion = rule.Version()
			next.Evidence = match.Evidence
			next.StatusReason = ""
			next.StatusActor = ""
			next.StatusChangedAt = nil
			next.SuppressExpiresAt = nil
			return &next, diffOpUpdate, counterOpened, nil
		}
		// Not expired (or no expiry): stay suppressed,
		// PRESERVE override metadata.
		next.LastSeenAt = now
		next.UpdatedAt = now
		next.Severity = rule.Severity()
		next.Title = rule.Title()
		next.RuleVersion = rule.Version()
		next.Evidence = match.Evidence
		return &next, diffOpUpdate, counterUpdated, nil

	default:
		// Any status outside open / resolved / acknowledged /
		// suppressed is unexpected. Fail loudly — see
		// CERTIFICATE_FINDINGS.md §5 "Defensive: unsupported
		// finding status fails loudly".
		return nil, diffOpNoChange, counterUnchanged, fmt.Errorf(
			"%w: finding %s has status %q (rule still matches)",
			ErrUnsupportedFindingStatus, prior.ID, prior.Status,
		)
	}
}

// decideNoMatchTransition is the H-023 state-machine kernel
// for the "rule NO LONGER matches" case. Pure function. The
// finding identified by `prior` was loaded from the DB and
// has no entry in this recompute's match set; the recompute
// must decide what to do with it.
//
// Behaviour matrix:
//
//	prior.Status == open                     → resolve; bucket = resolved
//	prior.Status in {acknowledged, suppressed} → resolve + clear override; bucket = resolved
//	prior.Status == resolved                 → unchanged; bucket = unchanged, op = noChange
//	prior.Status == other                    → ErrUnsupportedFindingStatus
//
// Same defensive-copy invariant as decideMatchTransition.
func decideNoMatchTransition(prior *Finding, now time.Time) (*Finding, diffOp, counterBucket, error) {
	if prior == nil {
		// No-match against a non-existent finding is a
		// no-op. Callers shouldn't reach this branch — it's
		// listed for completeness so a future caller that
		// passes a nil prior surfaces as a contract bug
		// rather than a nil dereference.
		return nil, diffOpNoChange, counterUnchanged, nil
	}

	next := *prior

	switch prior.Status {
	case StatusOpen:
		resolvedAt := now
		next.Status = StatusResolved
		next.ResolvedAt = &resolvedAt
		next.UpdatedAt = now
		return &next, diffOpUpdate, counterResolved, nil

	case StatusAcknowledged, StatusSuppressed:
		// The underlying problem is gone, so the operator
		// override is moot. Resolve AND clear override
		// metadata so the row's current state reflects "no
		// operator intent". Audit history remains in
		// audit_events.
		resolvedAt := now
		next.Status = StatusResolved
		next.ResolvedAt = &resolvedAt
		next.UpdatedAt = now
		next.StatusReason = ""
		next.StatusActor = ""
		next.StatusChangedAt = nil
		next.SuppressExpiresAt = nil
		return &next, diffOpUpdate, counterResolved, nil

	case StatusResolved:
		return nil, diffOpNoChange, counterUnchanged, nil

	default:
		return nil, diffOpNoChange, counterUnchanged, fmt.Errorf(
			"%w: finding %s has status %q (rule no longer matches)",
			ErrUnsupportedFindingStatus, prior.ID, prior.Status,
		)
	}
}

// applyDecision runs the repository call corresponding to
// `op`. Centralizes the Insert / Update plumbing so both diff
// variants stay focused on orchestration.
func applyDecision(ctx context.Context, repo Repository, next *Finding, op diffOp) error {
	switch op {
	case diffOpNoChange:
		return nil
	case diffOpInsert:
		return repo.InsertFinding(ctx, next)
	case diffOpUpdate:
		return repo.UpdateFinding(ctx, next)
	default:
		return fmt.Errorf("findings: unknown diffOp %d", op)
	}
}

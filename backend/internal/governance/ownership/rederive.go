package ownership

import (
	"context"
	"fmt"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/ids"
)

// rederiveResult reports the outcome of a single-certificate
// re-derivation so the caller can emit the right transition audit.
type rederiveResult struct {
	fromDecision governance.Decision
	toDecision   governance.Decision
	fromService  *string
	toService    *string
	winningRule  *string
	changed      bool // true when (decision, service) actually moved
}

// rederiveCertificate recomputes ownership for ONE certificate inside
// the caller's transaction (the override mutations call it under
// WithTxLockedOwnership). It is the single-cert analogue of the
// streaming pass's processCert, minus the fleet recomputeOutcome
// accounting: it loads the cert's signals + active override + enabled
// rules + prior ownership, runs the same deterministic decideOwnership,
// and writes the explanation + ownership rows on a real change.
//
// All reads are bounded single-cert / per-org lookups — no fleet scan.
// Determinism and the §5.1 state-machine semantics match processCert:
//
//   - no prior row → INSERT (explanation always; ownership row).
//   - prior, same (decision, service) but changed basis → refresh
//     metadata + explanation, preserve last_changed_at.
//   - prior, same (decision, service), same basis → bump
//     last_evaluated_at only (no new explanation).
//   - owner transition → new explanation, last_changed_at = now.
//
// It does NOT auto-expire overrides (that is the recompute's job); the
// override the caller passes is assumed active for this evaluation, or
// nil to re-derive from rules (used by the clear path).
func (s *Service) rederiveCertificate(
	ctx context.Context,
	organizationID, certificateID string,
	override *governance.CertificateOwnershipOverride,
	now time.Time,
) (*rederiveResult, error) {
	sig, err := s.repo.Ownership.GetCertificateSignals(ctx, organizationID, certificateID)
	if err != nil {
		return nil, fmt.Errorf("ownership: load cert signals: %w", err)
	}
	if sig == nil {
		// Defensive: the override mutation already verified the cert
		// exists before opening the tx. Reaching here means it vanished
		// mid-tx — fail closed.
		return nil, ErrOverrideCertNotFound
	}

	rawRules, err := s.repo.Ownership.ListOwnershipRulesForEngine(ctx, organizationID)
	if err != nil {
		return nil, fmt.Errorf("ownership: load rules: %w", err)
	}
	rules, _, err := compileRules(rawRules)
	if err != nil {
		return nil, err // unknown tier / kind: fail loud (same as recompute)
	}

	prior, err := s.repo.Ownership.GetCertificateOwnership(ctx, organizationID, certificateID)
	if err != nil && err != governance.ErrCertificateOwnershipNotFound {
		return nil, fmt.Errorf("ownership: load prior ownership: %w", err)
	}
	if err == governance.ErrCertificateOwnershipNotFound {
		prior = nil
	}

	d := decideOwnership(*sig, override, rules, now)
	res := &rederiveResult{
		toDecision:  d.decision,
		toService:   d.serviceID,
		winningRule: d.winningRuleID,
	}

	if prior == nil {
		expID := ids.New()
		if err := s.writeExplanation(ctx, organizationID, *sig, d, expID, now); err != nil {
			return nil, err
		}
		if err := s.repo.Ownership.UpsertCertificateOwnership(ctx, buildOwnership(organizationID, certificateID, d, expID, now, now, now)); err != nil {
			return nil, fmt.Errorf("ownership: upsert (new): %w", err)
		}
		res.fromDecision = governance.DecisionUnowned
		res.changed = d.serviceID != nil // unowned→unowned is not a transition
		return res, nil
	}

	res.fromDecision = prior.Decision
	res.fromService = prior.ServiceID
	sameService := samePtr(prior.ServiceID, d.serviceID)
	ownerChanged := prior.Decision != d.decision || !sameService

	if !ownerChanged {
		basisChanged := !samePtr(prior.WinningRuleID, d.winningRuleID) ||
			!samePtr(prior.OverrideID, d.overrideID) ||
			prior.Confidence != d.confidence
		if !basisChanged {
			co := *prior
			co.LastEvaluatedAt = now
			if err := s.repo.Ownership.UpsertCertificateOwnership(ctx, &co); err != nil {
				return nil, fmt.Errorf("ownership: upsert (unchanged): %w", err)
			}
			res.changed = false
			return res, nil
		}
		// Owner-stable reclassification: refresh metadata + explanation,
		// preserve last_changed_at, no transition.
		expID := ids.New()
		if err := s.writeExplanation(ctx, organizationID, *sig, d, expID, now); err != nil {
			return nil, err
		}
		if err := s.repo.Ownership.UpsertCertificateOwnership(ctx, buildOwnership(organizationID, certificateID, d, expID, prior.FirstAssignedAt, now, prior.LastChangedAt)); err != nil {
			return nil, fmt.Errorf("ownership: upsert (reclassified): %w", err)
		}
		res.changed = false
		return res, nil
	}

	// Owner transition.
	priorOwned := prior.ServiceID != nil
	nowOwned := d.serviceID != nil
	firstAssigned := prior.FirstAssignedAt
	if !priorOwned && nowOwned {
		firstAssigned = now
	}
	expID := ids.New()
	if err := s.writeExplanation(ctx, organizationID, *sig, d, expID, now); err != nil {
		return nil, err
	}
	if err := s.repo.Ownership.UpsertCertificateOwnership(ctx, buildOwnership(organizationID, certificateID, d, expID, firstAssigned, now, now)); err != nil {
		return nil, fmt.Errorf("ownership: upsert (changed): %w", err)
	}
	res.changed = true
	return res, nil
}

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

// maxOverrideReasonLen bounds the operator's free-text justification,
// matching the ≤ 1000-byte cap the governance plan §3.9 documents for
// certificate_ownership_overrides.reason.
const maxOverrideReasonLen = 1000

// CreateOverrideInput is the validated input to CreateOverride.
// ExpiresAt is optional (nil = never auto-expires). A non-nil value
// must be strictly in the future.
type CreateOverrideInput struct {
	OrganizationID string
	ActorUserID    string
	CertificateID  string
	ServiceID      string
	Reason         string
	ExpiresAt      *time.Time
}

// ClearOverrideInput is the validated input to ClearOverride.
type ClearOverrideInput struct {
	OrganizationID string
	ActorUserID    string
	CertificateID  string
	Reason         string
}

// CreateOverride pins a certificate to a service via an operator
// override, then immediately re-derives that one certificate so the
// ownership row reflects the pin before the call returns (governance
// plan §3.9 operator-immediate effect). The override row write, the
// single-cert re-derivation, and the security audit all commit in one
// transaction holding the per-org ownership advisory lock, so the
// mutation serializes against any in-flight full recompute and is
// atomic (audit failure rolls everything back).
//
// Rejects: missing/oversized reason, missing service, nonexistent or
// disabled service, nonexistent / cross-org certificate (collapsed to
// ErrOverrideCertNotFound), past expires_at, and an already-active
// override (ErrOverrideConflict → 409).
func (s *Service) CreateOverride(ctx context.Context, in CreateOverrideInput) (*governance.CertificateOwnershipOverride, error) {
	in.CertificateID = strings.TrimSpace(in.CertificateID)
	in.ServiceID = strings.TrimSpace(in.ServiceID)
	in.Reason = strings.TrimSpace(in.Reason)
	if err := requireOverrideOrgActor(in.OrganizationID, in.ActorUserID); err != nil {
		return nil, err
	}
	if in.CertificateID == "" {
		return nil, fmt.Errorf("%w: certificate id required", ErrInvalidOverride)
	}
	if in.ServiceID == "" {
		return nil, fmt.Errorf("%w: service_id required", ErrInvalidOverride)
	}
	if in.Reason == "" {
		return nil, fmt.Errorf("%w: reason required", ErrInvalidOverride)
	}
	if len(in.Reason) > maxOverrideReasonLen {
		return nil, fmt.Errorf("%w: reason length %d exceeds cap %d", ErrInvalidOverride, len(in.Reason), maxOverrideReasonLen)
	}
	now := s.clock.Now()
	if in.ExpiresAt != nil && !in.ExpiresAt.After(now) {
		return nil, ErrOverrideExpiryInPast
	}

	// Bounded existence checks BEFORE opening the tx: the cert must
	// exist in the org (cross-org → not found, no enumeration), and
	// the pinned service must be active.
	sig, err := s.repo.Ownership.GetCertificateSignals(ctx, in.OrganizationID, in.CertificateID)
	if err != nil {
		return nil, fmt.Errorf("ownership: resolve certificate: %w", err)
	}
	if sig == nil {
		return nil, fmt.Errorf("%w: %q", ErrOverrideCertNotFound, in.CertificateID)
	}
	ok, err := s.resolver.ActiveServiceExists(ctx, in.OrganizationID, in.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("ownership: resolve service: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: service_id %q", ErrOverrideServiceNotFound, in.ServiceID)
	}

	override := &governance.CertificateOwnershipOverride{
		ID:             ids.New(),
		OrganizationID: in.OrganizationID,
		CertificateID:  in.CertificateID,
		ServiceID:      in.ServiceID,
		Reason:         in.Reason,
		SetBy:          in.ActorUserID,
		SetAt:          now,
		ExpiresAt:      in.ExpiresAt,
	}
	if err := s.tx.WithTxLockedOwnership(ctx, in.OrganizationID, func(ctx context.Context) error {
		if err := s.repo.Ownership.CreateOwnershipOverride(ctx, override); err != nil {
			if err == governance.ErrOwnershipOverrideAlreadyExists {
				return ErrOverrideConflict
			}
			return fmt.Errorf("ownership: create override: %w", err)
		}
		// Immediate single-cert re-derivation so the override takes
		// effect before the response returns.
		if _, err := s.rederiveCertificate(ctx, in.OrganizationID, in.CertificateID, override, now); err != nil {
			return err
		}
		return s.recordOverrideAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "ownership.overridden",
			TargetType:     "certificate",
			TargetID:       in.CertificateID,
			Metadata: overrideAuditMetadata(map[string]any{
				"override_id": override.ID,
				"service_id":  override.ServiceID,
			}),
		})
	}); err != nil {
		return nil, err
	}
	return override, nil
}

// ClearOverride clears the active override for a certificate, then
// immediately re-derives that one certificate from rules so the
// ownership row reflects the removed pin before the call returns. Same
// transaction + advisory-lock + audit-atomicity guarantees as
// CreateOverride. Clearing a nonexistent / already-cleared /
// cross-org override returns ErrOverrideCertNotFound (→ 404), which
// does not leak whether a foreign cert or override exists.
func (s *Service) ClearOverride(ctx context.Context, in ClearOverrideInput) (*governance.CertificateOwnershipOverride, error) {
	in.CertificateID = strings.TrimSpace(in.CertificateID)
	in.Reason = strings.TrimSpace(in.Reason)
	if err := requireOverrideOrgActor(in.OrganizationID, in.ActorUserID); err != nil {
		return nil, err
	}
	if in.CertificateID == "" {
		return nil, fmt.Errorf("%w: certificate id required", ErrInvalidOverride)
	}
	if in.Reason == "" {
		return nil, fmt.Errorf("%w: reason required", ErrInvalidOverride)
	}
	if len(in.Reason) > maxOverrideReasonLen {
		return nil, fmt.Errorf("%w: reason length %d exceeds cap %d", ErrInvalidOverride, len(in.Reason), maxOverrideReasonLen)
	}

	// Resolve the active override BEFORE the tx. A missing active
	// override (including a cross-org cert) collapses to
	// ErrOverrideCertNotFound — no enumeration.
	active, err := s.repo.Ownership.GetActiveOwnershipOverride(ctx, in.OrganizationID, in.CertificateID)
	if err != nil {
		return nil, fmt.Errorf("ownership: resolve active override: %w", err)
	}
	if active == nil {
		return nil, fmt.Errorf("%w: %q", ErrOverrideCertNotFound, in.CertificateID)
	}

	now := s.clock.Now()
	var cleared *governance.CertificateOwnershipOverride
	if err := s.tx.WithTxLockedOwnership(ctx, in.OrganizationID, func(ctx context.Context) error {
		if err := s.repo.Ownership.ClearOwnershipOverride(ctx, in.OrganizationID, active.ID, in.ActorUserID, in.Reason, now); err != nil {
			// Lost a race with auto-expiry / another clear: treat the
			// now-absent active override as not-found.
			if err == governance.ErrOwnershipOverrideNotFound {
				return ErrOverrideCertNotFound
			}
			return fmt.Errorf("ownership: clear override: %w", err)
		}
		// Re-derive from rules (no override now).
		if _, err := s.rederiveCertificate(ctx, in.OrganizationID, in.CertificateID, nil, now); err != nil {
			return err
		}
		got, err := s.repo.Ownership.GetOwnershipOverride(ctx, in.OrganizationID, active.ID)
		if err != nil {
			return err
		}
		cleared = got
		return s.recordOverrideAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "ownership.override_cleared",
			TargetType:     "certificate",
			TargetID:       in.CertificateID,
			Metadata: overrideAuditMetadata(map[string]any{
				"override_id": active.ID,
			}),
		})
	}); err != nil {
		return nil, err
	}
	return cleared, nil
}

// --- helpers ----------------------------------------------------------

// requireOverrideOrgActor validates the mandatory org + actor inputs.
func requireOverrideOrgActor(orgID, actor string) error {
	if strings.TrimSpace(orgID) == "" {
		return fmt.Errorf("%w: organization id required", ErrInvalidOverride)
	}
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor user id required", ErrInvalidOverride)
	}
	return nil
}

// overrideAuditMetadata marshals the metadata map plus the mandatory
// severity:"security" field (CLAUDE.md §9). Marshal of documented
// scalar types cannot fail in practice.
func overrideAuditMetadata(extra map[string]any) []byte {
	combined := make(map[string]any, len(extra)+1)
	combined["severity"] = "security"
	for k, v := range extra {
		combined[k] = v
	}
	b, _ := json.Marshal(combined)
	return b
}

func (s *Service) recordOverrideAudit(ctx context.Context, e audit.Event) error {
	if err := s.audit.Record(ctx, e); err != nil {
		return fmt.Errorf("ownership: record override audit: %w", err)
	}
	return nil
}

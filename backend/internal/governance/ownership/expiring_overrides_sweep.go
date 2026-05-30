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
	"github.com/kidcarmi/anchorix/backend/internal/ids"
)

const (
	// DefaultExpiringOverridesSweepPageSize is the number of expired-
	// active overrides one sweep page processes when the caller passes
	// pageSize <= 0. Mirrors the H-027 retention prune default and the
	// repo-level PR-1 default (deliberately the same number so a future
	// caller does not have to think about two different bounds).
	DefaultExpiringOverridesSweepPageSize = 500
	// maxExpiringOverridesSweepPageSize caps a single page so a caller
	// cannot request an unbounded transaction. A larger request is
	// clamped, not rejected. The repo's PR-1 ListExpiringOverridesPaged
	// applies the same bound as a defense-in-depth re-clamp; here the
	// service-level cap keeps the per-row work (clear + rederive +
	// audit) bounded as well.
	maxExpiringOverridesSweepPageSize = 1000
)

// sweepExpiringSystemActor is the actor recorded on the per-override
// ownership.override_expired audit row a sweep emits. The sweep is
// system-initiated (an operator triggers it via a future endpoint or
// scheduler; the sweep itself never carries an end-user identity), so
// the actor and actor_type are both "system" — matching the recompute
// auto-expiry path which records `actor_kind=system` for the same
// action.
const sweepExpiringSystemActor = "system"

// ExpiringOverridesSweepResult summarizes one bounded sweep page. The
// caller (a future scheduler or manual operator trigger — not this
// phase) loops pages by passing NextCursor back as cursorCertID until
// Done is true.
//
// CertsScanned is the number of expired-active overrides the listing
// read returned for this page (i.e. candidates considered); the page
// stays bounded by pageSize. ClearedCount is the number of overrides
// actually cleared (and therefore audited); it is <= CertsScanned
// because rows lost to a concurrent operator clear between the listing
// read and the per-row clear are silently skipped (the design's race
// semantic, see §14 of the H-029 design).
type ExpiringOverridesSweepResult struct {
	OrganizationID string
	// StartCursor is the cursorCertID this page began after.
	StartCursor string
	// NextCursor is the last certificate_id examined on this page; pass
	// it as the next call's cursorCertID. Unchanged from StartCursor on
	// an empty terminal page.
	NextCursor string
	// SweepID is the per-page identifier stamped on every audit row
	// emitted by this call (analogous to the recompute's run_id). It
	// lets operators correlate the audited expirations of one page.
	SweepID string
	// CertsScanned is the number of expired-active override rows the
	// listing read returned for this page.
	CertsScanned int
	// ClearedCount is the number of overrides successfully cleared and
	// audited (<= CertsScanned; the difference is rows lost to a
	// concurrent operator clear).
	ClearedCount int
	// Done is true when the page returned fewer rows than the page
	// size, i.e. the org's expiring-override walk is complete (as of
	// the page's `now`).
	Done bool
}

// SweepExpiringOverridesPage clears one BOUNDED page of an
// organization's active overrides whose expires_at has passed.
//
// It is a dormant primitive: no scheduler, background loop, or HTTP
// endpoint invokes it in this phase. A future B4 scheduler or optional
// manual operator trigger will drive it page by page.
//
// One call == one page == one transaction holding the per-org ownership
// advisory lock (WithTxLockedOwnership), so the sweep serializes with
// recompute / override mutations for that org and never holds the lock
// across a full-org sweep. Within the page it:
//
//   - reads up to pageSize expired-active overrides via the bounded
//     ListExpiringOverridesPaged SQL primitive (cert_id ASC, exclusive
//     of cursorCertID);
//   - for each row, clears the override via ClearOwnershipOverride
//     (cleared_by="system", cleared_reason="auto-expired") — a row
//     that lost a race with a concurrent operator clear surfaces
//     ErrOwnershipOverrideNotFound and is silently skipped, no audit;
//   - re-derives the certificate via rederiveCertificate(..., nil, ...)
//     so the cert's ownership reflects the absent override (matched
//     rule / unowned / etc.);
//   - emits ONE per-override ownership.override_expired audit row
//     (severity:"security", target_type:"certificate",
//     target_id:cert_id, metadata:
//     {severity, override_id, service_id, reason:"auto-expired",
//     sweep_id}). Per-override cardinality is low by design (operator
//     pins) — no rollup, mirroring the B2 recompute auto-expiry
//     contract.
//
// Audit atomicity: all clears + re-derivations + audit rows commit in
// the SAME transaction. An audit failure rolls the ENTIRE page back,
// not just the failing row — no partial cleared-without-audit state is
// observable. The same holds for a re-derivation failure or any
// non-NotFound clear error.
//
// Fails closed: empty organization id is rejected before the lock is
// acquired. pageSize <= 0 falls back to
// DefaultExpiringOverridesSweepPageSize; pageSize >
// maxExpiringOverridesSweepPageSize is clamped down.
func (s *Service) SweepExpiringOverridesPage(ctx context.Context, organizationID, cursorCertID string, pageSize int) (*ExpiringOverridesSweepResult, error) {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil, fmt.Errorf("ownership: organization id required")
	}
	if pageSize <= 0 {
		pageSize = DefaultExpiringOverridesSweepPageSize
	}
	if pageSize > maxExpiringOverridesSweepPageSize {
		pageSize = maxExpiringOverridesSweepPageSize
	}

	now := s.clock.Now()
	sweepID := ids.New()
	result := &ExpiringOverridesSweepResult{
		OrganizationID: organizationID,
		StartCursor:    cursorCertID,
		NextCursor:     cursorCertID,
		SweepID:        sweepID,
	}

	err := s.tx.WithTxLockedOwnership(ctx, organizationID, func(txCtx context.Context) error {
		expiring, err := s.repo.Ownership.ListExpiringOverridesPaged(txCtx, organizationID, now, cursorCertID, pageSize)
		if err != nil {
			return fmt.Errorf("ownership: list expiring overrides: %w", err)
		}
		result.CertsScanned = len(expiring)
		result.Done = len(expiring) < pageSize
		for _, override := range expiring {
			cleared, err := s.sweepOneExpiringOverride(txCtx, organizationID, override, sweepID, now)
			if err != nil {
				return err
			}
			if cleared {
				result.ClearedCount++
			}
			result.NextCursor = override.CertificateID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// sweepOneExpiringOverride performs the per-row clear + re-derive +
// audit cycle inside the page's locked transaction. Returns
// (true, nil) when the override was cleared and audited;
// (false, nil) when the override was lost to a concurrent operator
// clear (silent no-op); and (false, err) on any other failure (which
// the caller propagates to roll the page back).
func (s *Service) sweepOneExpiringOverride(ctx context.Context, organizationID string, override governance.CertificateOwnershipOverride, sweepID string, now time.Time) (bool, error) {
	if err := s.repo.Ownership.ClearOwnershipOverride(ctx, organizationID, override.ID, sweepExpiringSystemActor, "auto-expired", now); err != nil {
		if errors.Is(err, governance.ErrOwnershipOverrideNotFound) {
			// Race window: a concurrent operator clear (or another
			// in-flight transaction that won the lock first) already
			// retired this override. The work is done; emit no audit
			// (the winner will have audited it), and continue the page.
			return false, nil
		}
		return false, fmt.Errorf("ownership: sweep clear override: %w", err)
	}
	// Re-derive from rules — the override is now cleared, so the cert's
	// ownership must flip to whatever the engine decides without it.
	if _, err := s.rederiveCertificate(ctx, organizationID, override.CertificateID, nil, now); err != nil {
		return false, fmt.Errorf("ownership: sweep rederive cert: %w", err)
	}
	if err := s.emitExpiredOverrideAudit(ctx, organizationID, override, sweepID, now); err != nil {
		return false, err
	}
	return true, nil
}

// sweepExpiredOverrideMetadata is the per-override audit shape a sweep
// emits. It mirrors the recompute auto-expiry metadata
// (overrideExpiredMetadata in service.go) but carries SweepID instead
// of RunID so an operator can distinguish "expired by a recompute
// pass" from "expired by a sweep page" in audit history without
// inspecting the action string. Both shapes share the
// ownership.override_expired action so downstream consumers do not
// need to special-case the source.
type sweepExpiredOverrideMetadata struct {
	Severity   string `json:"severity"`
	SweepID    string `json:"sweep_id"`
	OverrideID string `json:"override_id"`
	ServiceID  string `json:"service_id"`
	Reason     string `json:"reason"`
}

func (s *Service) emitExpiredOverrideAudit(ctx context.Context, organizationID string, override governance.CertificateOwnershipOverride, sweepID string, now time.Time) error {
	md, _ := json.Marshal(sweepExpiredOverrideMetadata{
		Severity: "security", SweepID: sweepID, OverrideID: override.ID, ServiceID: override.ServiceID, Reason: "auto-expired",
	})
	if err := s.audit.Record(ctx, audit.Event{
		OrganizationID: organizationID,
		OccurredAt:     now,
		Actor:          sweepExpiringSystemActor,
		ActorType:      "system",
		Action:         "ownership.override_expired",
		TargetType:     "certificate",
		TargetID:       override.CertificateID,
		Metadata:       md,
	}); err != nil {
		return fmt.Errorf("ownership: record expired-override audit: %w", err)
	}
	return nil
}

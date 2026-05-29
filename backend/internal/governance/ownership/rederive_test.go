package ownership

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// nilSignalsRepo is a governance.OwnershipRepository whose only
// implemented method is GetCertificateSignals, which returns
// (nil, nil) — the "certificate not found" shape. Every other method
// panics: rederiveCertificate's missing-signals branch must return
// before touching them, so a panic would be a real regression. The
// embedded interface gives us the full method set without stubbing
// each one.
type nilSignalsRepo struct {
	governance.OwnershipRepository
}

func (nilSignalsRepo) GetCertificateSignals(ctx context.Context, organizationID, certificateID string) (*governance.CertificateSignals, error) {
	return nil, nil
}

// TestRederiveCertificateFailsClosedOnMissingSignals covers
// rederiveCertificate's fail-closed branch directly: when the cert's
// signals cannot be loaded (GetCertificateSignals returns nil), it
// returns ErrOverrideCertNotFound WITHOUT reading rules, prior
// ownership, or writing anything.
//
// This path is unreachable through the CreateOverride / ClearOverride
// service entry points — the certificate_ownership_overrides → certificates
// composite FK (ON DELETE CASCADE) means a mid-tx cert deletion fails
// the override INSERT before rederive runs (see the integration test
// TestOverrideCreateRaceCertDeletedInWindow). The branch is defensive
// depth-in-depth, so it is exercised here in isolation.
func TestRederiveCertificateFailsClosedOnMissingSignals(t *testing.T) {
	svc := &Service{
		repo: &governance.Repo{Ownership: nilSignalsRepo{}},
		// tx / audit / resolver / clock are intentionally nil: the
		// missing-signals branch returns before any of them is used.
		// A nil-pointer panic here would prove the guard moved.
	}

	res, err := svc.rederiveCertificate(context.Background(), "anchorix", "cert-gone", nil, time.Now())
	if res != nil {
		t.Fatalf("result = %+v; want nil on missing signals", res)
	}
	if !errors.Is(err, ErrOverrideCertNotFound) {
		t.Fatalf("err = %v; want ErrOverrideCertNotFound", err)
	}
}

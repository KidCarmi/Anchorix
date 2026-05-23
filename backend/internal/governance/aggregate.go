package governance

import "errors"

// Repo is the aggregate handle for the three governance
// repository interfaces. The H-026B engine and the H-026D
// engine each take exactly one constructor argument of this
// type instead of three separate interfaces, so the
// composition-root wiring stays a single short call:
//
//	govRepo := &governance.Repo{
//	    Ownership:     postgres.NewOwnershipRepository(db),
//	    Policy:        postgres.NewPolicyRepository(db),
//	    RecomputeRuns: postgres.NewGovernanceRecomputeRunsRepository(db),
//	}
//	ownershipSvc, _ := ownership.NewService(govRepo, ...)
//	policySvc,    _ := policy.NewService(govRepo, ...)
//
// Why a struct, not a constructor:
//
// The three repos are independent: each implements its own
// interface with no inter-repo invariants the aggregate needs
// to enforce. A struct with public fields makes the wiring
// trivially auditable from the composition root — no hidden
// constructor logic, no validation that the engine then
// duplicates. The aggregate exists to compress the parameter
// list, not to add behavior.
//
// Validate() is a one-shot helper engines can call once at
// construction to fail-closed on a partially-wired aggregate
// rather than discovering nil receivers mid-recompute.
type Repo struct {
	Ownership     OwnershipRepository
	Policy        PolicyRepository
	RecomputeRuns GovernanceRecomputeRunsRepository
}

// ErrIncompleteRepo is returned by Repo.Validate when one of
// the three interface fields is nil. Used by the H-026B /
// H-026D engine constructors during composition so a missing
// dependency surfaces at startup, not on the first recompute.
var ErrIncompleteRepo = errors.New("governance: incomplete Repo (Ownership + Policy + RecomputeRuns required)")

// Validate returns ErrIncompleteRepo when any of the three
// interface fields is nil. Engines invoke this once during
// their own constructor so a partially-wired Repo can never
// reach a runtime call site. The check is intentionally
// shallow — it does NOT exercise the database, just the
// in-process composition shape.
func (r *Repo) Validate() error {
	if r == nil {
		return ErrIncompleteRepo
	}
	if r.Ownership == nil || r.Policy == nil || r.RecomputeRuns == nil {
		return ErrIncompleteRepo
	}
	return nil
}

package governance

import (
	"errors"
	"reflect"
)

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
// interface fields is nil OR holds a typed-nil pointer.
// Engines invoke this once during their own constructor so a
// partially-wired Repo can never reach a runtime call site.
// The check is intentionally shallow — it does NOT exercise
// the database, just the in-process composition shape.
//
// Why typed-nil matters (Go gotcha): an interface value holding
// a nil concrete pointer is NOT == nil. A composition root that
// wires
//
//	var ownership *postgres.OwnershipRepository // nil
//	&Repo{Ownership: ownership, ...}
//
// produces a non-nil interface that a plain `== nil` check
// passes — and then the first method call dereferences the nil
// receiver and panics mid-recompute. The whole point of the
// aggregate is fail-closed composition at startup, so Validate
// must catch this. isNilInterface uses reflection to reject
// typed-nil values of any nilable kind.
func (r *Repo) Validate() error {
	if r == nil {
		return ErrIncompleteRepo
	}
	if isNilInterface(r.Ownership) || isNilInterface(r.Policy) || isNilInterface(r.RecomputeRuns) {
		return ErrIncompleteRepo
	}
	return nil
}

// isNilInterface reports whether v is a nil interface OR an
// interface holding a nil value of a nilable kind (pointer,
// interface, map, slice, func, channel). A non-nilable kind
// (e.g. a struct value) is never "nil" and returns false.
//
// This is the standard guard for the typed-nil-in-interface
// trap: `v == nil` only catches the untyped-nil case; the
// reflect path catches `(*T)(nil)` boxed into the interface.
func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map,
		reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

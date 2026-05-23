package governance

import (
	"errors"
	"testing"
)

// nilRepo implements the three interface contracts with no-op
// methods. The Validate test only needs non-nil interface
// values; the bodies are never called.
type nilOwnershipRepo struct{ OwnershipRepository }
type nilPolicyRepo struct{ PolicyRepository }
type nilRecomputeRunsRepo struct {
	GovernanceRecomputeRunsRepository
}

func TestRepoValidate(t *testing.T) {
	tests := []struct {
		name string
		repo *Repo
		want error
	}{
		{
			name: "nil pointer",
			repo: nil,
			want: ErrIncompleteRepo,
		},
		{
			name: "zero-value struct",
			repo: &Repo{},
			want: ErrIncompleteRepo,
		},
		{
			name: "missing ownership",
			repo: &Repo{
				Policy:        nilPolicyRepo{},
				RecomputeRuns: nilRecomputeRunsRepo{},
			},
			want: ErrIncompleteRepo,
		},
		{
			name: "missing policy",
			repo: &Repo{
				Ownership:     nilOwnershipRepo{},
				RecomputeRuns: nilRecomputeRunsRepo{},
			},
			want: ErrIncompleteRepo,
		},
		{
			name: "missing recompute_runs",
			repo: &Repo{
				Ownership: nilOwnershipRepo{},
				Policy:    nilPolicyRepo{},
			},
			want: ErrIncompleteRepo,
		},
		{
			name: "all three wired",
			repo: &Repo{
				Ownership:     nilOwnershipRepo{},
				Policy:        nilPolicyRepo{},
				RecomputeRuns: nilRecomputeRunsRepo{},
			},
			want: nil,
		},
		// Typed-nil cases: an interface field holding a nil
		// CONCRETE POINTER is non-nil at the interface level
		// (v == nil is false) but would panic on first method
		// call. Validate must reject these via the reflect
		// path. Each subtest uses a nil *nilXxxRepo (the
		// pointer receiver still satisfies the interface via
		// the embedded interface's promoted method set).
		{
			name: "typed-nil ownership",
			repo: &Repo{
				Ownership:     (*nilOwnershipRepo)(nil),
				Policy:        nilPolicyRepo{},
				RecomputeRuns: nilRecomputeRunsRepo{},
			},
			want: ErrIncompleteRepo,
		},
		{
			name: "typed-nil policy",
			repo: &Repo{
				Ownership:     nilOwnershipRepo{},
				Policy:        (*nilPolicyRepo)(nil),
				RecomputeRuns: nilRecomputeRunsRepo{},
			},
			want: ErrIncompleteRepo,
		},
		{
			name: "typed-nil recompute_runs",
			repo: &Repo{
				Ownership:     nilOwnershipRepo{},
				Policy:        nilPolicyRepo{},
				RecomputeRuns: (*nilRecomputeRunsRepo)(nil),
			},
			want: ErrIncompleteRepo,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.repo.Validate()
			if tc.want == nil && got != nil {
				t.Fatalf("Validate() = %v; want nil", got)
			}
			if tc.want != nil && !errors.Is(got, tc.want) {
				t.Fatalf("Validate() = %v; want %v", got, tc.want)
			}
		})
	}
}

// TestIsNilInterface pins the panic-safety + correctness
// contract of the reflect-based nil detector directly. The
// Validate cases above exercise it through the three interface
// fields, but only with values that implement the repository
// interfaces; this test covers the helper's full kind matrix —
// crucially confirming it NEVER calls reflect.Value.IsNil on a
// non-nilable kind (which would panic).
func TestIsNilInterface(t *testing.T) {
	var nilPtr *int
	var nilMap map[string]int
	var nilSlice []int
	var nilFunc func()
	var nilChan chan int
	var nilIface OwnershipRepository

	cases := []struct {
		name string
		v    any
		want bool
	}{
		// untyped nil
		{"untyped nil", nil, true},

		// nilable kinds, nil
		{"nil pointer", nilPtr, true},
		{"nil map", nilMap, true},
		{"nil slice", nilSlice, true},
		{"nil func", nilFunc, true},
		{"nil chan", nilChan, true},
		{"nil interface field", nilIface, true},
		{"typed-nil repo pointer", (*nilOwnershipRepo)(nil), true},

		// nilable kinds, non-nil
		{"non-nil pointer", new(int), false},
		{"non-nil map", map[string]int{}, false},
		{"non-nil slice", []int{}, false},
		{"non-nil chan", make(chan int), false},

		// non-nilable kinds MUST return false WITHOUT panicking
		// (reflect.Value.IsNil panics on these — the helper must
		// not reach it for them).
		{"int", 42, false},
		{"string", "x", false},
		{"bool", false, false},
		{"struct value", struct{ X int }{X: 1}, false},
		{"zero struct value", nilOwnershipRepo{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A panic here (e.g. IsNil on a non-nilable kind)
			// fails the test rather than crashing the binary.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("isNilInterface(%s) panicked: %v", tc.name, r)
				}
			}()
			if got := isNilInterface(tc.v); got != tc.want {
				t.Fatalf("isNilInterface(%s) = %v; want %v", tc.name, got, tc.want)
			}
		})
	}
}

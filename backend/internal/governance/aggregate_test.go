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

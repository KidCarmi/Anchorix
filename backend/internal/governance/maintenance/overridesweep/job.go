package overridesweep

import (
	"context"
	"errors"
	"fmt"

	"github.com/kidcarmi/anchorix/backend/internal/governance/maintenance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
)

// JobName is the stable registry / config / cursor key for the expired
// override sweep job. It MUST NOT change across releases — it keys the
// persisted governance_scheduler_job row (PR-1).
const JobName = "expired_override_sweep"

// ExpiredOverrideSweeper is the narrow, consumer-owned interface the
// adapter calls. It is exactly the H-029 dormant primitive's signature
// (CLAUDE.md §8.8: the consumer owns the interface). The production
// implementation is *ownership.Service, injected by the composition root
// in a later PR; PR-3 wires nothing.
//
// Defining a narrow interface here (rather than taking *ownership.Service
// directly) keeps the adapter unit-testable with a fake and documents
// the exact, single capability this Job depends on.
type ExpiredOverrideSweeper interface {
	SweepExpiringOverridesPage(ctx context.Context, organizationID, cursorCertID string, pageSize int) (*ownership.ExpiringOverridesSweepResult, error)
}

// Job is the maintenance.Job adapter for the H-029 expired-override
// sweep. One RunPage call drives exactly one bounded sweep page; the
// adapter owns no state and performs no side effect beyond invoking the
// primitive (which owns its own transaction, lock, and audit).
type Job struct {
	sweeper ExpiredOverrideSweeper
}

// NewJob wires the adapter. Constructor DI (CLAUDE.md §8.8); the sweeper
// is required.
func NewJob(sweeper ExpiredOverrideSweeper) (*Job, error) {
	if sweeper == nil {
		return nil, errors.New("overridesweep.NewJob: sweeper required")
	}
	return &Job{sweeper: sweeper}, nil
}

// Name returns the stable job key.
func (j *Job) Name() string { return JobName }

// RunPage executes exactly ONE expired-override sweep page for a single
// organization, starting after cursor, with the supplied page size, and
// maps the primitive's result onto maintenance.PageResult.
//
// Mapping (B4 design §5.1):
//   - organizationID, cursor, limits.PageSize are passed through unchanged
//   - PageResult.NextCursor   <- result.NextCursor
//   - PageResult.Done         <- result.Done
//   - PageResult.ItemsScanned <- result.CertsScanned
//   - PageResult.ItemsChanged <- result.ClearedCount
//
// The adapter calls the primitive once and only once. A primitive error
// propagates fail-closed (the runner leaves the cursor un-advanced and
// records a failed run). The adapter never mutates scheduler state and
// never emits audit — the primitive owns its transaction, advisory lock,
// and per-override audit rows; adding any here would duplicate the audit
// layer (CLAUDE.md §9).
func (j *Job) RunPage(ctx context.Context, organizationID, cursor string, limits maintenance.PageLimits) (maintenance.PageResult, error) {
	result, err := j.sweeper.SweepExpiringOverridesPage(ctx, organizationID, cursor, limits.PageSize)
	if err != nil {
		return maintenance.PageResult{}, fmt.Errorf("overridesweep: sweep page %s: %w", organizationID, err)
	}
	if result == nil {
		// Defensive: a nil result with a nil error is a primitive
		// contract violation. Fail closed rather than reporting a bogus
		// completed page.
		return maintenance.PageResult{}, fmt.Errorf("overridesweep: sweep page %s: nil result without error", organizationID)
	}
	return maintenance.PageResult{
		NextCursor:   result.NextCursor,
		Done:         result.Done,
		ItemsScanned: result.CertsScanned,
		ItemsChanged: result.ClearedCount,
	}, nil
}

// Compile-time guards:
//   - the adapter satisfies the maintenance.Job contract; and
//   - the production *ownership.Service satisfies the consumer-owned
//     ExpiredOverrideSweeper interface, so a future wiring PR can inject
//     it directly. A signature drift on either side fails the build here
//     rather than at wiring time.
var (
	_ maintenance.Job        = (*Job)(nil)
	_ ExpiredOverrideSweeper = (*ownership.Service)(nil)
)

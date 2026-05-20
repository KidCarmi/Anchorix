package findings

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
)

// DefaultSchedulerInterval is the v0.1 default tick spacing for
// the background findings recompute loop. Six hours is a
// trade-off between freshness (findings reflect inventory
// changes within the same operator shift) and DB pressure (one
// org with a few thousand certs runs a single recompute
// transaction per tick; cheaper than reactive recompute on
// every inventory write).
//
// Operators can override via ANCHORIX_FINDINGS_SCHEDULER_INTERVAL.
const DefaultSchedulerInterval = 6 * time.Hour

// MinSchedulerInterval is the lower bound the scheduler config
// validator accepts. Anything tighter risks tick-overlap during
// a long recompute and adds DB churn for no operator benefit;
// the WithTxLockedFindings advisory lock would serialize the
// overlap anyway. 30 seconds is generous for v0.1.
const MinSchedulerInterval = 30 * time.Second

// SchedulerConfig is the operator-tunable shape passed to
// NewScheduler. The composition root builds this from
// internal/config — the scheduler package never reads env
// directly (CLAUDE.md §8.9).
type SchedulerConfig struct {
	// Enabled toggles the loop. When false, NewScheduler still
	// constructs a Scheduler so the composition root has a
	// stable wiring point; Run becomes a noop that returns
	// immediately. Useful in CI / disabled-by-policy
	// deployments.
	Enabled bool

	// Interval is the spacing between ticks. Must be >=
	// MinSchedulerInterval when Enabled.
	Interval time.Duration
}

// OrganizationLister returns the set of organization ids the
// scheduler should sweep on every tick. The interface is
// consumer-owned (CLAUDE.md §8.8): the scheduler defines what
// it needs, the postgres layer satisfies it.
type OrganizationLister interface {
	ListOrganizationIDs(ctx context.Context) ([]string, error)
}

// ScheduledService is the narrow subset of *Service the
// scheduler invokes. Unit tests inject a fake to verify the
// loop's invocation pattern without standing up a real
// findings service.
type ScheduledService interface {
	RecomputeScheduled(ctx context.Context, organizationID string) (*RecomputeResult, error)
}

// Scheduler is the background loop that recomputes findings on
// the configured tick. One owner (the composition root in
// cmd/anchorix/serve.go); one cancellation path
// (context.Context); bounded lifetime (Run exits on ctx done).
// CLAUDE.md §8.10 concurrency discipline.
//
// The scheduler does NOT add any locking layer of its own. The
// findings.Service already serializes concurrent recomputes
// per-organization via WithTxLockedFindings, so a scheduled
// run and a simultaneous operator-triggered manual run for the
// same org will serialize at the advisory-lock barrier the
// same way two concurrent manual runs do.
type Scheduler struct {
	service ScheduledService
	orgs    OrganizationLister
	log     *logger.Logger
	clock   clock.Clock
	cfg     SchedulerConfig
}

// NewScheduler constructs the scheduler. Returns an error for
// missing dependencies, an invalid configuration (interval
// below MinSchedulerInterval when Enabled), or a nil logger /
// clock. Constructor DI per CLAUDE.md §8.8.
func NewScheduler(
	service ScheduledService,
	orgs OrganizationLister,
	log *logger.Logger,
	clk clock.Clock,
	cfg SchedulerConfig,
) (*Scheduler, error) {
	switch {
	case service == nil:
		return nil, errors.New("findings.NewScheduler: scheduled service required")
	case orgs == nil:
		return nil, errors.New("findings.NewScheduler: organization lister required")
	case log == nil:
		return nil, errors.New("findings.NewScheduler: logger required")
	case clk == nil:
		return nil, errors.New("findings.NewScheduler: clock required")
	}
	if cfg.Enabled {
		if cfg.Interval <= 0 {
			return nil, fmt.Errorf("findings.NewScheduler: interval must be positive (got %s)", cfg.Interval)
		}
		if cfg.Interval < MinSchedulerInterval {
			return nil, fmt.Errorf(
				"findings.NewScheduler: interval %s below minimum %s",
				cfg.Interval, MinSchedulerInterval,
			)
		}
	}
	return &Scheduler{
		service: service,
		orgs:    orgs,
		log:     log,
		clock:   clk,
		cfg:     cfg,
	}, nil
}

// Run starts the loop. Blocks until ctx is cancelled.
//
// When SchedulerConfig.Enabled is false, Run logs the
// disabled-state line and returns nil immediately — the
// composition root can still wire and spawn a goroutine
// unconditionally, simplifying the startup sequence.
//
// The loop:
//
//   - waits for the first tick (NO immediate-on-start tick;
//     the manual POST endpoint stays the way to force a
//     recompute right now);
//   - on each tick, enumerates organizations and recomputes
//     findings for each one;
//   - a failure in one organization's recompute is logged and
//     the loop continues to the next org;
//   - a panic in one organization's recompute is recovered
//     (logged) and the loop continues — a buggy rule must not
//     take down the scheduler.
//
// Returns nil on graceful shutdown (ctx done). Any non-nil
// error is reserved for fatal startup failures the composition
// root should surface; the v0.1 loop body itself does not
// return errors — it logs them.
func (s *Scheduler) Run(ctx context.Context) error {
	if !s.cfg.Enabled {
		s.log.Info("findings scheduler disabled (ANCHORIX_FINDINGS_SCHEDULER_ENABLED=false)")
		return nil
	}
	s.log.Info("findings scheduler started", "interval", s.cfg.Interval.String())
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.log.Info("findings scheduler stopped")
			return nil
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce executes one sweep across all organizations. Exported
// only via the package-internal pkg (no `_test.go` build tag),
// so unit tests that want to step the loop without waiting for
// the ticker can call it directly via the test file in the same
// package. External callers should NOT depend on this method.
func (s *Scheduler) runOnce(ctx context.Context) {
	orgIDs, err := s.orgs.ListOrganizationIDs(ctx)
	if err != nil {
		s.log.Error("findings scheduler: list organizations failed",
			"err", err.Error(),
		)
		return
	}
	for _, orgID := range orgIDs {
		// ctx.Done() check between orgs so a shutdown during a
		// long sweep exits promptly without starting work on
		// the next org.
		if err := ctx.Err(); err != nil {
			s.log.Info("findings scheduler: shutdown during sweep, skipping remaining orgs",
				"completed_before_shutdown", true,
			)
			return
		}
		s.recomputeOrg(ctx, orgID)
	}
}

// recomputeOrg invokes the service for one organization and
// logs the outcome. The deferred recover() ensures that even a
// rule that panics (e.g., a future regression in a new rule
// body) does not take down the scheduler — the orchestration
// continues to the next org on the next loop iteration.
func (s *Scheduler) recomputeOrg(ctx context.Context, organizationID string) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("findings scheduler: recompute panicked",
				"organization_id", organizationID,
				"panic", fmt.Sprintf("%v", r),
			)
		}
	}()
	start := s.clock.Now()
	out, err := s.service.RecomputeScheduled(ctx, organizationID)
	duration := s.clock.Now().Sub(start)
	if err != nil {
		// One org's failure must not stop others — log and
		// return. ctx.Err() being non-nil indicates shutdown
		// in progress; we still log because the failure was
		// real (the tx rolled back).
		s.log.Error("findings scheduler: recompute failed",
			"organization_id", organizationID,
			"duration", duration.String(),
			"err", err.Error(),
		)
		return
	}
	s.log.Info("findings scheduler: recompute ok",
		"organization_id", organizationID,
		"duration", duration.String(),
		"evaluated_certificates", out.EvaluatedCertificates,
		"opened", out.Opened,
		"updated", out.Updated,
		"resolved", out.Resolved,
		"unchanged", out.Unchanged,
		"rule_count", out.RuleCount,
	)
}

// ValidateSchedulerConfig is the public-facing variant of the
// NewScheduler validation rules. The composition root can call
// it BEFORE constructing a real Service if it wants to fail at
// startup on a bad ANCHORIX_FINDINGS_SCHEDULER_INTERVAL without
// having a service / org lister ready yet.
//
// Used by internal/config.validate() to surface invalid intervals
// at process startup rather than at NewScheduler call time.
func ValidateSchedulerConfig(cfg SchedulerConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Interval <= 0 {
		return errors.New("interval must be positive when scheduler is enabled")
	}
	if cfg.Interval < MinSchedulerInterval {
		return fmt.Errorf("interval %s below minimum %s",
			cfg.Interval, MinSchedulerInterval)
	}
	return nil
}

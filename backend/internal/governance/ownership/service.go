package ownership

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// DefaultBulkAuditThreshold is the per-pass, per-transition-group
// count above which the engine emits a single rollup audit row
// instead of N per-cert rows (governance plan §4.6). Configurable via
// ServiceConfig so a deployment can tune it; the default matches
// ANCHORIX_OWNERSHIP_BULK_AUDIT_THRESHOLD in the plan.
const DefaultBulkAuditThreshold = 500

// ownershipRecomputePageSize is the streaming page size for the
// recompute's certificate / ownership / override reads. 500 mirrors
// the findings recompute: large enough that round-trips don't
// dominate, small enough that per-page memory stays in the low
// megabytes at fleet scale.
const ownershipRecomputePageSize = 500

// schedulerActorID is the actor recorded for a scheduled recompute.
// (No scheduler is wired in H-026B2; the constant exists so
// RecomputeScheduled has a stable, filterable actor for when H-026B4
// adds the loop.)
const schedulerActorID = "scheduler"

// Transactor is the consumer-owned slice of the storage transaction
// surface the engine needs. The concrete *postgres.DB satisfies it.
// Defining it here (not importing postgres) keeps the boundary in
// doc.go intact: ownership never imports storage/postgres.
//
// TryWithTxLockedOwnershipRepeatableRead is the non-blocking variant
// used by the H-026B3A `?nowait=true` recompute trigger; it returns
// (acquired=false, nil) when the lock is already held by another
// holder so the handler can map to 409 without enqueuing.
type Transactor interface {
	WithTxLockedOwnershipRepeatableRead(ctx context.Context, organizationID string, fn func(ctx context.Context) error) error
	TryWithTxLockedOwnershipRepeatableRead(ctx context.Context, organizationID string, fn func(ctx context.Context) error) (bool, error)

	// WithTx runs fn in a single plain transaction (no advisory lock,
	// READ COMMITTED). The H-026B3B rule mutations use it so the repo
	// write and the security audit row commit atomically — an audit
	// failure rolls the mutation back. Rule mutations do not touch the
	// recompute lock: they are single-row writes whose effect is
	// applied by the NEXT recompute, not synchronously.
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error

	// WithTxLockedOwnership runs fn inside a single transaction holding
	// the per-org ownership advisory lock (xact-scope, READ COMMITTED).
	// The H-026B3B override mutations use it so the override row write +
	// the single-cert re-derivation + the security audit commit
	// atomically AND serialize against any in-flight full recompute
	// (governance plan §3.9). The lock hold is bounded by the
	// single-cert work, so it does not stall a sweep meaningfully.
	WithTxLockedOwnership(ctx context.Context, organizationID string, fn func(ctx context.Context) error) error
}

// RuleTargetResolver answers the bounded existence questions the
// rule-mutation validator asks. Consumer-owned (CLAUDE.md §8.8); the
// concrete postgres.OwnershipRuleTargetResolver satisfies it. Both
// methods return (true,nil) when the active row exists, (false,nil)
// when it does not, and an error only for repository failures.
type RuleTargetResolver interface {
	ActiveServiceExists(ctx context.Context, organizationID, serviceID string) (bool, error)
	ActiveAgentGroupExists(ctx context.Context, organizationID, agentGroupID string) (bool, error)
}

// ServiceConfig carries the operator-tunable knobs. Zero values fall
// back to the package defaults so callers can pass an empty struct.
type ServiceConfig struct {
	BulkAuditThreshold int
}

// Service is the ownership engine entry point. It owns recompute
// orchestration (streaming pass, decision, explanation, audit) but no
// background loop and no HTTP surface — those land in later phases.
//
// HTTP handlers (H-026B3) will depend on this struct, never on the
// repository / transactor directly (CLAUDE.md §8.6, §8.8).
type Service struct {
	repo     *governance.Repo
	tx       Transactor
	audit    audit.Recorder
	clock    clock.Clock
	resolver RuleTargetResolver

	bulkAuditThreshold int
	pageOverride       int // test-only; 0 = production page size
}

// NewService wires the engine. Constructor DI (CLAUDE.md §8.8). Fails
// closed on a missing dependency or a partially-wired Repo (the
// typed-nil trap is caught by Repo.Validate). The resolver validates
// rule-mutation targets (H-026B3B); it is required because rule
// creation must reject nonexistent services / agent groups.
func NewService(repo *governance.Repo, tx Transactor, auditRec audit.Recorder, clk clock.Clock, resolver RuleTargetResolver, cfg ServiceConfig) (*Service, error) {
	if repo == nil || tx == nil || auditRec == nil || clk == nil || resolver == nil {
		return nil, ErrIncompleteService
	}
	if err := repo.Validate(); err != nil {
		return nil, fmt.Errorf("ownership.NewService: %w", err)
	}
	threshold := cfg.BulkAuditThreshold
	if threshold <= 0 {
		threshold = DefaultBulkAuditThreshold
	}
	return &Service{
		repo:               repo,
		tx:                 tx,
		audit:              auditRec,
		clock:              clk,
		resolver:           resolver,
		bulkAuditThreshold: threshold,
	}, nil
}

// SetPageSizeForTest forces the streaming page size so cross-package
// integration tests can exercise multi-page walks (and page-boundary
// snapshot isolation) against small fixtures. Production code MUST NOT
// call it — operators tune memory via fixture scale, not page size.
func (s *Service) SetPageSizeForTest(size int) { s.pageOverride = size }

func (s *Service) pageSize() int {
	if s.pageOverride > 0 {
		return s.pageOverride
	}
	return ownershipRecomputePageSize
}

// RecomputeResult is the per-pass summary returned to the caller
// (and, in B3+, to the operator-triggered recompute handler).
type RecomputeResult struct {
	RunID                 string
	FirstRun              bool
	EvaluatedCertificates int
	ChangedCertificates   int
	UnchangedCertificates int
	Reclassified          int
	BecameOwned           int
	BecameUnowned         int
	FlippedOwner          int
	CreatedUnownedRows    int
	ExpiredOverrides      int
	RuleCompileFailures   int
	EngineVersion         int
}

// Recompute runs an operator-triggered ownership recompute for one
// organization. ActorUserID attributes the governance.recomputed
// audit row; an empty value falls back to ("system","system").
func (s *Service) Recompute(ctx context.Context, organizationID, actorUserID string) (*RecomputeResult, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("ownership: organization id required")
	}
	actor := strings.TrimSpace(actorUserID)
	actorKind := governance.RecomputeActorUser
	if actor == "" {
		actor, actorKind = "system", governance.RecomputeActorSystem
	}
	return s.recompute(ctx, organizationID, actor, actorKind)
}

// RecomputeScheduled is the entry point a future background scheduler
// (H-026B4) uses. Behavior is identical to Recompute except the actor
// is the fixed schedulerActorID with actor_kind=system, so operators
// can separate scheduled passes from operator-triggered ones in audit
// history without inspecting metadata. Not wired to any loop in B2.
func (s *Service) RecomputeScheduled(ctx context.Context, organizationID string) (*RecomputeResult, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("ownership: organization id required")
	}
	return s.recompute(ctx, organizationID, schedulerActorID, governance.RecomputeActorSystem)
}

// recompute opens the locked REPEATABLE READ transaction and runs the
// streaming pass inside it. The advisory lock serializes concurrent
// recomputes per org; REPEATABLE READ pins one input snapshot across
// every paginated read. Any error (including an audit failure) rolls
// the whole pass back — run row, ownership writes, explanations, and
// audit rows are all-or-nothing.
func (s *Service) recompute(ctx context.Context, organizationID, actor string, actorKind governance.RecomputeActorKind) (*RecomputeResult, error) {
	now := s.clock.Now()
	var result *RecomputeResult
	err := s.tx.WithTxLockedOwnershipRepeatableRead(ctx, organizationID, func(txCtx context.Context) error {
		r, err := s.runRecomputeTx(txCtx, organizationID, actor, actorKind, now)
		if err != nil {
			return err
		}
		result = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RecomputeNoWait is the non-blocking entry point used by the
// H-026B3A `POST /ownership/recompute?nowait=true` path. It returns
// ErrRecomputeInProgress when another recompute is already holding
// the per-org advisory lock; the handler maps this to 409
// `ownership_recompute_in_progress`. Otherwise it runs the same
// pass as Recompute under the same RR snapshot.
func (s *Service) RecomputeNoWait(ctx context.Context, organizationID, actorUserID string) (*RecomputeResult, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("ownership: organization id required")
	}
	actor := strings.TrimSpace(actorUserID)
	actorKind := governance.RecomputeActorUser
	if actor == "" {
		actor, actorKind = "system", governance.RecomputeActorSystem
	}
	now := s.clock.Now()
	var result *RecomputeResult
	acquired, err := s.tx.TryWithTxLockedOwnershipRepeatableRead(ctx, organizationID, func(txCtx context.Context) error {
		r, err := s.runRecomputeTx(txCtx, organizationID, actor, actorKind, now)
		if err != nil {
			return err
		}
		result = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, ErrRecomputeInProgress
	}
	return result, nil
}

// --- audit emission (all inside the recompute tx) -----------------

// recomputedAuditMetadata is the governance.recomputed summary shape.
type recomputedAuditMetadata struct {
	Severity              string               `json:"severity"`
	OrganizationID        string               `json:"organization_id"`
	RunID                 string               `json:"run_id"`
	FirstRun              bool                 `json:"first_run"`
	CreatedUnownedRows    int                  `json:"created_unowned_rows"`
	EvaluatedCertificates int                  `json:"evaluated_certificates"`
	ChangedCertificates   int                  `json:"changed_certificates"`
	UnchangedCertificates int                  `json:"unchanged_certificates"`
	Reclassified          int                  `json:"reclassified"`
	BecameOwned           int                  `json:"became_owned"`
	BecameUnowned         int                  `json:"became_unowned"`
	FlippedOwner          int                  `json:"flipped_owner"`
	EngineVersion         int                  `json:"engine_version"`
	RuleCompileFailures   []ruleCompileFailure `json:"rule_compile_failures,omitempty"`
}

func (s *Service) emitRecomputed(ctx context.Context, organizationID, actor string, actorKind governance.RecomputeActorKind, runID string, now time.Time, out *recomputeOutcome) error {
	md, _ := json.Marshal(recomputedAuditMetadata{
		Severity:              "security",
		OrganizationID:        organizationID,
		RunID:                 runID,
		FirstRun:              out.firstRun,
		CreatedUnownedRows:    out.createdUnowned,
		EvaluatedCertificates: out.evaluated,
		ChangedCertificates:   out.changed,
		UnchangedCertificates: out.unchanged,
		Reclassified:          out.reclassified,
		BecameOwned:           out.becameOwned,
		BecameUnowned:         out.becameUnowned,
		FlippedOwner:          out.flippedOwner,
		EngineVersion:         engineVersion,
		RuleCompileFailures:   out.compileFailures,
	})
	at := string(actorKind)
	return s.audit.Record(ctx, audit.Event{
		OrganizationID: organizationID,
		OccurredAt:     now,
		Actor:          actor,
		ActorType:      at,
		Action:         "governance.recomputed",
		TargetType:     "organization",
		TargetID:       organizationID,
		Metadata:       md,
	})
}

// overrideExpiredMetadata is the per-override ownership.override_expired
// audit shape, emitted when the recompute auto-clears an expired
// override. Low cardinality (operator pins), so no rollup.
type overrideExpiredMetadata struct {
	Severity   string `json:"severity"`
	RunID      string `json:"run_id"`
	OverrideID string `json:"override_id"`
	ServiceID  string `json:"service_id"`
	Reason     string `json:"reason"`
}

func (s *Service) emitExpiredOverrides(ctx context.Context, organizationID, actor string, actorKind governance.RecomputeActorKind, runID string, now time.Time, out *recomputeOutcome) error {
	at := string(actorKind)
	for _, e := range out.expiredOverrides {
		md, _ := json.Marshal(overrideExpiredMetadata{
			Severity: "security", RunID: runID, OverrideID: e.overrideID, ServiceID: e.serviceID, Reason: "auto-expired",
		})
		if err := s.audit.Record(ctx, audit.Event{
			OrganizationID: organizationID,
			OccurredAt:     now,
			Actor:          actor,
			ActorType:      at,
			Action:         "ownership.override_expired",
			TargetType:     "certificate",
			TargetID:       e.certID,
			Metadata:       md,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ruleCompileFailedMetadata is the per-failed-rule audit shape.
type ruleCompileFailedMetadata struct {
	Severity string `json:"severity"`
	RunID    string `json:"run_id"`
	Reason   string `json:"reason"`
}

func (s *Service) emitCompileFailures(ctx context.Context, organizationID, actor string, actorKind governance.RecomputeActorKind, runID string, now time.Time, failures []ruleCompileFailure) error {
	at := string(actorKind)
	for _, f := range failures {
		md, _ := json.Marshal(ruleCompileFailedMetadata{Severity: "security", RunID: runID, Reason: f.Reason})
		if err := s.audit.Record(ctx, audit.Event{
			OrganizationID: organizationID,
			OccurredAt:     now,
			Actor:          actor,
			ActorType:      at,
			Action:         "ownership.rule_compile_failed",
			TargetType:     "ownership_rule",
			TargetID:       f.RuleID,
			Metadata:       md,
		}); err != nil {
			return err
		}
	}
	return nil
}

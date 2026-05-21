package findings

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// Defaults / bounds for cursor-paginated GET /findings. Match
// the H-010 / H-020 list pattern so the operator UI sees one
// consistent paging model across the resource list endpoints.
const (
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// Service is the findings domain entrypoint. Owns:
//
//   - rule evaluation orchestration (Recompute),
//   - the finding lifecycle (open / update / resolve / reopen),
//   - the operator read surface (GetFinding, ListFindings).
//
// HTTP handlers depend on this struct, never on Repository /
// CertificateLister / Transactor types directly (CLAUDE.md §8.6,
// §8.8).
type Service struct {
	repo                  Repository
	certs                 CertificateLister
	tx                    Transactor
	audit                 audit.Recorder
	clock                 clock.Clock
	rules                 []Rule
	streamingPageOverride int
}

// NewService wires the service. Constructor-based DI per
// CLAUDE.md §8.8. Returns an error if any dependency is missing
// or if no rules are registered (a no-op recompute is a
// configuration bug, not a runtime condition).
func NewService(
	repo Repository,
	certs CertificateLister,
	tx Transactor,
	auditRec audit.Recorder,
	clk clock.Clock,
	rules []Rule,
) (*Service, error) {
	switch {
	case repo == nil:
		return nil, errors.New("findings.NewService: repository required")
	case certs == nil:
		return nil, errors.New("findings.NewService: certificate lister required")
	case tx == nil:
		return nil, errors.New("findings.NewService: transactor required")
	case auditRec == nil:
		return nil, errors.New("findings.NewService: audit recorder required")
	case clk == nil:
		return nil, errors.New("findings.NewService: clock required")
	case len(rules) == 0:
		return nil, errors.New("findings.NewService: at least one rule required")
	}
	return &Service{
		repo:  repo,
		certs: certs,
		tx:    tx,
		audit: auditRec,
		clock: clk,
		rules: rules,
	}, nil
}

// SetStreamingPageSizeForTest overrides
// `recomputeStreamingPageSize` for the duration of this
// Service instance. The default (0) means "use the
// production const". Anything > 0 forces the streaming diff
// to page at that size instead.
//
// Public to support cross-package integration tests that
// need to exercise multi-page walks against small fixtures —
// notably the H-024B snapshot-isolation test, which seeds
// only a handful of certs but needs the streaming loop to
// make MORE than one paginated cert read so the
// REPEATABLE READ + session-lock guarantee can be observed
// across page boundaries. Without this knob the test could
// not distinguish READ COMMITTED from REPEATABLE READ at
// fixture scale.
//
// Marked "ForTest" in the name so production callers
// reaching for it see the documented intent. Production
// code paths MUST NOT call this — operators tune memory
// budget through fixture size, not page size.
func (s *Service) SetStreamingPageSizeForTest(size int) {
	s.streamingPageOverride = size
}

// effectiveStreamingPageSize returns the override when one
// is set, the production const otherwise. Keeps the
// `runDiffStreaming` body free of conditional logic.
func (s *Service) effectiveStreamingPageSize() int {
	if s.streamingPageOverride > 0 {
		return s.streamingPageOverride
	}
	return recomputeStreamingPageSize
}

// SchedulerActorID is the value the scheduled-recompute path
// records in the audit row's `actor` column. ActorType is then
// "system" (the scheduler is not a user). Stable string so
// operators can filter `audit_events.actor = 'scheduler'` to
// see every background recompute.
const SchedulerActorID = "scheduler"

// RecomputeInput is the validated input to Service.Recompute.
// OrganizationID is required; ActorUserID is the operator
// whose session triggered the recompute (used as the audit
// event's Actor so post-hoc filtering by user works). The HTTP
// handler MUST populate ActorUserID from the authenticated
// session — never from a request body or query parameter.
//
// For scheduled recomputes the scheduler MUST use
// Service.RecomputeScheduled, NOT this method with
// ActorUserID="" — that path is reserved for the explicit
// scheduler entry point that emits the documented
// `actor="scheduler"` audit row.
type RecomputeInput struct {
	OrganizationID string
	ActorUserID    string
}

// Recompute evaluates every registered rule against every
// certificate in the organization and applies the diff against
// the existing findings table state.
//
// State transitions:
//
//   - No existing row + rule matches → INSERT (counted: Opened).
//   - Existing row in `open` state + rule matches → UPDATE
//     last_seen_at / evidence / rule_version / severity / title
//     (counted: Updated).
//   - Existing row in `resolved` state + rule matches → UPDATE
//     status=open, last_seen_at=now, resolved_at=NULL; first_seen_at
//     stays at the original detection time (counted: Opened — from
//     the operator's POV the finding is now newly visible again).
//   - Existing row in `open` state + rule does NOT match →
//     UPDATE status=resolved, resolved_at=now; last_seen_at
//     unchanged (counted: Resolved).
//   - Existing row in `resolved` state + rule does NOT match →
//     no DB write (counted: Unchanged).
//
// Concurrency: a per-organization advisory lock
// (Transactor.WithTxLockedFindings) serializes simultaneous
// recompute calls for the same org. Without the lock, two
// callers' in-memory snapshots could both miss a row and both
// attempt to INSERT the same
// `(organization_id, certificate_id, rule_id)` triple — the
// second INSERT would fail the unique constraint and surface as
// 500. With the lock, the second caller sees the first caller's
// inserts (and counts them as Updated, not Opened).
//
// Audit policy:
//
//   - ONE audit row per Recompute call, action="findings.recomputed".
//   - Actor is in.ActorUserID, ActorType is "user".
//   - Audit row is inserted in the same transaction as the
//     finding state changes. An audit failure ROLLS BACK the
//     entire recompute (H-021 brief).
//   - No per-finding audit rows. The recompute audit row's
//     metadata carries the counter set so operators can reason
//     about the volume of state change without reading every
//     finding row.
//
// Determinism: rules are pure functions of (cert, now). With
// unchanged cert inventory and unchanged time, Recompute is a
// no-op (all matched findings move to Updated, no Opened or
// Resolved). Re-running is therefore safe.
func (s *Service) Recompute(ctx context.Context, in RecomputeInput) (*RecomputeResult, error) {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return nil, fmt.Errorf("%w: organization id required", ErrInvalidRecomputeInput)
	}
	// ActorUserID drives the audit row. An empty value falls back
	// to ("system", "system") rather than the previous misleading
	// "operator" placeholder; the H-021 review pinned this
	// behavior with TestFindingsRecomputeAuditCarriesRealActorID.
	// The scheduler path uses RecomputeScheduled to get the
	// dedicated "scheduler" actor.
	actor := strings.TrimSpace(in.ActorUserID)
	actorType := "user"
	if actor == "" {
		actor = "system"
		actorType = "system"
	}
	return s.recomputeWithActor(ctx, in.OrganizationID, actor, actorType)
}

// RecomputeScheduled is the entry point the H-022 background
// scheduler uses. Behavior is identical to Recompute except the
// audit row's Actor is hardcoded to SchedulerActorID and
// ActorType is "system" — operators filtering audit history by
// actor can therefore separate scheduled runs from
// operator-triggered ones without inspecting the metadata.
//
// Kept as a separate method (rather than a Recompute flag) so
// the audit envelope shape lives in one place. The HTTP handler
// MUST NOT call this — it would mis-attribute an
// operator-triggered recompute to the scheduler.
func (s *Service) RecomputeScheduled(ctx context.Context, organizationID string) (*RecomputeResult, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("%w: organization id required", ErrInvalidRecomputeInput)
	}
	return s.recomputeWithActor(ctx, organizationID, SchedulerActorID, "system")
}

// recomputeWithActor is the shared implementation behind
// Recompute and RecomputeScheduled. Both entry points validate
// their inputs and then delegate here with the resolved
// (actor, actorType) pair. The split keeps Recompute /
// RecomputeScheduled as thin API surfaces and centralizes the
// lock+diff+audit orchestration.
//
// H-024B: the production path is `runDiffStreaming` under
// `WithTxLockedFindingsRepeatableRead`. The legacy load-all
// path stays in-tree behind RecomputeLegacyLoadAll for the
// byte-identical equivalence test; the cleanup PR after the
// H-024B soak removes both.
func (s *Service) recomputeWithActor(
	ctx context.Context,
	organizationID, actor, actorType string,
) (*RecomputeResult, error) {
	now := s.clock.Now()
	var result RecomputeResult
	if err := s.tx.WithTxLockedFindingsRepeatableRead(ctx, organizationID, func(ctx context.Context) error {
		summary, err := s.runDiffStreaming(ctx, organizationID, now)
		if err != nil {
			return err
		}
		result = summary.toRecomputeResult(len(s.rules))
		if err := s.recordRecomputeAudit(ctx, organizationID, actor, actorType, &result, now); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &result, nil
}

// RecomputeLegacyLoadAll runs the pre-H-024B load-all
// recompute path under `WithTxLockedFindings` (READ COMMITTED).
// Kept exported so the H-024B byte-identical equivalence test
// in `backend/test/integration/` can drive it side-by-side
// with the streaming path against the same Smallv01 fixture.
//
// NOT used by production traffic — `Recompute` and
// `RecomputeScheduled` always invoke the streaming variant
// under REPEATABLE READ. Will be removed by the cleanup PR
// after H-024B soaks (per H024_PERFORMANCE_PLAN.md §9.B item
// 3); no other caller should depend on it.
//
// Same audit envelope as Recompute: ONE `findings.recomputed`
// row with the supplied actor/actorType. Audit failure rolls
// back the diff. Use only with the operator's own user id (or
// SchedulerActorID for the scheduler-driven legacy path,
// which exists only for completeness — the scheduler uses
// RecomputeScheduled).
func (s *Service) RecomputeLegacyLoadAll(ctx context.Context, in RecomputeInput) (*RecomputeResult, error) {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return nil, fmt.Errorf("%w: organization id required", ErrInvalidRecomputeInput)
	}
	actor := strings.TrimSpace(in.ActorUserID)
	actorType := "user"
	if actor == "" {
		actor = "system"
		actorType = "system"
	}
	now := s.clock.Now()
	var result RecomputeResult
	if err := s.tx.WithTxLockedFindings(ctx, in.OrganizationID, func(ctx context.Context) error {
		summary, err := s.runDiffLoadAll(ctx, in.OrganizationID, now)
		if err != nil {
			return err
		}
		result = summary.toRecomputeResult(len(s.rules))
		if err := s.recordRecomputeAudit(ctx, in.OrganizationID, actor, actorType, &result, now); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &result, nil
}

// diffSummary is the orchestration-layer return value from
// the two runDiff variants. The counter layout matches
// RecomputeResult.toRecomputeResult derives the public shape
// from this internal one.
type diffSummary struct {
	evaluatedCertificates int
	loadedCertificates    int
	loadedFindings        int
	counters              [4]int
}

func (d diffSummary) toRecomputeResult(ruleCount int) RecomputeResult {
	return RecomputeResult{
		EvaluatedCertificates: d.evaluatedCertificates,
		Opened:                d.counters[counterOpened],
		Updated:               d.counters[counterUpdated],
		Resolved:              d.counters[counterResolved],
		Unchanged:             d.counters[counterUnchanged],
		RuleCount:             ruleCount,
		LoadedCertificates:    d.loadedCertificates,
		LoadedFindings:        d.loadedFindings,
	}
}

// runDiffLoadAll is the legacy load-all diff algorithm. Kept
// in-tree until the post-H-024B soak cleanup PR so the
// byte-identical equivalence test in the integration suite
// can drive both implementations against the same fixture and
// compare the resulting `findings` table state.
//
// The behaviour is byte-equivalent to the original H-021
// implementation — the per-(cert, rule) decisions are
// delegated to decideMatchTransition / decideNoMatchTransition
// (service_diff.go), and the orchestration loops match the
// pre-H-024B shape exactly. Refactoring through the shared
// helpers is what guarantees this path and runDiffStreaming
// produce identical final state for the same input.
func (s *Service) runDiffLoadAll(
	ctx context.Context,
	organizationID string,
	now time.Time,
) (diffSummary, error) {
	certs, err := s.certs.ListAllCertificateSummariesForOrg(ctx, organizationID)
	if err != nil {
		return diffSummary{}, fmt.Errorf("findings: list certificates: %w", err)
	}

	// Build the rule-match set keyed by (cert_id, rule_id).
	matches := make(map[matchKey]matchEntry)
	for i := range certs {
		cert := &certs[i]
		for _, rule := range s.rules {
			m := rule.Evaluate(cert, now)
			if m == nil {
				continue
			}
			matches[matchKey{cert.ID, rule.ID()}] = matchEntry{rule: rule, match: m}
		}
	}

	// Load every existing finding for the org.
	existing, err := s.repo.ListAllForOrg(ctx, organizationID)
	if err != nil {
		return diffSummary{}, fmt.Errorf("findings: list existing: %w", err)
	}
	existingByKey := make(map[matchKey]*Finding, len(existing))
	for i := range existing {
		f := &existing[i]
		existingByKey[matchKey{f.CertificateID, f.RuleID}] = f
	}

	var counters [4]int

	// Apply matches first (insert / update / reopen).
	for k, m := range matches {
		prior := existingByKey[k]
		next, op, bucket, err := decideMatchTransition(prior, organizationID, k.certID, m.rule, m.match, now)
		if err != nil {
			return diffSummary{}, err
		}
		if err := applyDecision(ctx, s.repo, next, op); err != nil {
			return diffSummary{}, fmt.Errorf("findings: apply match diff: %w", err)
		}
		counters[bucket]++
	}

	// Then walk existing rows that did NOT match.
	for k, f := range existingByKey {
		if _, matched := matches[k]; matched {
			continue
		}
		next, op, bucket, err := decideNoMatchTransition(f, now)
		if err != nil {
			return diffSummary{}, err
		}
		if err := applyDecision(ctx, s.repo, next, op); err != nil {
			return diffSummary{}, fmt.Errorf("findings: apply no-match diff: %w", err)
		}
		counters[bucket]++
	}

	return diffSummary{
		evaluatedCertificates: len(certs),
		loadedCertificates:    len(certs),
		loadedFindings:        len(existing),
		counters:              counters,
	}, nil
}

// recomputeStreamingPageSize is the page-size knob for the
// H-024B streaming diff. 500 is a deliberate trade-off: large
// enough that round-trip latency does not dominate; small
// enough that per-page memory (cert summaries + per-page
// finding rows + per-page rule matches) stays in the
// low-megabytes range at fleet scale. The page-size choice is
// internal; callers do not see it. If pilot-tier measurements
// surface a different sweet spot, this is the one constant to
// tune.
const recomputeStreamingPageSize = 500

// runDiffStreaming is the H-024B production diff algorithm.
// Walks the org's certificates and existing findings in
// fixed-size pages so peak memory stays bounded by
// recomputeStreamingPageSize × (cert summary + finding row).
// The full match map is still built in memory (it is bounded
// by the rule-match cardinality, which is a subset of the
// (cert × rule) cross product and typically far smaller than
// the cert table itself), but the bulky per-finding `Evidence`
// JSON is never loaded into a long-lived structure.
//
// Algorithm (three phases):
//
//  1. Page through CERTS by id ASC. For each cert × rule,
//     evaluate the rule. Matches accumulate into the
//     `matches` map keyed by (cert_id, rule_id).
//
//  2. Page through EXISTING FINDINGS by id ASC. For each
//     finding, look up its (cert_id, rule_id) in `matches`:
//
//     - present → decideMatchTransition(prior, rule, match)
//     and delete the entry from `matches` so phase 3 only
//     sees never-existed-before matches.
//     - absent  → decideNoMatchTransition(prior).
//
//  3. Remaining entries in `matches` have no prior finding,
//     so they're brand-new INSERTs.
//
// State-machine equivalence with runDiffLoadAll comes from
// both paths delegating to the SAME pure helpers
// (decideMatchTransition / decideNoMatchTransition). The
// orchestration differs (paged vs in-memory) but the
// per-(cert, rule) decisions are byte-equivalent.
//
// Snapshot isolation: the calling tx is opened at REPEATABLE
// READ via WithTxLockedFindingsRepeatableRead (Transactor
// interface). Without that, the multiple paginated SELECTs
// inside this function could each see a different snapshot
// when a concurrent ingestion batch commits, breaking the
// determinism guarantee CERTIFICATE_FINDINGS.md §5 commits
// to.
func (s *Service) runDiffStreaming(
	ctx context.Context,
	organizationID string,
	now time.Time,
) (diffSummary, error) {
	pageSize := s.effectiveStreamingPageSize()

	// Phase 1: page through certs, build matches map.
	matches := make(map[matchKey]matchEntry)
	totalCerts := 0
	certCursor := ""
	for {
		page, err := s.certs.ListCertificateBareSummariesForOrgPaged(ctx, organizationID, certCursor, pageSize)
		if err != nil {
			return diffSummary{}, fmt.Errorf("findings: list bare cert summaries: %w", err)
		}
		if len(page) == 0 {
			break
		}
		totalCerts += len(page)
		for i := range page {
			s.evaluateRulesForCert(&page[i], now, matches)
		}
		certCursor = page[len(page)-1].ID
		if len(page) < pageSize {
			break
		}
	}

	var counters [4]int

	// Phase 2: page through existing findings, apply
	// match or no-match transitions per finding.
	totalFindings := 0
	findingCursor := ""
	for {
		page, err := s.repo.ListAllFindingsForOrgPaged(ctx, organizationID, findingCursor, pageSize)
		if err != nil {
			return diffSummary{}, fmt.Errorf("findings: list findings page: %w", err)
		}
		if len(page) == 0 {
			break
		}
		totalFindings += len(page)
		for i := range page {
			prior := &page[i]
			key := matchKey{prior.CertificateID, prior.RuleID}
			if m, hasMatch := matches[key]; hasMatch {
				next, op, bucket, err := decideMatchTransition(prior, organizationID, key.certID, m.rule, m.match, now)
				if err != nil {
					return diffSummary{}, err
				}
				if err := applyDecision(ctx, s.repo, next, op); err != nil {
					return diffSummary{}, fmt.Errorf("findings: apply streamed match diff: %w", err)
				}
				counters[bucket]++
				// This match has been handled; remove it so
				// phase 3 only sees true new inserts.
				delete(matches, key)
				continue
			}
			next, op, bucket, err := decideNoMatchTransition(prior, now)
			if err != nil {
				return diffSummary{}, err
			}
			if err := applyDecision(ctx, s.repo, next, op); err != nil {
				return diffSummary{}, fmt.Errorf("findings: apply streamed no-match diff: %w", err)
			}
			counters[bucket]++
		}
		findingCursor = page[len(page)-1].ID
		if len(page) < pageSize {
			break
		}
	}

	// Phase 3: remaining matches have no prior finding —
	// INSERT them. Map iteration order is randomised, which is
	// fine: each (key, m) decision is independent and the
	// final table state is identical regardless of insert
	// order.
	for k, m := range matches {
		next, op, bucket, err := decideMatchTransition(nil, organizationID, k.certID, m.rule, m.match, now)
		if err != nil {
			return diffSummary{}, err
		}
		if err := applyDecision(ctx, s.repo, next, op); err != nil {
			return diffSummary{}, fmt.Errorf("findings: apply streamed insert diff: %w", err)
		}
		counters[bucket]++
	}

	return diffSummary{
		evaluatedCertificates: totalCerts,
		loadedCertificates:    totalCerts,
		loadedFindings:        totalFindings,
		counters:              counters,
	}, nil
}

// evaluateRulesForCert applies the registered rules to one
// certificate and records every matching (cert, rule) pair in
// the supplied map. Extracted from the cert-page loop so the
// in-page work reads as a single statement; no behaviour change
// vs an inline loop.
func (s *Service) evaluateRulesForCert(
	cert *inventory.CertificateSummary,
	now time.Time,
	matches map[matchKey]matchEntry,
) {
	for _, rule := range s.rules {
		m := rule.Evaluate(cert, now)
		if m == nil {
			continue
		}
		matches[matchKey{cert.ID, rule.ID()}] = matchEntry{rule: rule, match: m}
	}
}

// recordRecomputeAudit writes the single audit row that summarizes
// one Recompute call. Failure surfaces as ErrInternalAudit which
// the tx wrapper propagates, rolling back the finding state
// changes (H-021 brief: "If audit fails: recompute state
// changes must roll back").
type recomputeAuditMetadata struct {
	OrganizationID        string `json:"organization_id"`
	EvaluatedCertificates int    `json:"evaluated_certificates"`
	Opened                int    `json:"opened"`
	Updated               int    `json:"updated"`
	Resolved              int    `json:"resolved"`
	Unchanged             int    `json:"unchanged"`
	RuleCount             int    `json:"rule_count"`

	// H-024B additive fields. Both streaming and legacy
	// load-all paths populate them. JSON additions are
	// backward-compatible per CLAUDE.md §17 — existing
	// audit-event consumers ignoring the new keys keep
	// working.
	LoadedCertificates int `json:"loaded_certificates"`
	LoadedFindings     int `json:"loaded_findings"`
}

// recordRecomputeAudit takes the resolved (actor, actorType)
// pair from its caller — Service.Recompute derives them from
// RecomputeInput.ActorUserID; Service.RecomputeScheduled passes
// (SchedulerActorID, "system"). The actor/actorType strings
// reach the audit row verbatim.
func (s *Service) recordRecomputeAudit(
	ctx context.Context,
	organizationID, actor, actorType string,
	r *RecomputeResult,
	now time.Time,
) error {
	md, _ := json.Marshal(recomputeAuditMetadata{
		OrganizationID:        organizationID,
		EvaluatedCertificates: r.EvaluatedCertificates,
		Opened:                r.Opened,
		Updated:               r.Updated,
		Resolved:              r.Resolved,
		Unchanged:             r.Unchanged,
		RuleCount:             r.RuleCount,
		LoadedCertificates:    r.LoadedCertificates,
		LoadedFindings:        r.LoadedFindings,
	})
	if err := s.audit.Record(ctx, audit.Event{
		OrganizationID: organizationID,
		OccurredAt:     now,
		Actor:          actor,
		ActorType:      actorType,
		Action:         "findings.recomputed",
		TargetType:     "organization",
		TargetID:       organizationID,
		Metadata:       md,
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrInternalAudit, err)
	}
	return nil
}

// GetFinding returns a single finding by id within the
// organization. Cross-org ids return ErrFindingNotFound — the
// repo's WHERE clause filters on organization_id. CLAUDE.md §6
// deterministic auth.
func (s *Service) GetFinding(ctx context.Context, organizationID, findingID string) (*Finding, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("%w: organization id required", ErrInvalidListInput)
	}
	if strings.TrimSpace(findingID) == "" {
		return nil, fmt.Errorf("%w: finding id required", ErrInvalidListInput)
	}
	return s.repo.GetFinding(ctx, organizationID, findingID)
}

// ListFindings returns one paginated page for the operator
// GET /findings endpoint. Pagination follows the H-010 cursor
// convention (base64 RawURL of "last_seen_at|id").
func (s *Service) ListFindings(ctx context.Context, in ListQuery) (*ListResult, error) {
	q, err := normalizeListQuery(in)
	if err != nil {
		return nil, err
	}
	rows, err := s.repo.ListFindings(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("findings: list: %w", err)
	}
	wantLimit := q.Limit - 1
	out := &ListResult{Items: rows}
	if len(rows) > wantLimit {
		last := rows[wantLimit-1]
		out.Items = rows[:wantLimit]
		out.NextCursor = encodeFindingCursor(last.LastSeenAt, last.ID)
	}
	return out, nil
}

// normalizeListQuery validates the operator-supplied filter
// shape and produces the storage-layer query, including the
// limit+1 sentinel that drives next-cursor detection.
func normalizeListQuery(in ListQuery) (ListQuery, error) {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return ListQuery{}, fmt.Errorf("%w: organization id required", ErrInvalidListInput)
	}
	switch in.Status {
	case "",
		StatusFilterOpen,
		StatusFilterResolved,
		StatusFilterAcknowledged,
		StatusFilterSuppressed,
		StatusFilterAll:
		// ok
	default:
		return ListQuery{}, fmt.Errorf("%w: invalid status filter %q", ErrInvalidListInput, in.Status)
	}
	if in.Status == "" {
		in.Status = StatusFilterOpen
	}
	if in.Severity != "" {
		switch in.Severity {
		case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
			// ok
		default:
			return ListQuery{}, fmt.Errorf("%w: invalid severity filter %q", ErrInvalidListInput, in.Severity)
		}
	}
	limit, err := normalizeLimit(in.Limit)
	if err != nil {
		return ListQuery{}, err
	}
	cursorAt, cursorID, err := decodeFindingCursor(in.Cursor)
	if err != nil {
		return ListQuery{}, err
	}
	in.Limit = limit + 1
	// Stash cursor decode result back onto the query — the repo
	// reads it via the dedicated fields below. To keep the
	// public ListQuery shape simple, the repo accepts the
	// already-parsed cursor through the same struct: the repo
	// treats Limit/Status/etc. as the authoritative shape and
	// extracts the cursor pieces via these helpers (it does NOT
	// re-decode the Cursor string).
	in.CursorLastSeenAt = cursorAt
	in.CursorID = cursorID
	return in, nil
}

// listCursorSeparator matches the H-010 / H-020 cursor format.
const listCursorSeparator = "|"

func encodeFindingCursor(lastSeenAt time.Time, findingID string) string {
	raw := lastSeenAt.UTC().Format(time.RFC3339Nano) + listCursorSeparator + findingID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeFindingCursor(raw string) (time.Time, string, error) {
	if raw == "" {
		return time.Time{}, "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: malformed cursor", ErrInvalidListInput)
	}
	parts := strings.SplitN(string(decoded), listCursorSeparator, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return time.Time{}, "", fmt.Errorf("%w: malformed cursor", ErrInvalidListInput)
	}
	at, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: malformed cursor", ErrInvalidListInput)
	}
	return at, parts[1], nil
}

// normalizeLimit applies the default/bounds policy for `limit`.
// 0 → DefaultListLimit; negative or > MaxListLimit → error
// wrapped with ErrInvalidListInput so the HTTP layer maps to
// 400. The HTTP layer additionally rejects an explicit `limit=0`
// (matching the H-020 fix) before reaching the service.
func normalizeLimit(raw int) (int, error) {
	if raw == 0 {
		return DefaultListLimit, nil
	}
	if raw < 0 {
		return 0, fmt.Errorf("%w: limit must be positive", ErrInvalidListInput)
	}
	if raw > MaxListLimit {
		return 0, fmt.Errorf("%w: limit exceeds %d", ErrInvalidListInput, MaxListLimit)
	}
	return raw, nil
}

// Ensure nowProvider stays referenced — the test fakes
// (service_test.go) implement it via clock.Clock, so the
// interface needs to be in the same package even though it is
// not re-exported.
var _ nowProvider = clock.System{}

// --- H-023 override workflow -------------------------------------

// AcknowledgeFinding transitions the (org, finding) row to
// status=acknowledged. The operator's reason is stored on the
// row (denormalized current state) and in the audit row
// (immutable history). Audit is written in the same transaction
// as the status update: a Record failure rolls back the status
// change.
//
// State transitions accepted: from any current status. v0.1
// deliberately keeps the API permissive — an operator can
// re-acknowledge an already-acknowledged finding (refresh the
// reason / actor) or acknowledge a resolved finding (a no-op
// from a rule-engine POV, but the operator's intent is
// recorded). The previous status is captured in the audit row's
// metadata so the history is reconstructable.
//
// Cross-org / missing finding id → ErrFindingNotFound (HTTP
// 404). Invalid input (empty reason, etc.) →
// ErrInvalidOverrideInput (HTTP 400).
func (s *Service) AcknowledgeFinding(ctx context.Context, in AcknowledgeInput) (*Finding, error) {
	if err := validateAcknowledgeInput(in); err != nil {
		return nil, err
	}
	return s.applyOverride(ctx, overrideRequest{
		OrganizationID: in.OrganizationID,
		FindingID:      in.FindingID,
		ActorUserID:    in.ActorUserID,
		Reason:         strings.TrimSpace(in.Reason),
		NewStatus:      StatusAcknowledged,
		AuditAction:    "finding.acknowledged",
	})
}

// SuppressFinding transitions the (org, finding) row to
// status=suppressed. Same semantics as AcknowledgeFinding plus
// an optional expiry — when set, recompute reopens the finding
// to `open` once wall-clock time crosses it (and the rule
// still matches).
//
// in.ExpiresAt may be nil (permanent suppression) or strictly
// in the future relative to the service clock; equal-to-now or
// past values are rejected.
func (s *Service) SuppressFinding(ctx context.Context, in SuppressInput) (*Finding, error) {
	if err := validateSuppressInput(in, s.clock.Now()); err != nil {
		return nil, err
	}
	return s.applyOverride(ctx, overrideRequest{
		OrganizationID:    in.OrganizationID,
		FindingID:         in.FindingID,
		ActorUserID:       in.ActorUserID,
		Reason:            strings.TrimSpace(in.Reason),
		NewStatus:         StatusSuppressed,
		SuppressExpiresAt: in.ExpiresAt,
		AuditAction:       "finding.suppressed",
	})
}

// overrideRequest is the internal envelope passed to
// applyOverride. Centralizes the load+mutate+audit logic so
// AcknowledgeFinding and SuppressFinding stay as thin
// validators.
type overrideRequest struct {
	OrganizationID    string
	FindingID         string
	ActorUserID       string
	Reason            string
	NewStatus         Status
	SuppressExpiresAt *time.Time
	AuditAction       string
}

// applyOverride loads the finding, applies the operator
// intent, and writes the audit row inside one transaction
// guarded by the per-org WithTxLockedFindings advisory lock —
// same lock the recompute path uses, so a manual override
// during a recompute sweep serializes correctly.
//
// Audit metadata carries severity:"security" per CLAUDE.md §9
// (finding overrides are listed in the security-event class).
func (s *Service) applyOverride(ctx context.Context, req overrideRequest) (*Finding, error) {
	now := s.clock.Now()
	var updated *Finding
	if err := s.tx.WithTxLockedFindings(ctx, req.OrganizationID, func(ctx context.Context) error {
		prior, err := s.repo.GetFinding(ctx, req.OrganizationID, req.FindingID)
		if err != nil {
			// Includes ErrFindingNotFound — propagated as-is
			// so the HTTP layer maps it to 404.
			return err
		}
		previousStatus := prior.Status
		prior.Status = req.NewStatus
		prior.StatusReason = req.Reason
		prior.StatusActor = req.ActorUserID
		prior.StatusChangedAt = &now
		prior.SuppressExpiresAt = req.SuppressExpiresAt
		prior.UpdatedAt = now
		// Clear ResolvedAt so the documented invariant
		// "resolved_at is non-null iff status == 'resolved'"
		// holds for the post-override row. An earlier draft
		// left ResolvedAt populated when an operator
		// overrode a resolved finding; the API would then
		// return rows with status="acknowledged" /
		// "suppressed" AND a non-null resolved_at, which
		// breaks both the wire contract and the
		// `?status=resolved` filter (which queries on
		// status, not resolved_at, but operators reading
		// the JSON would be confused). Recompute re-stamps
		// resolved_at when transitioning an override BACK
		// to resolved (rule no longer matches).
		prior.ResolvedAt = nil
		if err := s.repo.UpdateFinding(ctx, prior); err != nil {
			return fmt.Errorf("findings: apply override: %w", err)
		}
		if err := s.recordOverrideAudit(ctx, req, previousStatus, now); err != nil {
			return err
		}
		updated = prior
		return nil
	}); err != nil {
		return nil, err
	}
	return updated, nil
}

// findingOverrideAuditMetadata is the JSONB shape stored on the
// `finding.acknowledged` / `finding.suppressed` audit rows.
// Severity is "security" per CLAUDE.md §9 — finding overrides
// are explicitly on the list of events that downstream alerting
// must be able to filter on.
type findingOverrideAuditMetadata struct {
	Severity          string     `json:"severity"`
	OrganizationID    string     `json:"organization_id"`
	FindingID         string     `json:"finding_id"`
	PreviousStatus    string     `json:"previous_status"`
	NewStatus         string     `json:"new_status"`
	Reason            string     `json:"reason"`
	SuppressExpiresAt *time.Time `json:"suppress_expires_at,omitempty"`
}

func (s *Service) recordOverrideAudit(
	ctx context.Context,
	req overrideRequest,
	previousStatus Status,
	now time.Time,
) error {
	md, _ := json.Marshal(findingOverrideAuditMetadata{
		Severity:          "security",
		OrganizationID:    req.OrganizationID,
		FindingID:         req.FindingID,
		PreviousStatus:    string(previousStatus),
		NewStatus:         string(req.NewStatus),
		Reason:            req.Reason,
		SuppressExpiresAt: req.SuppressExpiresAt,
	})
	if err := s.audit.Record(ctx, audit.Event{
		OrganizationID: req.OrganizationID,
		OccurredAt:     now,
		Actor:          req.ActorUserID,
		ActorType:      "user",
		Action:         req.AuditAction,
		TargetType:     "finding",
		TargetID:       req.FindingID,
		Metadata:       md,
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrInternalAudit, err)
	}
	return nil
}

func validateAcknowledgeInput(in AcknowledgeInput) error {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return fmt.Errorf("%w: organization id required", ErrInvalidOverrideInput)
	}
	if strings.TrimSpace(in.FindingID) == "" {
		return fmt.Errorf("%w: finding id required", ErrInvalidOverrideInput)
	}
	if strings.TrimSpace(in.ActorUserID) == "" {
		return fmt.Errorf("%w: actor user id required", ErrInvalidOverrideInput)
	}
	if err := validateReason(in.Reason); err != nil {
		return err
	}
	return nil
}

func validateSuppressInput(in SuppressInput, now time.Time) error {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return fmt.Errorf("%w: organization id required", ErrInvalidOverrideInput)
	}
	if strings.TrimSpace(in.FindingID) == "" {
		return fmt.Errorf("%w: finding id required", ErrInvalidOverrideInput)
	}
	if strings.TrimSpace(in.ActorUserID) == "" {
		return fmt.Errorf("%w: actor user id required", ErrInvalidOverrideInput)
	}
	if err := validateReason(in.Reason); err != nil {
		return err
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(now) {
		return fmt.Errorf("%w: expires_at must be strictly in the future (got %s, now %s)",
			ErrInvalidOverrideInput, in.ExpiresAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

func validateReason(reason string) error {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return fmt.Errorf("%w: reason required (non-empty after trim)", ErrInvalidOverrideInput)
	}
	if len(trimmed) > MaxOverrideReasonLength {
		return fmt.Errorf("%w: reason exceeds %d bytes", ErrInvalidOverrideInput, MaxOverrideReasonLength)
	}
	return nil
}

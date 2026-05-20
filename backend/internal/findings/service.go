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
	"github.com/kidcarmi/anchorix/backend/internal/ids"
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
	repo  Repository
	certs CertificateLister
	tx    Transactor
	audit audit.Recorder
	clock clock.Clock
	rules []Rule
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
func (s *Service) recomputeWithActor(
	ctx context.Context,
	organizationID, actor, actorType string,
) (*RecomputeResult, error) {
	now := s.clock.Now()
	var result RecomputeResult
	if err := s.tx.WithTxLockedFindings(ctx, organizationID, func(ctx context.Context) error {
		evaluated, opened, updated, resolved, unchanged, err := s.runDiff(ctx, organizationID, now)
		if err != nil {
			return err
		}
		result = RecomputeResult{
			EvaluatedCertificates: evaluated,
			Opened:                opened,
			Updated:               updated,
			Resolved:              resolved,
			Unchanged:             unchanged,
			RuleCount:             len(s.rules),
		}
		if err := s.recordRecomputeAudit(ctx, organizationID, actor, actorType, &result, now); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &result, nil
}

// runDiff executes the rule pass and applies the diff. Pulled
// out of Recompute so the orchestration sits in one tx callback
// and Recompute itself stays focused on the audit + result
// shaping.
func (s *Service) runDiff(
	ctx context.Context,
	organizationID string,
	now time.Time,
) (evaluated, opened, updated, resolved, unchanged int, err error) {
	certs, err := s.certs.ListAllCertificateSummariesForOrg(ctx, organizationID)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("findings: list certificates: %w", err)
	}
	evaluated = len(certs)

	// Build the rule-match set keyed by (cert_id, rule_id).
	type matchKey struct{ certID, ruleID string }
	type match struct {
		rule  Rule
		match *RuleMatch
	}
	matches := make(map[matchKey]match)
	for i := range certs {
		cert := &certs[i]
		for _, rule := range s.rules {
			m := rule.Evaluate(cert, now)
			if m == nil {
				continue
			}
			matches[matchKey{cert.ID, rule.ID()}] = match{rule: rule, match: m}
		}
	}

	// Load every existing finding (open + resolved) for the org.
	// At v0.1 scale this is a small set; at findings-era scale
	// it gets paginated. See HARDENING_BACKLOG.
	existing, err := s.repo.ListAllForOrg(ctx, organizationID)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("findings: list existing: %w", err)
	}
	existingByKey := make(map[matchKey]*Finding, len(existing))
	for i := range existing {
		f := &existing[i]
		existingByKey[matchKey{f.CertificateID, f.RuleID}] = f
	}

	// Apply matches first (insert / update / reopen).
	for k, m := range matches {
		prior, hasPrior := existingByKey[k]
		switch {
		case !hasPrior:
			newID := ids.New()
			if err := s.repo.InsertFinding(ctx, &Finding{
				ID:             newID,
				OrganizationID: organizationID,
				CertificateID:  k.certID,
				RuleID:         k.ruleID,
				RuleVersion:    m.rule.Version(),
				Severity:       m.rule.Severity(),
				Status:         StatusOpen,
				Title:          m.rule.Title(),
				Evidence:       m.match.Evidence,
				FirstSeenAt:    now,
				LastSeenAt:     now,
				ResolvedAt:     nil,
				UpdatedAt:      now,
			}); err != nil {
				return 0, 0, 0, 0, 0, fmt.Errorf("findings: insert: %w", err)
			}
			opened++
		case prior.Status == StatusOpen:
			prior.LastSeenAt = now
			prior.UpdatedAt = now
			prior.Severity = m.rule.Severity()
			prior.Title = m.rule.Title()
			prior.RuleVersion = m.rule.Version()
			prior.Evidence = m.match.Evidence
			if err := s.repo.UpdateFinding(ctx, prior); err != nil {
				return 0, 0, 0, 0, 0, fmt.Errorf("findings: update: %w", err)
			}
			updated++
		case prior.Status == StatusResolved:
			// resolved → reopen: rule matches again, lift the
			// finding back into the operator-visible state.
			// `opened_at` (= FirstSeenAt) is intentionally NOT
			// touched here — it preserves the original detection
			// moment across resolve/reopen cycles.
			prior.Status = StatusOpen
			prior.LastSeenAt = now
			prior.UpdatedAt = now
			prior.ResolvedAt = nil
			prior.Severity = m.rule.Severity()
			prior.Title = m.rule.Title()
			prior.RuleVersion = m.rule.Version()
			prior.Evidence = m.match.Evidence
			if err := s.repo.UpdateFinding(ctx, prior); err != nil {
				return 0, 0, 0, 0, 0, fmt.Errorf("findings: reopen: %w", err)
			}
			opened++
		case prior.Status == StatusAcknowledged:
			// acknowledged + rule still matches: stay
			// acknowledged. Bump the rule-derived fields so
			// last_seen_at + evidence + rule_version reflect
			// the current evaluation, but PRESERVE the
			// operator's override metadata (status_reason,
			// status_actor, status_changed_at).
			prior.LastSeenAt = now
			prior.UpdatedAt = now
			prior.Severity = m.rule.Severity()
			prior.Title = m.rule.Title()
			prior.RuleVersion = m.rule.Version()
			prior.Evidence = m.match.Evidence
			if err := s.repo.UpdateFinding(ctx, prior); err != nil {
				return 0, 0, 0, 0, 0, fmt.Errorf("findings: update acknowledged: %w", err)
			}
			updated++
		case prior.Status == StatusSuppressed:
			// suppressed + rule still matches: either stay
			// suppressed (not expired) or reopen (expired).
			// `now` is the recompute's anchor — we compare
			// against the operator-set SuppressExpiresAt
			// strictly (>=) so a suppression that expires
			// EXACTLY at `now` is considered expired and the
			// finding reopens.
			if prior.SuppressExpiresAt != nil && !now.Before(*prior.SuppressExpiresAt) {
				// Suppression expired: reopen to `open` and
				// clear the override metadata so the row no
				// longer claims operator intent. The audit
				// history of the original suppression remains
				// in audit_events.
				prior.Status = StatusOpen
				prior.LastSeenAt = now
				prior.UpdatedAt = now
				prior.ResolvedAt = nil
				prior.Severity = m.rule.Severity()
				prior.Title = m.rule.Title()
				prior.RuleVersion = m.rule.Version()
				prior.Evidence = m.match.Evidence
				prior.StatusReason = ""
				prior.StatusActor = ""
				prior.StatusChangedAt = nil
				prior.SuppressExpiresAt = nil
				if err := s.repo.UpdateFinding(ctx, prior); err != nil {
					return 0, 0, 0, 0, 0, fmt.Errorf("findings: reopen expired suppression: %w", err)
				}
				opened++
				break
			}
			// Not expired (or no expiry): stay suppressed,
			// PRESERVE the override metadata.
			prior.LastSeenAt = now
			prior.UpdatedAt = now
			prior.Severity = m.rule.Severity()
			prior.Title = m.rule.Title()
			prior.RuleVersion = m.rule.Version()
			prior.Evidence = m.match.Evidence
			if err := s.repo.UpdateFinding(ctx, prior); err != nil {
				return 0, 0, 0, 0, 0, fmt.Errorf("findings: update suppressed: %w", err)
			}
			updated++
		default:
			// Any status outside open / resolved /
			// acknowledged / suppressed is unexpected. Fail
			// loudly so a future status addition (the
			// schema's CHECK constraint is permissive enough
			// to accept new strings via an upcoming migration)
			// is forced to extend this switch explicitly.
			return 0, 0, 0, 0, 0, fmt.Errorf(
				"%w: finding %s has status %q (rule still matches)",
				ErrUnsupportedFindingStatus, prior.ID, prior.Status,
			)
		}
	}

	// Then walk existing rows that did NOT match. open / ack /
	// suppressed all become resolved (rule no longer fires —
	// nothing to override). resolved stays resolved (unchanged).
	for k, f := range existingByKey {
		if _, matched := matches[k]; matched {
			continue
		}
		switch f.Status {
		case StatusOpen:
			resolvedAt := now
			f.Status = StatusResolved
			f.ResolvedAt = &resolvedAt
			f.UpdatedAt = now
			if err := s.repo.UpdateFinding(ctx, f); err != nil {
				return 0, 0, 0, 0, 0, fmt.Errorf("findings: resolve: %w", err)
			}
			resolved++
		case StatusAcknowledged, StatusSuppressed:
			// acknowledged / suppressed + rule no longer
			// matches: the underlying problem is gone, so the
			// operator override is moot. Resolve the finding
			// AND clear the override metadata so the row's
			// current state reflects "nothing here, nothing to
			// override". Audit history of the original
			// override remains in audit_events.
			resolvedAt := now
			f.Status = StatusResolved
			f.ResolvedAt = &resolvedAt
			f.UpdatedAt = now
			f.StatusReason = ""
			f.StatusActor = ""
			f.StatusChangedAt = nil
			f.SuppressExpiresAt = nil
			if err := s.repo.UpdateFinding(ctx, f); err != nil {
				return 0, 0, 0, 0, 0, fmt.Errorf("findings: resolve overridden: %w", err)
			}
			resolved++
		case StatusResolved:
			unchanged++
		default:
			return 0, 0, 0, 0, 0, fmt.Errorf(
				"%w: finding %s has status %q (rule no longer matches)",
				ErrUnsupportedFindingStatus, f.ID, f.Status,
			)
		}
	}
	return evaluated, opened, updated, resolved, unchanged, nil
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
	case "", StatusFilterOpen, StatusFilterResolved, StatusFilterAll:
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

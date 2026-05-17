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
// Audit policy:
//
//   - ONE audit row per Recompute call, action="findings.recomputed".
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
func (s *Service) Recompute(ctx context.Context, organizationID string) (*RecomputeResult, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("%w: organization id required", ErrInvalidRecomputeInput)
	}
	now := s.clock.Now()

	var result RecomputeResult
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
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
		if err := s.recordRecomputeAudit(ctx, organizationID, &result, now); err != nil {
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
		default: // resolved → reopen
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
		}
	}

	// Then walk existing rows that did NOT match. Open ones
	// become resolved; resolved ones stay resolved (unchanged).
	for k, f := range existingByKey {
		if _, matched := matches[k]; matched {
			continue
		}
		if f.Status == StatusOpen {
			resolvedAt := now
			f.Status = StatusResolved
			f.ResolvedAt = &resolvedAt
			f.UpdatedAt = now
			if err := s.repo.UpdateFinding(ctx, f); err != nil {
				return 0, 0, 0, 0, 0, fmt.Errorf("findings: resolve: %w", err)
			}
			resolved++
		} else {
			unchanged++
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

func (s *Service) recordRecomputeAudit(
	ctx context.Context,
	organizationID string,
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
		// The HTTP handler populates a real actor id when one
		// is available; the service is called inside a request
		// context, but the audit recorder accepts the actor on
		// the event itself. Service.Recompute is called from the
		// handler which sets the actor; the wire shape leaves
		// the actor blank only when called from a tool or
		// internal path. v0.1 has only one path (operator HTTP)
		// — actor lives in the metadata via the request context
		// when needed; the action+target are sufficient for
		// the recompute envelope.
		Actor:      "operator",
		ActorType:  "user",
		Action:     "findings.recomputed",
		TargetType: "organization",
		TargetID:   organizationID,
		Metadata:   md,
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

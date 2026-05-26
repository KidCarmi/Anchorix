package ownership

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/ids"
)

// auditSampleCap bounds the sample_cert_ids list carried on a bulk
// rollup audit row (governance plan §4.6).
const auditSampleCap = 100

// recomputeOutcome accumulates the per-pass counters, the first-run
// flag, the compile failures, and the grouped audit intents. It is
// the bridge between the streaming pass and the audit emission +
// run-finish steps, all of which run inside the same transaction.
type recomputeOutcome struct {
	firstRun         bool
	evaluated        int
	changed          int
	unchanged        int
	reclassified     int
	becameOwned      int
	becameUnowned    int
	flippedOwner     int
	createdUnowned   int
	compileFailures  []ruleCompileFailure
	expiredOverrides []expiredOverrideInfo
	auditGroups      map[auditGroupKey]*auditGroup
}

// expiredOverrideInfo records an override the pass auto-cleared
// because its expiry passed, for the ownership.override_expired audit.
type expiredOverrideInfo struct {
	certID     string
	overrideID string
	serviceID  string
}

// auditGroupKey groups per-cert transitions so the emitter can roll
// up high-volume groups into one row. The action is part of the key
// so each group is homogeneous (governance plan §4.6).
type auditGroupKey struct {
	action string
	from   governance.Decision
	to     governance.Decision
	driver string
}

// auditGroup tracks one transition group. While the count is at or
// below the threshold it retains per-cert ids so the emitter can
// write per-cert rows; once it crosses the threshold it discards them
// (rolledUp) and keeps only the count + a bounded sample, capping
// memory at O(threshold) per group rather than O(fleet).
type auditGroup struct {
	count    int
	samples  []string
	certIDs  []string
	rolledUp bool
}

func (o *recomputeOutcome) addAudit(action string, from, to governance.Decision, driver, certID string, threshold int) {
	key := auditGroupKey{action: action, from: from, to: to, driver: driver}
	g := o.auditGroups[key]
	if g == nil {
		g = &auditGroup{}
		o.auditGroups[key] = g
	}
	g.count++
	if len(g.samples) < auditSampleCap {
		g.samples = append(g.samples, certID)
	}
	if g.rolledUp {
		return
	}
	if g.count > threshold {
		g.rolledUp = true
		g.certIDs = nil // free retained ids; this group is a rollup
		return
	}
	g.certIDs = append(g.certIDs, certID)
}

// runRecomputeTx is the whole streaming pass, executed inside the
// caller's locked REPEATABLE READ transaction. Order: start the run
// row, compile rules (loud-fail on structural drift), load active
// overrides, stream certs + prior ownership in lockstep deciding each,
// then emit audit (compile failures, transition rows/rollups, the
// governance.recomputed summary) and finish the run row. Every write
// is in the one transaction, so any error rolls the entire pass back.
func (s *Service) runRecomputeTx(ctx context.Context, organizationID, actor string, actorKind governance.RecomputeActorKind, now time.Time) (*RecomputeResult, error) {
	runID := ids.New()
	run := &governance.GovernanceRecomputeRun{
		ID:             runID,
		OrganizationID: organizationID,
		Kind:           governance.RecomputeKindOwnership,
		StartedAt:      now,
		Actor:          actor,
		ActorKind:      actorKind,
		EngineVersion:  engineVersion,
	}
	if err := s.repo.RecomputeRuns.StartRecomputeRun(ctx, run); err != nil {
		return nil, fmt.Errorf("ownership: start recompute run: %w", err)
	}

	rawRules, err := s.repo.Ownership.ListOwnershipRulesForEngine(ctx, organizationID)
	if err != nil {
		return nil, fmt.Errorf("ownership: load rules: %w", err)
	}
	rules, compileFailures, err := compileRules(rawRules)
	if err != nil {
		return nil, err // unknown tier / match_kind: fail loud, roll back
	}

	overrides, err := s.loadActiveOverrides(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	out := &recomputeOutcome{
		firstRun:        true,
		compileFailures: compileFailures,
		auditGroups:     make(map[auditGroupKey]*auditGroup),
	}
	if err := s.streamAndDecide(ctx, organizationID, rules, overrides, now, out); err != nil {
		return nil, err
	}

	if err := s.emitCompileFailures(ctx, organizationID, actor, actorKind, runID, now, compileFailures); err != nil {
		return nil, err
	}
	if err := s.emitExpiredOverrides(ctx, organizationID, actor, actorKind, runID, now, out); err != nil {
		return nil, err
	}
	if err := s.emitAuditGroups(ctx, organizationID, actor, actorKind, runID, now, out); err != nil {
		return nil, err
	}
	if err := s.emitRecomputed(ctx, organizationID, actor, actorKind, runID, now, out); err != nil {
		return nil, err
	}

	finished := s.clock.Now()
	succeeded := true
	run.FinishedAt = &finished
	run.Succeeded = &succeeded
	run.EvaluatedCount = out.evaluated
	run.ChangedCount = out.changed
	run.UnchangedCount = out.unchanged
	run.BecameOwnedCount = out.becameOwned
	run.BecameUnownedCount = out.becameUnowned
	run.FlippedOwnerCount = out.flippedOwner
	if err := s.repo.RecomputeRuns.FinishRecomputeRun(ctx, run); err != nil {
		return nil, fmt.Errorf("ownership: finish recompute run: %w", err)
	}

	return &RecomputeResult{
		RunID:                 runID,
		FirstRun:              out.firstRun,
		EvaluatedCertificates: out.evaluated,
		ChangedCertificates:   out.changed,
		UnchangedCertificates: out.unchanged,
		Reclassified:          out.reclassified,
		BecameOwned:           out.becameOwned,
		BecameUnowned:         out.becameUnowned,
		FlippedOwner:          out.flippedOwner,
		CreatedUnownedRows:    out.createdUnowned,
		ExpiredOverrides:      len(out.expiredOverrides),
		RuleCompileFailures:   len(compileFailures),
		EngineVersion:         engineVersion,
	}, nil
}

// loadActiveOverrides pages every active override into a map keyed by
// certificate id. Overrides are low-cardinality operator pins, so the
// map is bounded well below the fleet (governance plan §3.4).
func (s *Service) loadActiveOverrides(ctx context.Context, organizationID string) (map[string]*governance.CertificateOwnershipOverride, error) {
	m := make(map[string]*governance.CertificateOwnershipOverride)
	cursor := ""
	limit := s.pageSize()
	for {
		page, err := s.repo.Ownership.ListActiveOwnershipOverridesPaged(ctx, organizationID, cursor, limit)
		if err != nil {
			return nil, fmt.Errorf("ownership: load active overrides: %w", err)
		}
		if len(page) == 0 {
			break
		}
		for i := range page {
			ov := page[i]
			m[ov.CertificateID] = &ov
		}
		cursor = page[len(page)-1].CertificateID
		if len(page) < limit {
			break
		}
	}
	return m, nil
}

// streamAndDecide merges the certificate-signal stream and the
// prior-ownership stream — both ordered by certificate_id ASC under
// the same REPEATABLE READ snapshot — and decides each cert. Memory
// is bounded to one page of each stream (no fleet in memory).
//
// Ordering invariant: the merge advances the ownership cursor using a
// Go string comparison (ownCur.CertificateID < sig.CertificateID),
// which must agree with the SQL ORDER BY certificate_id of both
// streams. It does, because every certificate_id is server-minted by
// ids.New() — a fixed-length lowercase-hex string ([0-9a-f]{32}) —
// for which byte order equals collation order under any PostgreSQL
// collation (C, en_US.UTF-8, …). Cert ids are never operator-supplied,
// so a punctuation/case/length collation surprise cannot occur. If
// that ever changes (non-hex cert ids), this merge must switch to a
// collation-independent pairing (see HARDENING_BACKLOG H-030).
func (s *Service) streamAndDecide(
	ctx context.Context,
	organizationID string,
	rules []compiledRule,
	overrides map[string]*governance.CertificateOwnershipOverride,
	now time.Time,
	out *recomputeOutcome,
) error {
	limit := s.pageSize()
	sigPager := &pager[governance.CertificateSignals]{
		fetch: func(ctx context.Context, cursor string, n int) ([]governance.CertificateSignals, error) {
			return s.repo.Ownership.ListCertificateSignalsPaged(ctx, organizationID, cursor, n)
		},
		key:   func(c governance.CertificateSignals) string { return c.CertificateID },
		limit: limit,
	}
	ownPager := &pager[governance.CertificateOwnership]{
		fetch: func(ctx context.Context, cursor string, n int) ([]governance.CertificateOwnership, error) {
			return s.repo.Ownership.ListCertificateOwnershipPaged(ctx, organizationID, cursor, n)
		},
		key:   func(o governance.CertificateOwnership) string { return o.CertificateID },
		limit: limit,
	}

	ownCur, ownHas, err := ownPager.next(ctx)
	if err != nil {
		return fmt.Errorf("ownership: read prior ownership: %w", err)
	}
	for {
		sig, ok, err := sigPager.next(ctx)
		if err != nil {
			return fmt.Errorf("ownership: read signals: %w", err)
		}
		if !ok {
			break
		}
		// Advance the ownership cursor past any cert id below the
		// current signal (defensive — every ownership row has a
		// matching cert, so this normally does not fire).
		for ownHas && ownCur.CertificateID < sig.CertificateID {
			out.firstRun = false
			if ownCur, ownHas, err = ownPager.next(ctx); err != nil {
				return fmt.Errorf("ownership: advance prior ownership: %w", err)
			}
		}
		var prior *governance.CertificateOwnership
		if ownHas && ownCur.CertificateID == sig.CertificateID {
			out.firstRun = false
			p := ownCur
			prior = &p
			if ownCur, ownHas, err = ownPager.next(ctx); err != nil {
				return fmt.Errorf("ownership: advance prior ownership: %w", err)
			}
		}
		if err := s.processCert(ctx, organizationID, sig, prior, overrides[sig.CertificateID], rules, now, out); err != nil {
			return err
		}
	}
	return nil
}

// processCert decides one cert, diffs against its prior ownership row,
// writes the explanation + ownership rows, and accumulates counters +
// audit intent. See the §5.1 state machine: a brand-new row always
// writes an explanation (even unowned, for explainability) but a
// first-materialization unowned is not an audited transition; a prior
// row with the same (decision, service) only bumps last_evaluated_at.
func (s *Service) processCert(
	ctx context.Context,
	organizationID string,
	sig governance.CertificateSignals,
	prior *governance.CertificateOwnership,
	override *governance.CertificateOwnershipOverride,
	rules []compiledRule,
	now time.Time,
	out *recomputeOutcome,
) error {
	out.evaluated++

	// Auto-expire: an active override past its expiry is cleared now
	// (cleared_by="system", reason="auto-expired"), which frees the
	// cleared_at IS NULL slot so a replacement override can be created
	// for this cert, and is recorded for an ownership.override_expired
	// audit row. The decision then re-derives as if no override exists
	// (the consequent flip/clear is audited by the normal diff below).
	if override != nil && override.ExpiresAt != nil && !override.ExpiresAt.After(now) {
		if err := s.repo.Ownership.ClearOwnershipOverride(ctx, organizationID, override.ID, "system", "auto-expired", now); err != nil {
			return fmt.Errorf("ownership: clear expired override: %w", err)
		}
		out.expiredOverrides = append(out.expiredOverrides, expiredOverrideInfo{
			certID: sig.CertificateID, overrideID: override.ID, serviceID: override.ServiceID,
		})
		override = nil
	}

	d := decideOwnership(sig, override, rules, now)
	nowOwned := d.serviceID != nil

	if prior == nil {
		expID := ids.New()
		if err := s.writeExplanation(ctx, organizationID, sig, d, expID, now); err != nil {
			return err
		}
		if err := s.repo.Ownership.UpsertCertificateOwnership(ctx, buildOwnership(organizationID, sig.CertificateID, d, expID, now, now, now)); err != nil {
			return fmt.Errorf("ownership: upsert (new): %w", err)
		}
		if d.decision == governance.DecisionUnowned {
			// First-materialization unowned: written for explainability,
			// counted unchanged, NOT audited (governance plan §5.1).
			out.unchanged++
			out.createdUnowned++
			return nil
		}
		out.changed++
		out.becameOwned++
		s.accumAudit(out, sig.CertificateID, governance.DecisionUnowned, d, false, false)
		return nil
	}

	priorOwned := prior.ServiceID != nil
	sameService := samePtr(prior.ServiceID, d.serviceID)
	ownerChanged := prior.Decision != d.decision || !sameService

	if !ownerChanged {
		// Same decision AND same service. Distinguish a true no-op from
		// an owner-stable RECLASSIFICATION: the owner is unchanged but
		// the decision BASIS moved — a different winning rule, override,
		// or confidence (e.g. a fallback owner later also matched by a
		// higher-precedence SAN rule pointing at the same service).
		// Without this, winning_rule_id / confidence / explanation_id /
		// signals_seen would go stale while the owner stayed put.
		basisChanged := !samePtr(prior.WinningRuleID, d.winningRuleID) ||
			!samePtr(prior.OverrideID, d.overrideID) ||
			prior.Confidence != d.confidence
		if !basisChanged {
			// True unchanged: bump last_evaluated_at only, keep the
			// existing explanation (caps explanation cardinality, §5.2).
			co := *prior
			co.LastEvaluatedAt = now
			if err := s.repo.Ownership.UpsertCertificateOwnership(ctx, &co); err != nil {
				return fmt.Errorf("ownership: upsert (unchanged): %w", err)
			}
			out.unchanged++
			return nil
		}
		// Reclassification: write a fresh explanation and refresh the
		// ownership metadata (winning_rule_id, override_id, confidence,
		// explanation_id), but PRESERVE last_changed_at — the owner did
		// not change — and emit NO transition audit (no assigned /
		// flipped spam for a same-owner basis refresh).
		expID := ids.New()
		if err := s.writeExplanation(ctx, organizationID, sig, d, expID, now); err != nil {
			return err
		}
		if err := s.repo.Ownership.UpsertCertificateOwnership(ctx, buildOwnership(organizationID, sig.CertificateID, d, expID, prior.FirstAssignedAt, now, prior.LastChangedAt)); err != nil {
			return fmt.Errorf("ownership: upsert (reclassified): %w", err)
		}
		out.changed++
		out.reclassified++
		return nil
	}

	// Owner transition: new explanation, last_changed_at=now, audit.
	// first_assigned_at is reset to now on the FIRST real assignment so
	// a cert that was materialized unowned does not carry the
	// unowned-creation timestamp forward as its first-owned time;
	// already-owned flips preserve the original assignment time.
	firstAssigned := prior.FirstAssignedAt
	if !priorOwned && nowOwned {
		firstAssigned = now
	}
	expID := ids.New()
	if err := s.writeExplanation(ctx, organizationID, sig, d, expID, now); err != nil {
		return err
	}
	if err := s.repo.Ownership.UpsertCertificateOwnership(ctx, buildOwnership(organizationID, sig.CertificateID, d, expID, firstAssigned, now, now)); err != nil {
		return fmt.Errorf("ownership: upsert (changed): %w", err)
	}
	out.changed++
	svcChanged := priorOwned && nowOwned && !sameService
	switch {
	case !priorOwned && nowOwned:
		out.becameOwned++
	case priorOwned && !nowOwned:
		out.becameUnowned++
	case svcChanged:
		out.flippedOwner++
	}
	s.accumAudit(out, sig.CertificateID, prior.Decision, d, svcChanged, prior.Decision == governance.DecisionAmbiguous)
	return nil
}

// accumAudit classifies the transition into an audit action and adds
// it to the rollup-aware accumulator. The owner-same-but-decision-
// class-changed case (e.g. matched→overridden on the same service,
// whose override creation B3 already audits) emits no row here to
// avoid double-auditing.
func (s *Service) accumAudit(out *recomputeOutcome, certID string, from governance.Decision, d ownershipDecision, svcChanged, priorAmbiguous bool) {
	fromOwned := from != governance.DecisionUnowned
	nowOwned := d.serviceID != nil
	to := d.decision

	var action string
	switch {
	case !fromOwned && nowOwned:
		if to == governance.DecisionAmbiguous {
			action = "ownership.ambiguous_match"
		} else {
			action = "ownership.assigned"
		}
	case fromOwned && !nowOwned:
		action = "ownership.cleared"
	case fromOwned && nowOwned && svcChanged:
		if to == governance.DecisionAmbiguous {
			action = "ownership.ambiguous_match"
		} else {
			action = "ownership.flipped"
		}
	case fromOwned && nowOwned && !svcChanged:
		if to == governance.DecisionAmbiguous && !priorAmbiguous {
			action = "ownership.ambiguous_match"
		} else {
			return // reclassification, same owner: no audit row
		}
	default:
		return
	}

	driver := ""
	if d.winningRuleID != nil {
		driver = *d.winningRuleID
	}
	out.addAudit(action, from, to, driver, certID, s.bulkAuditThreshold)
}

func (s *Service) writeExplanation(ctx context.Context, organizationID string, sig governance.CertificateSignals, d ownershipDecision, expID string, now time.Time) error {
	exp := &governance.OwnershipMatchExplanation{
		ID:               expID,
		OrganizationID:   organizationID,
		CertificateID:    sig.CertificateID,
		DecidedAt:        now,
		DecidedDecision:  d.decision,
		DecidedServiceID: d.serviceID,
		WinningRuleID:    d.winningRuleID,
		LosingRules:      buildLosingRulesJSON(d.losing),
		SignalsSeen:      buildSignalsSeenJSON(sig),
		EngineVersion:    engineVersion,
	}
	if err := s.repo.Ownership.CreateOwnershipExplanation(ctx, exp); err != nil {
		return fmt.Errorf("ownership: write explanation: %w", err)
	}
	return nil
}

func buildOwnership(organizationID, certID string, d ownershipDecision, explanationID string, firstAssigned, lastEvaluated, lastChanged time.Time) *governance.CertificateOwnership {
	return &governance.CertificateOwnership{
		OrganizationID:  organizationID,
		CertificateID:   certID,
		ServiceID:       d.serviceID,
		Decision:        d.decision,
		WinningRuleID:   d.winningRuleID,
		OverrideID:      d.overrideID,
		ExplanationID:   explanationID,
		Confidence:      d.confidence,
		FirstAssignedAt: firstAssigned,
		LastEvaluatedAt: lastEvaluated,
		LastChangedAt:   lastChanged,
	}
}

func samePtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// --- audit-group emission ----------------------------------------

type perCertAuditMetadata struct {
	Severity       string `json:"severity"`
	OrganizationID string `json:"organization_id"`
	RunID          string `json:"run_id"`
	FromDecision   string `json:"from_decision"`
	ToDecision     string `json:"to_decision"`
	DriverRuleID   string `json:"driver_rule_id,omitempty"`
}

type bulkAuditMetadata struct {
	Severity       string   `json:"severity"`
	OrganizationID string   `json:"organization_id"`
	RunID          string   `json:"run_id"`
	Count          int      `json:"count"`
	FromDecision   string   `json:"from_decision"`
	ToDecision     string   `json:"to_decision"`
	DriverRuleID   string   `json:"driver_rule_id,omitempty"`
	SampleCertIDs  []string `json:"sample_cert_ids"`
}

// emitAuditGroups writes the accumulated transition audit rows in a
// deterministic order: groups are sorted by key, and a group over the
// bulk threshold emits one rollup row while a group at or below it
// emits per-cert rows. This is what keeps a 50k-cert bulk flip from
// amplifying the audit table by 50k rows (governance plan §4.6).
func (s *Service) emitAuditGroups(ctx context.Context, organizationID, actor string, actorKind governance.RecomputeActorKind, runID string, now time.Time, out *recomputeOutcome) error {
	keys := make([]auditGroupKey, 0, len(out.auditGroups))
	for k := range out.auditGroups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.action != b.action {
			return a.action < b.action
		}
		if a.from != b.from {
			return a.from < b.from
		}
		if a.to != b.to {
			return a.to < b.to
		}
		return a.driver < b.driver
	})

	at := string(actorKind)
	for _, k := range keys {
		g := out.auditGroups[k]
		if g.rolledUp {
			md, _ := json.Marshal(bulkAuditMetadata{
				Severity: "security", OrganizationID: organizationID, RunID: runID,
				Count: g.count, FromDecision: string(k.from), ToDecision: string(k.to),
				DriverRuleID: k.driver, SampleCertIDs: g.samples,
			})
			if err := s.audit.Record(ctx, audit.Event{
				OrganizationID: organizationID, OccurredAt: now, Actor: actor, ActorType: at,
				Action: bulkActionFor(k.action), TargetType: "organization", TargetID: organizationID, Metadata: md,
			}); err != nil {
				return fmt.Errorf("ownership: emit bulk audit: %w", err)
			}
			continue
		}
		for _, certID := range g.certIDs {
			md, _ := json.Marshal(perCertAuditMetadata{
				Severity: "security", OrganizationID: organizationID, RunID: runID,
				FromDecision: string(k.from), ToDecision: string(k.to), DriverRuleID: k.driver,
			})
			if err := s.audit.Record(ctx, audit.Event{
				OrganizationID: organizationID, OccurredAt: now, Actor: actor, ActorType: at,
				Action: k.action, TargetType: "certificate", TargetID: certID, Metadata: md,
			}); err != nil {
				return fmt.Errorf("ownership: emit per-cert audit: %w", err)
			}
		}
	}
	return nil
}

func bulkActionFor(action string) string {
	switch action {
	case "ownership.assigned":
		return "ownership.bulk_assigned"
	case "ownership.cleared":
		return "ownership.bulk_cleared"
	case "ownership.flipped":
		return "ownership.bulk_flipped"
	case "ownership.ambiguous_match":
		return "ownership.bulk_ambiguous_match"
	default:
		return "ownership.bulk_changed"
	}
}

// pager is a generic forward cursor over a paginated repository read,
// keyed by a monotonic string (certificate id). It buffers one page
// at a time so the streaming pass never holds the whole fleet.
type pager[T any] struct {
	fetch  func(ctx context.Context, cursor string, limit int) ([]T, error)
	key    func(T) string
	limit  int
	buf    []T
	idx    int
	cursor string
	done   bool
}

func (p *pager[T]) next(ctx context.Context) (T, bool, error) {
	var zero T
	for p.idx >= len(p.buf) {
		if p.done {
			return zero, false, nil
		}
		page, err := p.fetch(ctx, p.cursor, p.limit)
		if err != nil {
			return zero, false, err
		}
		if len(page) == 0 {
			p.done = true
			return zero, false, nil
		}
		p.buf = page
		p.idx = 0
		p.cursor = p.key(page[len(page)-1])
		if len(page) < p.limit {
			p.done = true
		}
	}
	item := p.buf[p.idx]
	p.idx++
	return item, true, nil
}

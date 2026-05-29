package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// OwnershipRepository implements governance.OwnershipRepository
// against PostgreSQL. Schema lives in migration 0010
// (backend/migrations/0010_governance_ownership.sql).
type OwnershipRepository struct {
	db *DB
}

// NewOwnershipRepository wires the repo. CLAUDE.md §8.8.
func NewOwnershipRepository(db *DB) *OwnershipRepository {
	return &OwnershipRepository{db: db}
}

// ----- ownership rules -----

func (r *OwnershipRepository) CreateOwnershipRule(ctx context.Context, rule *governance.OwnershipRule) error {
	if rule == nil {
		return errors.New("postgres: nil ownership rule")
	}
	const q = `
		INSERT INTO ownership_rules (
			id, organization_id, name, description, service_id,
			precedence_tier, priority, match_kind, match_value,
			enabled, created_at, updated_at, created_by, disabled_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13, $14
		)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		rule.ID, rule.OrganizationID, rule.Name, rule.Description, rule.ServiceID,
		string(rule.PrecedenceTier), rule.Priority, string(rule.MatchKind), rule.MatchValue,
		rule.Enabled, rule.CreatedAt, rule.UpdatedAt, rule.CreatedBy, rule.DisabledAt,
	); err != nil {
		// The (organization_id, name) UNIQUE constraint surfaces as a
		// typed conflict so the H-026B3B service maps it to a
		// deterministic 409 rather than a generic 500.
		if isUniqueViolation(err) {
			return governance.ErrOwnershipRuleAlreadyExists
		}
		return fmt.Errorf("postgres: create ownership rule: %w", err)
	}
	return nil
}

func (r *OwnershipRepository) GetOwnershipRule(
	ctx context.Context,
	organizationID, ruleID string,
) (*governance.OwnershipRule, error) {
	const q = `
		SELECT id, organization_id, name, description, service_id,
		       precedence_tier, priority, match_kind, match_value,
		       enabled, created_at, updated_at, created_by, disabled_at
		  FROM ownership_rules
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, ruleID)
	rule, err := scanOwnershipRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrOwnershipRuleNotFound
		}
		return nil, fmt.Errorf("postgres: get ownership rule: %w", err)
	}
	return rule, nil
}

func (r *OwnershipRepository) ListOwnershipRules(
	ctx context.Context,
	organizationID string,
	enabledOnly bool,
) ([]governance.OwnershipRule, error) {
	q := `
		SELECT id, organization_id, name, description, service_id,
		       precedence_tier, priority, match_kind, match_value,
		       enabled, created_at, updated_at, created_by, disabled_at
		  FROM ownership_rules
		 WHERE organization_id = $1`
	if enabledOnly {
		q += ` AND enabled = TRUE`
	}
	q += ` ORDER BY id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list ownership rules: %w", err)
	}
	defer rows.Close()
	return scanOwnershipRuleList(rows)
}

// ListOwnershipRulesPaged is the cursor-paged variant of
// ListOwnershipRules, used by the H-026B3A operator
// /ownership-rules view. Ordered by id ASC. The enabledFilter is
// tri-state: nil returns all rules, &true returns only enabled,
// &false returns only disabled.
func (r *OwnershipRepository) ListOwnershipRulesPaged(
	ctx context.Context,
	organizationID, cursorRuleID string,
	pageSize int,
	enabledFilter *bool,
) ([]governance.OwnershipRule, error) {
	q := `
		SELECT id, organization_id, name, description, service_id,
		       precedence_tier, priority, match_kind, match_value,
		       enabled, created_at, updated_at, created_by, disabled_at
		  FROM ownership_rules
		 WHERE organization_id = $1 AND id > $2`
	if enabledFilter != nil {
		if *enabledFilter {
			q += ` AND enabled = TRUE`
		} else {
			q += ` AND enabled = FALSE`
		}
	}
	q += ` ORDER BY id ASC LIMIT $3`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, cursorRuleID, pageSize)
	if err != nil {
		return nil, fmt.Errorf("postgres: list ownership rules paged: %w", err)
	}
	defer rows.Close()
	return scanOwnershipRuleList(rows)
}

func (r *OwnershipRepository) ListOwnershipRulesByService(
	ctx context.Context,
	organizationID, serviceID string,
) ([]governance.OwnershipRule, error) {
	const q = `
		SELECT id, organization_id, name, description, service_id,
		       precedence_tier, priority, match_kind, match_value,
		       enabled, created_at, updated_at, created_by, disabled_at
		  FROM ownership_rules
		 WHERE organization_id = $1 AND service_id = $2
		 ORDER BY id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list ownership rules by service: %w", err)
	}
	defer rows.Close()
	return scanOwnershipRuleList(rows)
}

// ListOwnershipRulesForEngine returns the org's enabled rules in the
// engine walk order. precedence_tier is CASE-mapped to the §4.2
// ladder ordinal so the ORDER BY is the ladder, not the lexical text
// order of the enum — a tier value rename therefore cannot silently
// reshuffle precedence. The ELSE 99 sinks any unknown tier below the
// known ladder rather than failing the read (fail-closed: an
// unrecognized tier loses to every recognized one, so even if the
// migration 0010 CHECK constraint ever drifted and let a bad tier in,
// that rule can never silently outrank a real one). Surfacing such a
// rule loudly is the H-026B engine's responsibility, not the read's.
// The `WHERE enabled = TRUE` clause is served by
// ownership_rules_org_enabled_walk_idx (migration 0010); the small
// rule set (≤ a few thousand) makes the CASE sort negligible.
func (r *OwnershipRepository) ListOwnershipRulesForEngine(
	ctx context.Context,
	organizationID string,
) ([]governance.OwnershipRule, error) {
	const q = `
		SELECT id, organization_id, name, description, service_id,
		       precedence_tier, priority, match_kind, match_value,
		       enabled, created_at, updated_at, created_by, disabled_at
		  FROM ownership_rules
		 WHERE organization_id = $1 AND enabled = TRUE
		 ORDER BY
		   CASE precedence_tier
		     WHEN 'explicit'        THEN 1
		     WHEN 'service_member'  THEN 2
		     WHEN 'agent_group'     THEN 3
		     WHEN 'san_pattern'     THEN 4
		     WHEN 'subject_pattern' THEN 5
		     WHEN 'tag'             THEN 6
		     WHEN 'issuer_store'    THEN 7
		     WHEN 'fallback'        THEN 8
		     ELSE 99
		   END ASC,
		   priority ASC, created_at ASC, id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list ownership rules for engine: %w", err)
	}
	defer rows.Close()
	return scanOwnershipRuleList(rows)
}

func (r *OwnershipRepository) UpdateOwnershipRuleMutable(
	ctx context.Context,
	organizationID, ruleID string,
	priority int,
	matchValue, description string,
) error {
	const q = `
		UPDATE ownership_rules
		   SET priority    = $3,
		       match_value = $4,
		       description = $5,
		       updated_at  = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, ruleID, priority, matchValue, description)
	if err != nil {
		return fmt.Errorf("postgres: update ownership rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return governance.ErrOwnershipRuleNotFound
	}
	return nil
}

func (r *OwnershipRepository) DisableOwnershipRule(ctx context.Context, organizationID, ruleID string) error {
	const q = `
		UPDATE ownership_rules
		   SET enabled     = FALSE,
		       disabled_at = COALESCE(disabled_at, now()),
		       updated_at  = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, ruleID)
	if err != nil {
		return fmt.Errorf("postgres: disable ownership rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return governance.ErrOwnershipRuleNotFound
	}
	return nil
}

func (r *OwnershipRepository) EnableOwnershipRule(ctx context.Context, organizationID, ruleID string) error {
	const q = `
		UPDATE ownership_rules
		   SET enabled     = TRUE,
		       disabled_at = NULL,
		       updated_at  = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, ruleID)
	if err != nil {
		return fmt.Errorf("postgres: enable ownership rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return governance.ErrOwnershipRuleNotFound
	}
	return nil
}

// ----- certificate ownership -----

func (r *OwnershipRepository) UpsertCertificateOwnership(
	ctx context.Context,
	o *governance.CertificateOwnership,
) error {
	if o == nil {
		return errors.New("postgres: nil certificate ownership")
	}
	const q = `
		INSERT INTO certificate_ownership (
			organization_id, certificate_id, service_id, decision,
			winning_rule_id, override_id, explanation_id, confidence,
			first_assigned_at, last_evaluated_at, last_changed_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11
		)
		ON CONFLICT (organization_id, certificate_id) DO UPDATE
		   SET service_id         = EXCLUDED.service_id,
		       decision           = EXCLUDED.decision,
		       winning_rule_id    = EXCLUDED.winning_rule_id,
		       override_id        = EXCLUDED.override_id,
		       explanation_id     = EXCLUDED.explanation_id,
		       confidence         = EXCLUDED.confidence,
		       first_assigned_at  = EXCLUDED.first_assigned_at,
		       last_evaluated_at  = EXCLUDED.last_evaluated_at,
		       last_changed_at    = EXCLUDED.last_changed_at`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		o.OrganizationID, o.CertificateID, o.ServiceID, string(o.Decision),
		o.WinningRuleID, o.OverrideID, o.ExplanationID, string(o.Confidence),
		o.FirstAssignedAt, o.LastEvaluatedAt, o.LastChangedAt,
	); err != nil {
		return fmt.Errorf("postgres: upsert certificate ownership: %w", err)
	}
	return nil
}

func (r *OwnershipRepository) GetCertificateOwnership(
	ctx context.Context,
	organizationID, certificateID string,
) (*governance.CertificateOwnership, error) {
	const q = `
		SELECT organization_id, certificate_id, service_id, decision,
		       winning_rule_id, override_id, explanation_id, confidence,
		       first_assigned_at, last_evaluated_at, last_changed_at
		  FROM certificate_ownership
		 WHERE organization_id = $1 AND certificate_id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, certificateID)
	o, err := scanCertificateOwnership(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrCertificateOwnershipNotFound
		}
		return nil, fmt.Errorf("postgres: get certificate ownership: %w", err)
	}
	return o, nil
}

func (r *OwnershipRepository) ListCertificateOwnershipByService(
	ctx context.Context,
	organizationID, serviceID string,
) ([]governance.CertificateOwnership, error) {
	const q = `
		SELECT organization_id, certificate_id, service_id, decision,
		       winning_rule_id, override_id, explanation_id, confidence,
		       first_assigned_at, last_evaluated_at, last_changed_at
		  FROM certificate_ownership
		 WHERE organization_id = $1 AND service_id = $2
		 ORDER BY certificate_id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list cert ownership by service: %w", err)
	}
	defer rows.Close()
	return scanCertificateOwnershipList(rows)
}

func (r *OwnershipRepository) ListCertificateOwnershipByDecision(
	ctx context.Context,
	organizationID string,
	decision governance.Decision,
) ([]governance.CertificateOwnership, error) {
	const q = `
		SELECT organization_id, certificate_id, service_id, decision,
		       winning_rule_id, override_id, explanation_id, confidence,
		       first_assigned_at, last_evaluated_at, last_changed_at
		  FROM certificate_ownership
		 WHERE organization_id = $1 AND decision = $2
		 ORDER BY certificate_id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, string(decision))
	if err != nil {
		return nil, fmt.Errorf("postgres: list cert ownership by decision: %w", err)
	}
	defer rows.Close()
	return scanCertificateOwnershipList(rows)
}

// ListCertificateOwnershipByDecisionPaged is the cursor-paged variant
// of ListCertificateOwnershipByDecision. Drives the
// /ownership/{unowned,ambiguous} operator views in H-026B3A.
func (r *OwnershipRepository) ListCertificateOwnershipByDecisionPaged(
	ctx context.Context,
	organizationID string,
	decision governance.Decision,
	cursorCertID string,
	pageSize int,
) ([]governance.CertificateOwnership, error) {
	const q = `
		SELECT organization_id, certificate_id, service_id, decision,
		       winning_rule_id, override_id, explanation_id, confidence,
		       first_assigned_at, last_evaluated_at, last_changed_at
		  FROM certificate_ownership
		 WHERE organization_id = $1 AND decision = $2 AND certificate_id > $3
		 ORDER BY certificate_id ASC
		 LIMIT $4`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, string(decision), cursorCertID, pageSize)
	if err != nil {
		return nil, fmt.Errorf("postgres: list cert ownership by decision paged: %w", err)
	}
	defer rows.Close()
	return scanCertificateOwnershipList(rows)
}

// ListCertificateOwnershipPaged returns one page of ownership rows
// keyed by certificate_id > cursor, ordered ASC, capped at pageSize.
// Backed by the certificate_ownership PK (organization_id,
// certificate_id), so the cursor range scan is index-only.
func (r *OwnershipRepository) ListCertificateOwnershipPaged(
	ctx context.Context,
	organizationID, cursorCertID string,
	pageSize int,
) ([]governance.CertificateOwnership, error) {
	const q = `
		SELECT organization_id, certificate_id, service_id, decision,
		       winning_rule_id, override_id, explanation_id, confidence,
		       first_assigned_at, last_evaluated_at, last_changed_at
		  FROM certificate_ownership
		 WHERE organization_id = $1 AND certificate_id > $2
		 ORDER BY certificate_id ASC
		 LIMIT $3`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, cursorCertID, pageSize)
	if err != nil {
		return nil, fmt.Errorf("postgres: list cert ownership paged: %w", err)
	}
	defer rows.Close()
	return scanCertificateOwnershipList(rows)
}

// ListCertificateOwnershipStale returns one page of ownership rows
// last evaluated before olderThan, keyed by certificate_id > cursor,
// ordered ASC, capped at limit.
func (r *OwnershipRepository) ListCertificateOwnershipStale(
	ctx context.Context,
	organizationID string,
	olderThan time.Time,
	cursorCertID string,
	limit int,
) ([]governance.CertificateOwnership, error) {
	const q = `
		SELECT organization_id, certificate_id, service_id, decision,
		       winning_rule_id, override_id, explanation_id, confidence,
		       first_assigned_at, last_evaluated_at, last_changed_at
		  FROM certificate_ownership
		 WHERE organization_id = $1
		   AND last_evaluated_at < $2
		   AND certificate_id > $3
		 ORDER BY certificate_id ASC
		 LIMIT $4`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, olderThan, cursorCertID, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list cert ownership stale: %w", err)
	}
	defer rows.Close()
	return scanCertificateOwnershipList(rows)
}

// ----- overrides -----

func (r *OwnershipRepository) CreateOwnershipOverride(
	ctx context.Context,
	o *governance.CertificateOwnershipOverride,
) error {
	if o == nil {
		return errors.New("postgres: nil ownership override")
	}
	const q = `
		INSERT INTO certificate_ownership_overrides (
			id, organization_id, certificate_id, service_id,
			reason, set_by, set_at, expires_at,
			cleared_at, cleared_by, cleared_reason
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11
		)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		o.ID, o.OrganizationID, o.CertificateID, o.ServiceID,
		o.Reason, o.SetBy, o.SetAt, o.ExpiresAt,
		o.ClearedAt, o.ClearedBy, o.ClearedReason,
	); err != nil {
		// The active partial-unique index (one active override per
		// cert) surfaces as a typed conflict so the H-026B3B service
		// maps it to a deterministic 409 rather than a generic 500.
		if isUniqueViolation(err) {
			return governance.ErrOwnershipOverrideAlreadyExists
		}
		return fmt.Errorf("postgres: create ownership override: %w", err)
	}
	return nil
}

func (r *OwnershipRepository) GetOwnershipOverride(
	ctx context.Context,
	organizationID, overrideID string,
) (*governance.CertificateOwnershipOverride, error) {
	const q = `
		SELECT id, organization_id, certificate_id, service_id,
		       reason, set_by, set_at, expires_at,
		       cleared_at, cleared_by, cleared_reason
		  FROM certificate_ownership_overrides
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, overrideID)
	o, err := scanOwnershipOverride(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrOwnershipOverrideNotFound
		}
		return nil, fmt.Errorf("postgres: get ownership override: %w", err)
	}
	return o, nil
}

func (r *OwnershipRepository) GetActiveOwnershipOverride(
	ctx context.Context,
	organizationID, certificateID string,
) (*governance.CertificateOwnershipOverride, error) {
	const q = `
		SELECT id, organization_id, certificate_id, service_id,
		       reason, set_by, set_at, expires_at,
		       cleared_at, cleared_by, cleared_reason
		  FROM certificate_ownership_overrides
		 WHERE organization_id = $1
		   AND certificate_id = $2
		   AND cleared_at IS NULL`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, certificateID)
	o, err := scanOwnershipOverride(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// "No active override" is not an error condition; the
			// caller distinguishes the nil return from a true error.
			return nil, nil
		}
		return nil, fmt.Errorf("postgres: get active ownership override: %w", err)
	}
	return o, nil
}

func (r *OwnershipRepository) ClearOwnershipOverride(
	ctx context.Context,
	organizationID, overrideID, clearedBy, clearedReason string,
	clearedAt time.Time,
) error {
	const q = `
		UPDATE certificate_ownership_overrides
		   SET cleared_at = $3, cleared_by = $4, cleared_reason = $5
		 WHERE organization_id = $1 AND id = $2 AND cleared_at IS NULL`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q,
		organizationID, overrideID, clearedAt, clearedBy, clearedReason,
	)
	if err != nil {
		return fmt.Errorf("postgres: clear ownership override: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return governance.ErrOwnershipOverrideNotFound
	}
	return nil
}

// ListActiveOwnershipOverridesPaged returns one page of active
// overrides keyed by certificate_id > cursor, ordered ASC, capped at
// pageSize. `cleared_at IS NULL` selects the active set; the active
// partial-unique index guarantees one active row per cert, so
// certificate_id is a unique, gap-free cursor.
func (r *OwnershipRepository) ListActiveOwnershipOverridesPaged(
	ctx context.Context,
	organizationID, cursorCertID string,
	pageSize int,
) ([]governance.CertificateOwnershipOverride, error) {
	const q = `
		SELECT id, organization_id, certificate_id, service_id,
		       reason, set_by, set_at, expires_at,
		       cleared_at, cleared_by, cleared_reason
		  FROM certificate_ownership_overrides
		 WHERE organization_id = $1
		   AND cleared_at IS NULL
		   AND certificate_id > $2
		 ORDER BY certificate_id ASC
		 LIMIT $3`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, cursorCertID, pageSize)
	if err != nil {
		return nil, fmt.Errorf("postgres: list active ownership overrides paged: %w", err)
	}
	defer rows.Close()
	return scanOwnershipOverrideList(rows)
}

// ListOverridesExpiringBy returns active overrides whose expiry has
// passed (expires_at non-NULL and <= now), ordered by certificate_id
// ASC. Unpaged: overrides are low-cardinality operator pins and the
// B2 recompute auto-clears them each pass, so the expired set stays
// bounded. Pagination is a documented backlog item (HARDENING_BACKLOG
// H-029) for the pathological bulk-import + long-outage case.
func (r *OwnershipRepository) ListOverridesExpiringBy(
	ctx context.Context,
	organizationID string,
	now time.Time,
) ([]governance.CertificateOwnershipOverride, error) {
	const q = `
		SELECT id, organization_id, certificate_id, service_id,
		       reason, set_by, set_at, expires_at,
		       cleared_at, cleared_by, cleared_reason
		  FROM certificate_ownership_overrides
		 WHERE organization_id = $1
		   AND cleared_at IS NULL
		   AND expires_at IS NOT NULL
		   AND expires_at <= $2
		 ORDER BY certificate_id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, now)
	if err != nil {
		return nil, fmt.Errorf("postgres: list overrides expiring by: %w", err)
	}
	defer rows.Close()
	return scanOwnershipOverrideList(rows)
}

// ----- explanations -----

func (r *OwnershipRepository) CreateOwnershipExplanation(
	ctx context.Context,
	e *governance.OwnershipMatchExplanation,
) error {
	if e == nil {
		return errors.New("postgres: nil ownership explanation")
	}
	const q = `
		INSERT INTO ownership_match_explanations (
			id, organization_id, certificate_id, decided_at, decided_decision,
			decided_service_id, winning_rule_id, losing_rules, signals_seen,
			engine_version
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10
		)`
	losing := jsonValueOr([]byte(e.LosingRules), "[]")
	signals := jsonValueOr([]byte(e.SignalsSeen), "{}")
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		e.ID, e.OrganizationID, e.CertificateID, e.DecidedAt, string(e.DecidedDecision),
		e.DecidedServiceID, e.WinningRuleID, losing, signals,
		e.EngineVersion,
	); err != nil {
		return fmt.Errorf("postgres: create ownership explanation: %w", err)
	}
	return nil
}

func (r *OwnershipRepository) GetOwnershipExplanation(
	ctx context.Context,
	organizationID, explanationID string,
) (*governance.OwnershipMatchExplanation, error) {
	const q = `
		SELECT id, organization_id, certificate_id, decided_at, decided_decision,
		       decided_service_id, winning_rule_id, losing_rules, signals_seen,
		       engine_version
		  FROM ownership_match_explanations
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, explanationID)
	e, err := scanOwnershipExplanation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrOwnershipExplanationNotFound
		}
		return nil, fmt.Errorf("postgres: get ownership explanation: %w", err)
	}
	return e, nil
}

func (r *OwnershipRepository) ListOwnershipExplanationsForCertificate(
	ctx context.Context,
	organizationID, certificateID string,
	limit int,
) ([]governance.OwnershipMatchExplanation, error) {
	q := `
		SELECT id, organization_id, certificate_id, decided_at, decided_decision,
		       decided_service_id, winning_rule_id, losing_rules, signals_seen,
		       engine_version
		  FROM ownership_match_explanations
		 WHERE organization_id = $1 AND certificate_id = $2
		 ORDER BY decided_at DESC, id ASC`
	var rows pgx.Rows
	var err error
	if limit > 0 {
		q += ` LIMIT $3`
		rows, err = r.db.querierFor(ctx).Query(ctx, q, organizationID, certificateID, limit)
	} else {
		rows, err = r.db.querierFor(ctx).Query(ctx, q, organizationID, certificateID)
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: list ownership explanations: %w", err)
	}
	defer rows.Close()
	var out []governance.OwnershipMatchExplanation
	for rows.Next() {
		e, err := scanOwnershipExplanation(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan ownership explanation: %w", err)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate ownership explanations: %w", err)
	}
	return out, nil
}

// ListOwnershipExplanationsForCertificatePaged is the cursor-paged
// variant. The empty-cursor sentinel (zero time + empty id) yields
// the unfiltered first page; subsequent calls pass the previous
// page's last (decided_at, id) to walk back through history. The
// `($3::timestamptz IS NULL OR ...)` guard handles the first-page
// case without a second query shape.
func (r *OwnershipRepository) ListOwnershipExplanationsForCertificatePaged(
	ctx context.Context,
	organizationID, certificateID string,
	cursorDecidedAt time.Time,
	cursorExplanationID string,
	limit int,
) ([]governance.OwnershipMatchExplanation, error) {
	var cursorAt *time.Time
	var cursorID *string
	if cursorExplanationID != "" {
		cursorAt = &cursorDecidedAt
		cursorID = &cursorExplanationID
	}
	const q = `
		SELECT id, organization_id, certificate_id, decided_at, decided_decision,
		       decided_service_id, winning_rule_id, losing_rules, signals_seen,
		       engine_version
		  FROM ownership_match_explanations
		 WHERE organization_id = $1
		   AND certificate_id  = $2
		   AND ($3::timestamptz IS NULL
		        OR decided_at < $3
		        OR (decided_at = $3 AND id > $4))
		 ORDER BY decided_at DESC, id ASC
		 LIMIT $5`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, certificateID, cursorAt, cursorID, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list ownership explanations paged: %w", err)
	}
	defer rows.Close()
	var out []governance.OwnershipMatchExplanation
	for rows.Next() {
		e, err := scanOwnershipExplanation(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan ownership explanation: %w", err)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate ownership explanations paged: %w", err)
	}
	return out, nil
}

// ListCertificateIDsWithExplanationsPagedQuery is the SQL behind
// ListCertificateIDsWithExplanationsPaged. Exported so the H-027 prune
// integration EXPLAIN test can assert the no-fleet-scan shape: a bounded
// index range over ownership_match_explanations_cert_timeline_idx
// (organization_id, certificate_id, decided_at DESC) deduplicated by
// certificate_id, with a Limit — never a Seq Scan over the whole table.
//
// $1 = organization_id, $2 = cursor certificate id (exclusive),
// $3 = page size.
const ListCertificateIDsWithExplanationsPagedQuery = `
		SELECT DISTINCT certificate_id
		  FROM ownership_match_explanations
		 WHERE organization_id = $1 AND certificate_id > $2
		 ORDER BY certificate_id ASC
		 LIMIT $3`

func (r *OwnershipRepository) ListCertificateIDsWithExplanationsPaged(
	ctx context.Context,
	organizationID, cursorCertID string,
	pageSize int,
) ([]string, error) {
	rows, err := r.db.querierFor(ctx).Query(ctx, ListCertificateIDsWithExplanationsPagedQuery, organizationID, cursorCertID, pageSize)
	if err != nil {
		return nil, fmt.Errorf("postgres: list certs with explanations paged: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var certID string
		if err := rows.Scan(&certID); err != nil {
			return nil, fmt.Errorf("postgres: scan cert id with explanations: %w", err)
		}
		out = append(out, certID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate certs with explanations: %w", err)
	}
	return out, nil
}

// DeleteOwnershipExplanationsForCertificate deletes the listed
// explanation ids for one cert, org- and cert-scoped, with a NOT EXISTS
// guard that makes deleting the FK-pinned current explanation
// impossible even if a caller passed it in error. An empty id slice
// short-circuits to a 0 no-op (a `= ANY('{}')` would also match nothing,
// but skipping the round-trip is cheaper and unambiguous).
func (r *OwnershipRepository) DeleteOwnershipExplanationsForCertificate(
	ctx context.Context,
	organizationID, certificateID string,
	explanationIDs []string,
) (int64, error) {
	if len(explanationIDs) == 0 {
		return 0, nil
	}
	const q = `
		DELETE FROM ownership_match_explanations e
		 WHERE e.organization_id = $1
		   AND e.certificate_id  = $2
		   AND e.id = ANY($3)
		   AND NOT EXISTS (
		       SELECT 1 FROM certificate_ownership co
		        WHERE co.organization_id = e.organization_id
		          AND co.certificate_id  = e.certificate_id
		          AND co.explanation_id  = e.id
		   )`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, certificateID, explanationIDs)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete ownership explanations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ----- engine signal reads -----

// CertificateSignalsPagedQuery is the SQL behind
// ListCertificateSignalsPaged. It is a package-level const (and
// exported) so the integration EXPLAIN test can assert the binding
// query shape from H026B plan §3.1: paged by the certificates table,
// with per-certificate LATERAL sub-aggregates, and NO fleet-wide
// GROUP BY (the plan must contain a Limit and must NOT contain a
// "Group Key"). Keeping the query in one named place means the test
// pins the exact production statement, not a paraphrase.
//
// $1 = organization_id, $2 = cursor certificate id (exclusive),
// $3 = page size.
const CertificateSignalsPagedQuery = `
		SELECT
		    c.id,
		    c.subject,
		    c.issuer,
		    c.sans,
		    COALESCE(sl.store_locations, ARRAY[]::text[])  AS store_locations,
		    COALESCE(ag.agent_ids,       ARRAY[]::text[])  AS agent_ids,
		    COALESCE(grp.agent_group_ids, ARRAY[]::text[]) AS agent_group_ids,
		    COALESCE(ct.cert_tags,  '[]'::jsonb)           AS cert_tags,
		    COALESCE(atg.agent_tags, '[]'::jsonb)          AS agent_tags
		FROM certificates c
		LEFT JOIN LATERAL (
		    SELECT array_agg(DISTINCT o.store_location ORDER BY o.store_location) AS store_locations
		      FROM certificate_observations o
		     WHERE o.organization_id = c.organization_id
		       AND o.certificate_id  = c.id
		       AND o.removed_at IS NULL
		) sl ON TRUE
		LEFT JOIN LATERAL (
		    SELECT array_agg(DISTINCT o.agent_id ORDER BY o.agent_id) AS agent_ids
		      FROM certificate_observations o
		     WHERE o.organization_id = c.organization_id
		       AND o.certificate_id  = c.id
		       AND o.removed_at IS NULL
		) ag ON TRUE
		LEFT JOIN LATERAL (
		    SELECT array_agg(DISTINCT m.agent_group_id ORDER BY m.agent_group_id) AS agent_group_ids
		      FROM certificate_observations o
		      JOIN agent_group_memberships m
		        ON m.organization_id = o.organization_id
		       AND m.agent_id        = o.agent_id
		      JOIN agent_groups g
		        ON g.organization_id = m.organization_id
		       AND g.id              = m.agent_group_id
		       AND g.disabled_at IS NULL
		     WHERE o.organization_id = c.organization_id
		       AND o.certificate_id  = c.id
		       AND o.removed_at IS NULL
		) grp ON TRUE
		LEFT JOIN LATERAL (
		    SELECT jsonb_agg(DISTINCT jsonb_build_object('key', t.key, 'value', t.value)) AS cert_tags
		      FROM tag_assignments ta
		      JOIN tags t
		        ON t.organization_id = ta.organization_id
		       AND t.id              = ta.tag_id
		       AND t.disabled_at IS NULL
		     WHERE ta.organization_id = c.organization_id
		       AND ta.target_type     = 'certificate'
		       AND ta.target_id       = c.id
		) ct ON TRUE
		LEFT JOIN LATERAL (
		    SELECT jsonb_agg(DISTINCT jsonb_build_object('key', t.key, 'value', t.value)) AS agent_tags
		      FROM certificate_observations o
		      JOIN tag_assignments ta
		        ON ta.organization_id = o.organization_id
		       AND ta.target_type     = 'agent'
		       AND ta.target_id       = o.agent_id
		      JOIN tags t
		        ON t.organization_id = ta.organization_id
		       AND t.id              = ta.tag_id
		       AND t.disabled_at IS NULL
		     WHERE o.organization_id = c.organization_id
		       AND o.certificate_id  = c.id
		       AND o.removed_at IS NULL
		) atg ON TRUE
		WHERE c.organization_id = $1
		  AND c.id > $2
		ORDER BY c.id ASC
		LIMIT $3`

// ListCertificateSignalsPaged assembles the per-certificate signal
// bundle the H-026B engine evaluates rules against, one page at a
// time.
//
// Query shape (binding, H026B plan §3.1): the FROM clause is the
// certificates table, paged by `id > cursor ORDER BY id ASC LIMIT n`
// — so the driver is an index range scan on the certificates PK and
// each page touches exactly that page's certs. The five signal sets
// are gathered by per-certificate LEFT JOIN LATERAL sub-aggregates,
// each correlated on the cert's (organization_id, id); the planner
// runs them as nested-loop lookups against
// certificate_observations_org_certificate_idx and the
// tag_assignments / agent_group_memberships indexes. There is NO
// fleet-wide GROUP BY across the cert × observation × membership ×
// tag cross product — that shape is explicitly forbidden because it
// would materialize the whole fleet and defeat paging.
//
// Active-observation scoping: every observation-derived LATERAL
// filters `o.removed_at IS NULL`, so store locations, observing
// agents, observing agent groups, and agent tags reflect only certs
// still present on a host. Intrinsic cert fields (subject, issuer,
// sans) are read straight off the certificates row regardless.
//
// Active-classification scoping: a soft-deleted classification is not
// a live signal. The cert-tag and agent-tag LATERALs filter
// `t.disabled_at IS NULL`, and the agent-group LATERAL joins
// agent_groups with `g.disabled_at IS NULL`, so disabled tags and
// disabled agent groups never reach the engine — consistent with the
// engine excluding disabled ownership rules. (tag_assignments and
// agent_group_memberships have no soft-delete of their own; the
// definition's disabled_at is the authority.)
//
// Determinism: the text-set aggregates use
// `array_agg(DISTINCT x ORDER BY x)` so store_locations / agent_ids /
// agent_group_ids come back sorted and de-duplicated; the tag
// aggregates de-duplicate via `jsonb_agg(DISTINCT …)` and the scan
// helper sorts them by (key, value). Multiple observations of the
// same cert therefore never produce duplicate signals.
func (r *OwnershipRepository) ListCertificateSignalsPaged(
	ctx context.Context,
	organizationID, cursorCertID string,
	pageSize int,
) ([]governance.CertificateSignals, error) {
	rows, err := r.db.querierFor(ctx).Query(ctx, CertificateSignalsPagedQuery, organizationID, cursorCertID, pageSize)
	if err != nil {
		return nil, fmt.Errorf("postgres: list certificate signals paged: %w", err)
	}
	defer rows.Close()
	var out []governance.CertificateSignals
	for rows.Next() {
		s, err := scanCertificateSignals(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan certificate signals: %w", err)
		}
		out = append(out, *s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate certificate signals: %w", err)
	}
	return out, nil
}

// certificateSignalsByIDQuery is the single-certificate variant of
// CertificateSignalsPagedQuery. It reuses the exact same SELECT +
// per-cert LATERAL body (the binding query shape) and only swaps the
// driving predicate from the `id > cursor … LIMIT n` page scan to a
// single `c.id = $2` PK lookup. Derived by string replacement so the
// two queries can never drift in their signal-assembly logic.
var certificateSignalsByIDQuery = strings.Replace(
	CertificateSignalsPagedQuery,
	`WHERE c.organization_id = $1
		  AND c.id > $2
		ORDER BY c.id ASC
		LIMIT $3`,
	`WHERE c.organization_id = $1
		  AND c.id = $2`,
	1,
)

// GetCertificateSignals returns the signal bundle for ONE certificate,
// or ErrCertificateNotFound-style nil when the cert does not exist in
// the org. Used by the H-026B3B single-cert override re-derivation —
// a bounded PK lookup, never a fleet scan. Returns (nil, nil) when no
// cert row matches (the override service treats that as "cert not
// found" and rejects the mutation).
func (r *OwnershipRepository) GetCertificateSignals(
	ctx context.Context,
	organizationID, certificateID string,
) (*governance.CertificateSignals, error) {
	row := r.db.querierFor(ctx).QueryRow(ctx, certificateSignalsByIDQuery, organizationID, certificateID)
	s, err := scanCertificateSignals(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres: get certificate signals: %w", err)
	}
	return s, nil
}

// ----- scan helpers -----

// jsonValueOr returns v if non-empty, otherwise the supplied
// literal (which the caller chooses to match the column's
// declared default — '[]' for arrays, '{}' for objects). Used
// by the explanation insert: losing_rules NOT NULL DEFAULT
// '[]'::jsonb cannot accept an empty input, and the
// findings_repository.jsonValue helper hard-codes '{}' which
// would be wrong for a JSONB array column.
func jsonValueOr(v []byte, fallback string) []byte {
	if len(v) == 0 {
		return []byte(fallback)
	}
	return v
}

func scanOwnershipRule(r rowScanner) (*governance.OwnershipRule, error) {
	var rule governance.OwnershipRule
	var tier, kind string
	if err := r.Scan(
		&rule.ID, &rule.OrganizationID, &rule.Name, &rule.Description, &rule.ServiceID,
		&tier, &rule.Priority, &kind, &rule.MatchValue,
		&rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt, &rule.CreatedBy, &rule.DisabledAt,
	); err != nil {
		return nil, err
	}
	rule.PrecedenceTier = governance.PrecedenceTier(tier)
	rule.MatchKind = governance.MatchKind(kind)
	return &rule, nil
}

func scanOwnershipRuleList(rows pgx.Rows) ([]governance.OwnershipRule, error) {
	var out []governance.OwnershipRule
	for rows.Next() {
		rule, err := scanOwnershipRule(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan ownership rule: %w", err)
		}
		out = append(out, *rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate ownership rules: %w", err)
	}
	return out, nil
}

func scanCertificateOwnership(r rowScanner) (*governance.CertificateOwnership, error) {
	var o governance.CertificateOwnership
	var decision, confidence string
	if err := r.Scan(
		&o.OrganizationID, &o.CertificateID, &o.ServiceID, &decision,
		&o.WinningRuleID, &o.OverrideID, &o.ExplanationID, &confidence,
		&o.FirstAssignedAt, &o.LastEvaluatedAt, &o.LastChangedAt,
	); err != nil {
		return nil, err
	}
	o.Decision = governance.Decision(decision)
	o.Confidence = governance.Confidence(confidence)
	return &o, nil
}

func scanCertificateOwnershipList(rows pgx.Rows) ([]governance.CertificateOwnership, error) {
	var out []governance.CertificateOwnership
	for rows.Next() {
		o, err := scanCertificateOwnership(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan certificate ownership: %w", err)
		}
		out = append(out, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate certificate ownership: %w", err)
	}
	return out, nil
}

func scanOwnershipOverride(r rowScanner) (*governance.CertificateOwnershipOverride, error) {
	var o governance.CertificateOwnershipOverride
	if err := r.Scan(
		&o.ID, &o.OrganizationID, &o.CertificateID, &o.ServiceID,
		&o.Reason, &o.SetBy, &o.SetAt, &o.ExpiresAt,
		&o.ClearedAt, &o.ClearedBy, &o.ClearedReason,
	); err != nil {
		return nil, err
	}
	return &o, nil
}

func scanOwnershipOverrideList(rows pgx.Rows) ([]governance.CertificateOwnershipOverride, error) {
	var out []governance.CertificateOwnershipOverride
	for rows.Next() {
		o, err := scanOwnershipOverride(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan ownership override: %w", err)
		}
		out = append(out, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate ownership overrides: %w", err)
	}
	return out, nil
}

// scanCertificateSignals reads one row of the signal-join query.
// SANs and the two tag sets arrive as JSON / JSONB and are
// unmarshalled here; the text-array sets arrive already DISTINCT and
// sorted from the SQL aggregates. Tag sets are sorted by (key, value)
// in Go so the bundle is deterministic regardless of jsonb_agg
// ordering.
func scanCertificateSignals(r rowScanner) (*governance.CertificateSignals, error) {
	var s governance.CertificateSignals
	var sansRaw, certTagsRaw, agentTagsRaw []byte
	if err := r.Scan(
		&s.CertificateID, &s.Subject, &s.Issuer, &sansRaw,
		&s.StoreLocations, &s.ObservingAgentIDs, &s.ObservingAgentGroupIDs,
		&certTagsRaw, &agentTagsRaw,
	); err != nil {
		return nil, err
	}
	if len(sansRaw) > 0 {
		if err := json.Unmarshal(sansRaw, &s.SANs); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal sans: %w", err)
		}
	}
	var err error
	if s.CertTags, err = unmarshalTagPairs(certTagsRaw); err != nil {
		return nil, fmt.Errorf("postgres: unmarshal cert tags: %w", err)
	}
	if s.AgentTags, err = unmarshalTagPairs(agentTagsRaw); err != nil {
		return nil, fmt.Errorf("postgres: unmarshal agent tags: %w", err)
	}
	return &s, nil
}

// unmarshalTagPairs decodes a jsonb array of {key,value} objects into
// a (key, value)-sorted slice. Empty / null input yields a nil slice.
func unmarshalTagPairs(raw []byte) ([]governance.TagPair, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var pairs []governance.TagPair
	if err := json.Unmarshal(raw, &pairs); err != nil {
		return nil, err
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Key != pairs[j].Key {
			return pairs[i].Key < pairs[j].Key
		}
		return pairs[i].Value < pairs[j].Value
	})
	return pairs, nil
}

func scanOwnershipExplanation(r rowScanner) (*governance.OwnershipMatchExplanation, error) {
	var e governance.OwnershipMatchExplanation
	var decision string
	if err := r.Scan(
		&e.ID, &e.OrganizationID, &e.CertificateID, &e.DecidedAt, &decision,
		&e.DecidedServiceID, &e.WinningRuleID, &e.LosingRules, &e.SignalsSeen,
		&e.EngineVersion,
	); err != nil {
		return nil, err
	}
	e.DecidedDecision = governance.Decision(decision)
	return &e, nil
}

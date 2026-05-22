package postgres

import (
	"context"
	"errors"
	"fmt"
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

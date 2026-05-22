package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// PolicyRepository implements governance.PolicyRepository
// against PostgreSQL. Schema lives in migration 0011
// (backend/migrations/0011_governance_policy.sql).
type PolicyRepository struct {
	db *DB
}

// NewPolicyRepository wires the repo. CLAUDE.md §8.8.
func NewPolicyRepository(db *DB) *PolicyRepository {
	return &PolicyRepository{db: db}
}

// ----- policy definitions -----

func (r *PolicyRepository) CreatePolicyDefinition(ctx context.Context, d *governance.PolicyDefinition) error {
	if d == nil {
		return errors.New("postgres: nil policy definition")
	}
	const q = `
		INSERT INTO policy_definitions (
			id, organization_id, slug, display_name, description,
			rules, schema_version, version,
			created_at, updated_at, created_by, disabled_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11, $12
		)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		d.ID, d.OrganizationID, d.Slug, d.DisplayName, d.Description,
		jsonValueOr([]byte(d.Rules), "[]"), d.SchemaVersion, d.Version,
		d.CreatedAt, d.UpdatedAt, d.CreatedBy, d.DisabledAt,
	); err != nil {
		return fmt.Errorf("postgres: create policy definition: %w", err)
	}
	return nil
}

func (r *PolicyRepository) GetPolicyDefinition(
	ctx context.Context,
	organizationID, definitionID string,
) (*governance.PolicyDefinition, error) {
	const q = `
		SELECT id, organization_id, slug, display_name, description,
		       rules, schema_version, version,
		       created_at, updated_at, created_by, disabled_at
		  FROM policy_definitions
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, definitionID)
	d, err := scanPolicyDefinition(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrPolicyDefinitionNotFound
		}
		return nil, fmt.Errorf("postgres: get policy definition: %w", err)
	}
	return d, nil
}

func (r *PolicyRepository) GetLatestPolicyDefinitionBySlug(
	ctx context.Context,
	organizationID, slug string,
) (*governance.PolicyDefinition, error) {
	const q = `
		SELECT id, organization_id, slug, display_name, description,
		       rules, schema_version, version,
		       created_at, updated_at, created_by, disabled_at
		  FROM policy_definitions
		 WHERE organization_id = $1 AND slug = $2
		 ORDER BY version DESC
		 LIMIT 1`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, slug)
	d, err := scanPolicyDefinition(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrPolicyDefinitionNotFound
		}
		return nil, fmt.Errorf("postgres: get latest policy definition: %w", err)
	}
	return d, nil
}

func (r *PolicyRepository) ListPolicyDefinitions(
	ctx context.Context,
	organizationID string,
	activeOnly bool,
) ([]governance.PolicyDefinition, error) {
	q := `
		SELECT id, organization_id, slug, display_name, description,
		       rules, schema_version, version,
		       created_at, updated_at, created_by, disabled_at
		  FROM policy_definitions
		 WHERE organization_id = $1`
	if activeOnly {
		q += ` AND disabled_at IS NULL`
	}
	q += ` ORDER BY slug ASC, version DESC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list policy definitions: %w", err)
	}
	defer rows.Close()
	var out []governance.PolicyDefinition
	for rows.Next() {
		d, err := scanPolicyDefinition(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan policy definition: %w", err)
		}
		out = append(out, *d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate policy definitions: %w", err)
	}
	return out, nil
}

func (r *PolicyRepository) DisablePolicyDefinition(ctx context.Context, organizationID, definitionID string) error {
	const q = `
		UPDATE policy_definitions
		   SET disabled_at = COALESCE(disabled_at, now()), updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, definitionID)
	if err != nil {
		return fmt.Errorf("postgres: disable policy definition: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return governance.ErrPolicyDefinitionNotFound
	}
	return nil
}

// ----- policy assignments -----

func (r *PolicyRepository) CreatePolicyAssignment(ctx context.Context, a *governance.PolicyAssignment) error {
	if a == nil {
		return errors.New("postgres: nil policy assignment")
	}
	const q = `
		INSERT INTO policy_assignments (
			id, organization_id, policy_definition_id, scope_kind, scope_id,
			assigned_by, assigned_at, cleared_at, cleared_by
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9
		)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		a.ID, a.OrganizationID, a.PolicyDefinitionID, string(a.ScopeKind), a.ScopeID,
		a.AssignedBy, a.AssignedAt, a.ClearedAt, a.ClearedBy,
	); err != nil {
		return fmt.Errorf("postgres: create policy assignment: %w", err)
	}
	return nil
}

func (r *PolicyRepository) GetPolicyAssignment(
	ctx context.Context,
	organizationID, assignmentID string,
) (*governance.PolicyAssignment, error) {
	const q = `
		SELECT id, organization_id, policy_definition_id, scope_kind, scope_id,
		       assigned_by, assigned_at, cleared_at, cleared_by
		  FROM policy_assignments
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, assignmentID)
	a, err := scanPolicyAssignment(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrPolicyAssignmentNotFound
		}
		return nil, fmt.Errorf("postgres: get policy assignment: %w", err)
	}
	return a, nil
}

func (r *PolicyRepository) ClearPolicyAssignment(
	ctx context.Context,
	organizationID, assignmentID, clearedBy string,
	clearedAt time.Time,
) error {
	const q = `
		UPDATE policy_assignments
		   SET cleared_at = $3, cleared_by = $4
		 WHERE organization_id = $1 AND id = $2 AND cleared_at IS NULL`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, assignmentID, clearedAt, clearedBy)
	if err != nil {
		return fmt.Errorf("postgres: clear policy assignment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return governance.ErrPolicyAssignmentNotFound
	}
	return nil
}

func (r *PolicyRepository) ListActivePolicyAssignmentsForScope(
	ctx context.Context,
	organizationID string,
	scopeKind governance.PolicyScopeKind,
	scopeID string,
) ([]governance.PolicyAssignment, error) {
	const q = `
		SELECT id, organization_id, policy_definition_id, scope_kind, scope_id,
		       assigned_by, assigned_at, cleared_at, cleared_by
		  FROM policy_assignments
		 WHERE organization_id = $1
		   AND scope_kind = $2
		   AND scope_id = $3
		   AND cleared_at IS NULL
		 ORDER BY assigned_at ASC, id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, string(scopeKind), scopeID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list active policy assignments for scope: %w", err)
	}
	defer rows.Close()
	return scanPolicyAssignmentList(rows)
}

func (r *PolicyRepository) ListActivePolicyAssignmentsForDefinition(
	ctx context.Context,
	organizationID, definitionID string,
) ([]governance.PolicyAssignment, error) {
	const q = `
		SELECT id, organization_id, policy_definition_id, scope_kind, scope_id,
		       assigned_by, assigned_at, cleared_at, cleared_by
		  FROM policy_assignments
		 WHERE organization_id = $1
		   AND policy_definition_id = $2
		   AND cleared_at IS NULL
		 ORDER BY assigned_at ASC, id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, definitionID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list active policy assignments for definition: %w", err)
	}
	defer rows.Close()
	return scanPolicyAssignmentList(rows)
}

// ----- policy waivers -----

func (r *PolicyRepository) CreatePolicyWaiver(ctx context.Context, w *governance.PolicyWaiver) error {
	if w == nil {
		return errors.New("postgres: nil policy waiver")
	}
	const q = `
		INSERT INTO policy_waivers (
			id, organization_id, policy_definition_id, policy_rule_local_id,
			scope_kind, scope_id, reason,
			granted_by, granted_at, expires_at,
			cleared_at, cleared_by
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10,
			$11, $12
		)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		w.ID, w.OrganizationID, w.PolicyDefinitionID, w.PolicyRuleLocalID,
		string(w.ScopeKind), w.ScopeID, w.Reason,
		w.GrantedBy, w.GrantedAt, w.ExpiresAt,
		w.ClearedAt, w.ClearedBy,
	); err != nil {
		return fmt.Errorf("postgres: create policy waiver: %w", err)
	}
	return nil
}

func (r *PolicyRepository) GetPolicyWaiver(
	ctx context.Context,
	organizationID, waiverID string,
) (*governance.PolicyWaiver, error) {
	const q = `
		SELECT id, organization_id, policy_definition_id, policy_rule_local_id,
		       scope_kind, scope_id, reason,
		       granted_by, granted_at, expires_at,
		       cleared_at, cleared_by
		  FROM policy_waivers
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, waiverID)
	w, err := scanPolicyWaiver(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, governance.ErrPolicyWaiverNotFound
		}
		return nil, fmt.Errorf("postgres: get policy waiver: %w", err)
	}
	return w, nil
}

func (r *PolicyRepository) ClearPolicyWaiver(
	ctx context.Context,
	organizationID, waiverID, clearedBy string,
	clearedAt time.Time,
) error {
	const q = `
		UPDATE policy_waivers
		   SET cleared_at = $3, cleared_by = $4
		 WHERE organization_id = $1 AND id = $2 AND cleared_at IS NULL`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, waiverID, clearedAt, clearedBy)
	if err != nil {
		return fmt.Errorf("postgres: clear policy waiver: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return governance.ErrPolicyWaiverNotFound
	}
	return nil
}

func (r *PolicyRepository) ListActivePolicyWaiversForScope(
	ctx context.Context,
	organizationID string,
	scopeKind governance.PolicyScopeKind,
	scopeID string,
) ([]governance.PolicyWaiver, error) {
	const q = `
		SELECT id, organization_id, policy_definition_id, policy_rule_local_id,
		       scope_kind, scope_id, reason,
		       granted_by, granted_at, expires_at,
		       cleared_at, cleared_by
		  FROM policy_waivers
		 WHERE organization_id = $1
		   AND scope_kind = $2
		   AND scope_id = $3
		   AND cleared_at IS NULL
		 ORDER BY granted_at ASC, id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, string(scopeKind), scopeID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list active policy waivers for scope: %w", err)
	}
	defer rows.Close()
	return scanPolicyWaiverList(rows)
}

func (r *PolicyRepository) ListActivePolicyWaiversForDefinition(
	ctx context.Context,
	organizationID, definitionID string,
) ([]governance.PolicyWaiver, error) {
	const q = `
		SELECT id, organization_id, policy_definition_id, policy_rule_local_id,
		       scope_kind, scope_id, reason,
		       granted_by, granted_at, expires_at,
		       cleared_at, cleared_by
		  FROM policy_waivers
		 WHERE organization_id = $1
		   AND policy_definition_id = $2
		   AND cleared_at IS NULL
		 ORDER BY granted_at ASC, id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, definitionID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list active policy waivers for definition: %w", err)
	}
	defer rows.Close()
	return scanPolicyWaiverList(rows)
}

// ----- scan helpers -----

func scanPolicyDefinition(r rowScanner) (*governance.PolicyDefinition, error) {
	var d governance.PolicyDefinition
	if err := r.Scan(
		&d.ID, &d.OrganizationID, &d.Slug, &d.DisplayName, &d.Description,
		&d.Rules, &d.SchemaVersion, &d.Version,
		&d.CreatedAt, &d.UpdatedAt, &d.CreatedBy, &d.DisabledAt,
	); err != nil {
		return nil, err
	}
	return &d, nil
}

func scanPolicyAssignment(r rowScanner) (*governance.PolicyAssignment, error) {
	var a governance.PolicyAssignment
	var scopeKind string
	if err := r.Scan(
		&a.ID, &a.OrganizationID, &a.PolicyDefinitionID, &scopeKind, &a.ScopeID,
		&a.AssignedBy, &a.AssignedAt, &a.ClearedAt, &a.ClearedBy,
	); err != nil {
		return nil, err
	}
	a.ScopeKind = governance.PolicyScopeKind(scopeKind)
	return &a, nil
}

func scanPolicyAssignmentList(rows pgx.Rows) ([]governance.PolicyAssignment, error) {
	var out []governance.PolicyAssignment
	for rows.Next() {
		a, err := scanPolicyAssignment(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan policy assignment: %w", err)
		}
		out = append(out, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate policy assignments: %w", err)
	}
	return out, nil
}

func scanPolicyWaiver(r rowScanner) (*governance.PolicyWaiver, error) {
	var w governance.PolicyWaiver
	var scopeKind string
	if err := r.Scan(
		&w.ID, &w.OrganizationID, &w.PolicyDefinitionID, &w.PolicyRuleLocalID,
		&scopeKind, &w.ScopeID, &w.Reason,
		&w.GrantedBy, &w.GrantedAt, &w.ExpiresAt,
		&w.ClearedAt, &w.ClearedBy,
	); err != nil {
		return nil, err
	}
	w.ScopeKind = governance.PolicyScopeKind(scopeKind)
	return &w, nil
}

func scanPolicyWaiverList(rows pgx.Rows) ([]governance.PolicyWaiver, error) {
	var out []governance.PolicyWaiver
	for rows.Next() {
		w, err := scanPolicyWaiver(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan policy waiver: %w", err)
		}
		out = append(out, *w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate policy waivers: %w", err)
	}
	return out, nil
}

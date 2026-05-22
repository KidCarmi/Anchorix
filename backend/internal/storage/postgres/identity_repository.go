package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/identity"
)

// IdentityRepository implements identity.Repository against
// PostgreSQL. Schema lives in migration 0009
// (backend/migrations/0009_governance_identity.sql).
//
// Cross-org safety: every query that takes an organization id
// filters on it in the WHERE clause, so a buggy caller passing
// the wrong organization id sees the row as missing rather than
// a foreign-org leak. This is the same defense-in-depth posture
// established by certificate_inventory_repository.go and
// findings_repository.go.
type IdentityRepository struct {
	db *DB
}

// NewIdentityRepository wires the repo. CLAUDE.md §8.8:
// constructor-based DI; no globals.
func NewIdentityRepository(db *DB) *IdentityRepository {
	return &IdentityRepository{db: db}
}

// ----- tags -----

func (r *IdentityRepository) CreateTag(ctx context.Context, t *identity.Tag) error {
	if t == nil {
		return errors.New("postgres: nil tag")
	}
	const q = `
		INSERT INTO tags (
			id, organization_id, key, value, description,
			created_at, updated_at, disabled_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		t.ID, t.OrganizationID, t.Key, t.Value, t.Description,
		t.CreatedAt, t.UpdatedAt, t.DisabledAt,
	); err != nil {
		return fmt.Errorf("postgres: create tag: %w", err)
	}
	return nil
}

func (r *IdentityRepository) GetTag(ctx context.Context, organizationID, tagID string) (*identity.Tag, error) {
	const q = `
		SELECT id, organization_id, key, value, description,
		       created_at, updated_at, disabled_at
		  FROM tags
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, tagID)
	t, err := scanTag(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrTagNotFound
		}
		return nil, fmt.Errorf("postgres: get tag: %w", err)
	}
	return t, nil
}

func (r *IdentityRepository) GetTagByKey(
	ctx context.Context,
	organizationID, key, value string,
) (*identity.Tag, error) {
	const q = `
		SELECT id, organization_id, key, value, description,
		       created_at, updated_at, disabled_at
		  FROM tags
		 WHERE organization_id = $1 AND key = $2 AND value = $3`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, key, value)
	t, err := scanTag(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrTagNotFound
		}
		return nil, fmt.Errorf("postgres: get tag by key: %w", err)
	}
	return t, nil
}

func (r *IdentityRepository) ListTags(
	ctx context.Context,
	organizationID string,
	activeOnly bool,
) ([]identity.Tag, error) {
	q := `
		SELECT id, organization_id, key, value, description,
		       created_at, updated_at, disabled_at
		  FROM tags
		 WHERE organization_id = $1`
	if activeOnly {
		q += ` AND disabled_at IS NULL`
	}
	q += ` ORDER BY id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list tags: %w", err)
	}
	defer rows.Close()
	var out []identity.Tag
	for rows.Next() {
		t, err := scanTag(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan tag: %w", err)
		}
		out = append(out, *t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate tags: %w", err)
	}
	return out, nil
}

func (r *IdentityRepository) UpdateTagDescription(
	ctx context.Context,
	organizationID, tagID, description string,
) error {
	const q = `
		UPDATE tags
		   SET description = $3, updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, tagID, description)
	if err != nil {
		return fmt.Errorf("postgres: update tag description: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrTagNotFound
	}
	return nil
}

func (r *IdentityRepository) DisableTag(ctx context.Context, organizationID, tagID string) error {
	const q = `
		UPDATE tags
		   SET disabled_at = COALESCE(disabled_at, now()), updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, tagID)
	if err != nil {
		return fmt.Errorf("postgres: disable tag: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrTagNotFound
	}
	return nil
}

func (r *IdentityRepository) EnableTag(ctx context.Context, organizationID, tagID string) error {
	const q = `
		UPDATE tags
		   SET disabled_at = NULL, updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, tagID)
	if err != nil {
		return fmt.Errorf("postgres: enable tag: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrTagNotFound
	}
	return nil
}

// ----- tag assignments -----

func (r *IdentityRepository) CreateTagAssignment(ctx context.Context, a *identity.TagAssignment) error {
	if a == nil {
		return errors.New("postgres: nil tag assignment")
	}
	const q = `
		INSERT INTO tag_assignments (
			id, organization_id, tag_id, target_type, target_id,
			assigned_by, assigned_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		a.ID, a.OrganizationID, a.TagID, string(a.TargetType), a.TargetID,
		a.AssignedBy, a.AssignedAt,
	); err != nil {
		return fmt.Errorf("postgres: create tag assignment: %w", err)
	}
	return nil
}

func (r *IdentityRepository) DeleteTagAssignmentByTarget(
	ctx context.Context,
	organizationID, tagID string,
	targetType identity.TagTargetType,
	targetID string,
) error {
	const q = `
		DELETE FROM tag_assignments
		 WHERE organization_id = $1
		   AND tag_id = $2
		   AND target_type = $3
		   AND target_id = $4`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, tagID, string(targetType), targetID)
	if err != nil {
		return fmt.Errorf("postgres: delete tag assignment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrTagAssignmentNotFound
	}
	return nil
}

func (r *IdentityRepository) ListTagAssignmentsForTarget(
	ctx context.Context,
	organizationID string,
	targetType identity.TagTargetType,
	targetID string,
) ([]identity.TagAssignment, error) {
	const q = `
		SELECT id, organization_id, tag_id, target_type, target_id,
		       assigned_by, assigned_at
		  FROM tag_assignments
		 WHERE organization_id = $1
		   AND target_type = $2
		   AND target_id = $3
		 ORDER BY assigned_at ASC, id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, string(targetType), targetID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list tag assignments for target: %w", err)
	}
	defer rows.Close()
	return scanTagAssignmentList(rows)
}

func (r *IdentityRepository) ListTagAssignmentsForTag(
	ctx context.Context,
	organizationID, tagID string,
) ([]identity.TagAssignment, error) {
	const q = `
		SELECT id, organization_id, tag_id, target_type, target_id,
		       assigned_by, assigned_at
		  FROM tag_assignments
		 WHERE organization_id = $1 AND tag_id = $2
		 ORDER BY assigned_at ASC, id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, tagID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list tag assignments for tag: %w", err)
	}
	defer rows.Close()
	return scanTagAssignmentList(rows)
}

// ----- services -----

func (r *IdentityRepository) CreateService(ctx context.Context, s *identity.Service) error {
	if s == nil {
		return errors.New("postgres: nil service")
	}
	const q = `
		INSERT INTO services (
			id, organization_id, slug, display_name, description,
			owner_email, owner_team, business_unit,
			created_at, updated_at, disabled_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11
		)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		s.ID, s.OrganizationID, s.Slug, s.DisplayName, s.Description,
		s.OwnerEmail, s.OwnerTeam, s.BusinessUnit,
		s.CreatedAt, s.UpdatedAt, s.DisabledAt,
	); err != nil {
		return fmt.Errorf("postgres: create service: %w", err)
	}
	return nil
}

func (r *IdentityRepository) GetService(ctx context.Context, organizationID, serviceID string) (*identity.Service, error) {
	const q = `
		SELECT id, organization_id, slug, display_name, description,
		       owner_email, owner_team, business_unit,
		       created_at, updated_at, disabled_at
		  FROM services
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, serviceID)
	s, err := scanService(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrServiceNotFound
		}
		return nil, fmt.Errorf("postgres: get service: %w", err)
	}
	return s, nil
}

func (r *IdentityRepository) GetServiceBySlug(ctx context.Context, organizationID, slug string) (*identity.Service, error) {
	const q = `
		SELECT id, organization_id, slug, display_name, description,
		       owner_email, owner_team, business_unit,
		       created_at, updated_at, disabled_at
		  FROM services
		 WHERE organization_id = $1 AND slug = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, slug)
	s, err := scanService(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrServiceNotFound
		}
		return nil, fmt.Errorf("postgres: get service by slug: %w", err)
	}
	return s, nil
}

func (r *IdentityRepository) ListServices(
	ctx context.Context,
	organizationID string,
	activeOnly bool,
) ([]identity.Service, error) {
	q := `
		SELECT id, organization_id, slug, display_name, description,
		       owner_email, owner_team, business_unit,
		       created_at, updated_at, disabled_at
		  FROM services
		 WHERE organization_id = $1`
	if activeOnly {
		q += ` AND disabled_at IS NULL`
	}
	q += ` ORDER BY id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list services: %w", err)
	}
	defer rows.Close()
	var out []identity.Service
	for rows.Next() {
		s, err := scanService(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan service: %w", err)
		}
		out = append(out, *s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate services: %w", err)
	}
	return out, nil
}

func (r *IdentityRepository) UpdateServiceMetadata(
	ctx context.Context,
	organizationID, serviceID string,
	displayName, description, ownerEmail, ownerTeam, businessUnit string,
) error {
	const q = `
		UPDATE services
		   SET display_name = $3,
		       description = $4,
		       owner_email = $5,
		       owner_team = $6,
		       business_unit = $7,
		       updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q,
		organizationID, serviceID,
		displayName, description, ownerEmail, ownerTeam, businessUnit,
	)
	if err != nil {
		return fmt.Errorf("postgres: update service metadata: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrServiceNotFound
	}
	return nil
}

func (r *IdentityRepository) DisableService(ctx context.Context, organizationID, serviceID string) error {
	const q = `
		UPDATE services
		   SET disabled_at = COALESCE(disabled_at, now()), updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, serviceID)
	if err != nil {
		return fmt.Errorf("postgres: disable service: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrServiceNotFound
	}
	return nil
}

func (r *IdentityRepository) EnableService(ctx context.Context, organizationID, serviceID string) error {
	const q = `
		UPDATE services
		   SET disabled_at = NULL, updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, serviceID)
	if err != nil {
		return fmt.Errorf("postgres: enable service: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrServiceNotFound
	}
	return nil
}

// ----- service groups -----

func (r *IdentityRepository) CreateServiceGroup(ctx context.Context, g *identity.ServiceGroup) error {
	if g == nil {
		return errors.New("postgres: nil service group")
	}
	const q = `
		INSERT INTO service_groups (
			id, organization_id, slug, display_name, parent_id,
			description, created_at, updated_at, disabled_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9
		)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		g.ID, g.OrganizationID, g.Slug, g.DisplayName, g.ParentID,
		g.Description, g.CreatedAt, g.UpdatedAt, g.DisabledAt,
	); err != nil {
		return fmt.Errorf("postgres: create service group: %w", err)
	}
	return nil
}

func (r *IdentityRepository) GetServiceGroup(ctx context.Context, organizationID, groupID string) (*identity.ServiceGroup, error) {
	const q = `
		SELECT id, organization_id, slug, display_name, parent_id,
		       description, created_at, updated_at, disabled_at
		  FROM service_groups
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, groupID)
	g, err := scanServiceGroup(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrServiceGroupNotFound
		}
		return nil, fmt.Errorf("postgres: get service group: %w", err)
	}
	return g, nil
}

func (r *IdentityRepository) GetServiceGroupBySlug(ctx context.Context, organizationID, slug string) (*identity.ServiceGroup, error) {
	const q = `
		SELECT id, organization_id, slug, display_name, parent_id,
		       description, created_at, updated_at, disabled_at
		  FROM service_groups
		 WHERE organization_id = $1 AND slug = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, slug)
	g, err := scanServiceGroup(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrServiceGroupNotFound
		}
		return nil, fmt.Errorf("postgres: get service group by slug: %w", err)
	}
	return g, nil
}

func (r *IdentityRepository) ListServiceGroups(
	ctx context.Context,
	organizationID string,
	activeOnly bool,
) ([]identity.ServiceGroup, error) {
	q := `
		SELECT id, organization_id, slug, display_name, parent_id,
		       description, created_at, updated_at, disabled_at
		  FROM service_groups
		 WHERE organization_id = $1`
	if activeOnly {
		q += ` AND disabled_at IS NULL`
	}
	q += ` ORDER BY id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list service groups: %w", err)
	}
	defer rows.Close()
	var out []identity.ServiceGroup
	for rows.Next() {
		g, err := scanServiceGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan service group: %w", err)
		}
		out = append(out, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate service groups: %w", err)
	}
	return out, nil
}

func (r *IdentityRepository) UpdateServiceGroupParent(
	ctx context.Context,
	organizationID, groupID string,
	parentID *string,
) error {
	const q = `
		UPDATE service_groups
		   SET parent_id = $3, updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, groupID, parentID)
	if err != nil {
		return fmt.Errorf("postgres: update service group parent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrServiceGroupNotFound
	}
	return nil
}

func (r *IdentityRepository) DisableServiceGroup(ctx context.Context, organizationID, groupID string) error {
	const q = `
		UPDATE service_groups
		   SET disabled_at = COALESCE(disabled_at, now()), updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, groupID)
	if err != nil {
		return fmt.Errorf("postgres: disable service group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrServiceGroupNotFound
	}
	return nil
}

// ----- service group memberships -----

func (r *IdentityRepository) SetServiceGroupMembership(ctx context.Context, m *identity.ServiceGroupMembership) error {
	if m == nil {
		return errors.New("postgres: nil service group membership")
	}
	const q = `
		INSERT INTO service_group_memberships (
			organization_id, service_id, service_group_id, assigned_at
		) VALUES ($1, $2, $3, $4)
		ON CONFLICT (organization_id, service_id) DO UPDATE
		   SET service_group_id = EXCLUDED.service_group_id,
		       assigned_at      = EXCLUDED.assigned_at`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		m.OrganizationID, m.ServiceID, m.ServiceGroupID, m.AssignedAt,
	); err != nil {
		return fmt.Errorf("postgres: set service group membership: %w", err)
	}
	return nil
}

func (r *IdentityRepository) ClearServiceGroupMembership(ctx context.Context, organizationID, serviceID string) error {
	const q = `
		DELETE FROM service_group_memberships
		 WHERE organization_id = $1 AND service_id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, serviceID)
	if err != nil {
		return fmt.Errorf("postgres: clear service group membership: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrServiceGroupMembershipNotFound
	}
	return nil
}

func (r *IdentityRepository) GetServiceGroupMembership(
	ctx context.Context,
	organizationID, serviceID string,
) (*identity.ServiceGroupMembership, error) {
	const q = `
		SELECT organization_id, service_id, service_group_id, assigned_at
		  FROM service_group_memberships
		 WHERE organization_id = $1 AND service_id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, serviceID)
	m, err := scanServiceGroupMembership(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrServiceGroupMembershipNotFound
		}
		return nil, fmt.Errorf("postgres: get service group membership: %w", err)
	}
	return m, nil
}

func (r *IdentityRepository) ListServicesInGroup(
	ctx context.Context,
	organizationID, groupID string,
) ([]identity.ServiceGroupMembership, error) {
	const q = `
		SELECT organization_id, service_id, service_group_id, assigned_at
		  FROM service_group_memberships
		 WHERE organization_id = $1 AND service_group_id = $2
		 ORDER BY service_id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, groupID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list services in group: %w", err)
	}
	defer rows.Close()
	var out []identity.ServiceGroupMembership
	for rows.Next() {
		m, err := scanServiceGroupMembership(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan service group membership: %w", err)
		}
		out = append(out, *m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate service group memberships: %w", err)
	}
	return out, nil
}

// ----- agent groups -----

func (r *IdentityRepository) CreateAgentGroup(ctx context.Context, g *identity.AgentGroup) error {
	if g == nil {
		return errors.New("postgres: nil agent group")
	}
	const q = `
		INSERT INTO agent_groups (
			id, organization_id, slug, display_name, description,
			created_at, updated_at, disabled_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		g.ID, g.OrganizationID, g.Slug, g.DisplayName, g.Description,
		g.CreatedAt, g.UpdatedAt, g.DisabledAt,
	); err != nil {
		return fmt.Errorf("postgres: create agent group: %w", err)
	}
	return nil
}

func (r *IdentityRepository) GetAgentGroup(ctx context.Context, organizationID, groupID string) (*identity.AgentGroup, error) {
	const q = `
		SELECT id, organization_id, slug, display_name, description,
		       created_at, updated_at, disabled_at
		  FROM agent_groups
		 WHERE organization_id = $1 AND id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, groupID)
	g, err := scanAgentGroup(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrAgentGroupNotFound
		}
		return nil, fmt.Errorf("postgres: get agent group: %w", err)
	}
	return g, nil
}

func (r *IdentityRepository) GetAgentGroupBySlug(ctx context.Context, organizationID, slug string) (*identity.AgentGroup, error) {
	const q = `
		SELECT id, organization_id, slug, display_name, description,
		       created_at, updated_at, disabled_at
		  FROM agent_groups
		 WHERE organization_id = $1 AND slug = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, organizationID, slug)
	g, err := scanAgentGroup(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrAgentGroupNotFound
		}
		return nil, fmt.Errorf("postgres: get agent group by slug: %w", err)
	}
	return g, nil
}

func (r *IdentityRepository) ListAgentGroups(
	ctx context.Context,
	organizationID string,
	activeOnly bool,
) ([]identity.AgentGroup, error) {
	q := `
		SELECT id, organization_id, slug, display_name, description,
		       created_at, updated_at, disabled_at
		  FROM agent_groups
		 WHERE organization_id = $1`
	if activeOnly {
		q += ` AND disabled_at IS NULL`
	}
	q += ` ORDER BY id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list agent groups: %w", err)
	}
	defer rows.Close()
	var out []identity.AgentGroup
	for rows.Next() {
		g, err := scanAgentGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan agent group: %w", err)
		}
		out = append(out, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate agent groups: %w", err)
	}
	return out, nil
}

func (r *IdentityRepository) DisableAgentGroup(ctx context.Context, organizationID, groupID string) error {
	const q = `
		UPDATE agent_groups
		   SET disabled_at = COALESCE(disabled_at, now()), updated_at = now()
		 WHERE organization_id = $1 AND id = $2`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, groupID)
	if err != nil {
		return fmt.Errorf("postgres: disable agent group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrAgentGroupNotFound
	}
	return nil
}

// ----- agent group memberships -----

func (r *IdentityRepository) AddAgentToGroup(ctx context.Context, m *identity.AgentGroupMembership) error {
	if m == nil {
		return errors.New("postgres: nil agent group membership")
	}
	const q = `
		INSERT INTO agent_group_memberships (
			organization_id, agent_id, agent_group_id, assigned_by, assigned_at
		) VALUES ($1, $2, $3, $4, $5)`
	if _, err := r.db.querierFor(ctx).Exec(ctx, q,
		m.OrganizationID, m.AgentID, m.AgentGroupID, m.AssignedBy, m.AssignedAt,
	); err != nil {
		return fmt.Errorf("postgres: add agent to group: %w", err)
	}
	return nil
}

func (r *IdentityRepository) RemoveAgentFromGroup(
	ctx context.Context,
	organizationID, agentID, groupID string,
) error {
	const q = `
		DELETE FROM agent_group_memberships
		 WHERE organization_id = $1 AND agent_id = $2 AND agent_group_id = $3`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, organizationID, agentID, groupID)
	if err != nil {
		return fmt.Errorf("postgres: remove agent from group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrAgentGroupMembershipNotFound
	}
	return nil
}

func (r *IdentityRepository) ListGroupsForAgent(
	ctx context.Context,
	organizationID, agentID string,
) ([]identity.AgentGroupMembership, error) {
	const q = `
		SELECT organization_id, agent_id, agent_group_id, assigned_by, assigned_at
		  FROM agent_group_memberships
		 WHERE organization_id = $1 AND agent_id = $2
		 ORDER BY agent_group_id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, agentID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list groups for agent: %w", err)
	}
	defer rows.Close()
	return scanAgentGroupMembershipList(rows)
}

func (r *IdentityRepository) ListAgentsInGroup(
	ctx context.Context,
	organizationID, groupID string,
) ([]identity.AgentGroupMembership, error) {
	const q = `
		SELECT organization_id, agent_id, agent_group_id, assigned_by, assigned_at
		  FROM agent_group_memberships
		 WHERE organization_id = $1 AND agent_group_id = $2
		 ORDER BY agent_id ASC`
	rows, err := r.db.querierFor(ctx).Query(ctx, q, organizationID, groupID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list agents in group: %w", err)
	}
	defer rows.Close()
	return scanAgentGroupMembershipList(rows)
}

// ----- scan helpers -----

// rowScanner mirrors pgx.Row/pgx.Rows in the narrow shape these
// scan helpers need.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanTag(r rowScanner) (*identity.Tag, error) {
	var t identity.Tag
	if err := r.Scan(
		&t.ID, &t.OrganizationID, &t.Key, &t.Value, &t.Description,
		&t.CreatedAt, &t.UpdatedAt, &t.DisabledAt,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

func scanTagAssignmentList(rows pgx.Rows) ([]identity.TagAssignment, error) {
	var out []identity.TagAssignment
	for rows.Next() {
		var a identity.TagAssignment
		var targetType string
		if err := rows.Scan(
			&a.ID, &a.OrganizationID, &a.TagID, &targetType, &a.TargetID,
			&a.AssignedBy, &a.AssignedAt,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan tag assignment: %w", err)
		}
		a.TargetType = identity.TagTargetType(targetType)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate tag assignments: %w", err)
	}
	return out, nil
}

func scanService(r rowScanner) (*identity.Service, error) {
	var s identity.Service
	if err := r.Scan(
		&s.ID, &s.OrganizationID, &s.Slug, &s.DisplayName, &s.Description,
		&s.OwnerEmail, &s.OwnerTeam, &s.BusinessUnit,
		&s.CreatedAt, &s.UpdatedAt, &s.DisabledAt,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

func scanServiceGroup(r rowScanner) (*identity.ServiceGroup, error) {
	var g identity.ServiceGroup
	if err := r.Scan(
		&g.ID, &g.OrganizationID, &g.Slug, &g.DisplayName, &g.ParentID,
		&g.Description, &g.CreatedAt, &g.UpdatedAt, &g.DisabledAt,
	); err != nil {
		return nil, err
	}
	return &g, nil
}

func scanServiceGroupMembership(r rowScanner) (*identity.ServiceGroupMembership, error) {
	var m identity.ServiceGroupMembership
	if err := r.Scan(
		&m.OrganizationID, &m.ServiceID, &m.ServiceGroupID, &m.AssignedAt,
	); err != nil {
		return nil, err
	}
	return &m, nil
}

func scanAgentGroup(r rowScanner) (*identity.AgentGroup, error) {
	var g identity.AgentGroup
	if err := r.Scan(
		&g.ID, &g.OrganizationID, &g.Slug, &g.DisplayName, &g.Description,
		&g.CreatedAt, &g.UpdatedAt, &g.DisabledAt,
	); err != nil {
		return nil, err
	}
	return &g, nil
}

func scanAgentGroupMembershipList(rows pgx.Rows) ([]identity.AgentGroupMembership, error) {
	var out []identity.AgentGroupMembership
	for rows.Next() {
		var m identity.AgentGroupMembership
		if err := rows.Scan(
			&m.OrganizationID, &m.AgentID, &m.AgentGroupID, &m.AssignedBy, &m.AssignedAt,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan agent group membership: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate agent group memberships: %w", err)
	}
	return out, nil
}

package identity

import "context"

// Repository is the storage contract for the identity domain.
// The concrete implementation lives in
// internal/storage/postgres; this interface is owned by the
// consumer (CLAUDE.md §8.8).
//
// H-026A1 ships the minimum surface needed to prove storage
// correctness and back integration tests. The service layer
// (H-026A2) composes higher-level validators (slug rules,
// service_group cycle detection, polymorphic target dispatch,
// tag identity-immutable PATCH rejection) over this interface.
//
// Conventions:
//
//   - Every read carries the organization id explicitly; cross-
//     org reads MUST return the not-found sentinel rather than
//     leaking the existence of a foreign-org row.
//   - List methods return rows ordered by id ASC for repeatable
//     pagination at the service layer.
//   - Soft-delete reads return active-by-default; the
//     IncludeDisabled toggle on each List query opts into the
//     full set when the operator needs it.
type Repository interface {
	// ----- tags -----

	// CreateTag inserts a new tag row. The caller MUST mint the
	// id (per the codebase convention — see ids.New).
	CreateTag(ctx context.Context, t *Tag) error

	// GetTag fetches a single tag by (organization_id, id).
	// Returns ErrTagNotFound on miss or cross-org id.
	GetTag(ctx context.Context, organizationID, tagID string) (*Tag, error)

	// GetTagByKey fetches a tag by (organization_id, key, value).
	// Returns ErrTagNotFound on miss. Used by the H-026A2 service
	// layer for "find or create" flows.
	GetTagByKey(ctx context.Context, organizationID, key, value string) (*Tag, error)

	// ListTags returns every tag in the organization ordered by
	// id ASC. When activeOnly is true, disabled_at IS NOT NULL
	// rows are excluded.
	ListTags(ctx context.Context, organizationID string, activeOnly bool) ([]Tag, error)

	// UpdateTagDescription updates only the description column.
	// The service layer enforces tag identity immutability (the
	// repository accepts the call regardless, so tests can
	// exercise the column independently).
	UpdateTagDescription(ctx context.Context, organizationID, tagID, description string) error

	// DisableTag stamps disabled_at on the row. Idempotent — a
	// second call is a no-op. Returns ErrTagNotFound on miss.
	DisableTag(ctx context.Context, organizationID, tagID string) error

	// EnableTag clears disabled_at. Idempotent. Returns
	// ErrTagNotFound on miss.
	EnableTag(ctx context.Context, organizationID, tagID string) error

	// ----- tag assignments -----

	// CreateTagAssignment inserts a new assignment row. The
	// caller MUST mint the id. Polymorphic target integrity
	// (verifying target_id exists in the same organization)
	// lives in the H-026A2 service layer.
	CreateTagAssignment(ctx context.Context, a *TagAssignment) error

	// DeleteTagAssignmentByTarget removes the assignment row
	// for (organization_id, tag_id, target_type, target_id).
	// Returns ErrTagAssignmentNotFound on miss.
	DeleteTagAssignmentByTarget(
		ctx context.Context,
		organizationID, tagID string,
		targetType TagTargetType,
		targetID string,
	) error

	// ListTagAssignmentsForTarget returns every tag assigned to
	// one (target_type, target_id) within the organization,
	// ordered by assigned_at ASC then id ASC. Empty result for
	// untagged targets.
	ListTagAssignmentsForTarget(
		ctx context.Context,
		organizationID string,
		targetType TagTargetType,
		targetID string,
	) ([]TagAssignment, error)

	// ListTagAssignmentsForTag returns every target the tag is
	// attached to, ordered by assigned_at ASC then id ASC.
	ListTagAssignmentsForTag(ctx context.Context, organizationID, tagID string) ([]TagAssignment, error)

	// ----- services -----

	CreateService(ctx context.Context, s *ServiceRecord) error
	GetService(ctx context.Context, organizationID, serviceID string) (*ServiceRecord, error)
	GetServiceBySlug(ctx context.Context, organizationID, slug string) (*ServiceRecord, error)
	ListServices(ctx context.Context, organizationID string, activeOnly bool) ([]ServiceRecord, error)
	UpdateServiceMetadata(
		ctx context.Context,
		organizationID, serviceID string,
		displayName, description, ownerEmail, ownerTeam, businessUnit string,
	) error
	DisableService(ctx context.Context, organizationID, serviceID string) error
	EnableService(ctx context.Context, organizationID, serviceID string) error

	// ----- service groups -----

	CreateServiceGroup(ctx context.Context, g *ServiceGroup) error
	GetServiceGroup(ctx context.Context, organizationID, groupID string) (*ServiceGroup, error)
	GetServiceGroupBySlug(ctx context.Context, organizationID, slug string) (*ServiceGroup, error)
	ListServiceGroups(ctx context.Context, organizationID string, activeOnly bool) ([]ServiceGroup, error)
	UpdateServiceGroupParent(
		ctx context.Context,
		organizationID, groupID string,
		parentID *string,
	) error
	DisableServiceGroup(ctx context.Context, organizationID, groupID string) error

	// ----- service group memberships -----

	// SetServiceGroupMembership UPSERTs the one-row-per-service
	// membership. Re-setting overwrites the prior group; the H-026A2
	// service layer is responsible for any audit recording.
	SetServiceGroupMembership(ctx context.Context, m *ServiceGroupMembership) error

	// ClearServiceGroupMembership removes the membership row.
	// Returns ErrServiceGroupMembershipNotFound on miss.
	ClearServiceGroupMembership(ctx context.Context, organizationID, serviceID string) error

	// GetServiceGroupMembership returns the current membership
	// for one service. ErrServiceGroupMembershipNotFound when
	// the service has no group.
	GetServiceGroupMembership(
		ctx context.Context,
		organizationID, serviceID string,
	) (*ServiceGroupMembership, error)

	// ListServicesInGroup returns every service whose direct
	// group is groupID, ordered by service_id ASC.
	ListServicesInGroup(ctx context.Context, organizationID, groupID string) ([]ServiceGroupMembership, error)

	// ----- agent groups -----

	CreateAgentGroup(ctx context.Context, g *AgentGroup) error
	GetAgentGroup(ctx context.Context, organizationID, groupID string) (*AgentGroup, error)
	GetAgentGroupBySlug(ctx context.Context, organizationID, slug string) (*AgentGroup, error)
	ListAgentGroups(ctx context.Context, organizationID string, activeOnly bool) ([]AgentGroup, error)
	DisableAgentGroup(ctx context.Context, organizationID, groupID string) error

	// ----- agent group memberships -----

	AddAgentToGroup(ctx context.Context, m *AgentGroupMembership) error
	RemoveAgentFromGroup(ctx context.Context, organizationID, agentID, groupID string) error
	ListGroupsForAgent(ctx context.Context, organizationID, agentID string) ([]AgentGroupMembership, error)
	ListAgentsInGroup(ctx context.Context, organizationID, groupID string) ([]AgentGroupMembership, error)
}

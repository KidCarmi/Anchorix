package identity

import "errors"

// Sentinel errors for the identity storage layer. Callers (the
// H-026A2 service layer and HTTP handlers) use errors.Is to map
// them to the canonical envelope.

// ErrTagNotFound is returned by Repository.GetTag and related
// lookups when no row matches (organization_id, id). Cross-org
// id lookups collapse to this sentinel — the WHERE clause in
// the SQL filters on organization_id, so a cross-org id is
// indistinguishable from a truly-missing one (CLAUDE.md §6
// deterministic auth, no enumeration via error code).
var ErrTagNotFound = errors.New("identity: tag not found")

// ErrTagAssignmentNotFound surfaces a missing assignment row.
var ErrTagAssignmentNotFound = errors.New("identity: tag assignment not found")

// ErrServiceNotFound mirrors ErrTagNotFound for services.
var ErrServiceNotFound = errors.New("identity: service not found")

// ErrServiceGroupNotFound mirrors ErrTagNotFound for service
// groups.
var ErrServiceGroupNotFound = errors.New("identity: service group not found")

// ErrServiceGroupMembershipNotFound surfaces a missing
// membership row.
var ErrServiceGroupMembershipNotFound = errors.New("identity: service group membership not found")

// ErrAgentGroupNotFound mirrors ErrTagNotFound for agent groups.
var ErrAgentGroupNotFound = errors.New("identity: agent group not found")

// ErrAgentGroupMembershipNotFound surfaces a missing membership
// row.
var ErrAgentGroupMembershipNotFound = errors.New("identity: agent group membership not found")

// ----- service-layer (H-026A2) sentinels -----

// ErrInvalidInput is returned by Service methods when the
// caller-supplied input violates a documented constraint
// (slug format, missing required field, value out of range,
// etc.). The HTTP layer maps to 400 bad_request.
var ErrInvalidInput = errors.New("identity: invalid input")

// ErrTagIdentityImmutable is returned when an operator
// attempts to PATCH a tag's key or value — both are part of
// the unique identity (organization_id, key, value) that
// TagAssignment rows point at. Renaming would silently break
// every assignment.
// Maps to 400 tag_identity_immutable.
var ErrTagIdentityImmutable = errors.New("identity: tag key and value are immutable")

// ErrTagInUse is returned by DisableTag when the tag still has
// active assignment rows. Operators must delete the assignments
// before disabling the tag.
// Maps to 409 tag_in_use.
var ErrTagInUse = errors.New("identity: tag still has active assignments")

// ErrServiceInUse is returned by DisableService when the service
// is still referenced by ownership rules, ownership overrides,
// or active certificate ownership rows.
// Maps to 409 service_in_use.
var ErrServiceInUse = errors.New("identity: service still referenced by governance state")

// ErrServiceGroupHasChildren is returned by DisableServiceGroup
// when child groups still point at the target via parent_id.
// Maps to 409 service_group_has_children.
var ErrServiceGroupHasChildren = errors.New("identity: service group still has children")

// ErrServiceGroupCycle is returned by CreateServiceGroup and
// UpdateServiceGroupParent when the proposed parent_id would
// create a cycle (the proposed parent is, transitively, a
// descendant of the group being modified).
// Maps to 400 service_group_cycle.
var ErrServiceGroupCycle = errors.New("identity: service group parent would create a cycle")

// ErrTagAssignmentTargetInvalid is returned when a tag
// assignment specifies a (target_type, target_id) pair that
// does not resolve to an existing row in the same organization.
// Maps to 400 bad_request.
var ErrTagAssignmentTargetInvalid = errors.New("identity: tag assignment target does not exist in this organization")

// ErrMembershipTargetInvalid is returned by SetServiceGroupMembership
// and AddAgentToGroup when the referenced service / group / agent
// does not exist in the same organization. The DB composite FKs
// would also reject these, but the service-layer check returns
// a clearer error than a generic FK violation.
// Maps to 400 bad_request.
var ErrMembershipTargetInvalid = errors.New("identity: membership target does not exist in this organization")

// ErrInternalAudit is returned by Service when an audit-write
// failure aborts a state-changing operation. The audit row is
// always written in the same transaction as the state change;
// audit failure rolls everything back (CLAUDE.md §9 — audits
// are not optional on security flows).
// Maps to 500 internal_error.
var ErrInternalAudit = errors.New("identity: audit write failed")

// ErrAlreadyExists is returned when a Create* call collides
// with an existing row's unique constraint:
//
//   - tags (organization_id, key, value)
//   - tag_assignments (organization_id, tag_id, target_type, target_id)
//   - services (organization_id, slug)
//   - service_groups (organization_id, slug)
//   - agent_groups (organization_id, slug)
//   - agent_group_memberships (organization_id, agent_id, agent_group_id) PK
//
// Without this sentinel the raw pgconn.PgError (SQLSTATE 23505)
// surfaces through the handler as 500 internal_error — which
// hides a routine operator misstep behind a server-fault code.
// The handler maps this sentinel to 409 conflict with a
// descriptive message.
var ErrAlreadyExists = errors.New("identity: resource already exists")

// ErrSlugImmutable is returned by UpdateService when the
// caller-supplied input would mutate the service's slug.
// Services share the same identity-immutability invariant as
// tags: slug is part of the unique key
// (organization_id, slug), and renaming would silently break
// every downstream reference (ownership rules, audit history,
// operator dashboards) that points at the slug.
// Maps to 400 service_slug_immutable.
var ErrSlugImmutable = errors.New("identity: service slug is immutable")

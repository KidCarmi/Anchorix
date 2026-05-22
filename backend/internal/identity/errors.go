package identity

import "errors"

// Sentinel errors for the identity storage layer. Callers (the
// future H-026A2 service and H-026A2 HTTP handlers) use
// errors.Is to map them to the canonical envelope.

// ErrTagNotFound is returned by Repository.GetTag and related
// lookups when no row matches (organization_id, id). Cross-org
// id lookups collapse to this sentinel so the HTTP layer can
// return 404 without enumerating cross-tenant state.
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

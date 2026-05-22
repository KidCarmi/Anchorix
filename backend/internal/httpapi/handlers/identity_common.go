package handlers

import (
	"errors"
	"net/http"

	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
)

// IdentityDeps bundles the identity service. CLAUDE.md §8.8:
// constructor-based DI; the router stitches the deps into one
// struct so the handler signatures stay small.
type IdentityDeps struct {
	Service *identity.Service
}

// writeIdentityError maps identity-package sentinel errors to
// the canonical envelope shape per the H-026 plan §7.14 error
// code table.
//
// Returns true when the error was mapped (caller should not
// write anything further); false means the caller should emit
// a generic 500 with internal_error.
func writeIdentityError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, identity.ErrTagNotFound),
		errors.Is(err, identity.ErrTagAssignmentNotFound),
		errors.Is(err, identity.ErrServiceNotFound),
		errors.Is(err, identity.ErrServiceGroupNotFound),
		errors.Is(err, identity.ErrServiceGroupMembershipNotFound),
		errors.Is(err, identity.ErrAgentGroupNotFound),
		errors.Is(err, identity.ErrAgentGroupMembershipNotFound):
		envelope.WriteError(w, http.StatusNotFound, "not_found", "resource not found")
		return true
	case errors.Is(err, identity.ErrTagIdentityImmutable):
		envelope.WriteError(w, http.StatusBadRequest, "tag_identity_immutable",
			"tag key and value cannot be changed after creation")
		return true
	case errors.Is(err, identity.ErrServiceGroupCycle):
		envelope.WriteError(w, http.StatusBadRequest, "service_group_cycle",
			"proposed parent would create a cycle")
		return true
	case errors.Is(err, identity.ErrTagInUse):
		envelope.WriteError(w, http.StatusConflict, "tag_in_use",
			"tag still has active assignments")
		return true
	case errors.Is(err, identity.ErrServiceInUse):
		envelope.WriteError(w, http.StatusConflict, "service_in_use",
			"service still referenced by governance state")
		return true
	case errors.Is(err, identity.ErrServiceGroupHasChildren):
		envelope.WriteError(w, http.StatusConflict, "service_group_has_children",
			"service group still has children")
		return true
	case errors.Is(err, identity.ErrTagAssignmentTargetInvalid),
		errors.Is(err, identity.ErrMembershipTargetInvalid):
		envelope.WriteError(w, http.StatusBadRequest, "bad_request",
			"target does not exist in this organization")
		return true
	case errors.Is(err, identity.ErrInvalidInput):
		envelope.WriteError(w, http.StatusBadRequest, "bad_request",
			"invalid input")
		return true
	}
	return false
}

package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
)

type serviceGroupRow struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	Slug           string  `json:"slug"`
	DisplayName    string  `json:"display_name"`
	Description    string  `json:"description"`
	ParentID       *string `json:"parent_id"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	DisabledAt     *string `json:"disabled_at"`
}

func serviceGroupToRow(g *identity.ServiceGroup) serviceGroupRow {
	var disabled *string
	if g.DisabledAt != nil {
		ds := g.DisabledAt.UTC().Format(time.RFC3339)
		disabled = &ds
	}
	return serviceGroupRow{
		ID:             g.ID,
		OrganizationID: g.OrganizationID,
		Slug:           g.Slug,
		DisplayName:    g.DisplayName,
		Description:    g.Description,
		ParentID:       g.ParentID,
		CreatedAt:      g.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      g.UpdatedAt.UTC().Format(time.RFC3339),
		DisabledAt:     disabled,
	}
}

type serviceGroupListResponse struct {
	Items      []serviceGroupRow `json:"items"`
	NextCursor *string           `json:"next_cursor"`
}

type createServiceGroupRequest struct {
	Slug        string  `json:"slug"`
	DisplayName string  `json:"display_name"`
	Description string  `json:"description"`
	ParentID    *string `json:"parent_id,omitempty"`
}

// ServiceGroupsList handles GET /api/v1/service-groups.
func ServiceGroupsList(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		activeOnly := r.URL.Query().Get("active_only") != "false"
		groups, err := deps.Service.ListServiceGroups(r.Context(), user.OrganizationID, activeOnly)
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not list service groups")
			}
			return
		}
		rows := make([]serviceGroupRow, 0, len(groups))
		for i := range groups {
			rows = append(rows, serviceGroupToRow(&groups[i]))
		}
		envelope.WriteJSON(w, http.StatusOK, serviceGroupListResponse{Items: rows, NextCursor: nil})
	}
}

// ServiceGroupsCreate handles POST /api/v1/service-groups.
func ServiceGroupsCreate(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body createServiceGroupRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		g, err := deps.Service.CreateServiceGroup(r.Context(), identity.CreateServiceGroupInput{
			OrganizationID: user.OrganizationID,
			Slug:           body.Slug,
			DisplayName:    body.DisplayName,
			Description:    body.Description,
			ParentID:       body.ParentID,
			ActorUserID:    user.ID,
		})
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not create service group")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusCreated, serviceGroupToRow(g))
	}
}

// ServiceGroupsGet handles GET /api/v1/service-groups/{id}.
func ServiceGroupsGet(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		g, err := deps.Service.GetServiceGroup(r.Context(), user.OrganizationID, r.PathValue("id"))
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not read service group")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusOK, serviceGroupToRow(g))
	}
}

// setParentRequest is the body for POST
// /service-groups/{id}/parent — separate POST endpoint so the
// "set parent to null" case has an unambiguous wire form.
//
// Body shape:
//
//	{ "parent_id": "sg-xxx" }   sets parent
//	{ "parent_id": null }        clears parent (group becomes root)
//
// The explicit null is required so callers cannot accidentally
// clear a parent by omitting the field. ParentID uses
// json.RawMessage rather than `*string` because Go's encoding/json
// cannot distinguish "field omitted" from "field set to null"
// with a `*string` — both decode to nil. RawMessage preserves
// the raw bytes so the handler can detect presence explicitly
// (len(ParentID) == 0 ⇒ missing field; "null" ⇒ explicit clear;
// quoted string ⇒ set).
type setParentRequest struct {
	ParentID json.RawMessage `json:"parent_id"`
}

// ServiceGroupsSetParent handles POST
// /api/v1/service-groups/{id}/parent.
func ServiceGroupsSetParent(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body setParentRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		// parent_id MUST be present. An omitted field would
		// silently clear the parent — that's a behavior bug
		// the explicit-null contract is designed to prevent.
		// Codex caught this on PR #45.
		if len(body.ParentID) == 0 {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"parent_id is required (use null to clear)")
			return
		}
		var parentID *string
		// Trim whitespace before the literal `null` check so
		// `{ "parent_id":  null }` parses cleanly.
		trimmed := bytes.TrimSpace(body.ParentID)
		if !bytes.Equal(trimmed, []byte("null")) {
			var s string
			if err := json.Unmarshal(body.ParentID, &s); err != nil {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"parent_id must be a string or null")
				return
			}
			parentID = &s
		}
		if err := deps.Service.UpdateServiceGroupParent(r.Context(), identity.UpdateServiceGroupParentInput{
			OrganizationID: user.OrganizationID,
			GroupID:        r.PathValue("id"),
			ParentID:       parentID,
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not update service group parent")
			}
			return
		}
		updated, err := deps.Service.GetServiceGroup(r.Context(), user.OrganizationID, r.PathValue("id"))
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not read service group")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusOK, serviceGroupToRow(updated))
	}
}

// ServiceGroupsDisable handles POST
// /api/v1/service-groups/{id}/disable.
func ServiceGroupsDisable(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body disableRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		if err := deps.Service.DisableServiceGroup(r.Context(), identity.DisableServiceGroupInput{
			OrganizationID: user.OrganizationID,
			GroupID:        r.PathValue("id"),
			Reason:         body.Reason,
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not disable service group")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

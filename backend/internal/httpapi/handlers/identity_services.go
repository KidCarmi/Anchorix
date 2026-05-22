package handlers

import (
	"net/http"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
)

// serviceRow is the wire shape for one service row.
type serviceRow struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	Slug           string  `json:"slug"`
	DisplayName    string  `json:"display_name"`
	Description    string  `json:"description"`
	OwnerEmail     string  `json:"owner_email"`
	OwnerTeam      string  `json:"owner_team"`
	BusinessUnit   string  `json:"business_unit"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	DisabledAt     *string `json:"disabled_at"`
}

func serviceToRow(s *identity.ServiceRecord) serviceRow {
	var disabled *string
	if s.DisabledAt != nil {
		ds := s.DisabledAt.UTC().Format(time.RFC3339)
		disabled = &ds
	}
	return serviceRow{
		ID:             s.ID,
		OrganizationID: s.OrganizationID,
		Slug:           s.Slug,
		DisplayName:    s.DisplayName,
		Description:    s.Description,
		OwnerEmail:     s.OwnerEmail,
		OwnerTeam:      s.OwnerTeam,
		BusinessUnit:   s.BusinessUnit,
		CreatedAt:      s.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      s.UpdatedAt.UTC().Format(time.RFC3339),
		DisabledAt:     disabled,
	}
}

type serviceListResponse struct {
	Items      []serviceRow `json:"items"`
	NextCursor *string      `json:"next_cursor"`
}

// createServiceRequest is the POST /services body.
type createServiceRequest struct {
	Slug         string `json:"slug"`
	DisplayName  string `json:"display_name"`
	Description  string `json:"description"`
	OwnerEmail   string `json:"owner_email"`
	OwnerTeam    string `json:"owner_team"`
	BusinessUnit string `json:"business_unit"`
}

// patchServiceRequest is the PATCH /services/{id} body. All
// fields are optional; the handler resolves missing fields by
// merging with the stored row.
type patchServiceRequest struct {
	DisplayName  *string `json:"display_name,omitempty"`
	Description  *string `json:"description,omitempty"`
	OwnerEmail   *string `json:"owner_email,omitempty"`
	OwnerTeam    *string `json:"owner_team,omitempty"`
	BusinessUnit *string `json:"business_unit,omitempty"`
}

// ServicesList handles GET /api/v1/services.
func ServicesList(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		activeOnly := r.URL.Query().Get("active_only") != "false"
		svcs, err := deps.Service.ListServices(r.Context(), user.OrganizationID, activeOnly)
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not list services")
			}
			return
		}
		rows := make([]serviceRow, 0, len(svcs))
		for i := range svcs {
			rows = append(rows, serviceToRow(&svcs[i]))
		}
		envelope.WriteJSON(w, http.StatusOK, serviceListResponse{Items: rows, NextCursor: nil})
	}
}

// ServicesCreate handles POST /api/v1/services.
func ServicesCreate(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body createServiceRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		svc, err := deps.Service.CreateService(r.Context(), identity.CreateServiceInput{
			OrganizationID: user.OrganizationID,
			Slug:           body.Slug,
			DisplayName:    body.DisplayName,
			Description:    body.Description,
			OwnerEmail:     body.OwnerEmail,
			OwnerTeam:      body.OwnerTeam,
			BusinessUnit:   body.BusinessUnit,
			ActorUserID:    user.ID,
		})
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not create service")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusCreated, serviceToRow(svc))
	}
}

// ServicesGet handles GET /api/v1/services/{id}.
func ServicesGet(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		svc, err := deps.Service.GetService(r.Context(), user.OrganizationID, r.PathValue("id"))
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not read service")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusOK, serviceToRow(svc))
	}
}

// ServicesUpdate handles PATCH /api/v1/services/{id}. Missing
// fields in the body are merged with the stored row so callers
// only need to ship the fields they want to change.
func ServicesUpdate(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		id := r.PathValue("id")
		current, err := deps.Service.GetService(r.Context(), user.OrganizationID, id)
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not read service")
			}
			return
		}
		var body patchServiceRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		display := current.DisplayName
		if body.DisplayName != nil {
			display = *body.DisplayName
		}
		desc := current.Description
		if body.Description != nil {
			desc = *body.Description
		}
		email := current.OwnerEmail
		if body.OwnerEmail != nil {
			email = *body.OwnerEmail
		}
		team := current.OwnerTeam
		if body.OwnerTeam != nil {
			team = *body.OwnerTeam
		}
		bu := current.BusinessUnit
		if body.BusinessUnit != nil {
			bu = *body.BusinessUnit
		}
		if err := deps.Service.UpdateService(r.Context(), identity.UpdateServiceInput{
			OrganizationID: user.OrganizationID,
			ServiceID:      id,
			DisplayName:    display,
			Description:    desc,
			OwnerEmail:     email,
			OwnerTeam:      team,
			BusinessUnit:   bu,
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not update service")
			}
			return
		}
		updated, err := deps.Service.GetService(r.Context(), user.OrganizationID, id)
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not read service")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusOK, serviceToRow(updated))
	}
}

// ServicesDisable handles POST /api/v1/services/{id}/disable.
func ServicesDisable(deps IdentityDeps) http.HandlerFunc {
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
		if err := deps.Service.DisableService(r.Context(), identity.DisableServiceInput{
			OrganizationID: user.OrganizationID,
			ServiceID:      r.PathValue("id"),
			Reason:         body.Reason,
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not disable service")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ServicesEnable handles POST /api/v1/services/{id}/enable.
func ServicesEnable(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		if err := deps.Service.EnableService(r.Context(), identity.EnableServiceInput{
			OrganizationID: user.OrganizationID,
			ServiceID:      r.PathValue("id"),
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not enable service")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// setGroupRequest is the body for POST /services/{id}/group.
type setGroupRequest struct {
	ServiceGroupID string `json:"service_group_id"`
}

// ServicesSetGroup handles POST /api/v1/services/{id}/group.
func ServicesSetGroup(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body setGroupRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		if err := deps.Service.SetServiceGroupMembership(r.Context(), identity.SetServiceGroupMembershipInput{
			OrganizationID: user.OrganizationID,
			ServiceID:      r.PathValue("id"),
			ServiceGroupID: body.ServiceGroupID,
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not set service group")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ServicesClearGroup handles DELETE /api/v1/services/{id}/group.
func ServicesClearGroup(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		if err := deps.Service.ClearServiceGroupMembership(r.Context(), identity.ClearServiceGroupMembershipInput{
			OrganizationID: user.OrganizationID,
			ServiceID:      r.PathValue("id"),
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not clear service group")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

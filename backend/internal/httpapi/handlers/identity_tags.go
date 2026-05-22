package handlers

import (
	"net/http"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
)

// tagRow is the wire shape for one tag in list / get / create
// responses. disabled_at is JSON `null` when the tag is active.
type tagRow struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	Key            string  `json:"key"`
	Value          string  `json:"value"`
	Description    string  `json:"description"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	DisabledAt     *string `json:"disabled_at"`
}

func tagToRow(t *identity.Tag) tagRow {
	var disabled *string
	if t.DisabledAt != nil {
		s := t.DisabledAt.UTC().Format(time.RFC3339)
		disabled = &s
	}
	return tagRow{
		ID:             t.ID,
		OrganizationID: t.OrganizationID,
		Key:            t.Key,
		Value:          t.Value,
		Description:    t.Description,
		CreatedAt:      t.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      t.UpdatedAt.UTC().Format(time.RFC3339),
		DisabledAt:     disabled,
	}
}

type tagListResponse struct {
	Items      []tagRow `json:"items"`
	NextCursor *string  `json:"next_cursor"`
}

// createTagRequest is the POST /tags body.
type createTagRequest struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

// patchTagRequest is the PATCH /tags/{id} body. Only
// description is settable; the service rejects key/value.
//
// We use pointer fields so a missing key in the JSON is
// distinguishable from an explicit "": a request that supplies
// `{ "key": "" }` carries an explicit empty key (REJECT for
// identity immutability), versus `{ "description": "..." }`
// which only ships description (ACCEPT).
type patchTagRequest struct {
	Key         *string `json:"key,omitempty"`
	Value       *string `json:"value,omitempty"`
	Description *string `json:"description,omitempty"`
}

// disableRequest is the standard POST .../disable body. reason
// is required across every disable endpoint.
type disableRequest struct {
	Reason string `json:"reason"`
}

// TagsList handles GET /api/v1/tags.
func TagsList(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		activeOnly := r.URL.Query().Get("active_only") != "false"
		tags, err := deps.Service.ListTags(r.Context(), user.OrganizationID, activeOnly)
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not list tags")
			}
			return
		}
		rows := make([]tagRow, 0, len(tags))
		for i := range tags {
			rows = append(rows, tagToRow(&tags[i]))
		}
		envelope.WriteJSON(w, http.StatusOK, tagListResponse{Items: rows, NextCursor: nil})
	}
}

// TagsCreate handles POST /api/v1/tags.
func TagsCreate(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body createTagRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		tag, err := deps.Service.CreateTag(r.Context(), identity.CreateTagInput{
			OrganizationID: user.OrganizationID,
			Key:            body.Key,
			Value:          body.Value,
			Description:    body.Description,
			ActorUserID:    user.ID,
		})
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not create tag")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusCreated, tagToRow(tag))
	}
}

// TagsGet handles GET /api/v1/tags/{id}.
func TagsGet(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		id := r.PathValue("id")
		t, err := deps.Service.GetTag(r.Context(), user.OrganizationID, id)
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not read tag")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusOK, tagToRow(t))
	}
}

// TagsUpdate handles PATCH /api/v1/tags/{id}.
//
// The handler explicitly rejects bodies that carry `key` or
// `value` fields (even if they're equal to the stored values)
// with tag_identity_immutable. The service-layer check is the
// trust boundary; the handler is the wire-shape pre-filter.
func TagsUpdate(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body patchTagRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		if body.Key != nil || body.Value != nil {
			envelope.WriteError(w, http.StatusBadRequest, "tag_identity_immutable",
				"tag key and value cannot be changed after creation")
			return
		}
		// Description is the only PATCHable field; missing
		// description in the body means "no change".
		if body.Description == nil {
			// No-op PATCH — return the current row.
			t, err := deps.Service.GetTag(r.Context(), user.OrganizationID, r.PathValue("id"))
			if err != nil {
				if !writeIdentityError(w, err) {
					envelope.WriteError(w, http.StatusInternalServerError,
						"internal_error", "could not read tag")
				}
				return
			}
			envelope.WriteJSON(w, http.StatusOK, tagToRow(t))
			return
		}
		if err := deps.Service.UpdateTagDescription(r.Context(), identity.UpdateTagDescriptionInput{
			OrganizationID: user.OrganizationID,
			TagID:          r.PathValue("id"),
			Description:    *body.Description,
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not update tag")
			}
			return
		}
		t, err := deps.Service.GetTag(r.Context(), user.OrganizationID, r.PathValue("id"))
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not read tag")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusOK, tagToRow(t))
	}
}

// TagsDisable handles POST /api/v1/tags/{id}/disable.
func TagsDisable(deps IdentityDeps) http.HandlerFunc {
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
		if err := deps.Service.DisableTag(r.Context(), identity.DisableTagInput{
			OrganizationID: user.OrganizationID,
			TagID:          r.PathValue("id"),
			Reason:         body.Reason,
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not disable tag")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// TagsEnable handles POST /api/v1/tags/{id}/enable.
func TagsEnable(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		if err := deps.Service.EnableTag(r.Context(), identity.EnableTagInput{
			OrganizationID: user.OrganizationID,
			TagID:          r.PathValue("id"),
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not enable tag")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// tagAssignmentRequest is the body for POST /tags/{id}/assignments
// and DELETE /tags/{id}/assignments.
type tagAssignmentRequest struct {
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
}

// tagAssignmentRow is the wire shape for a single tag
// assignment row.
type tagAssignmentRow struct {
	ID         string `json:"id"`
	TagID      string `json:"tag_id"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	AssignedBy string `json:"assigned_by"`
	AssignedAt string `json:"assigned_at"`
}

type tagAssignmentListResponse struct {
	Items      []tagAssignmentRow `json:"items"`
	NextCursor *string            `json:"next_cursor"`
}

// TagAssignmentsCreate handles POST /api/v1/tags/{id}/assignments.
func TagAssignmentsCreate(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body tagAssignmentRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		a, err := deps.Service.AssignTag(r.Context(), identity.AssignTagInput{
			OrganizationID: user.OrganizationID,
			TagID:          r.PathValue("id"),
			TargetType:     identity.TagTargetType(body.TargetType),
			TargetID:       body.TargetID,
			ActorUserID:    user.ID,
		})
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not assign tag")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusCreated, tagAssignmentRow{
			ID:         a.ID,
			TagID:      a.TagID,
			TargetType: string(a.TargetType),
			TargetID:   a.TargetID,
			AssignedBy: a.AssignedBy,
			AssignedAt: a.AssignedAt.UTC().Format(time.RFC3339),
		})
	}
}

// TagAssignmentsDelete handles DELETE /api/v1/tags/{id}/assignments.
func TagAssignmentsDelete(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body tagAssignmentRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		if err := deps.Service.UnassignTag(r.Context(), identity.UnassignTagInput{
			OrganizationID: user.OrganizationID,
			TagID:          r.PathValue("id"),
			TargetType:     identity.TagTargetType(body.TargetType),
			TargetID:       body.TargetID,
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not unassign tag")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// TagAssignmentsList handles GET /api/v1/tags/{id}/assignments.
func TagAssignmentsList(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		assignments, err := deps.Service.ListTagAssignmentsForTag(
			r.Context(), user.OrganizationID, r.PathValue("id"),
		)
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not list tag assignments")
			}
			return
		}
		rows := make([]tagAssignmentRow, 0, len(assignments))
		for _, a := range assignments {
			rows = append(rows, tagAssignmentRow{
				ID:         a.ID,
				TagID:      a.TagID,
				TargetType: string(a.TargetType),
				TargetID:   a.TargetID,
				AssignedBy: a.AssignedBy,
				AssignedAt: a.AssignedAt.UTC().Format(time.RFC3339),
			})
		}
		envelope.WriteJSON(w, http.StatusOK, tagAssignmentListResponse{Items: rows, NextCursor: nil})
	}
}

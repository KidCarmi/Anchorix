package handlers

import (
	"net/http"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
)

type agentGroupRow struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	Slug           string  `json:"slug"`
	DisplayName    string  `json:"display_name"`
	Description    string  `json:"description"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	DisabledAt     *string `json:"disabled_at"`
}

func agentGroupToRow(g *identity.AgentGroup) agentGroupRow {
	var disabled *string
	if g.DisabledAt != nil {
		ds := g.DisabledAt.UTC().Format(time.RFC3339)
		disabled = &ds
	}
	return agentGroupRow{
		ID:             g.ID,
		OrganizationID: g.OrganizationID,
		Slug:           g.Slug,
		DisplayName:    g.DisplayName,
		Description:    g.Description,
		CreatedAt:      g.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      g.UpdatedAt.UTC().Format(time.RFC3339),
		DisabledAt:     disabled,
	}
}

type agentGroupListResponse struct {
	Items      []agentGroupRow `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

type createAgentGroupRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

// AgentGroupsList handles GET /api/v1/agent-groups.
func AgentGroupsList(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		activeOnly := r.URL.Query().Get("active_only") != "false"
		groups, err := deps.Service.ListAgentGroups(r.Context(), user.OrganizationID, activeOnly)
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not list agent groups")
			}
			return
		}
		rows := make([]agentGroupRow, 0, len(groups))
		for i := range groups {
			rows = append(rows, agentGroupToRow(&groups[i]))
		}
		envelope.WriteJSON(w, http.StatusOK, agentGroupListResponse{Items: rows, NextCursor: nil})
	}
}

// AgentGroupsCreate handles POST /api/v1/agent-groups.
func AgentGroupsCreate(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body createAgentGroupRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		g, err := deps.Service.CreateAgentGroup(r.Context(), identity.CreateAgentGroupInput{
			OrganizationID: user.OrganizationID,
			Slug:           body.Slug,
			DisplayName:    body.DisplayName,
			Description:    body.Description,
			ActorUserID:    user.ID,
		})
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not create agent group")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusCreated, agentGroupToRow(g))
	}
}

// AgentGroupsGet handles GET /api/v1/agent-groups/{id}.
func AgentGroupsGet(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		g, err := deps.Service.GetAgentGroup(r.Context(), user.OrganizationID, r.PathValue("id"))
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not read agent group")
			}
			return
		}
		envelope.WriteJSON(w, http.StatusOK, agentGroupToRow(g))
	}
}

// AgentGroupsDisable handles POST /api/v1/agent-groups/{id}/disable.
func AgentGroupsDisable(deps IdentityDeps) http.HandlerFunc {
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
		if err := deps.Service.DisableAgentGroup(r.Context(), identity.DisableAgentGroupInput{
			OrganizationID: user.OrganizationID,
			GroupID:        r.PathValue("id"),
			Reason:         body.Reason,
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not disable agent group")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// agentMembershipRequest is the body for POST/DELETE
// /agent-groups/{id}/members.
type agentMembershipRequest struct {
	AgentID string `json:"agent_id"`
}

// AgentGroupsAddMember handles POST /api/v1/agent-groups/{id}/members.
func AgentGroupsAddMember(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body agentMembershipRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		if err := deps.Service.AddAgentToGroup(r.Context(), identity.AddAgentToGroupInput{
			OrganizationID: user.OrganizationID,
			AgentID:        body.AgentID,
			GroupID:        r.PathValue("id"),
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not add agent to group")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// AgentGroupsRemoveMember handles DELETE /api/v1/agent-groups/{id}/members.
func AgentGroupsRemoveMember(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		var body agentMembershipRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		if err := deps.Service.RemoveAgentFromGroup(r.Context(), identity.RemoveAgentFromGroupInput{
			OrganizationID: user.OrganizationID,
			AgentID:        body.AgentID,
			GroupID:        r.PathValue("id"),
			ActorUserID:    user.ID,
		}); err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not remove agent from group")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type agentMembershipRow struct {
	AgentID      string `json:"agent_id"`
	AgentGroupID string `json:"agent_group_id"`
	AssignedBy   string `json:"assigned_by"`
	AssignedAt   string `json:"assigned_at"`
}

type agentMembershipListResponse struct {
	Items      []agentMembershipRow `json:"items"`
	NextCursor *string              `json:"next_cursor"`
}

// AgentGroupsListMembers handles GET /api/v1/agent-groups/{id}/members.
func AgentGroupsListMembers(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		members, err := deps.Service.ListAgentsInGroup(r.Context(), user.OrganizationID, r.PathValue("id"))
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not list members")
			}
			return
		}
		rows := make([]agentMembershipRow, 0, len(members))
		for _, m := range members {
			rows = append(rows, agentMembershipRow{
				AgentID:      m.AgentID,
				AgentGroupID: m.AgentGroupID,
				AssignedBy:   m.AssignedBy,
				AssignedAt:   m.AssignedAt.UTC().Format(time.RFC3339),
			})
		}
		envelope.WriteJSON(w, http.StatusOK, agentMembershipListResponse{Items: rows, NextCursor: nil})
	}
}

// AgentsListGroups handles GET /api/v1/agents/{id}/groups.
func AgentsListGroups(deps IdentityDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		groups, err := deps.Service.ListGroupsForAgent(r.Context(), user.OrganizationID, r.PathValue("id"))
		if err != nil {
			if !writeIdentityError(w, err) {
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "could not list groups for agent")
			}
			return
		}
		rows := make([]agentMembershipRow, 0, len(groups))
		for _, m := range groups {
			rows = append(rows, agentMembershipRow{
				AgentID:      m.AgentID,
				AgentGroupID: m.AgentGroupID,
				AssignedBy:   m.AssignedBy,
				AssignedAt:   m.AssignedAt.UTC().Format(time.RFC3339),
			})
		}
		envelope.WriteJSON(w, http.StatusOK, agentMembershipListResponse{Items: rows, NextCursor: nil})
	}
}

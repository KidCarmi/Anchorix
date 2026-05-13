package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/enrollment"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
)

// AgentsDeps bundles the dependencies the agent endpoints need.
type AgentsDeps struct {
	Service *enrollment.Service
}

// enrollRequest is the JSON body for POST /api/v1/agents/enroll.
type enrollRequest struct {
	BootstrapSecret    string `json:"bootstrap_secret"`
	Hostname           string `json:"hostname"`
	AgentVersion       string `json:"agent_version"`
	MachineFingerprint string `json:"machine_fingerprint"`
	InstallID          string `json:"install_id"`
}

// enrollResponse is the JSON returned on a successful enrollment.
// agent_credential appears here ONCE per agent and is never echoed
// by any other endpoint.
type enrollResponse struct {
	AgentID         string `json:"agent_id"`
	OrganizationID  string `json:"organization_id"`
	Status          string `json:"status"`
	AgentCredential string `json:"agent_credential"`
	EnrolledAt      string `json:"enrolled_at"`
}

// agentListItem is the JSON shape returned by GET /api/v1/agents.
// The credential hash, fingerprint hash, and install id are
// deliberately omitted — operators see the human-readable view.
type agentListItem struct {
	ID                  string   `json:"id"`
	OrganizationID      string   `json:"organization_id"`
	Hostname            string   `json:"hostname"`
	Status              string   `json:"status"`
	AgentVersion        string   `json:"agent_version,omitempty"`
	EnrolledAt          string   `json:"enrolled_at"`
	LastSeenAt          string   `json:"last_seen_at"`
	DeploymentPackageID string   `json:"deployment_package_id,omitempty"`
	GroupName           string   `json:"group_name,omitempty"`
	Labels              []string `json:"labels,omitempty"`
}

// agentsListResponse uses the envelope shape REST_API.md documents
// for list endpoints. next_cursor is null in this PR because v0.1
// returns the full list — pagination arrives when fleets get
// large.
type agentsListResponse struct {
	Items      []agentListItem `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

// AgentsEnroll handles POST /api/v1/agents/enroll. Anonymous —
// the bootstrap secret IS the auth.
//
// Rejection envelope: every failure mode collapses to a single
// generic 401 with code "enrollment_rejected" so the caller cannot
// enumerate package state. The audit trail carries the specific
// reason for operator diagnosis.
func AgentsEnroll(deps AgentsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body enrollRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			// A malformed body cannot be distinguished from a bad
			// secret without leaking information. Send the same
			// envelope as a rejected enrollment.
			envelope.WriteError(w, http.StatusUnauthorized,
				"enrollment_rejected", "enrollment rejected")
			return
		}

		out, err := deps.Service.EnrollAgent(r.Context(), enrollment.EnrollAgentInput{
			BootstrapSecret:    body.BootstrapSecret,
			Hostname:           strings.TrimSpace(body.Hostname),
			AgentVersion:       strings.TrimSpace(body.AgentVersion),
			MachineFingerprint: body.MachineFingerprint,
			InstallID:          strings.TrimSpace(body.InstallID),
			RequestID:          r.Header.Get("X-Request-Id"),
		})
		if err != nil {
			if errors.Is(err, enrollment.ErrEnrollmentRejected) {
				envelope.WriteError(w, http.StatusUnauthorized,
					"enrollment_rejected", "enrollment rejected")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "enrollment failed")
			return
		}

		envelope.WriteJSON(w, http.StatusCreated, enrollResponse{
			AgentID:         out.Agent.ID,
			OrganizationID:  out.OrganizationID,
			Status:          string(out.Agent.Status),
			AgentCredential: out.AgentCredential,
			EnrolledAt:      out.Agent.EnrolledAt.UTC().Format(time.RFC3339),
		})
	}
}

// AgentsList handles GET /api/v1/agents. Operator-only — the route
// is wrapped with middleware.RequireAuth in the router.
func AgentsList(deps AgentsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		agents, err := deps.Service.ListAgents(r.Context(), user.OrganizationID)
		if err != nil {
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not list agents")
			return
		}
		items := make([]agentListItem, 0, len(agents))
		for _, a := range agents {
			items = append(items, agentListItem{
				ID:                  a.ID,
				OrganizationID:      a.OrganizationID,
				Hostname:            a.Hostname,
				Status:              string(a.Status),
				AgentVersion:        a.AgentVersion,
				EnrolledAt:          a.EnrolledAt.UTC().Format(time.RFC3339),
				LastSeenAt:          a.LastSeenAt.UTC().Format(time.RFC3339),
				DeploymentPackageID: a.DeploymentPackageID,
				GroupName:           a.GroupName,
				Labels:              a.Labels,
			})
		}
		envelope.WriteJSON(w, http.StatusOK, agentsListResponse{Items: items, NextCursor: nil})
	}
}

// AgentsGet remains stub (single-agent detail page arrives in a
// later phase).
func AgentsGet(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AgentsHeartbeat remains stub (heartbeat lands in Phase 3).
func AgentsHeartbeat(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AgentsInventory remains stub (inventory lands in Phase 3).
func AgentsInventory(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AgentsCreateEnrollmentToken was the original single-use-token
// enrollment endpoint from the v0.1 schema proposal. It is
// REMOVED in PR-013 — deployment packages
// (POST /api/v1/deployment-packages) replace the concept. The
// router no longer exposes the legacy path, so unknown-URL
// requests now return the canonical 404 envelope instead of a
// confusing 501 stub. The handler is retained in this file as a
// no-op only because external callers might still import the
// package symbol; remove on the next handler-package cleanup PR.
func AgentsCreateEnrollmentToken(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

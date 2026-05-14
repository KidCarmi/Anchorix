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

// AgentsHeartbeat and AgentsInventory used to live here as
// unrouted operator-keyed stubs (POST /agents/{id}/heartbeat,
// POST /agents/{id}/inventory) carried over from the original v0.1
// schema proposal. PR-017 (heartbeat) and PR-018 (inventory)
// replaced both with the agent-bearer-keyed singular-prefix
// endpoints (POST /agent/heartbeat, POST /agent/inventory). The
// stubs were unrouted at the time of those PRs but kept as
// exported symbols out of caution around external imports — a
// caution that turned out to be unwarranted (no other package
// imports them). PR-019 deletes them under CLAUDE.md §8.5 (no
// dead code) and §19 (no TODO-driven architecture).
//
// AgentsGet remains stub: the operator-side single-agent detail
// page is real Phase 2 continuation work, not a deprecated path.
func AgentsGet(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// nextHeartbeatSeconds is the cadence hint returned to agents.
// v0.1 hard-codes 5 minutes; future revisions can read this from
// config or compute it from server load. Keeping it as a named
// constant centralizes the value so docs, tests, and operators
// have a single source of truth.
const nextHeartbeatSeconds = 300

// heartbeatRequest is the JSON body for POST /api/v1/agent/heartbeat.
// Both fields are optional — the agent may omit them when neither
// has changed since the last heartbeat. The agent ID is taken
// from the authenticated context, NEVER from the request body.
type heartbeatRequest struct {
	AgentVersion string `json:"agent_version"`
	Hostname     string `json:"hostname"`
}

// heartbeatResponse is the JSON returned on a successful heartbeat.
// Deliberately minimal: a status sentinel for client-side
// readability, the server's current time so the agent can detect
// clock drift, and a cadence hint so the agent knows when to
// heartbeat next without consulting external configuration.
type heartbeatResponse struct {
	Status               string `json:"status"`
	ServerTime           string `json:"server_time"`
	NextHeartbeatSeconds int    `json:"next_heartbeat_seconds"`
}

// AgentHeartbeat handles POST /api/v1/agent/heartbeat.
//
// Authenticated-agent only — the route is wrapped with
// middleware.RequireAuthenticatedAgent in the router.
//
// On every successful heartbeat the agent's last_seen_at is bumped
// and (optionally) agent_version / hostname are refreshed when the
// agent reports a non-empty value. No audit row is emitted; see
// the audit-policy comment on enrollment.Service.RecordHeartbeat
// for the rationale (heartbeat is telemetry, not an audit stream).
func AgentHeartbeat(deps AgentsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agent := middleware.AgentFromContext(r.Context())
		if agent == nil {
			// Defensive: RequireAuthenticatedAgent should have
			// blocked unauthenticated requests. Fail closed.
			envelope.WriteError(w, http.StatusUnauthorized,
				"agent_unauthorized", "agent authentication required")
			return
		}

		// Body is OPTIONAL — agents that have nothing to report send
		// an empty body. envelope.DecodeStrictOptionalJSON enforces
		// the canonical contract: empty body OK, single JSON object
		// OK, anything else (malformed, trailing JSON, trailing
		// garbage, oversize) → ErrInvalidJSONBody → 400. See
		// envelope/decode.go for the full behavior contract and the
		// rationale for the second-Decode check.
		var body heartbeatRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}

		if err := deps.Service.RecordHeartbeat(r.Context(), enrollment.RecordHeartbeatInput{
			AgentID:        agent.AgentID,
			OrganizationID: agent.OrganizationID,
			AgentVersion:   body.AgentVersion,
			Hostname:       body.Hostname,
		}); err != nil {
			if errors.Is(err, enrollment.ErrAgentNotFound) {
				// The agent disappeared between auth and update.
				// Surface the same 401 envelope the auth path
				// would have produced so the client cannot
				// distinguish "deleted mid-request" from "never
				// existed".
				envelope.WriteError(w, http.StatusUnauthorized,
					"agent_unauthorized", "agent authentication required")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not record heartbeat")
			return
		}

		envelope.WriteJSON(w, http.StatusOK, heartbeatResponse{
			Status:               "ok",
			ServerTime:           time.Now().UTC().Format(time.RFC3339),
			NextHeartbeatSeconds: nextHeartbeatSeconds,
		})
	}
}

// agentMeResponse is the JSON shape returned by GET /api/v1/agent/me.
// Deliberately minimal: no credential, no credential hash, no
// machine fingerprint. The handler echoes only the identity facts
// the agent already knows about itself.
type agentMeResponse struct {
	AgentID             string   `json:"agent_id"`
	OrganizationID      string   `json:"organization_id"`
	Status              string   `json:"status"`
	DeploymentPackageID string   `json:"deployment_package_id,omitempty"`
	AgentVersion        string   `json:"agent_version,omitempty"`
	GroupName           string   `json:"group_name,omitempty"`
	Labels              []string `json:"labels,omitempty"`
}

// AgentMe handles GET /api/v1/agent/me. Authenticated-agent only.
// The endpoint exists primarily to prove the agent-auth model
// works end-to-end: an agent that successfully exchanges its
// bearer credential gets a deterministic identity payload it can
// log against its own state.
//
// The route is wrapped with middleware.RequireAuthenticatedAgent
// in the router, so this handler is only ever invoked with a
// non-nil AgentFromContext.
func AgentMe() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agent := middleware.AgentFromContext(r.Context())
		if agent == nil {
			// Defensive: RequireAuthenticatedAgent should have
			// blocked this case. If we somehow got here, fail
			// closed with the same envelope the middleware would
			// have written.
			envelope.WriteError(w, http.StatusUnauthorized,
				"agent_unauthorized", "agent authentication required")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, agentMeResponse{
			AgentID:             agent.AgentID,
			OrganizationID:      agent.OrganizationID,
			Status:              string(agent.Status),
			DeploymentPackageID: agent.DeploymentPackageID,
			AgentVersion:        agent.AgentVersion,
			GroupName:           agent.GroupName,
			Labels:              agent.Labels,
		})
	}
}

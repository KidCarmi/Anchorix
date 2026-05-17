package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/agentinventory"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
)

// AgentInventoryDeps bundles the dependencies the agent-inventory
// handlers need. CLAUDE.md §8.8: constructor-based DI.
type AgentInventoryDeps struct {
	Service *agentinventory.Service
}

// agentInventoryRequest is the JSON body for
// POST /api/v1/agent/inventory. The endpoint owner — the agent —
// reports its current host facts. agent_id / organization_id are
// NEVER read from the body; both come from the authenticated agent
// principal in AgentFromContext (CLAUDE.md §6.8 default deny).
//
// installed_at is a pointer so we can distinguish "agent omitted it"
// from "agent reported the zero time". The JSON contract is RFC3339
// for the value, or null/absent for "unknown".
type agentInventoryRequest struct {
	Hostname     string     `json:"hostname"`
	OSName       string     `json:"os_name"`
	OSVersion    string     `json:"os_version"`
	AgentVersion string     `json:"agent_version"`
	MachineArch  string     `json:"machine_arch"`
	LocalIPs     []string   `json:"local_ips"`
	InstalledAt  *time.Time `json:"installed_at"`
}

// agentInventoryResponse is the JSON returned on a successful
// snapshot submission. Deliberately minimal: a status sentinel
// matching the heartbeat shape so an agent log line is easy to
// recognize, and the server-assigned `received_at` so an agent
// can detect clock drift / confirm acceptance.
//
// next_inventory_seconds is intentionally NOT included in v0.1:
// inventory cadence is operator-controlled (config or scheduler),
// not negotiated per request. Adding a cadence hint later is an
// additive API change per CLAUDE.md §17.
type agentInventoryResponse struct {
	Status     string `json:"status"`
	ReceivedAt string `json:"received_at"`
}

// AgentInventorySubmit handles POST /api/v1/agent/inventory.
//
// Authenticated-agent only — the route is wrapped with
// middleware.RequireAuthenticatedAgent in the router. The agent's
// id and organization come from the authenticated principal; the
// body is parsed strictly (single JSON object, no trailing bytes)
// and rejected with 400 bad_request on malformed input.
//
// Snapshot semantics: each successful submission REPLACES the
// agent's current snapshot row (UPSERT in the storage layer). There
// is no history table in v0.1; repeated identical submissions are
// naturally idempotent at the row level (CLAUDE.md §18).
//
// Audit policy: this is operational state sync, like heartbeat. NO
// audit_events row is emitted on success regardless of whether
// fields drifted. Failed bearer auth is already audited by the
// agent-auth middleware upstream of this handler. The rationale
// mirrors AGENT_ENROLLMENT.md "Heartbeat".
func AgentInventorySubmit(deps AgentInventoryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agent := middleware.AgentFromContext(r.Context())
		if agent == nil {
			// Defensive: RequireAuthenticatedAgent should have
			// blocked unauthenticated requests. Fail closed.
			envelope.WriteError(w, http.StatusUnauthorized,
				"agent_unauthorized", "agent authentication required")
			return
		}

		// Body is OPTIONAL — every field is optional, so a `{}` (or
		// empty body) is a valid no-op snapshot. The strict decoder
		// enforces: empty body OK, single JSON object OK, anything
		// else (malformed, trailing JSON, trailing garbage, oversize
		// body) → ErrInvalidJSONBody → 400. See envelope/decode.go
		// for the full behavior contract.
		var body agentInventoryRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}

		snapshot, err := deps.Service.Submit(r.Context(), agentinventory.SubmitInput{
			OrganizationID: agent.OrganizationID,
			AgentID:        agent.AgentID,
			Hostname:       body.Hostname,
			OSName:         body.OSName,
			OSVersion:      body.OSVersion,
			AgentVersion:   body.AgentVersion,
			MachineArch:    body.MachineArch,
			LocalIPs:       body.LocalIPs,
			InstalledAt:    body.InstalledAt,
		})
		if err != nil {
			if errors.Is(err, agentinventory.ErrInvalidSnapshotInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"agent inventory input invalid")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not record agent inventory")
			return
		}

		envelope.WriteJSON(w, http.StatusOK, agentInventoryResponse{
			Status:     "ok",
			ReceivedAt: snapshot.ReceivedAt.UTC().Format(time.RFC3339),
		})
	}
}

// operatorInventoryResponse is the JSON shape returned by
// GET /api/v1/agents/{id}/inventory to an operator. It echoes the
// stored snapshot plus the server-assigned timestamps. Field names
// match the wire shape of the agent-side POST request so operators
// see the same vocabulary in both directions.
type operatorInventoryResponse struct {
	AgentID        string     `json:"agent_id"`
	OrganizationID string     `json:"organization_id"`
	Hostname       string     `json:"hostname"`
	OSName         string     `json:"os_name"`
	OSVersion      string     `json:"os_version"`
	AgentVersion   string     `json:"agent_version"`
	MachineArch    string     `json:"machine_arch"`
	LocalIPs       []string   `json:"local_ips"`
	InstalledAt    *time.Time `json:"installed_at"`
	ReceivedAt     string     `json:"received_at"`
	UpdatedAt      string     `json:"updated_at"`
}

// AgentInventoryGet handles GET /api/v1/agents/{id}/inventory.
// Operator-only — the route is wrapped with middleware.RequireAuth
// in the router. The agent id comes from the URL path; the
// organization id comes from the operator's authenticated session.
//
// A snapshot belonging to an agent in a different organization
// surfaces as 404 not_found — the same envelope a truly-missing id
// produces — so operators cannot enumerate snapshots in
// neighboring tenants (CLAUDE.md §6 deterministic auth).
func AgentInventoryGet(deps AgentInventoryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		agentID := r.PathValue("id")
		if agentID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"agent id required")
			return
		}

		snapshot, err := deps.Service.GetForAgent(r.Context(), agentID, user.OrganizationID)
		if err != nil {
			if errors.Is(err, agentinventory.ErrSnapshotNotFound) {
				envelope.WriteError(w, http.StatusNotFound, "not_found",
					"agent inventory snapshot not found")
				return
			}
			if errors.Is(err, agentinventory.ErrInvalidSnapshotInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"invalid agent inventory request")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not read agent inventory")
			return
		}

		envelope.WriteJSON(w, http.StatusOK, operatorInventoryResponse{
			AgentID:        snapshot.AgentID,
			OrganizationID: snapshot.OrganizationID,
			Hostname:       snapshot.Hostname,
			OSName:         snapshot.OSName,
			OSVersion:      snapshot.OSVersion,
			AgentVersion:   snapshot.AgentVersion,
			MachineArch:    snapshot.MachineArch,
			LocalIPs:       snapshot.LocalIPs,
			InstalledAt:    snapshot.InstalledAt,
			ReceivedAt:     snapshot.ReceivedAt.UTC().Format(time.RFC3339),
			UpdatedAt:      snapshot.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
}

// inventorySummaryItem is one row of the operator-side list
// response. It is deliberately slimmer than operatorInventoryResponse:
//
//   - LocalIPs is reported as a count, not the full list, so the
//     list payload stays small at fleet scale. Operators wanting
//     the full snapshot use GET /agents/{id}/inventory.
//   - No credential, hash, or fingerprint fields appear here — same
//     as the per-agent GET. The list endpoint MUST NOT broaden the
//     leak surface beyond what the per-agent endpoint already
//     exposes (CLAUDE.md §6.9 redaction, AGENT_ENROLLMENT.md
//     "Security properties").
type inventorySummaryItem struct {
	AgentID       string     `json:"agent_id"`
	Hostname      string     `json:"hostname"`
	OSName        string     `json:"os_name"`
	OSVersion     string     `json:"os_version"`
	AgentVersion  string     `json:"agent_version"`
	MachineArch   string     `json:"machine_arch"`
	LocalIPsCount int        `json:"local_ips_count"`
	InstalledAt   *time.Time `json:"installed_at"`
	ReceivedAt    string     `json:"received_at"`
	UpdatedAt     string     `json:"updated_at"`
}

// inventoryListResponse follows the documented v0.1 list envelope:
// `{items: [...], next_cursor: null|string}` (see REST_API.md
// "Pagination"). NextCursor is *string so an empty cursor encodes
// as JSON null — clients use the truthiness of the field to decide
// whether to fetch another page.
type inventoryListResponse struct {
	Items      []inventorySummaryItem `json:"items"`
	NextCursor *string                `json:"next_cursor"`
}

// AgentInventoryList handles GET /api/v1/agent-inventory.
//
// Operator-only — the route is wrapped with middleware.RequireAuth
// in the router. Agent bearer credentials are NOT honored on this
// path (operator and agent identity remain separate axes per
// CLAUDE.md §8.6); a misrouted agent request lands on the operator
// resolver and is rejected as 401 unauthorized.
//
// Org scoping: organization_id comes from the authenticated
// operator session, NEVER from a query param. The repository's
// SQL WHERE clause filters on the same id, so cross-org rows
// cannot surface.
//
// Pagination: cursor-based, with `limit` (default 50, max 200)
// and opaque `cursor`. Non-positive `limit`, an oversize `limit`,
// a non-integer `limit`, or a malformed `cursor` all surface as
// 400 bad_request. See agentinventory.ListSummaries for the full
// contract.
//
// Audit policy: read-only, operator-side. No audit row is emitted
// (CLAUDE.md §9 — audits record state changes; a list call does
// not change state). Failed authentication is already audited by
// the operator session resolver.
func AgentInventoryList(deps AgentInventoryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}

		limit, err := parseLimitQuery(r.URL.Query().Get("limit"))
		if err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"invalid limit query parameter")
			return
		}

		out, err := deps.Service.ListSummaries(r.Context(), agentinventory.ListSummariesInput{
			OrganizationID: user.OrganizationID,
			Limit:          limit,
			Cursor:         r.URL.Query().Get("cursor"),
		})
		if err != nil {
			if errors.Is(err, agentinventory.ErrInvalidListInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"invalid agent inventory list request")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not list agent inventory")
			return
		}

		items := make([]inventorySummaryItem, 0, len(out.Items))
		for _, row := range out.Items {
			items = append(items, inventorySummaryItem{
				AgentID:       row.AgentID,
				Hostname:      row.Hostname,
				OSName:        row.OSName,
				OSVersion:     row.OSVersion,
				AgentVersion:  row.AgentVersion,
				MachineArch:   row.MachineArch,
				LocalIPsCount: row.LocalIPsCount,
				InstalledAt:   row.InstalledAt,
				ReceivedAt:    row.ReceivedAt.UTC().Format(time.RFC3339),
				UpdatedAt:     row.UpdatedAt.UTC().Format(time.RFC3339),
			})
		}
		var nextCursor *string
		if out.NextCursor != "" {
			c := out.NextCursor
			nextCursor = &c
		}
		envelope.WriteJSON(w, http.StatusOK, inventoryListResponse{
			Items:      items,
			NextCursor: nextCursor,
		})
	}
}

// parseLimitQuery converts a raw `limit` query parameter into the
// integer the service expects. An empty value is "use the service
// default"; a non-integer or non-positive value is rejected at the
// HTTP boundary. Out-of-bounds upper-limits (above MaxListLimit)
// are still validated by the service's normalizeLimit so the
// MaxListLimit constant lives in one place — this helper only
// catches non-numeric input and the explicit-zero case the service
// cannot distinguish from "use default" once both collapse to int.
func parseLimitQuery(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		// Explicit `?limit=0` and negative values are caller-input
		// bugs; rejecting them here preserves the documented 1–200
		// bounds and prevents the service from silently treating
		// "0" as "use default".
		return 0, errors.New("limit must be positive")
	}
	return n, nil
}

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
)

// FindingsDeps bundles the dependencies the findings handlers
// need. CLAUDE.md §8.8: constructor-based DI, no globals.
type FindingsDeps struct {
	Service *findings.Service
}

// findingRow is the wire shape for one finding in both the
// list and detail responses. Differences between list and
// detail are minimal at v0.1 (evidence is included in both —
// the schema is small and v0.1 doesn't yet generate huge
// evidence payloads), so one shape covers both.
//
// `fingerprint_sha256` and `subject` are response-shaping
// context populated by the repository's JOIN to `certificates`.
// They are part of the documented H-021 wire contract; the
// fields appear in every response, defaulting to empty strings
// only when the underlying cert row is gone (LEFT JOIN
// degraded; not reachable in v0.1 because ON DELETE CASCADE
// removes the finding with the cert).
type findingRow struct {
	ID                string          `json:"id"`
	RuleID            string          `json:"rule_id"`
	RuleVersion       int             `json:"rule_version"`
	Title             string          `json:"title"`
	Severity          string          `json:"severity"`
	Status            string          `json:"status"`
	CertificateID     string          `json:"certificate_id"`
	FingerprintSHA256 string          `json:"fingerprint_sha256"`
	Subject           string          `json:"subject"`
	Evidence          json.RawMessage `json:"evidence"`
	FirstSeenAt       string          `json:"first_seen_at"`
	LastSeenAt        string          `json:"last_seen_at"`
	ResolvedAt        *string         `json:"resolved_at"`
	UpdatedAt         string          `json:"updated_at"`
	// H-023 override metadata. Always present in the JSON
	// object; populated only when an operator has overridden
	// the finding. StatusReason / StatusActor degrade to ""
	// when null; StatusChangedAt / SuppressExpiresAt to
	// JSON null.
	StatusReason      string  `json:"status_reason"`
	StatusActor       string  `json:"status_actor"`
	StatusChangedAt   *string `json:"status_changed_at"`
	SuppressExpiresAt *string `json:"suppress_expires_at"`
}

type findingsListResponse struct {
	Items      []findingRow `json:"items"`
	NextCursor *string      `json:"next_cursor"`
}

// recomputeResponse mirrors the H-021 contract for
// POST /findings/recompute.
type recomputeResponse struct {
	Status                string `json:"status"`
	EvaluatedCertificates int    `json:"evaluated_certificates"`
	Opened                int    `json:"opened"`
	Updated               int    `json:"updated"`
	Resolved              int    `json:"resolved"`
	Unchanged             int    `json:"unchanged"`
	RuleCount             int    `json:"rule_count"`
}

// FindingsRecompute handles POST /api/v1/findings/recompute.
//
// Operator-only. The route is wrapped with middleware.RequireAuth
// in the router. Agent bearer credentials are NOT honored.
//
// Synchronous: the request blocks until the recompute pass
// finishes. v0.1 fleet scale keeps the pass well under typical
// request budgets; at findings-era scale this moves behind a
// scheduled background worker (HARDENING_BACKLOG follow-up).
//
// Audit policy: one audit row per call (severity intentionally
// NOT "security" — recompute is operational, not a security
// transition). Audit failure rolls back finding state changes
// because the audit row is written in the same transaction.
func FindingsRecompute(deps FindingsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}

		result, err := deps.Service.Recompute(r.Context(), findings.RecomputeInput{
			OrganizationID: user.OrganizationID,
			ActorUserID:    user.ID,
		})
		if err != nil {
			if errors.Is(err, findings.ErrInvalidRecomputeInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"invalid recompute input")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not recompute findings")
			return
		}

		envelope.WriteJSON(w, http.StatusOK, recomputeResponse{
			Status:                "ok",
			EvaluatedCertificates: result.EvaluatedCertificates,
			Opened:                result.Opened,
			Updated:               result.Updated,
			Resolved:              result.Resolved,
			Unchanged:             result.Unchanged,
			RuleCount:             result.RuleCount,
		})
	}
}

// FindingsList handles GET /api/v1/findings.
//
// Operator-only. Org-scoped via the session's organization_id;
// cross-org filter values surface as empty results, never as
// cross-org leaks (the SQL WHERE clause binds the same id).
func FindingsList(deps FindingsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}

		in, err := parseFindingsListQuery(r, user.OrganizationID)
		if err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"invalid findings list query")
			return
		}
		out, err := deps.Service.ListFindings(r.Context(), in)
		if err != nil {
			if errors.Is(err, findings.ErrInvalidListInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"invalid findings list query")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not list findings")
			return
		}

		items := make([]findingRow, 0, len(out.Items))
		for i := range out.Items {
			items = append(items, findingToRow(&out.Items[i]))
		}
		var nextCursor *string
		if out.NextCursor != "" {
			c := out.NextCursor
			nextCursor = &c
		}
		envelope.WriteJSON(w, http.StatusOK, findingsListResponse{
			Items:      items,
			NextCursor: nextCursor,
		})
	}
}

// FindingsGet handles GET /api/v1/findings/{id}.
//
// Operator-only, org-scoped. Cross-org or missing id maps to
// 404 not_found — same envelope a truly-missing id produces, so
// operators cannot enumerate cross-org findings (CLAUDE.md §6).
func FindingsGet(deps FindingsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		findingID := r.PathValue("id")
		if findingID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"finding id required")
			return
		}

		f, err := deps.Service.GetFinding(r.Context(), user.OrganizationID, findingID)
		if err != nil {
			if errors.Is(err, findings.ErrFindingNotFound) {
				envelope.WriteError(w, http.StatusNotFound, "not_found",
					"finding not found")
				return
			}
			if errors.Is(err, findings.ErrInvalidListInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"invalid finding request")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not read finding")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, findingToRow(f))
	}
}

// --- query parsing -------------------------------------------------

func parseFindingsListQuery(r *http.Request, organizationID string) (findings.ListQuery, error) {
	qs := r.URL.Query()

	// status: empty / "open" / "resolved" / "acknowledged" /
	// "suppressed" / "all". Anything else is bad_request. The
	// service applies the "default=open" when the value is
	// empty. The H-023 additions (acknowledged, suppressed)
	// MUST stay in lockstep with findings.StatusFilter — a new
	// enum value added without updating this switch surfaces
	// as 400 here, exactly as TestFindingsList_StatusFilters
	// caught when this list was incomplete.
	rawStatus := qs.Get("status")
	switch findings.StatusFilter(rawStatus) {
	case "",
		findings.StatusFilterOpen,
		findings.StatusFilterResolved,
		findings.StatusFilterAcknowledged,
		findings.StatusFilterSuppressed,
		findings.StatusFilterAll:
		// ok
	default:
		return findings.ListQuery{}, errors.New("invalid status filter")
	}

	limit, err := parseLimitQuery(qs.Get("limit"))
	if err != nil {
		return findings.ListQuery{}, err
	}

	return findings.ListQuery{
		OrganizationID: organizationID,
		Status:         findings.StatusFilter(rawStatus),
		Severity:       findings.Severity(strings.TrimSpace(qs.Get("severity"))),
		RuleID:         strings.TrimSpace(qs.Get("rule_id")),
		CertificateID:  strings.TrimSpace(qs.Get("certificate_id")),
		Limit:          limit,
		Cursor:         qs.Get("cursor"),
	}, nil
}

// --- H-023 acknowledge / suppress -----------------------------------

// acknowledgeRequest is the JSON body shape for
// POST /api/v1/findings/{id}/acknowledge.
type acknowledgeRequest struct {
	Reason string `json:"reason"`
}

// suppressRequest is the JSON body shape for
// POST /api/v1/findings/{id}/suppress. ExpiresAt is a pointer so
// the wire can distinguish "no expiry" (null/missing) from "an
// explicit timestamp". The service's validator then enforces
// strictly-future when present.
type suppressRequest struct {
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// FindingsAcknowledge handles POST /api/v1/findings/{id}/acknowledge.
//
// Operator-only. Org-scoped: cross-org / missing finding id →
// 404 not_found (CLAUDE.md §6 — same envelope a truly-missing
// id returns, so cross-org existence is not enumerable).
//
// Audit: one `finding.acknowledged` row, severity:"security"
// (CLAUDE.md §9 lists finding overrides as security events).
// Audit row is in the same transaction as the status update;
// an audit failure rolls back the override.
func FindingsAcknowledge(deps FindingsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		findingID := r.PathValue("id")
		if findingID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"finding id required")
			return
		}

		var body acknowledgeRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}

		updated, err := deps.Service.AcknowledgeFinding(r.Context(), findings.AcknowledgeInput{
			OrganizationID: user.OrganizationID,
			FindingID:      findingID,
			ActorUserID:    user.ID,
			Reason:         body.Reason,
		})
		if err != nil {
			writeOverrideError(w, err)
			return
		}
		envelope.WriteJSON(w, http.StatusOK, findingToRow(updated))
	}
}

// FindingsSuppress handles POST /api/v1/findings/{id}/suppress.
//
// Same auth + org-scoping + audit posture as
// FindingsAcknowledge, plus optional expires_at on the request
// body. expires_at, if present, MUST be strictly in the future
// (the service re-validates with the injected clock).
func FindingsSuppress(deps FindingsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		findingID := r.PathValue("id")
		if findingID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"finding id required")
			return
		}

		var body suppressRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}

		updated, err := deps.Service.SuppressFinding(r.Context(), findings.SuppressInput{
			OrganizationID: user.OrganizationID,
			FindingID:      findingID,
			ActorUserID:    user.ID,
			Reason:         body.Reason,
			ExpiresAt:      body.ExpiresAt,
		})
		if err != nil {
			writeOverrideError(w, err)
			return
		}
		envelope.WriteJSON(w, http.StatusOK, findingToRow(updated))
	}
}

// writeOverrideError maps the service-layer sentinels onto the
// HTTP envelope. Shared between acknowledge and suppress.
func writeOverrideError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, findings.ErrFindingNotFound):
		envelope.WriteError(w, http.StatusNotFound, "not_found", "finding not found")
	case errors.Is(err, findings.ErrInvalidOverrideInput):
		envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid override input")
	default:
		envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not apply finding override")
	}
}

// findingToRow translates one domain Finding into its wire shape.
// H-023 added the four override-metadata fields; they are always
// present in the JSON object (no `omitempty`) — empty strings or
// JSON null when the finding has never been overridden.
func findingToRow(f *findings.Finding) findingRow {
	var resolvedAt *string
	if f.ResolvedAt != nil {
		s := f.ResolvedAt.UTC().Format(time.RFC3339)
		resolvedAt = &s
	}
	var statusChangedAt *string
	if f.StatusChangedAt != nil {
		s := f.StatusChangedAt.UTC().Format(time.RFC3339)
		statusChangedAt = &s
	}
	var suppressExpiresAt *string
	if f.SuppressExpiresAt != nil {
		s := f.SuppressExpiresAt.UTC().Format(time.RFC3339)
		suppressExpiresAt = &s
	}
	evidence := f.Evidence
	if evidence == nil {
		evidence = json.RawMessage(`{}`)
	}
	return findingRow{
		ID:                f.ID,
		RuleID:            f.RuleID,
		RuleVersion:       f.RuleVersion,
		Title:             f.Title,
		Severity:          string(f.Severity),
		Status:            string(f.Status),
		CertificateID:     f.CertificateID,
		FingerprintSHA256: f.FingerprintSHA256,
		Subject:           f.Subject,
		Evidence:          evidence,
		FirstSeenAt:       f.FirstSeenAt.UTC().Format(time.RFC3339),
		LastSeenAt:        f.LastSeenAt.UTC().Format(time.RFC3339),
		ResolvedAt:        resolvedAt,
		UpdatedAt:         f.UpdatedAt.UTC().Format(time.RFC3339),
		StatusReason:      f.StatusReason,
		StatusActor:       f.StatusActor,
		StatusChangedAt:   statusChangedAt,
		SuppressExpiresAt: suppressExpiresAt,
	}
}

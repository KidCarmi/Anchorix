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
type findingRow struct {
	ID                string          `json:"id"`
	RuleID            string          `json:"rule_id"`
	RuleVersion       int             `json:"rule_version"`
	Title             string          `json:"title"`
	Severity          string          `json:"severity"`
	Status            string          `json:"status"`
	CertificateID     string          `json:"certificate_id"`
	FingerprintSHA256 string          `json:"fingerprint_sha256,omitempty"`
	Subject           string          `json:"subject,omitempty"`
	Evidence          json.RawMessage `json:"evidence"`
	FirstSeenAt       string          `json:"first_seen_at"`
	LastSeenAt        string          `json:"last_seen_at"`
	ResolvedAt        *string         `json:"resolved_at"`
	UpdatedAt         string          `json:"updated_at"`
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

	// status: empty / "open" / "resolved" / "all". Anything else
	// is bad_request. Service applies the "default=open" when
	// the value is empty.
	rawStatus := qs.Get("status")
	switch findings.StatusFilter(rawStatus) {
	case "", findings.StatusFilterOpen, findings.StatusFilterResolved, findings.StatusFilterAll:
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

// FindingsAcknowledge is the placeholder for the acknowledge
// workflow (operator marks a finding as acknowledged with a
// reason; the audit row records the override). Reserved by the
// 0001-era schema's status CHECK; not in scope for H-021.
func FindingsAcknowledge(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// FindingsSuppress is the placeholder for the suppression
// workflow (operator hides a finding with an expiry + reason).
// Same reservation as FindingsAcknowledge.
func FindingsSuppress(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// findingToRow translates one domain Finding into its wire shape.
// The certificate-side fields (fingerprint_sha256, subject) are
// omitted in v0.1 — the operator UI can JOIN at presentation
// time via the certificate id. A future iteration can populate
// them server-side once the recompute path joins certificates;
// keeping them omitted today keeps the wire contract additive
// per CLAUDE.md §17.
func findingToRow(f *findings.Finding) findingRow {
	var resolvedAt *string
	if f.ResolvedAt != nil {
		s := f.ResolvedAt.UTC().Format(time.RFC3339)
		resolvedAt = &s
	}
	evidence := f.Evidence
	if evidence == nil {
		evidence = json.RawMessage(`{}`)
	}
	return findingRow{
		ID:            f.ID,
		RuleID:        f.RuleID,
		RuleVersion:   f.RuleVersion,
		Title:         f.Title,
		Severity:      string(f.Severity),
		Status:        string(f.Status),
		CertificateID: f.CertificateID,
		Evidence:      evidence,
		FirstSeenAt:   f.FirstSeenAt.UTC().Format(time.RFC3339),
		LastSeenAt:    f.LastSeenAt.UTC().Format(time.RFC3339),
		ResolvedAt:    resolvedAt,
		UpdatedAt:     f.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

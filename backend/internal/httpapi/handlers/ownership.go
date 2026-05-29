package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
)

// OwnershipDeps bundles the H-026B3A ownership handler dependencies.
// StaleAfter comes from ANCHORIX_OWNERSHIP_STALE_THRESHOLD; the
// handler honors a `?older_than=` override on /ownership/stale.
type OwnershipDeps struct {
	Service    *ownership.Service
	StaleAfter time.Duration
}

// Wire / page-size policy. ownershipListLimit caps every paginated
// read to keep response bodies bounded regardless of operator query.
// Mirrors findings.MaxListLimit.
const (
	ownershipDefaultListLimit = 50
	ownershipMaxListLimit     = 200
)

// --- wire shapes ----------------------------------------------------

type ownershipRow struct {
	CertificateID   string  `json:"certificate_id"`
	Decision        string  `json:"decision"`
	ServiceID       *string `json:"service_id"`
	WinningRuleID   *string `json:"winning_rule_id"`
	OverrideID      *string `json:"override_id"`
	Confidence      string  `json:"confidence"`
	ExplanationID   string  `json:"explanation_id"`
	FirstAssignedAt string  `json:"first_assigned_at"`
	LastEvaluatedAt string  `json:"last_evaluated_at"`
	LastChangedAt   string  `json:"last_changed_at"`
}

func ownershipToRow(o *governance.CertificateOwnership) ownershipRow {
	return ownershipRow{
		CertificateID:   o.CertificateID,
		Decision:        string(o.Decision),
		ServiceID:       o.ServiceID,
		WinningRuleID:   o.WinningRuleID,
		OverrideID:      o.OverrideID,
		Confidence:      string(o.Confidence),
		ExplanationID:   o.ExplanationID,
		FirstAssignedAt: o.FirstAssignedAt.UTC().Format(time.RFC3339Nano),
		LastEvaluatedAt: o.LastEvaluatedAt.UTC().Format(time.RFC3339Nano),
		LastChangedAt:   o.LastChangedAt.UTC().Format(time.RFC3339Nano),
	}
}

type ownershipListResponse struct {
	Items      []ownershipRow `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

type explanationRow struct {
	ID               string          `json:"id"`
	CertificateID    string          `json:"certificate_id"`
	DecidedAt        string          `json:"decided_at"`
	DecidedDecision  string          `json:"decided_decision"`
	DecidedServiceID *string         `json:"decided_service_id"`
	WinningRuleID    *string         `json:"winning_rule_id"`
	LosingRules      json.RawMessage `json:"losing_rules"`
	SignalsSeen      json.RawMessage `json:"signals_seen"`
	EngineVersion    int             `json:"engine_version"`
}

func explanationToRow(e *governance.OwnershipMatchExplanation) explanationRow {
	return explanationRow{
		ID:               e.ID,
		CertificateID:    e.CertificateID,
		DecidedAt:        e.DecidedAt.UTC().Format(time.RFC3339Nano),
		DecidedDecision:  string(e.DecidedDecision),
		DecidedServiceID: e.DecidedServiceID,
		WinningRuleID:    e.WinningRuleID,
		LosingRules:      e.LosingRules,
		SignalsSeen:      e.SignalsSeen,
		EngineVersion:    e.EngineVersion,
	}
}

type ownershipDetailResponse struct {
	CertificateID string          `json:"certificate_id"`
	Ownership     *ownershipRow   `json:"ownership"`
	Current       *explanationRow `json:"current_explanation"`
}

type explanationResponse struct {
	CertificateID string           `json:"certificate_id"`
	Current       *explanationRow  `json:"current"`
	History       []explanationRow `json:"history,omitempty"`
	NextCursor    *string          `json:"next_cursor,omitempty"`
}

type overrideRow struct {
	ID            string  `json:"id"`
	CertificateID string  `json:"certificate_id"`
	ServiceID     string  `json:"service_id"`
	Reason        string  `json:"reason"`
	SetBy         string  `json:"set_by"`
	SetAt         string  `json:"set_at"`
	ExpiresAt     *string `json:"expires_at"`
	ClearedAt     *string `json:"cleared_at"`
	ClearedBy     *string `json:"cleared_by"`
	ClearedReason *string `json:"cleared_reason"`
}

func overrideToRow(o *governance.CertificateOwnershipOverride) overrideRow {
	row := overrideRow{
		ID:            o.ID,
		CertificateID: o.CertificateID,
		ServiceID:     o.ServiceID,
		Reason:        o.Reason,
		SetBy:         o.SetBy,
		SetAt:         o.SetAt.UTC().Format(time.RFC3339Nano),
		ClearedBy:     o.ClearedBy,
		ClearedReason: o.ClearedReason,
	}
	if o.ExpiresAt != nil {
		s := o.ExpiresAt.UTC().Format(time.RFC3339Nano)
		row.ExpiresAt = &s
	}
	if o.ClearedAt != nil {
		s := o.ClearedAt.UTC().Format(time.RFC3339Nano)
		row.ClearedAt = &s
	}
	return row
}

type overrideResponse struct {
	Active *overrideRow `json:"active"`
}

type ruleRow struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Description    string  `json:"description"`
	ServiceID      string  `json:"service_id"`
	PrecedenceTier string  `json:"precedence_tier"`
	Priority       int     `json:"priority"`
	MatchKind      string  `json:"match_kind"`
	MatchValue     string  `json:"match_value"`
	Enabled        bool    `json:"enabled"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	CreatedBy      string  `json:"created_by"`
	DisabledAt     *string `json:"disabled_at"`
}

func ruleToRow(r *governance.OwnershipRule) ruleRow {
	row := ruleRow{
		ID:             r.ID,
		Name:           r.Name,
		Description:    r.Description,
		ServiceID:      r.ServiceID,
		PrecedenceTier: string(r.PrecedenceTier),
		Priority:       r.Priority,
		MatchKind:      string(r.MatchKind),
		MatchValue:     r.MatchValue,
		Enabled:        r.Enabled,
		CreatedAt:      r.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:      r.UpdatedAt.UTC().Format(time.RFC3339Nano),
		CreatedBy:      r.CreatedBy,
	}
	if r.DisabledAt != nil {
		s := r.DisabledAt.UTC().Format(time.RFC3339Nano)
		row.DisabledAt = &s
	}
	return row
}

type ruleListResponse struct {
	Items      []ruleRow `json:"items"`
	NextCursor *string   `json:"next_cursor"`
}

type recomputeRunRow struct {
	ID                 string  `json:"id"`
	Kind               string  `json:"kind"`
	StartedAt          string  `json:"started_at"`
	FinishedAt         *string `json:"finished_at"`
	Actor              string  `json:"actor"`
	ActorKind          string  `json:"actor_kind"`
	Succeeded          *bool   `json:"succeeded"`
	ErrorClass         string  `json:"error_class"`
	EvaluatedCount     int     `json:"evaluated_count"`
	ChangedCount       int     `json:"changed_count"`
	UnchangedCount     int     `json:"unchanged_count"`
	BecameOwnedCount   int     `json:"became_owned_count"`
	BecameUnownedCount int     `json:"became_unowned_count"`
	FlippedOwnerCount  int     `json:"flipped_owner_count"`
	EngineVersion      int     `json:"engine_version"`
}

func recomputeRunToRow(r *governance.GovernanceRecomputeRun) recomputeRunRow {
	row := recomputeRunRow{
		ID:                 r.ID,
		Kind:               string(r.Kind),
		StartedAt:          r.StartedAt.UTC().Format(time.RFC3339Nano),
		Actor:              r.Actor,
		ActorKind:          string(r.ActorKind),
		Succeeded:          r.Succeeded,
		ErrorClass:         r.ErrorClass,
		EvaluatedCount:     r.EvaluatedCount,
		ChangedCount:       r.ChangedCount,
		UnchangedCount:     r.UnchangedCount,
		BecameOwnedCount:   r.BecameOwnedCount,
		BecameUnownedCount: r.BecameUnownedCount,
		FlippedOwnerCount:  r.FlippedOwnerCount,
		EngineVersion:      r.EngineVersion,
	}
	if r.FinishedAt != nil {
		s := r.FinishedAt.UTC().Format(time.RFC3339Nano)
		row.FinishedAt = &s
	}
	return row
}

type recomputeRunListResponse struct {
	Items []recomputeRunRow `json:"items"`
}

// Recompute trigger wire shape. Includes all engine result fields so
// operators can verify the pass; not capped to {"status":"ok"}.
type recomputeTriggerResponse struct {
	RunID                 string `json:"run_id"`
	FirstRun              bool   `json:"first_run"`
	EvaluatedCertificates int    `json:"evaluated_certificates"`
	ChangedCertificates   int    `json:"changed_certificates"`
	UnchangedCertificates int    `json:"unchanged_certificates"`
	Reclassified          int    `json:"reclassified"`
	BecameOwned           int    `json:"became_owned"`
	BecameUnowned         int    `json:"became_unowned"`
	FlippedOwner          int    `json:"flipped_owner"`
	CreatedUnownedRows    int    `json:"created_unowned_rows"`
	ExpiredOverrides      int    `json:"expired_overrides"`
	RuleCompileFailures   int    `json:"rule_compile_failures"`
	EngineVersion         int    `json:"engine_version"`
	DurationMs            int64  `json:"duration_ms"`
}

// --- helpers --------------------------------------------------------

// parseListLimit applies the default/bounds policy used by every
// paginated ownership read. Empty → default; 0/negative/over-cap →
// (0, false). The caller maps `ok==false` to a 400 bad_request so an
// operator passing `?limit=0` gets immediate feedback.
func parseListLimit(raw string) (int, bool) {
	if raw == "" {
		return ownershipDefaultListLimit, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > ownershipMaxListLimit {
		return 0, false
	}
	return n, true
}

// encodeCursor base64-encodes a cursor token. The token format is
// opaque to the operator — internally a single certificate_id (or
// rule id) — but treating it as opaque means a future composite key
// can land without an API break (CLAUDE.md §17).
func encodeCursor(raw string) string { return base64.RawURLEncoding.EncodeToString([]byte(raw)) }

// decodeCursor inverts encodeCursor. An empty input is the "start
// from the beginning" sentinel.
func decodeCursor(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func writeOwnershipPage(w http.ResponseWriter, rows []governance.CertificateOwnership, requested int) {
	out := ownershipListResponse{Items: make([]ownershipRow, 0, len(rows))}
	if len(rows) > requested {
		// We over-fetched by one to detect more pages.
		next := encodeCursor(rows[requested-1].CertificateID)
		out.NextCursor = &next
		rows = rows[:requested]
	}
	for i := range rows {
		out.Items = append(out.Items, ownershipToRow(&rows[i]))
	}
	envelope.WriteJSON(w, http.StatusOK, out)
}

// --- handlers -------------------------------------------------------

// OwnershipRecompute handles POST /api/v1/ownership/recompute.
// Operator-only. `?nowait=true` returns 409 ownership_recompute_in_progress
// instead of blocking when the per-org advisory lock is held.
func OwnershipRecompute(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		nowait := r.URL.Query().Get("nowait") == "true"
		start := time.Now()
		var (
			result *ownership.RecomputeResult
			err    error
		)
		if nowait {
			result, err = deps.Service.RecomputeNoWait(r.Context(), user.OrganizationID, user.ID)
			if errors.Is(err, ownership.ErrRecomputeInProgress) {
				envelope.WriteError(w, http.StatusConflict, "ownership_recompute_in_progress",
					"a recompute is already in progress for this organization")
				return
			}
		} else {
			result, err = deps.Service.Recompute(r.Context(), user.OrganizationID, user.ID)
		}
		if err != nil {
			if errors.Is(err, ownership.ErrUnknownPrecedenceTier) ||
				errors.Is(err, ownership.ErrUnknownMatchKind) {
				envelope.WriteError(w, http.StatusInternalServerError, "internal_error",
					"ownership rules contain an unrecognized tier or match kind")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error",
				"could not recompute ownership")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, recomputeTriggerResponse{
			RunID:                 result.RunID,
			FirstRun:              result.FirstRun,
			EvaluatedCertificates: result.EvaluatedCertificates,
			ChangedCertificates:   result.ChangedCertificates,
			UnchangedCertificates: result.UnchangedCertificates,
			Reclassified:          result.Reclassified,
			BecameOwned:           result.BecameOwned,
			BecameUnowned:         result.BecameUnowned,
			FlippedOwner:          result.FlippedOwner,
			CreatedUnownedRows:    result.CreatedUnownedRows,
			ExpiredOverrides:      result.ExpiredOverrides,
			RuleCompileFailures:   result.RuleCompileFailures,
			EngineVersion:         result.EngineVersion,
			DurationMs:            time.Since(start).Milliseconds(),
		})
	}
}

func ownershipByDecision(deps OwnershipDeps, decision governance.Decision) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		limit, ok := parseListLimit(r.URL.Query().Get("limit"))
		if !ok {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid limit")
			return
		}
		cursor, ok := decodeCursor(r.URL.Query().Get("cursor"))
		if !ok {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid cursor")
			return
		}
		rows, err := deps.Service.ListCertificateOwnershipByDecisionPaged(
			r.Context(), user.OrganizationID, decision, cursor, limit+1,
		)
		if err != nil {
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not list ownership")
			return
		}
		writeOwnershipPage(w, rows, limit)
	}
}

// OwnershipUnowned handles GET /api/v1/ownership/unowned.
func OwnershipUnowned(deps OwnershipDeps) http.HandlerFunc {
	return ownershipByDecision(deps, governance.DecisionUnowned)
}

// OwnershipAmbiguous handles GET /api/v1/ownership/ambiguous.
func OwnershipAmbiguous(deps OwnershipDeps) http.HandlerFunc {
	return ownershipByDecision(deps, governance.DecisionAmbiguous)
}

// OwnershipStale handles GET /api/v1/ownership/stale. The threshold
// defaults to ANCHORIX_OWNERSHIP_STALE_THRESHOLD and accepts an
// `?older_than=` duration override (e.g. `?older_than=24h`).
func OwnershipStale(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		limit, ok := parseListLimit(r.URL.Query().Get("limit"))
		if !ok {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid limit")
			return
		}
		cursor, ok := decodeCursor(r.URL.Query().Get("cursor"))
		if !ok {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid cursor")
			return
		}
		threshold := deps.StaleAfter
		if raw := r.URL.Query().Get("older_than"); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil || d <= 0 {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid older_than")
				return
			}
			threshold = d
		}
		olderThan := time.Now().UTC().Add(-threshold)
		rows, err := deps.Service.ListCertificateOwnershipStale(
			r.Context(), user.OrganizationID, olderThan, cursor, limit+1,
		)
		if err != nil {
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not list stale ownership")
			return
		}
		writeOwnershipPage(w, rows, limit)
	}
}

// CertificateOwnershipGet handles GET /api/v1/certificates/{id}/ownership.
func CertificateOwnershipGet(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		certID := strings.TrimSpace(r.PathValue("id"))
		if certID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "certificate id required")
			return
		}
		co, err := deps.Service.GetCertificateOwnership(r.Context(), user.OrganizationID, certID)
		if err != nil {
			if errors.Is(err, governance.ErrCertificateOwnershipNotFound) {
				envelope.WriteError(w, http.StatusNotFound, "not_found", "ownership has not been derived for this certificate")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not load ownership")
			return
		}
		exps, err := deps.Service.ListOwnershipExplanationsForCertificate(r.Context(), user.OrganizationID, certID, 1)
		if err != nil {
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not load explanation")
			return
		}
		var current *explanationRow
		if len(exps) > 0 {
			row := explanationToRow(&exps[0])
			current = &row
		}
		oRow := ownershipToRow(co)
		envelope.WriteJSON(w, http.StatusOK, ownershipDetailResponse{
			CertificateID: certID,
			Ownership:     &oRow,
			Current:       current,
		})
	}
}

// CertificateOwnershipExplanation handles GET /api/v1/certificates/{id}/ownership/explanation.
//
// Default (no query): returns only the current (most recent)
// explanation, no history, no cursor.
//
// `?include_history=true` returns the per-cert explanation timeline
// ordered (decided_at DESC, id ASC) as a BOUNDED page:
//   - `limit` defaults to 50 and is hard-capped at 200; limit=0,
//     negative, or > 200 is rejected with 400 (no path can request
//     "all rows").
//   - the response carries `next_cursor` when more history remains;
//     `?cursor=` walks back through the full timeline page by page.
//
// Each page therefore holds at most `limit` rows in memory; there is
// no unbounded "full history in one response" path.
func CertificateOwnershipExplanation(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		certID := strings.TrimSpace(r.PathValue("id"))
		if certID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "certificate id required")
			return
		}
		includeHistory := r.URL.Query().Get("include_history") == "true"

		// Default path (history not requested): return the most recent
		// explanation only, no cursor.
		if !includeHistory {
			exps, err := deps.Service.ListOwnershipExplanationsForCertificate(r.Context(), user.OrganizationID, certID, 1)
			if err != nil {
				envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not load explanations")
				return
			}
			if len(exps) == 0 {
				envelope.WriteError(w, http.StatusNotFound, "not_found", "no explanation for this certificate")
				return
			}
			current := explanationToRow(&exps[0])
			envelope.WriteJSON(w, http.StatusOK, explanationResponse{
				CertificateID: certID,
				Current:       &current,
			})
			return
		}

		// History path: cursor-paged walk back through time. The
		// over-fetch detects more pages without an extra round trip;
		// memory stays bounded by limit (≤ 200).
		limit, ok := parseListLimit(r.URL.Query().Get("limit"))
		if !ok {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid limit")
			return
		}
		cursorAt, cursorID, ok := decodeExplanationCursor(r.URL.Query().Get("cursor"))
		if !ok {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid cursor")
			return
		}
		exps, err := deps.Service.ListOwnershipExplanationsForCertificatePaged(
			r.Context(), user.OrganizationID, certID, cursorAt, cursorID, limit+1,
		)
		if err != nil {
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not load explanations")
			return
		}
		// First page (no cursor) AND empty result → no explanation row exists.
		if cursorID == "" && len(exps) == 0 {
			envelope.WriteError(w, http.StatusNotFound, "not_found", "no explanation for this certificate")
			return
		}
		resp := explanationResponse{CertificateID: certID, History: []explanationRow{}}
		if len(exps) > limit {
			// More pages remain — drop the over-fetch and encode the
			// cursor from the LAST row of THIS page.
			last := exps[limit-1]
			next := encodeExplanationCursor(last.DecidedAt, last.ID)
			resp.NextCursor = &next
			exps = exps[:limit]
		}
		// On the first page (no incoming cursor), the most recent row
		// is the current explanation; history walks back from there.
		// On subsequent pages, omit `current` — the operator already
		// has it from page 1 — and just stream history.
		if cursorID == "" && len(exps) > 0 {
			current := explanationToRow(&exps[0])
			resp.Current = &current
			for i := 1; i < len(exps); i++ {
				resp.History = append(resp.History, explanationToRow(&exps[i]))
			}
		} else {
			for i := range exps {
				resp.History = append(resp.History, explanationToRow(&exps[i]))
			}
		}
		envelope.WriteJSON(w, http.StatusOK, resp)
	}
}

// encodeExplanationCursor builds the opaque cursor token for the
// per-cert explanation timeline (decided_at DESC, id ASC ordering).
// Format inside the base64 wrap: `<RFC3339Nano>|<id>`.
func encodeExplanationCursor(decidedAt time.Time, id string) string {
	raw := decidedAt.UTC().Format(time.RFC3339Nano) + "|" + id
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeExplanationCursor inverts encodeExplanationCursor. Empty
// input is the "from the beginning" sentinel and yields a zero time
// + empty id, which the storage layer treats as "no cursor filter."
func decodeExplanationCursor(raw string) (time.Time, string, bool) {
	if raw == "" {
		return time.Time{}, "", true
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", false
	}
	parts := strings.SplitN(string(b), "|", 2)
	if len(parts) != 2 || parts[1] == "" {
		return time.Time{}, "", false
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", false
	}
	return t, parts[1], true
}

// CertificateOwnershipOverrideGet handles GET /api/v1/certificates/{id}/ownership/override.
// Returns the unique active override or null.
func CertificateOwnershipOverrideGet(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		certID := strings.TrimSpace(r.PathValue("id"))
		if certID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "certificate id required")
			return
		}
		ov, err := deps.Service.GetActiveOwnershipOverride(r.Context(), user.OrganizationID, certID)
		if err != nil {
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not load override")
			return
		}
		var active *overrideRow
		if ov != nil {
			row := overrideToRow(ov)
			active = &row
		}
		envelope.WriteJSON(w, http.StatusOK, overrideResponse{Active: active})
	}
}

// OwnershipRulesList handles GET /api/v1/ownership-rules.
// `?enabled=true|false` filters by enabled state (default: all).
func OwnershipRulesList(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		limit, ok := parseListLimit(r.URL.Query().Get("limit"))
		if !ok {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid limit")
			return
		}
		cursor, ok := decodeCursor(r.URL.Query().Get("cursor"))
		if !ok {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid cursor")
			return
		}
		// enabled is tri-state: absent = all, "true" = enabled only,
		// "false" = disabled only. An unrecognized value is 400 so a
		// typo (e.g. ?enabled=yes) cannot silently collapse to "all".
		var enabledFilter *bool
		switch r.URL.Query().Get("enabled") {
		case "":
			enabledFilter = nil
		case "true":
			t := true
			enabledFilter = &t
		case "false":
			f := false
			enabledFilter = &f
		default:
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid enabled (want true|false)")
			return
		}
		rules, err := deps.Service.ListOwnershipRulesPaged(r.Context(), user.OrganizationID, cursor, limit+1, enabledFilter)
		if err != nil {
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not list ownership rules")
			return
		}
		out := ruleListResponse{Items: make([]ruleRow, 0, len(rules))}
		if len(rules) > limit {
			next := encodeCursor(rules[limit-1].ID)
			out.NextCursor = &next
			rules = rules[:limit]
		}
		for i := range rules {
			out.Items = append(out.Items, ruleToRow(&rules[i]))
		}
		envelope.WriteJSON(w, http.StatusOK, out)
	}
}

// OwnershipRulesGet handles GET /api/v1/ownership-rules/{id}.
func OwnershipRulesGet(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		ruleID := strings.TrimSpace(r.PathValue("id"))
		if ruleID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "rule id required")
			return
		}
		rule, err := deps.Service.GetOwnershipRule(r.Context(), user.OrganizationID, ruleID)
		if err != nil {
			if errors.Is(err, governance.ErrOwnershipRuleNotFound) {
				envelope.WriteError(w, http.StatusNotFound, "not_found", "ownership rule not found")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not load ownership rule")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, ruleToRow(rule))
	}
}

// GovernanceRecomputeRunsList handles GET /api/v1/governance/recompute-runs.
// `?kind=ownership` (default) or `?kind=policy`. `?limit=` capped.
func GovernanceRecomputeRunsList(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		kind := governance.RecomputeKindOwnership
		switch r.URL.Query().Get("kind") {
		case "", "ownership":
			kind = governance.RecomputeKindOwnership
		case "policy":
			kind = governance.RecomputeKindPolicy
		default:
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid kind")
			return
		}
		limit, ok := parseListLimit(r.URL.Query().Get("limit"))
		if !ok {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid limit")
			return
		}
		runs, err := deps.Service.ListRecentRecomputeRuns(r.Context(), user.OrganizationID, kind, limit)
		if err != nil {
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not list recompute runs")
			return
		}
		out := recomputeRunListResponse{Items: make([]recomputeRunRow, 0, len(runs))}
		for i := range runs {
			out.Items = append(out.Items, recomputeRunToRow(&runs[i]))
		}
		envelope.WriteJSON(w, http.StatusOK, out)
	}
}

// --- H-026B3B rule mutations ----------------------------------------

// createOwnershipRuleRequest is the POST /ownership-rules body.
// precedence_tier is optional — when omitted it is derived from
// match_kind's canonical tier.
type createOwnershipRuleRequest struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	ServiceID      string `json:"service_id"`
	MatchKind      string `json:"match_kind"`
	PrecedenceTier string `json:"precedence_tier"`
	MatchValue     string `json:"match_value"`
	Priority       int    `json:"priority"`
}

// updateOwnershipRuleRequest is the PATCH /ownership-rules/{id} body.
// Only the mutable fields are accepted; identity-shaping fields
// (name, match_kind, service_id, tier) are immutable after creation.
//
// Fields are pointers so an omitted key is distinguished from an
// explicit value: a nil field is preserved from the stored row by the
// service (PATCH semantics), so `{"description":"x"}` does not blank
// match_value or reset priority to 0.
type updateOwnershipRuleRequest struct {
	Description *string `json:"description"`
	MatchValue  *string `json:"match_value"`
	Priority    *int    `json:"priority"`
}

// writeOwnershipRuleError maps the rule-mutation sentinels to the
// canonical envelope. Returns true when handled. Order matters:
// specific sentinels before the generic ErrInvalidRule.
func writeOwnershipRuleError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, governance.ErrOwnershipRuleNotFound):
		envelope.WriteError(w, http.StatusNotFound, "not_found", "ownership rule not found")
		return true
	case errors.Is(err, governance.ErrOwnershipRuleAlreadyExists):
		envelope.WriteError(w, http.StatusConflict, "ownership_rule_conflict",
			"an ownership rule with this name already exists")
		return true
	case errors.Is(err, ownership.ErrServiceMemberReserved):
		envelope.WriteError(w, http.StatusBadRequest, "ownership_rule_tier_reserved",
			"the service_member precedence tier is reserved and cannot be used")
		return true
	case errors.Is(err, ownership.ErrRuleServiceNotFound):
		envelope.WriteError(w, http.StatusBadRequest, "ownership_rule_service_not_found",
			"the target service does not exist or is disabled")
		return true
	case errors.Is(err, ownership.ErrRuleTargetNotFound):
		envelope.WriteError(w, http.StatusBadRequest, "ownership_rule_target_not_found",
			"the rule match target does not exist or is disabled")
		return true
	case errors.Is(err, ownership.ErrInvalidRule):
		envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid ownership rule")
		return true
	}
	return false
}

// OwnershipRulesCreate handles POST /api/v1/ownership-rules.
func OwnershipRulesCreate(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		var body createOwnershipRuleRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		rule, err := deps.Service.CreateRule(r.Context(), ownership.CreateRuleInput{
			OrganizationID: user.OrganizationID,
			ActorUserID:    user.ID,
			Name:           body.Name,
			Description:    body.Description,
			ServiceID:      body.ServiceID,
			MatchKind:      governance.MatchKind(body.MatchKind),
			PrecedenceTier: governance.PrecedenceTier(body.PrecedenceTier),
			MatchValue:     body.MatchValue,
			Priority:       body.Priority,
		})
		if err != nil {
			if writeOwnershipRuleError(w, err) {
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not create ownership rule")
			return
		}
		envelope.WriteJSON(w, http.StatusCreated, ruleToRow(rule))
	}
}

// OwnershipRulesUpdate handles PATCH /api/v1/ownership-rules/{id}.
func OwnershipRulesUpdate(deps OwnershipDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		ruleID := strings.TrimSpace(r.PathValue("id"))
		if ruleID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "rule id required")
			return
		}
		var body updateOwnershipRuleRequest
		if err := envelope.DecodeStrictOptionalJSON(w, r, &body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
		rule, err := deps.Service.UpdateRule(r.Context(), ownership.UpdateRuleInput{
			OrganizationID: user.OrganizationID,
			ActorUserID:    user.ID,
			RuleID:         ruleID,
			Description:    body.Description,
			MatchValue:     body.MatchValue,
			Priority:       body.Priority,
		})
		if err != nil {
			if writeOwnershipRuleError(w, err) {
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not update ownership rule")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, ruleToRow(rule))
	}
}

// OwnershipRulesEnable handles POST /api/v1/ownership-rules/{id}/enable.
func OwnershipRulesEnable(deps OwnershipDeps) http.HandlerFunc {
	return ruleEnableDisable(deps, true)
}

// OwnershipRulesDisable handles POST /api/v1/ownership-rules/{id}/disable.
func OwnershipRulesDisable(deps OwnershipDeps) http.HandlerFunc {
	return ruleEnableDisable(deps, false)
}

func ruleEnableDisable(deps OwnershipDeps, enable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		ruleID := strings.TrimSpace(r.PathValue("id"))
		if ruleID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "rule id required")
			return
		}
		var (
			rule *governance.OwnershipRule
			err  error
		)
		if enable {
			rule, err = deps.Service.EnableRule(r.Context(), user.OrganizationID, user.ID, ruleID)
		} else {
			rule, err = deps.Service.DisableRule(r.Context(), user.OrganizationID, user.ID, ruleID)
		}
		if err != nil {
			if writeOwnershipRuleError(w, err) {
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError, "internal_error", "could not change ownership rule state")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, ruleToRow(rule))
	}
}

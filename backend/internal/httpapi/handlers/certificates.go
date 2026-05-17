package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/middleware"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// CertificatesDeps bundles the dependencies the operator-facing
// certificate read handlers (H-020) need. CLAUDE.md §8.8:
// constructor-based DI, no globals.
type CertificatesDeps struct {
	Service *inventory.Service
}

// certificateSummaryRow is the slim wire shape for the
// `/certificates` list response. PEM, SANs, and key-usage arrays
// are deliberately excluded so list payloads stay small at fleet
// scale; the per-cert detail endpoint exposes them.
type certificateSummaryRow struct {
	ID                     string `json:"id"`
	FingerprintSHA256      string `json:"fingerprint_sha256"`
	Subject                string `json:"subject"`
	Issuer                 string `json:"issuer"`
	SerialNumberHex        string `json:"serial_number_hex"`
	SignatureAlgorithm     string `json:"signature_algorithm"`
	PublicKeyAlgorithm     string `json:"public_key_algorithm"`
	PublicKeyBits          int    `json:"public_key_bits"`
	NotBefore              string `json:"not_before"`
	NotAfter               string `json:"not_after"`
	IsSelfSigned           bool   `json:"is_self_signed"`
	IsCA                   bool   `json:"is_ca"`
	FirstSeenAt            string `json:"first_seen_at"`
	LastSeenAt             string `json:"last_seen_at"`
	ObservationCount       int    `json:"observation_count"`
	ActiveObservationCount int    `json:"active_observation_count"`
}

// certificateListResponse follows the documented v0.1 list
// envelope `{items, next_cursor}` (REST_API.md "Pagination").
type certificateListResponse struct {
	Items      []certificateSummaryRow `json:"items"`
	NextCursor *string                 `json:"next_cursor"`
}

// certificateDetailResponse is the wire shape for
// `GET /certificates/{id}`. Includes the full PEM and the
// normalized field set; observation counts mirror the list row.
type certificateDetailResponse struct {
	ID                     string   `json:"id"`
	FingerprintSHA256      string   `json:"fingerprint_sha256"`
	Subject                string   `json:"subject"`
	Issuer                 string   `json:"issuer"`
	SerialNumberHex        string   `json:"serial_number_hex"`
	SignatureAlgorithm     string   `json:"signature_algorithm"`
	PublicKeyAlgorithm     string   `json:"public_key_algorithm"`
	PublicKeyBits          int      `json:"public_key_bits"`
	NotBefore              string   `json:"not_before"`
	NotAfter               string   `json:"not_after"`
	SANs                   []string `json:"sans"`
	KeyUsages              []string `json:"key_usages"`
	ExtKeyUsages           []string `json:"ext_key_usages"`
	IsSelfSigned           bool     `json:"is_self_signed"`
	IsCA                   bool     `json:"is_ca"`
	PEM                    string   `json:"pem"`
	FirstSeenAt            string   `json:"first_seen_at"`
	LastSeenAt             string   `json:"last_seen_at"`
	ObservationCount       int      `json:"observation_count"`
	ActiveObservationCount int      `json:"active_observation_count"`
}

// observationRow is one row of the
// `/certificates/{id}/observations` list response.
type observationRow struct {
	ID            string  `json:"id"`
	AgentID       string  `json:"agent_id"`
	Hostname      string  `json:"hostname"`
	StoreLocation string  `json:"store_location"`
	FriendlyName  string  `json:"friendly_name"`
	FirstSeenAt   string  `json:"first_seen_at"`
	LastSeenAt    string  `json:"last_seen_at"`
	RemovedAt     *string `json:"removed_at"`
	Status        string  `json:"status"`
}

type observationListResponse struct {
	Items      []observationRow `json:"items"`
	NextCursor *string          `json:"next_cursor"`
}

// CertificatesList handles GET /api/v1/certificates.
//
// Operator-only — the route is wrapped with middleware.RequireAuth
// in the router. Agent bearer credentials are NOT honored
// (operator and agent identity remain separate axes per
// CLAUDE.md §8.6).
//
// Org scoping: organization_id comes from the authenticated
// operator session, NEVER from a query param. The repository's
// SQL WHERE clause filters on the same id, so cross-org rows
// cannot surface.
//
// Filters (all optional):
//
//	q                — substring match (subject/issuer/fingerprint/SANs)
//	expiring_before  — RFC3339; returns certs with not_after < value
//	is_ca            — boolean
//	agent_id         — restrict to certs observed by this agent
//	current_only     — boolean; default TRUE (excludes certs whose
//	                   only observations have removed_at IS NOT NULL)
//	cursor, limit    — H-010 cursor pagination
//
// Audit policy: read-only. No audit row is emitted (CLAUDE.md §9
// — audits record state changes; a list call does not change
// state).
func CertificatesList(deps CertificatesDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}

		in, err := parseCertificatesListQuery(r, user.OrganizationID)
		if err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"invalid certificate list query")
			return
		}
		out, err := deps.Service.ListCertificates(r.Context(), in)
		if err != nil {
			if errors.Is(err, inventory.ErrInvalidListInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"invalid certificate list query")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not list certificates")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, certificateListToResponse(out))
	}
}

// CertificatesGet handles GET /api/v1/certificates/{id}.
//
// Operator-only, org-scoped. Cross-org or missing id maps to
// 404 not_found — same envelope a truly-missing id produces, so
// operators cannot enumerate cross-org certs (CLAUDE.md §6).
func CertificatesGet(deps CertificatesDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		certID := r.PathValue("id")
		if certID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"certificate id required")
			return
		}

		detail, err := deps.Service.GetCertificateDetail(r.Context(),
			user.OrganizationID, certID)
		if err != nil {
			if errors.Is(err, inventory.ErrCertificateNotFound) {
				envelope.WriteError(w, http.StatusNotFound, "not_found",
					"certificate not found")
				return
			}
			if errors.Is(err, inventory.ErrInvalidListInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"invalid certificate request")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not read certificate")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, certificateDetailToResponse(detail))
	}
}

// CertificateObservationsList handles
// GET /api/v1/certificates/{id}/observations.
//
// Operator-only, org-scoped. Cross-org or missing certificate_id
// maps to 404 not_found via the service's pre-check on
// GetCertificate.
//
// Filters: current_only (default TRUE), cursor, limit.
func CertificateObservationsList(deps CertificatesDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}
		certID := r.PathValue("id")
		if certID == "" {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"certificate id required")
			return
		}

		in, err := parseObservationsListQuery(r, user.OrganizationID, certID)
		if err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"invalid observation list query")
			return
		}
		out, err := deps.Service.ListCertificateObservations(r.Context(), in)
		if err != nil {
			if errors.Is(err, inventory.ErrCertificateNotFound) {
				envelope.WriteError(w, http.StatusNotFound, "not_found",
					"certificate not found")
				return
			}
			if errors.Is(err, inventory.ErrInvalidListInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"invalid observation list query")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not list observations")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, observationsToResponse(out))
	}
}

// AgentCertificatesList handles GET /api/v1/agents/{id}/certificates.
//
// Operator-only, org-scoped. Cross-org or missing agent_id maps
// to 404 not_found via the service's AgentExistsInOrg pre-check —
// distinguished from "agent exists with zero certs" which returns
// 200 with empty items.
func AgentCertificatesList(deps CertificatesDeps) http.HandlerFunc {
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

		in, err := parseCertificatesListQuery(r, user.OrganizationID)
		if err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"invalid certificate list query")
			return
		}
		// Path-bound agent_id wins over any query param of the
		// same name — the URL is the explicit binding.
		in.AgentID = agentID

		out, err := deps.Service.ListAgentCertificates(r.Context(), in)
		if err != nil {
			if errors.Is(err, inventory.ErrAgentNotFound) {
				envelope.WriteError(w, http.StatusNotFound, "not_found",
					"agent not found")
				return
			}
			if errors.Is(err, inventory.ErrInvalidListInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"invalid certificate list query")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not list agent certificates")
			return
		}
		envelope.WriteJSON(w, http.StatusOK, certificateListToResponse(out))
	}
}

// --- query parsers -------------------------------------------------

// parseCertificatesListQuery turns URL query parameters into a
// validated inventory.ListCertificatesInput. The HTTP layer owns
// the bool / int / time parsing; the service trusts what it is
// handed. current_only defaults to TRUE when the parameter is
// absent (per CERTIFICATE_INVENTORY.md §12).
func parseCertificatesListQuery(r *http.Request, organizationID string) (inventory.ListCertificatesInput, error) {
	qs := r.URL.Query()

	currentOnly, err := parseBoolQueryDefault(qs.Get("current_only"), true)
	if err != nil {
		return inventory.ListCertificatesInput{}, err
	}
	isCA, err := parseOptionalBoolQuery(qs.Get("is_ca"))
	if err != nil {
		return inventory.ListCertificatesInput{}, err
	}
	expiringBefore, err := parseOptionalRFC3339Query(qs.Get("expiring_before"))
	if err != nil {
		return inventory.ListCertificatesInput{}, err
	}
	limit, err := parseLimitQuery(qs.Get("limit"))
	if err != nil {
		return inventory.ListCertificatesInput{}, err
	}

	return inventory.ListCertificatesInput{
		OrganizationID: organizationID,
		Search:         strings.TrimSpace(qs.Get("q")),
		ExpiringBefore: expiringBefore,
		IsCA:           isCA,
		AgentID:        strings.TrimSpace(qs.Get("agent_id")),
		CurrentOnly:    currentOnly,
		Limit:          limit,
		Cursor:         qs.Get("cursor"),
	}, nil
}

// parseObservationsListQuery is the same idea for the observation
// list endpoint. current_only defaults to TRUE.
func parseObservationsListQuery(r *http.Request, organizationID, certificateID string) (inventory.ListObservationsInput, error) {
	qs := r.URL.Query()

	currentOnly, err := parseBoolQueryDefault(qs.Get("current_only"), true)
	if err != nil {
		return inventory.ListObservationsInput{}, err
	}
	limit, err := parseLimitQuery(qs.Get("limit"))
	if err != nil {
		return inventory.ListObservationsInput{}, err
	}

	return inventory.ListObservationsInput{
		OrganizationID: organizationID,
		CertificateID:  certificateID,
		CurrentOnly:    currentOnly,
		Limit:          limit,
		Cursor:         qs.Get("cursor"),
	}, nil
}

// parseBoolQueryDefault parses an explicit "true"/"false" string.
// Empty returns the supplied default. Anything else is rejected.
func parseBoolQueryDefault(raw string, def bool) (bool, error) {
	if raw == "" {
		return def, nil
	}
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, errors.New("invalid boolean query param")
}

// parseOptionalBoolQuery returns nil for empty input, *bool
// otherwise. Same accepted values as parseBoolQueryDefault.
func parseOptionalBoolQuery(raw string) (*bool, error) {
	if raw == "" {
		return nil, nil
	}
	switch raw {
	case "true":
		t := true
		return &t, nil
	case "false":
		f := false
		return &f, nil
	}
	return nil, errors.New("invalid boolean query param")
}

// parseOptionalRFC3339Query returns nil for empty input, a parsed
// *time.Time otherwise. Invalid values are rejected.
func parseOptionalRFC3339Query(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// --- response shaping ----------------------------------------------

func certificateListToResponse(out *inventory.ListCertificatesOutput) certificateListResponse {
	items := make([]certificateSummaryRow, 0, len(out.Items))
	for _, row := range out.Items {
		items = append(items, certificateSummaryToRow(row))
	}
	var nextCursor *string
	if out.NextCursor != "" {
		c := out.NextCursor
		nextCursor = &c
	}
	return certificateListResponse{Items: items, NextCursor: nextCursor}
}

func certificateSummaryToRow(s inventory.CertificateSummary) certificateSummaryRow {
	return certificateSummaryRow{
		ID:                     s.ID,
		FingerprintSHA256:      s.FingerprintSHA256,
		Subject:                s.Subject,
		Issuer:                 s.Issuer,
		SerialNumberHex:        s.SerialNumberHex,
		SignatureAlgorithm:     s.SignatureAlg,
		PublicKeyAlgorithm:     s.PublicKeyAlg,
		PublicKeyBits:          s.PublicKeyBits,
		NotBefore:              s.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:               s.NotAfter.UTC().Format(time.RFC3339),
		IsSelfSigned:           s.IsSelfSigned,
		IsCA:                   s.IsCA,
		FirstSeenAt:            s.FirstSeenAt.UTC().Format(time.RFC3339),
		LastSeenAt:             s.LastSeenAt.UTC().Format(time.RFC3339),
		ObservationCount:       s.ObservationCount,
		ActiveObservationCount: s.ActiveObservationCount,
	}
}

func certificateDetailToResponse(d *inventory.CertificateDetail) certificateDetailResponse {
	c := d.Certificate
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	keyUsages := c.KeyUsages
	if keyUsages == nil {
		keyUsages = []string{}
	}
	extKeyUsages := c.ExtKeyUsages
	if extKeyUsages == nil {
		extKeyUsages = []string{}
	}
	return certificateDetailResponse{
		ID:                     c.ID,
		FingerprintSHA256:      c.FingerprintSHA256,
		Subject:                c.Subject,
		Issuer:                 c.Issuer,
		SerialNumberHex:        c.SerialNumberHex,
		SignatureAlgorithm:     c.SignatureAlg,
		PublicKeyAlgorithm:     c.PublicKeyAlg,
		PublicKeyBits:          c.PublicKeyBits,
		NotBefore:              c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:               c.NotAfter.UTC().Format(time.RFC3339),
		SANs:                   sans,
		KeyUsages:              keyUsages,
		ExtKeyUsages:           extKeyUsages,
		IsSelfSigned:           c.IsSelfSigned,
		IsCA:                   c.IsCA,
		PEM:                    c.PEM,
		FirstSeenAt:            c.FirstSeenAt.UTC().Format(time.RFC3339),
		LastSeenAt:             c.LastSeenAt.UTC().Format(time.RFC3339),
		ObservationCount:       d.ObservationCount,
		ActiveObservationCount: d.ActiveObservationCount,
	}
}

func observationsToResponse(out *inventory.ListObservationsOutput) observationListResponse {
	items := make([]observationRow, 0, len(out.Items))
	for _, it := range out.Items {
		var removedAt *string
		if it.RemovedAt != nil {
			s := it.RemovedAt.UTC().Format(time.RFC3339)
			removedAt = &s
		}
		items = append(items, observationRow{
			ID:            it.ID,
			AgentID:       it.AgentID,
			Hostname:      it.Hostname,
			StoreLocation: it.StoreLocation,
			FriendlyName:  it.FriendlyName,
			FirstSeenAt:   it.FirstSeenAt.UTC().Format(time.RFC3339),
			LastSeenAt:    it.LastSeenAt.UTC().Format(time.RFC3339),
			RemovedAt:     removedAt,
			Status:        it.Status,
		})
	}
	var nextCursor *string
	if out.NextCursor != "" {
		c := out.NextCursor
		nextCursor = &c
	}
	return observationListResponse{Items: items, NextCursor: nextCursor}
}

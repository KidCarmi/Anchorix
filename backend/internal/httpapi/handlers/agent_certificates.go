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

// AgentCertificatesDeps bundles the dependencies the certificate
// ingestion handler needs. CLAUDE.md §8.8: constructor-based DI.
type AgentCertificatesDeps struct {
	Service *inventory.Service
}

// Per-field byte / count caps enforced by AgentCertificatesIngest.
// Values come from CERTIFICATE_INVENTORY.md §4 size limits. The
// handler enforces SHAPE caps (body size, count, per-field byte
// length); the service enforces SEMANTIC validation (private-key
// markers, PEM parse, store_coverage, duplicates, clock skew).
// Both rejection paths surface as 400 with the same generic
// envelope so callers cannot enumerate validation state (CLAUDE.md
// §6 deterministic auth) — except for the two agent-visible
// reasons CERTIFICATE_INVENTORY.md §4 commits to:
// private_key_rejected and certificate_unparseable.
const (
	// MaxCertificateBatchBodyBytes is the JSON body cap for the
	// ingestion endpoint. 4 MiB easily holds hundreds of certs at
	// ~2 KiB PEM each + JSON overhead, while bounding what a
	// single misbehaving agent can submit.
	MaxCertificateBatchBodyBytes int64 = 4 * 1024 * 1024
	MaxCertsPerBatch                   = 5000
	MaxCertPEMBytes                    = 32 * 1024
	MaxStoreCoverageEntries            = 64
	MaxStoreLocationLength             = 255
	MaxFriendlyNameLength              = 255
)

// agentCertificateEntry is the per-entry wire format. The server
// parses CertificatePEM authoritatively — every other identifying
// field (fingerprint, subject, issuer, etc.) is derived from the
// PEM, not from the wire. The agent does NOT report them.
type agentCertificateEntry struct {
	StoreLocation  string `json:"store_location"`
	FriendlyName   string `json:"friendly_name,omitempty"`
	CertificatePEM string `json:"certificate_pem"`
}

// agentCertificatesRequest is the full POST body shape. agent_id /
// organization_id are NEVER on the wire — both come from
// AgentFromContext via the bearer credential.
type agentCertificatesRequest struct {
	CollectedAt   time.Time               `json:"collected_at"`
	StoreCoverage []string                `json:"store_coverage"`
	Certificates  []agentCertificateEntry `json:"certificates"`
}

// agentCertificatesResponse is the JSON envelope returned on a
// successful ingestion. Mirrors CERTIFICATE_INVENTORY.md §4.
//
// `accepted` is the number of (cert, store) observations upserted;
// `reconciled_absent` is the number of pre-existing observations
// in the declared store_coverage that the batch did NOT include
// and that consequently transitioned to removed_at.
type agentCertificatesResponse struct {
	Status           string `json:"status"`
	ReceivedAt       string `json:"received_at"`
	Accepted         int    `json:"accepted"`
	ReconciledAbsent int    `json:"reconciled_absent"`
}

// AgentCertificatesIngest handles POST /api/v1/agent/certificates.
//
// Authenticated-agent only — the route is wrapped with
// middleware.RequireAuthenticatedAgent in the router. Operator
// session cookies are NOT honored. Identity (agent_id,
// organization_id) comes from AgentFromContext; the request body
// CANNOT override it (CERTIFICATE_INVENTORY.md §4 / CLAUDE.md §6.8
// default deny).
//
// Validation runs in two layers:
//
//   - this handler: SHAPE caps (per-field byte length, count
//     limits, body size cap via the shared
//     envelope.DecodeStrictOptionalJSON helper). Failures →
//     400 bad_request.
//   - the inventory.Service: SEMANTIC validation (private-key
//     marker scan, PEM parse, store_coverage / duplicate /
//     clock-skew). Failures → 400 bad_request, with two specific
//     code variants for the agent-visible reject reasons that
//     CERTIFICATE_INVENTORY.md §4 documents:
//     400 private_key_rejected   — private-key material detected
//     400 certificate_unparseable — at least one PEM didn't parse
//     Both rejections write an audit_events row inside the
//     service (severity:"security" for private-key); audit
//     failures surface as 500.
//
// Audit policy: successful batches do NOT emit audit rows
// (CERTIFICATE_INVENTORY.md §6 cardinality argument). Failed
// authentication is already audited by the H-007 middleware.
func AgentCertificatesIngest(deps AgentCertificatesDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agent := middleware.AgentFromContext(r.Context())
		if agent == nil {
			// Defensive: RequireAuthenticatedAgent should have
			// blocked unauthenticated requests. Fail closed.
			envelope.WriteError(w, http.StatusUnauthorized,
				"agent_unauthorized", "agent authentication required")
			return
		}

		// Strict body decode: empty body NOT valid (the request
		// must carry at minimum collected_at + store_coverage),
		// but the shared helper's "empty body OK" semantics are
		// compatible — we explicitly check for non-empty
		// store_coverage below, which an empty body's
		// zero-valued struct will fail.
		//
		// MaxJSONBodyBytes = 64 KiB in the shared helper; the
		// certificate-ingestion endpoint may legitimately submit
		// hundreds of certs × multi-KiB PEMs, so we use a larger
		// cap dedicated to this endpoint.
		var body agentCertificatesRequest
		if err := envelope.DecodeStrictJSONWithLimit(w, r, &body, MaxCertificateBatchBodyBytes); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}

		// Shape caps. Each individual cap is a 400 bad_request;
		// the specific cause is NOT exposed on the wire (callers
		// cannot enumerate which cap they hit).
		if err := validateRequestShape(body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request",
				"certificate batch input invalid")
			return
		}

		in := inventory.IngestionInput{
			OrganizationID: agent.OrganizationID,
			AgentID:        agent.AgentID,
			CollectedAt:    body.CollectedAt,
			StoreCoverage:  body.StoreCoverage,
			Certificates:   convertCertificates(body.Certificates),
		}
		out, err := deps.Service.Submit(r.Context(), in)
		if err != nil {
			switch {
			case errors.Is(err, inventory.ErrPrivateKeyMaterial):
				envelope.WriteError(w, http.StatusBadRequest, "private_key_rejected",
					"private key material is not accepted")
				return
			case errors.Is(err, inventory.ErrInvalidCertificate):
				envelope.WriteError(w, http.StatusBadRequest, "certificate_unparseable",
					"one or more certificates could not be parsed")
				return
			case errors.Is(err, inventory.ErrInvalidBatch):
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"certificate batch input invalid")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not record certificate batch")
			return
		}

		envelope.WriteJSON(w, http.StatusOK, agentCertificatesResponse{
			Status:           "ok",
			ReceivedAt:       time.Now().UTC().Format(time.RFC3339),
			Accepted:         out.Accepted,
			ReconciledAbsent: out.ReconciledAbsent,
		})
	}
}

// validateRequestShape enforces the per-field byte / count caps the
// service does not need to know about. Returns a generic sentinel
// — the handler maps to 400 bad_request without echoing the
// specific cap to the wire.
func validateRequestShape(body agentCertificatesRequest) error {
	if len(body.StoreCoverage) == 0 {
		return errors.New("store_coverage required")
	}
	if len(body.StoreCoverage) > MaxStoreCoverageEntries {
		return errors.New("store_coverage too large")
	}
	for _, s := range body.StoreCoverage {
		if len(s) == 0 || len(s) > MaxStoreLocationLength {
			return errors.New("store_coverage entry length out of range")
		}
	}
	if len(body.Certificates) == 0 {
		return errors.New("certificates required")
	}
	if len(body.Certificates) > MaxCertsPerBatch {
		return errors.New("certificates count exceeds cap")
	}
	for _, c := range body.Certificates {
		if len(c.StoreLocation) == 0 || len(c.StoreLocation) > MaxStoreLocationLength {
			return errors.New("certificate store_location length out of range")
		}
		if len(c.FriendlyName) > MaxFriendlyNameLength {
			return errors.New("certificate friendly_name too long")
		}
		if len(c.CertificatePEM) == 0 || len(c.CertificatePEM) > MaxCertPEMBytes {
			return errors.New("certificate PEM length out of range")
		}
	}
	return nil
}

// convertCertificates maps the wire DTOs to the service's
// IngestionCertificate type, trimming whitespace on the
// per-entry descriptive fields (store_location, friendly_name).
// CertificatePEM is NOT trimmed — the parser normalizes it
// authoritatively, and pre-trimming here would silently mask
// agents that submit padding around their PEM blocks.
func convertCertificates(in []agentCertificateEntry) []inventory.IngestionCertificate {
	out := make([]inventory.IngestionCertificate, 0, len(in))
	for _, c := range in {
		out = append(out, inventory.IngestionCertificate{
			StoreLocation:  strings.TrimSpace(c.StoreLocation),
			FriendlyName:   strings.TrimSpace(c.FriendlyName),
			CertificatePEM: c.CertificatePEM,
		})
	}
	return out
}

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

// DeploymentPackageDeps bundles the dependencies the deployment-
// package handlers need. CLAUDE.md §8.8: constructor-based DI;
// handlers are returned by factory functions, never by init() or
// globals.
type DeploymentPackageDeps struct {
	Service       *enrollment.Service
	PublicBaseURL string
}

// deploymentPackageRequest is the JSON body for
// POST /api/v1/deployment-packages. Field names are the public
// HTTP contract — see docs/api/REST_API.md.
type deploymentPackageRequest struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	PackageType      string   `json:"package_type"`
	AgentVersion     string   `json:"agent_version"`
	TTLSeconds       int      `json:"ttl_seconds"`
	MaxUses          int      `json:"max_uses"`
	DefaultGroupName string   `json:"default_group_name"`
	DefaultLabels    []string `json:"default_labels"`
}

// deploymentPackageResponse is the JSON returned on a successful
// create. The bootstrap_secret field appears here ONCE per package
// and is never echoed by any other endpoint.
type deploymentPackageResponse struct {
	ID                string            `json:"id"`
	OrganizationID    string            `json:"organization_id"`
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	PackageType       string            `json:"package_type"`
	AgentVersion      string            `json:"agent_version"`
	MaxUses           int               `json:"max_uses"`
	UsesCount         int               `json:"uses_count"`
	ExpiresAt         string            `json:"expires_at"`
	CreatedAt         string            `json:"created_at"`
	DefaultGroupName  string            `json:"default_group_name,omitempty"`
	DefaultLabels     []string          `json:"default_labels,omitempty"`
	BootstrapSecret   string            `json:"bootstrap_secret"`
	BootstrapMetadata bootstrapMetadata `json:"bootstrap_metadata"`
}

// bootstrapMetadata carries the small handful of values an installer
// needs to know to call /api/v1/agents/enroll. It is returned
// alongside the package response so the future installer-package
// generator does not have to look anything up server-side after
// creation.
type bootstrapMetadata struct {
	ControlPlaneURL string `json:"control_plane_url"`
	OrganizationID  string `json:"organization_id"`
	PackageID       string `json:"package_id"`
	ExpiresAt       string `json:"expires_at"`
	MaxUses         int    `json:"max_uses"`
}

// DeploymentPackagesCreate handles POST /api/v1/deployment-packages.
// Admin-only — the route is wrapped with middleware.RequireAdmin in
// the router. The response includes the plaintext bootstrap secret
// EXACTLY ONCE; the server never has the plaintext after this
// response is written.
func DeploymentPackagesCreate(deps DeploymentPackageDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.UserFromContext(r.Context())
		if user == nil {
			// RequireAdmin guards the route, so this should never
			// happen. Defensive 401 keeps a misconfigured router
			// from leaking an internal-error envelope.
			envelope.WriteError(w, http.StatusUnauthorized,
				"unauthorized", "authentication required")
			return
		}

		var body deploymentPackageRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			envelope.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}

		out, err := deps.Service.CreatePackage(r.Context(), enrollment.CreatePackageInput{
			OrganizationID:   user.OrganizationID,
			CreatedByUserID:  user.ID,
			Name:             strings.TrimSpace(body.Name),
			Description:      strings.TrimSpace(body.Description),
			PackageType:      enrollment.PackageType(strings.TrimSpace(body.PackageType)),
			AgentVersion:     strings.TrimSpace(body.AgentVersion),
			TTL:              time.Duration(body.TTLSeconds) * time.Second,
			MaxUses:          body.MaxUses,
			DefaultGroupName: strings.TrimSpace(body.DefaultGroupName),
			DefaultLabels:    body.DefaultLabels,
		})
		if err != nil {
			if errors.Is(err, enrollment.ErrInvalidPackageInput) {
				envelope.WriteError(w, http.StatusBadRequest, "bad_request",
					"deployment package input invalid")
				return
			}
			envelope.WriteError(w, http.StatusInternalServerError,
				"internal_error", "could not create deployment package")
			return
		}

		resp := deploymentPackageResponse{
			ID:               out.Package.ID,
			OrganizationID:   out.Package.OrganizationID,
			Name:             out.Package.Name,
			Description:      out.Package.Description,
			PackageType:      string(out.Package.PackageType),
			AgentVersion:     out.Package.AgentVersion,
			MaxUses:          out.Package.MaxUses,
			UsesCount:        out.Package.UsesCount,
			ExpiresAt:        out.Package.ExpiresAt.UTC().Format(time.RFC3339),
			CreatedAt:        out.Package.CreatedAt.UTC().Format(time.RFC3339),
			DefaultGroupName: out.Package.DefaultGroupName,
			DefaultLabels:    out.Package.DefaultLabels,
			BootstrapSecret:  out.BootstrapSecret,
			BootstrapMetadata: bootstrapMetadata{
				ControlPlaneURL: deps.PublicBaseURL,
				OrganizationID:  out.Package.OrganizationID,
				PackageID:       out.Package.ID,
				ExpiresAt:       out.Package.ExpiresAt.UTC().Format(time.RFC3339),
				MaxUses:         out.Package.MaxUses,
			},
		}
		envelope.WriteJSON(w, http.StatusCreated, resp)
	}
}

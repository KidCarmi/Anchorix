// Package transport is the agent-side HTTPS client to the control plane.
//
// The client pins the control plane's certificate fingerprint after
// enrollment and refuses to talk to a different one (CLAUDE.md §11).
package transport

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Client is a thin wrapper over net/http with timeouts and pinned trust.
type Client struct {
	baseURL     string
	httpClient  *http.Client
	bearerToken string
	pinnedSPKI  string // base64 SHA-256 of control plane SPKI; pinned after enrollment
}

// New constructs a Client. Concrete TLS pinning, retries, and bearer-token
// signing are wired in Phase 2.
func New(baseURL string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// SetBearer attaches the bearer token issued at enrollment.
func (c *Client) SetBearer(token string) { c.bearerToken = token }

// SetPinnedSPKI configures the control plane's pinned key fingerprint.
func (c *Client) SetPinnedSPKI(fp string) { c.pinnedSPKI = fp }

// Heartbeat is a placeholder for the real heartbeat call (Phase 3).
func (c *Client) Heartbeat(_ context.Context) error {
	return errors.New("heartbeat not yet implemented (Phase 3)")
}

// UploadInventory is a placeholder for the real inventory upload (Phase 3).
func (c *Client) UploadInventory(_ context.Context) error {
	return errors.New("upload inventory not yet implemented (Phase 3)")
}

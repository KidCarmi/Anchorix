package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/kidcarmi/anchorix/backend/internal/enrollment"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
)

// AgentAuthenticator is the dependency consumed by the agent-auth
// middleware. The single implementation is enrollment.Service —
// declaring the interface here (not in the enrollment package)
// keeps it owned by the consumer per CLAUDE.md §8.8.
type AgentAuthenticator interface {
	AuthenticateAgent(ctx context.Context, in enrollment.AuthenticateAgentInput) (*enrollment.AuthenticatedAgent, error)
}

// agentCtxKey is the unexported context key for the authenticated
// agent principal. Distinct from the operator session ctxKey
// constants so operator and agent identities can never collide on
// a single request — and so a misuse like reading the operator
// user out of a /agent/me request returns nil rather than a
// confusing mismatched type assertion.
type agentCtxKey int

const ctxKeyAgent agentCtxKey = iota

// AgentFromContext returns the authenticated agent attached by
// RequireAuthenticatedAgent, or nil if no agent is bound to ctx.
// Handlers behind RequireAuthenticatedAgent can rely on a non-nil
// return; defensive nil checks are still cheap insurance.
func AgentFromContext(ctx context.Context) *enrollment.AuthenticatedAgent {
	v, _ := ctx.Value(ctxKeyAgent).(*enrollment.AuthenticatedAgent)
	return v
}

// RequireAuthenticatedAgent guards an http.Handler so only requests
// carrying a valid Authorization: Bearer <agent_credential> header
// pass through. Every failure mode (missing header, malformed
// scheme, empty token, unknown credential, disabled agent)
// collapses to a single deterministic 401 envelope so the caller
// cannot enumerate state (CLAUDE.md §6 deterministic auth).
//
// The middleware is DELIBERATELY independent of the operator
// session resolver — operator cookies are not consulted, and a
// successful agent auth does not populate UserFromContext.
// Operator vs. agent identity are separate axes (CLAUDE.md §8.6
// decoupling).
func RequireAuthenticatedAgent(authenticator AgentAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plaintext, headerRejection := parseBearer(r.Header.Get("Authorization"))

			input := enrollment.AuthenticateAgentInput{
				AgentCredential: plaintext,
				HeaderRejection: headerRejection,
				RequestID:       r.Header.Get("X-Request-Id"),
				RemoteAddr:      r.RemoteAddr,
			}
			// IMPORTANT: AuthenticateAgent is called on EVERY path,
			// including malformed-header paths, so the security
			// audit feed records header_missing /
			// header_wrong_scheme / header_empty_token rejections
			// the same way it records credential_unknown and
			// agent_status_* rejections. Returning 401 before the
			// service call would leave a blind spot for the most
			// common probing patterns (CLAUDE.md §9).
			agent, err := authenticator.AuthenticateAgent(r.Context(), input)
			if err != nil {
				if errors.Is(err, enrollment.ErrAgentAuthenticationFailed) {
					envelope.WriteError(w, http.StatusUnauthorized,
						"agent_unauthorized", "agent authentication required")
					return
				}
				envelope.WriteError(w, http.StatusInternalServerError,
					"internal_error", "agent authentication failed")
				return
			}

			ctx := context.WithValue(r.Context(), ctxKeyAgent, agent)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// parseBearer parses the Authorization header and returns the
// token portion of a Bearer scheme. The scheme name is matched
// case-insensitively (RFC 6750 §2.1 specifies a case-insensitive
// scheme), but the rest of the header is taken verbatim.
//
// On failure, returns ("", reason) where reason is one of:
//
//   - "header_missing": no Authorization header at all
//   - "header_wrong_scheme": header present but not Bearer
//   - "header_empty_token": "Bearer" with no token after it
//
// The reason is passed through to the service via
// AuthenticateAgentInput.HeaderRejection so the audit feed
// distinguishes between the three probing patterns. The HTTP
// envelope remains the same generic 401 either way (CLAUDE.md
// §6 deterministic auth — no enumeration via error code).
func parseBearer(header string) (token, reason string) {
	const schemePrefix = "bearer "
	header = strings.TrimSpace(header)
	if header == "" {
		return "", "header_missing"
	}
	if len(header) < len(schemePrefix) ||
		!strings.EqualFold(header[:len(schemePrefix)], schemePrefix) {
		return "", "header_wrong_scheme"
	}
	token = strings.TrimSpace(header[len(schemePrefix):])
	if token == "" {
		return "", "header_empty_token"
	}
	return token, ""
}

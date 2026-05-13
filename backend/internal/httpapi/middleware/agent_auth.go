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
			plaintext, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				envelope.WriteError(w, http.StatusUnauthorized,
					"agent_unauthorized", "agent authentication required")
				return
			}

			agent, err := authenticator.AuthenticateAgent(r.Context(), enrollment.AuthenticateAgentInput{
				BootstrapCredential: plaintext,
				RequestID:           r.Header.Get("X-Request-Id"),
				RemoteAddr:          r.RemoteAddr,
			})
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

// bearerToken parses the Authorization header and returns the
// token portion of a Bearer scheme. The scheme name is matched
// case-insensitively (RFC 6750 §2.1 specifies a case-insensitive
// scheme), but the rest of the header is taken verbatim.
//
// Empty token, missing header, or non-Bearer scheme all return
// (_, false) — the middleware translates that into the standard
// 401 envelope without exposing which specific check failed.
func bearerToken(header string) (string, bool) {
	const schemePrefix = "bearer "
	header = strings.TrimSpace(header)
	if len(header) < len(schemePrefix) {
		return "", false
	}
	if !strings.EqualFold(header[:len(schemePrefix)], schemePrefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(schemePrefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

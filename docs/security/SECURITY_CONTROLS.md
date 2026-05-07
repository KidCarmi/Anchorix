# Security Controls — v0.1

A concise inventory of the controls Anchorix implements (or commits to
implementing within v0.1). Each control points at where it lives in code
or configuration.

## Authentication & Session

| Control                              | Where                                                  |
| ------------------------------------ | ------------------------------------------------------ |
| bcrypt password hashing              | `internal/auth` (Phase 1)                              |
| HttpOnly + Secure + SameSite cookies | `internal/httpapi/middleware.go`, `internal/auth`      |
| CSRF tokens for state-changing POSTs | `internal/httpapi/middleware.go` (Phase 1)             |
| Short-lived sessions w/ idle timeout | `sessions` table + `internal/auth` (Phase 1)           |
| Audit on login / logout              | `internal/audit`                                       |

## Agent Trust

| Control                                       | Where                                       |
| --------------------------------------------- | ------------------------------------------- |
| Single-use enrollment tokens, hashed at rest  | `agent_enrollment_tokens` table             |
| Agent generates key pair locally              | `agent/windows/internal/transport`          |
| Pinned control-plane TLS fingerprint          | `agent/windows/internal/transport/client.go`|
| No private key reads on the agent             | `agent/windows/internal/discovery`          |
| Server-side rejection of private-key payloads | `internal/inventory.rejectPrivateKeyMaterial` |

## Transport

| Control                                   | Where                                   |
| ----------------------------------------- | --------------------------------------- |
| HTTPS in production (proxy or process)    | `deploy/compose`, `Dockerfile`          |
| HSTS in production                        | `internal/httpapi/middleware.go`        |
| `X-Content-Type-Options: nosniff`         | `internal/httpapi/middleware.go`        |
| `X-Frame-Options: DENY`                   | `internal/httpapi/middleware.go`        |
| `Referrer-Policy: no-referrer`            | `internal/httpapi/middleware.go`        |

## Storage

| Control                                       | Where                          |
| --------------------------------------------- | ------------------------------ |
| Parameterized queries only                    | `internal/storage/postgres`    |
| Audit log immutability via DB triggers        | `migrations/0001_init.sql`     |
| No column for private key material            | `migrations/0001_init.sql`     |
| `organization_id` on every domain table       | `migrations/0001_init.sql`     |

## Secrets

| Control                                       | Where                                |
| --------------------------------------------- | ------------------------------------ |
| Centralized secret retrieval                  | `internal/providers/secrets`         |
| No plaintext secrets in code or repo          | `.gitignore`, repo policy            |
| Redaction in structured logs                  | `internal/logger/redact.go`          |

## Build & Release

| Control                                       | Status        |
| --------------------------------------------- | ------------- |
| `go vet` + `golangci-lint` in CI              | Phase 1       |
| `npm run lint` + `npm run typecheck` in CI    | Phase 1       |
| Container image CVE scan                      | Phase 6       |
| SBOM for releases                             | Phase 6       |
| Signed release artifacts                      | post-v0.1     |
| Secret scanning in CI (e.g. gitleaks)         | Phase 1       |

## Operational

| Control                                       | Where                                      |
| --------------------------------------------- | ------------------------------------------ |
| Structured JSON logs                          | `internal/logger`                          |
| Per-request `X-Request-Id` correlation        | `internal/httpapi/middleware.go`           |
| Liveness `/healthz` & readiness `/readyz`     | `internal/httpapi/handlers/health.go`      |
| Graceful shutdown on SIGTERM                  | `internal/httpapi/server.go`               |
| Distroless runtime image                      | `backend/Dockerfile`                       |

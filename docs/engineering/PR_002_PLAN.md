# PR-002 — Implementation Plan

**Status:** approved scope, not yet implemented.
**Owner:** to be assigned at PR-002 open.
**Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If this
plan and CLAUDE.md disagree, CLAUDE.md wins.

## Goal

Bring the control plane from "skeleton with no persistence" to a
walking-skeleton state where:

- a real PostgreSQL connection backs the process,
- migrations are applied through an explicit, repeatable runner,
- the auth domain has working session storage and an authenticating
  middleware,
- request identity propagates from HTTP edge to domain,
- `/readyz` reflects real database connectivity (and fails closed
  when the DB is unreachable),
- a fresh developer or fresh CI runner can bring the stack up
  end-to-end with a single deterministic startup path,
- every behavior added is covered by tests in CI.

## In Scope

| Area                              | Concrete deliverable                                                                     |
| --------------------------------- | ---------------------------------------------------------------------------------------- |
| **pgx wiring**                    | `internal/storage/postgres.{Open, Close, Ping, Tx}` backed by `*pgxpool.Pool`.           |
| **Migration runner**              | `cmd/anchorix migrate up` and `migrate status`, embed-loaded `migrations/*.sql`.         |
| **Repository implementations**    | Concrete `auth.Repository`, `agents.Repository` (skeletal, only what auth needs), and the `audit.Recorder` interface, all in `internal/storage/postgres/*.go`. Inventory and risks repositories stay stub-only in PR-002. |
| **Session storage**               | `sessions` table writes/reads owned by `internal/auth`; signed cookie carries the session id; cookie HMAC key from `cfg.SessionKey`. |
| **Auth middleware**               | `internal/httpapi/middleware/auth.go` resolves a session cookie to a `*auth.User`, attaches it to `context.Context`, and rejects expired / revoked sessions with the canonical envelope. |
| **Request identity propagation**  | `httpapi.RequestID` extended to also carry actor identity in context; the audit recorder reads both from context and never from globals. |
| **Readiness DB probe**            | `srv.Readiness().Register("postgres", db.Ping)` wired in `cmdServe`. Removes the "no probes registered" Phase-0 state. |
| **Integration tests**             | `backend/test/integration/` exercising the migration runner against a real PostgreSQL service container, the readiness probe in both ready and unready states, the session round-trip, and one full handler path through middleware → domain → repo → DB. |
| **Deterministic local startup**   | `make dev` brings postgres + api up, runs `migrate up`, applies the bootstrap admin (per `docs/BOOTSTRAP.md`), and waits until `/readyz` returns 200. |

## Out of Scope (deferred to later PRs)

The following are explicitly **not** in PR-002. Adding any of them
expands the review surface beyond what the user approved:

- RBAC UI, advanced auth flows (TOTP, WebAuthn, password reset email).
- SSO / OIDC / SAML.
- Agent enrollment UI or any frontend changes (the SPA stays as it
  is in PR-001's foundation).
- Renewal / revocation logic.
- Background workers, scheduled tasks, or any goroutine that is not
  the HTTP server itself.
- Async orchestration (queues, message buses).
- Kubernetes manifests, Helm charts, k8s probes.
- Linux agent.
- AI-assisted findings, anomaly detection, ML.
- Multi-tenancy beyond a single `organizations` row.

If a reviewer or an implementing PR finds itself reaching into any of
these, it pauses and asks before proceeding (CLAUDE.md §19).

## Architectural Constraints (binding)

PR-002 implementation is not free design. It must obey CLAUDE.md
§§8.6–8.11 and §§16–19 verbatim. Concrete implications:

1. **Storage layer ownership (§16).** All SQL lives in
   `internal/storage/postgres/*.go`. The migration runner does not
   contain business logic. Indexes added in PR-002 are documented in
   the migration that introduces them (none expected in PR-002 — the
   schema added in `migrations/0001_init.sql` already covers session
   storage).
2. **Decoupling (§8.6).** `httpapi/handlers/auth.go` does not import
   `storage/postgres`. It calls into a domain function that takes an
   `auth.Repository` interface; the concrete pgx repo is wired in
   `cmd/anchorix/main.go`.
3. **Constructor DI (§8.8).** Every new struct is created via
   `NewX(deps...)`. No package-level `var DB *pgxpool.Pool`. No init
   functions that mutate state.
4. **Configuration discipline (§8.9).** No new `os.Getenv` calls
   outside `internal/config`. The DB DSN, session-cookie name, and
   any new secrets are added to `internal/config/config.go` with
   validation. Startup fails closed on malformed values.
5. **Robustness (§18).** Every blocking call accepts
   `context.Context`. Login, session lookup, and migration apply all
   honor cancellation. The migration runner is idempotent and
   repeatable. Session creation is idempotent under retry.
6. **Concurrency (§8.10).** PR-002 introduces zero new goroutines
   beyond what `httpapi.Server.Run` already starts. Background
   loops, cache refresh, or async writers do **not** appear in this
   PR.
7. **Outbound clients (§8.11).** The control plane does not initiate
   outbound HTTP in PR-002. No `http.Client` constructed in this
   diff.
8. **API evolution (§17).** New endpoints (`/auth/login`,
   `/auth/logout`, `/auth/me`) are documented in
   `docs/api/REST_API.md` in the same PR. Error codes added
   (`unauthorized`, `session_expired`, `invalid_credentials`) are
   appended to the existing table; no existing code changes meaning.
9. **`doc.go` (§19).** New domain-bearing packages
   (`internal/auth/session`, `internal/storage/postgres`) get a
   `doc.go`. Trivial helper packages do not need one.

## Files Added

```
backend/
  cmd/anchorix/
    migrate.go                      # cmdMigrate full implementation
    serve.go                        # extracted from main.go — composition only
  internal/
    storage/
      postgres/
        doc.go
        db.go                        # Open / Close / Ping / Tx
        migrations.go                # //go:embed migrations/*.sql + runner
        agents_repository.go         # skeletal — only what auth flow needs
        auth_repository.go
        sessions_repository.go
        audit_repository.go
    auth/
      doc.go
      sessions.go                    # Session, SessionStore (interface)
      service.go                     # Login, Logout, Authenticate
      cookies.go                     # signed-cookie encode/decode
    httpapi/
      middleware/
        auth.go                      # session resolver middleware
  test/integration/
    integration_test.go              # shared TestMain + postgres service ctn helper
    migrations_test.go
    readiness_test.go
    auth_session_test.go
    request_identity_test.go
```

Approximate size: 700–900 LOC product code + 400–600 LOC tests. Stays
within CLAUDE.md §8.7 file-size guidance (each file < 500 LOC; each
function < 80 LOC).

## Files Modified

- `backend/cmd/anchorix/main.go` — `main()` becomes a thin dispatcher;
  per-subcommand bodies move to `cmdServe`/`cmdMigrate`/`cmdAdmin` in
  their own files (composition root only, §8.7). The wiring of pgx
  pool + repositories + services happens here.
- `backend/migrations/README.md` — adds the migration-runner usage
  paragraph and a note that `cmd/anchorix migrate up` is the canonical
  entry point.
- `docs/api/REST_API.md` — adds `/auth/login`, `/auth/logout`,
  `/auth/me` request/response shapes; appends new error codes.
- `backend/internal/config/config.go` — adds session cookie name, validates DB
  SSL mode in production (already partially present; tightens), adds
  bcrypt cost validation if a non-default value is provided.

## Files NOT Touched

- No agent code (`agent/windows/**`).
- No frontend code (`frontend/src/**`). The login UI lands in PR-003.
- PR-002 may modify `ci.yml` only to add the PostgreSQL service
  container and integration-test step to the existing
  `backend (go)` job. No new workflow files or required-check
  names are added. Design lives in
  [`CI_PLAN.md`](./CI_PLAN.md).
- No new dependencies beyond `github.com/jackc/pgx/v5`. Lockfile and
  obituary scope unchanged. (`pgx` is the only Go third-party dep
  the project will adopt in PR-002; the foundation has been stdlib-only
  until now.)
- No CLAUDE.md changes.
- No `.depobituaryignore` changes.

## Test Plan

Required by CLAUDE.md §11 + [`TESTING_STRATEGY.md`](./TESTING_STRATEGY.md):

| Tier            | Lives at                                  | Required for PR-002                                                                           |
| --------------- | ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| **Unit**        | `_test.go` next to code                   | session encoder; cookie sign/verify; password hash & compare; migration parser                |
| **Integration** | `backend/test/integration/`                | migration runner end-to-end; `Ping`/`/readyz` ready & unready; login → cookie → /me; audit row written; idempotent migrate up |
| **Smoke**       | existing `docker (config + build + smoke)` | extends to: stack up + `migrate up` + `/readyz` returns 200 (replaces today's no-probes state) |

All tests are deterministic. No `time.Sleep`, no network egress beyond
the postgres service container. The integration package uses an
injected `clock.Clock`, never `time.Now()`.

## Acceptance Criteria

PR-002 is done when:

1. `make dev` (a fresh checkout, fresh postgres) brings the stack up
   end-to-end and `curl http://localhost:8080/readyz` returns
   `{"status":"ready","checks":{"postgres":"ok"}}`.
2. Stopping postgres and re-hitting `/readyz` returns HTTP 503 with
   `{"status":"unready","checks":{"postgres":"error: ..."}}`.
3. `anchorix admin create --email alice@example.com` (per
   `docs/BOOTSTRAP.md`) succeeds, prints the generated password once,
   and writes one user row.
4. `POST /api/v1/auth/login` returns a session cookie; subsequent
   `GET /api/v1/auth/me` returns the profile; `POST /api/v1/auth/logout`
   revokes the session and a follow-up `GET /api/v1/auth/me` returns
   401.
5. An `audit_events` row is written for each login, logout, and admin
   creation.
6. CI (all 14 blocking gates) passes on the PR's HEAD commit.

## Sequencing

PR-002 is a **single PR**. Splitting further (e.g. DB-only first,
auth second) would leave `/readyz` registering a probe with nothing
to authenticate, which is not a useful intermediate state and would
require revert-style follow-up work. The bundled scope is small
enough (under ~1.5k LOC including tests) to review in one sitting.

PR-003 picks up the login UI on the frontend; PR-004 picks up agent
enrollment.

## Open Questions

1. **bcrypt cost.** Default 12 unless the user prefers stronger.
   Configurable via `ANCHORIX_AUTH_BCRYPT_COST` with bounds [10, 14].
2. **Session lifetime.** Proposed 8h idle / 24h absolute, both
   configurable via `internal/config`. Defaults align with §8.9
   (no silent fallback for security-sensitive settings).
3. **`pgx` major version.** Proposed v5 (current stable, native
   support for cancellation, structured logger interface). Falls
   under §8.11 outbound-client rules even though the database is
   "internal" — same retry/timeout/structured-error discipline.

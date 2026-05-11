# Testing Strategy

**Source of truth for binding rules:** [`CLAUDE.md`](../../CLAUDE.md).
This document describes **what** to test and **where** it lives. It
does not redefine any rule — every `MUST` below maps to a CLAUDE.md
section.

## Tier Model

```
Tier 1  Unit                  fastest, lowest scope, every package owns its own
Tier 2  Backend integration   real DB + real HTTP, in-process
Tier 3  Frontend tests        vitest + jsdom, no real network
Tier 4  Smoke / e2e           docker compose up, real binaries
Tier 5  Windows e2e           windows-latest runner, real agent + real control plane
```

Each tier runs in CI; the higher the tier, the smaller the test
count and the broader each test's scope.

## Tier 1 — Unit Tests (Backend)

**Lives at:** `<package>/_test.go` next to the code. Same package
unless using `_test` package for black-box only when a public API
demands it.

**Required for every package** that exposes domain behavior. Trivial
helper packages (e.g. `clock`, `ids`) carry minimal tests but still
have a smoke test for any non-obvious branch.

**Required coverage areas (per CLAUDE.md §19 + product surface):**

- Configuration (TLS posture validation, session-key length, DB SSL
  posture in production, env defaults). Already in
  `internal/config/config_test.go`.
- Logger redaction (sensitive-key allowlist, suffix heuristic, request
  IDs survive). Already in `internal/logger/redact_test.go`.
- HTTP envelope (success and error shapes; request-id round-trip).
  Already in `internal/httpapi/router_test.go`.
- Inventory ingestion (private-key rejection). Already in
  `internal/inventory/inventory_test.go`.
- Auth (password hash/compare, cookie sign/verify, session lifetime
  semantics). Landed in PR-002 — `internal/auth/{cookies,passwords,sessions}_test.go`.
- Migration runner (parse, version detection, idempotence at the
  parser layer). Exercised end-to-end via the Tier-2 integration suite
  (`migrations_test.go`); parser-only unit coverage is intentionally
  thin because the runner code is small and the integration test runs
  in CI on every PR.
- Agent enrollment (token-hash equality, single-use semantics).
  Required when the enrollment domain lands.
- Risk-rule evaluation (deterministic given a fixed cert + clock).
  Required when the first rule lands.
- Provider abstraction (descriptor consistency, capability
  negotiation). Required when the first concrete provider lands.

**Determinism rules:**

- No `time.Sleep`. Use injected clocks (CLAUDE.md §8.2).
- No real network. The test must pass with `-count=1` on an offline
  machine.
- No reliance on filesystem outside `t.TempDir()`.
- No reliance on goroutine scheduling order. Tests assert observable
  state, not internal interleaving.

## Tier 2 — Backend Integration Tests

**Lives at:** `backend/test/integration/`. Build-tagged
`//go:build integration` so default `go test ./...` skips them. Run
locally with a live Postgres reachable via `DATABASE_URL`:

```bash
go run ./cmd/anchorix migrate up
go test -tags integration -count=1 ./test/integration/...
```

**Runs in CI** under the existing `backend (go)` job, with the
postgres service container described in
[`CI_PLAN.md`](./CI_PLAN.md).

**Scope (PR-002, merged):**

| Test                              | Asserts                                                                              |
| --------------------------------- | ------------------------------------------------------------------------------------ |
| `migrations_test.go`              | Fresh DB → `migrate up` succeeds; `schema_migrations` shows the expected version. Repeat `migrate up` is a no-op. |
| `readiness_test.go`               | With probe registered + DB up → `/readyz` returns 200 with `postgres:"ok"`. Liveness `/healthz` is unconditional. |
| `auth_session_test.go`            | Login with valid creds → 200 + Set-Cookie. `GET /me` with cookie → 200. Logout → cookie revoked. `GET /me` after logout → 401 with the canonical envelope. |
| `audit_test.go`                   | `auth.admin_created` / `login_succeeded` / `login_failed` / `logout` all produce audit rows. `X-Request-Id` propagates from the request header into `audit_events.request_id` (the request-identity assertion lives here rather than in a separate file). `audit_events` is insert-only at the DB level — UPDATE / DELETE are rejected by trigger. |
| `atomicity_test.go`               | A synthetic `failingRecorder` makes the audit write error mid-flow; the test asserts that no `sessions` row persists after a failed Login and no `users` row persists after a failed CreateUser. Proves the `auth.Service` ↔ `db.WithTx` atomic-tx contract (CLAUDE.md §18). |

**Scope (PR-003+):**

- Inventory ingestion happy path with a real cert PEM.
- Risk evaluation against fixture certs.
- Agent enrollment token round-trip.
- Provider abstraction registry behavior.

**Determinism rules (in addition to Tier 1):**

- One postgres database per test process. Each test starts in a
  fresh transaction; rolls back at end.
- Time injected via `clock.Clock`. No wall-clock comparisons.
- Test data is created in fixtures or factory functions, not by
  hitting external APIs.
- Total Tier-2 wall-clock budget: under 60 seconds. If it exceeds,
  refactor into more focused tests rather than relaxing the budget.

## Tier 3 — Frontend Tests

**Lives at:** `frontend/src/**/*.test.ts(x)`.

**Runs in CI** under the existing `frontend` job (`vitest run`).

**Required coverage:**

- Typed API client error envelope (`ApiError` shape; status / code
  preserved). Already in `src/lib/api.test.ts`.
- Auth flow (login form posts to API, on 200 navigates to dashboard,
  on 401 shows error). Required in PR-003.
- AppShell rendering (empty states render the documented copy).
  Required when each page gains real content.
- Component-level prop-shape regression for the typed API client
  (component receives `Certificate`, renders columns; mismatch
  surfaces as a TS error at build, not a runtime error).

**Determinism rules:**

- The API client is **always** mocked at the boundary in unit tests.
  No `fetch` call hits real network.
- vitest `globals` is on; `vi.useFakeTimers()` for any timing
  assertions.
- Tests run in `jsdom`. Snapshot tests are forbidden — they are
  brittle and obscure intent. Assert on visible text, accessible
  roles, and observable behavior instead.

## Tier 4 — Smoke / End-to-End

**Lives at:** the `docker (config + build + smoke)` job in
`ci.yml`.

**Validates** that the stack actually starts, `/healthz` and
`/readyz` respond as documented, and the bootstrap admin path works
once PR-002 lands.

**Determinism:** the only Tier here that touches Docker. The runner
has Docker; the control-plane and postgres images are pinned. The
job has a 3-minute timeout; longer would indicate a real regression.

## Tier 5 — Windows End-to-End

**Lives at:** `windows-latest` job described in
[`WINDOWS_CI.md`](./WINDOWS_CI.md). Activated in Phase 6.

## Test Data Strategy

- **Fixtures** live next to the code that consumes them, under
  `<package>/testdata/` (Go convention). Committed, deterministic,
  reviewed.
- **Generated data** in tests must use seeded randomness
  (`rand.New(rand.NewSource(42))`). Never `crypto/rand` for
  test-only data.
- **Sensitive-looking strings** (PEM blocks, base64 keys) used as
  inputs to negative tests are allowlisted in `.gitleaks.toml` per
  CLAUDE.md §11. The current allowlist contains exactly one test
  file (`backend/internal/inventory/inventory_test.go`); adding more
  requires a CLAUDE.md amendment.

## Audit & Logging Tests

CLAUDE.md §9 makes audit a first-class behavior. Where practical:

- Domain operations that mutate state include a test that asserts an
  `audit_events` row was written with the expected `actor`,
  `action`, `target_type`, `target_id`. Lives in Tier 2
  (`audit_test.go`).
- The redaction allow-list is unit-tested (Tier 1, already present).
- PR-002 ships a `login_failed`-metadata assertion in `audit_test.go`:
  `auth.login_failed` metadata carries `severity:"security"` and never
  contains the plaintext password. The full "no plaintext secrets in
  any log line" sweep is tracked as a follow-up in
  [`HARDENING_BACKLOG.md`](./HARDENING_BACKLOG.md) — the redaction
  unit tests cover the same surface at the formatter layer, so the
  product invariant is enforced; what's deferred is the
  belt-and-braces full-flow assertion.

## What's Forbidden

These are CLAUDE.md §19 / §11 carry-overs, restated for emphasis:

- Flaky tests. Quarantining a flaky test is not acceptable; the
  underlying race is the bug.
- Network-dependent tests. Even "trusted" public endpoints are
  forbidden — they introduce upstream-availability flakes.
- Timing-sensitive assertions. Inject the clock.
- Goroutine-leak tolerance. A test that leaves a goroutine running
  is failing, even if the assertions pass.
- Conditional skips that hide regressions ("skip on Windows", "skip
  in CI"). If a test can't run somewhere, the code under test
  should be refactored to support running it.
- Snapshot tests on UI components. Use behavior assertions.
- Tests that depend on external state (filesystem locations, env
  vars not set by the test itself, services on the host).

## CI Determinism Guarantee

Every PR runs the same gates against the same code. CI never makes
its own determination about which tests to run; that's the test
configuration's job. If a PR's CI run differs from a local run,
the difference is a defect in either the test or the workflow, not
a property to live with.

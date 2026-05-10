# CI Plan — Growth Roadmap

**Source of truth for required gates:**
[`CLAUDE.md`](../../CLAUDE.md) §11 and
[`.github/workflows/README.md`](../../.github/workflows/README.md).
This document plans how CI grows; it does not redefine the current
required-checks set.

## Determinism Bar (binding)

A CI job is added to the **blocking** set only when it is:

- **Deterministic** — same commit + same upstream advisory snapshot
  always produces the same conclusion.
- **Reliable** — no transient red on a clean repo. Transient upstream
  outages surface as real reds (not silent passes).
- **Reproducible** — a contributor can run an equivalent locally.
- **Observable** — a failure produces actionable logs.
- **Bounded** — completes within a sensible wall-clock budget so it
  doesn't hold up the queue.

A flaky check is fixed at the source, never wrapped in retries or
`continue-on-error`. CLAUDE.md §11 closes that escape valve
permanently.

## Today (post-PR #1, post-PR #2)

The 14 blocking jobs already required on `main`:

```
backend (go)            agent/windows (go)        frontend
docker (config + build + smoke)
codeql (go)             codeql (javascript-typescript)
govulncheck (backend)   govulncheck (agent/windows)
npm audit (frontend)    trivy (filesystem)
gitleaks                dependency obituary
```

(Plus the auto-generated `Trivy` and `CodeQL` SARIF-upload runs that
GitHub renders separately.)

## PR-002 — Additive CI Changes

PR-002 introduces real PostgreSQL persistence, so CI must exercise
it. The changes below are **additive** to the existing
`backend (go)` job — no new top-level workflow, no new required-check
name, no new gate to configure in branch protection.

### `ci.yml backend (go)` — postgres service container

```yaml
backend:
  services:
    postgres:
      image: postgres:16-alpine
      env:
        POSTGRES_USER: anchorix
        POSTGRES_PASSWORD: ci-password
        POSTGRES_DB: anchorix
      ports: ['5432:5432']
      options: >-
        --health-cmd "pg_isready -U anchorix -d anchorix"
        --health-interval 5s --health-timeout 3s --health-retries 10
  steps:
    - … existing gofmt / vet / build / test steps unchanged …
    - name: integration tests
      env:
        DATABASE_URL: postgres://anchorix:ci-password@localhost:5432/anchorix?sslmode=disable
        ANCHORIX_ENV: development
        ANCHORIX_SESSION_KEY: ci-session-key-32-bytes-padding-aaaaaaaa
      run: |
        go run ./cmd/anchorix migrate up
        go test -count=1 -tags=integration ./test/integration/...
```

Notes:
- The integration tests live under `backend/test/integration/` and
  carry a `//go:build integration` tag so they don't run in the
  default `go test ./...` pass. The unit-test step keeps its current
  scope; the integration step runs after migrate.
- `ci-password` is hard-coded to a clearly synthetic value
  (Gitleaks already accepts strings of this shape; if a future
  Gitleaks rule flags it, the right answer is to use a `repository
  secret` rather than weakening the gate).
- The job's wall-clock budget grows by ~30 seconds (postgres health
  + migrate + integration suite). Acceptable.

### `docker (config + build + smoke)` — readiness assertion tightens

Currently the smoke step asserts `{"status":"ready"}` on `/readyz`
when no probes are registered. After PR-002, postgres is a registered
probe, so the existing assertion still holds — the probe is healthy
because the api container `depends_on: postgres: condition: service_healthy`.

The smoke step gains one additional check: stop postgres mid-run and
assert that `/readyz` flips to 503. This validates fail-closed
behavior end-to-end. Adds another ~10s to the job.

### What does **not** change in CI for PR-002

- No new top-level workflow file.
- No new required-check name in branch protection.
- No `golang/govulncheck-action` parameter changes — `pgx` is the
  only new dep and govulncheck on `stable` Go covers it.
- No `npm audit` parameter changes — frontend tree is untouched.
- No `dependency obituary` exclusions added — `pgx` is healthy in the
  obituary DB; if it weren't, the answer would be a CLAUDE.md
  amendment, not a `.depobituaryignore` line.

## PR-003+ — Tracked, Not Yet Wired

| When           | Addition                                                                 | Notes                                                                              |
| -------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| PR-003 (UI)    | `frontend` job extended with a Playwright (or `@testing-library/react`) auth round-trip against a containerized backend. | Inside the existing `frontend` job; no new required-check. |
| PR-004 (agents)| Integration test that exercises `POST /agents/enrollment-tokens` → simulated agent enrollment → heartbeat. Uses an in-process fake "agent" client. | Lives under `backend/test/integration/`; same job. |
| PR-005 (inv.)  | Inventory ingest integration test: post a 100-cert batch, assert dedup + observation rows. | Same job. |
| PR-006 (Wi.)   | **Windows CI** — see [`WINDOWS_CI.md`](./WINDOWS_CI.md). New required job `agent (windows-latest)`. **First** new required-check since PR #1. |
| Phase 6        | SBOM generation on release tags (cyclonedx via Trivy). Cosign signing target. Not blocking on every PR; gates the release pipeline. |
| Phase 6        | DAST smoke against the running stack (e.g. `zap-baseline`). Advisory at first; promoted to blocking once it produces zero false positives over a release window. |

Promoting any of the "tracked" items to blocking requires: a green
streak ≥ 10 PRs, an explicit CLAUDE.md §11 amendment, and an update
to both this doc and `.github/workflows/README.md`.

## Anti-patterns Forbidden in CI (from CLAUDE.md §11 and §18)

- `continue-on-error: true` on any required gate.
- Retry wrappers around a flaky check (fix the check, not the
  symptom).
- Caching across runs that hides reproducibility issues. Module
  caches and toolchain caches are fine; *result* caches are not.
- Time-based assertions in tests. Inject a clock per CLAUDE.md §8.2.
- Tests that reach the public internet. Use service containers or
  fixtures; if a test needs a remote service, it isn't a test, it's
  monitoring.
- Secret values written to job logs. The `gitleaks` job covers
  source; CI must also avoid `echo "$TOKEN"` and similar.

## Acceptance Criteria for This Plan

This plan is "done" when:

1. PR-002 lands using exactly the additive changes above.
2. Branch protection on `main` still requires the same 14 jobs (no
   gate added without a §11 amendment).
3. The "Tracked, not yet wired" list is updated as each phase lands,
   with a row removed and a "Today" line added.

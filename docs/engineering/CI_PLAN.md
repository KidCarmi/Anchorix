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

## PR-002 — Additive CI Changes (merged)

PR-002 introduced real PostgreSQL persistence, so CI exercises it.
The changes below are **additive** to the existing `backend (go)` job
— no new top-level workflow, no new required-check name, no new gate
to configure in branch protection. All landed in `ci.yml` on commit
`482188b` (merge of PR #4).

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
- The CI database password is a synthetic test credential scoped
  only to the ephemeral CI service container. It is not a secret
  and must never be reused outside CI. Moving it to a repository
  secret would imply it protects a real external resource, which
  it does not — the postgres container is created and destroyed
  inside this single CI job and is not reachable from outside the
  runner. If a future Gitleaks rule flags the literal, the right
  answer is to rename the literal (e.g. `ci-test-postgres`),
  not to elevate it into the secrets store.
- The job's wall-clock budget grows by ~30 seconds (postgres health
  + migrate + integration suite). Acceptable.

### `docker (config + build + smoke)` — readiness assertion (merged)

Pre-PR-002 the smoke step asserted `{"status":"ready"}` on `/readyz`
when no probes were registered. The merged step now grep-asserts
`"postgres":"ok"` in `/readyz`, which fails closed when the api
container can't reach postgres. The "stop postgres mid-run, assert
503" sweep is retained as a follow-up in
[`HARDENING_BACKLOG.md`](./HARDENING_BACKLOG.md): the current smoke
proves the happy path; the negative-path assertion is deferred so
that adding it doesn't expand the smoke step's wall-clock budget on
every PR.

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
| PR-006 (Wi.)   | **Windows CI** — see [`WINDOWS_CI.md`](./WINDOWS_CI.md). New required job `agent (windows e2e)` (runs on `windows-latest`). **First** new required-check since PR #1. |
| Phase 6        | SBOM generation on release tags (cyclonedx via Trivy). Cosign signing target. Not blocking on every PR; gates the release pipeline. |
| Phase 6        | DAST smoke against the running stack (e.g. `zap-baseline`). Advisory at first; promoted to blocking once it produces zero false positives over a release window. |

Promoting any of the "tracked" items to blocking requires: a green
streak ≥ 10 PRs, an explicit CLAUDE.md §11 amendment, and an update
to both this doc and `.github/workflows/README.md`.

## Perf and Stress Tiers (H-024A)

The H-024A PR introduces two new on-demand test tiers under
`backend/test/`. **Neither tier joins the blocking-CI set.** They
are explicitly off the §11 required-check list and only run when
asked. The blocking set stays at 14 jobs (per `Today`).

| Tier   | Build tag | Location               | What it does                                                                                                                                       |
| ------ | --------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Perf   | `perf`    | `backend/test/perf/`   | Smallv01 fixture (10 agents, 60 certs) against the live PostgreSQL service container. Skeleton for query-count assertions; H-024B fleshes those out. |
| Stress | `stress`  | `backend/test/stress/` | Pilot fixture (1K agents, 5K certs) against the live PostgreSQL service container. Heavy — minutes, not seconds. Wall-clock budget assertions land with H-024B. |

### Running locally

```bash
# Perf (fast, requires DATABASE_URL):
DATABASE_URL='postgres://anchorix:ci-password@127.0.0.1:5432/anchorix?sslmode=disable' \
    ANCHORIX_SESSION_KEY='ci-session-key-32-bytes-padding-aaaaaaaa' \
    ANCHORIX_ENV=development \
    go test -tags=perf -count=1 ./backend/test/perf/...

# Stress (heavy, allow generous timeout):
DATABASE_URL='postgres://anchorix:ci-password@127.0.0.1:5432/anchorix?sslmode=disable' \
    ANCHORIX_SESSION_KEY='ci-session-key-32-bytes-padding-aaaaaaaa' \
    ANCHORIX_ENV=development \
    go test -tags=stress -count=1 -timeout 30m ./backend/test/stress/...
```

Both tiers SKIP cleanly when `DATABASE_URL` is unset, matching the
`integration` tier's behavior so developer machines without
postgres compile the suite without surprises.

### Build-tag conventions

- `//go:build integration` — requires PostgreSQL; runs in the
  existing `backend (go)` job (blocking).
- `//go:build perf` — requires PostgreSQL; on-demand only; the
  default `go test ./...` pass excludes the directory entirely.
  NOT blocking.
- `//go:build stress` — requires PostgreSQL; on-demand only;
  generates pilot-scale fixtures and takes minutes. NOT
  blocking, NOT run nightly in H-024A.

Promoting either tier to a nightly workflow or to the blocking
set is a future PR with its own CLAUDE.md §11 conversation —
nothing in H-024A wires that. The skeleton landing now is the
substrate; the assertions that motivate gating land alongside
H-024B's streaming-recompute rewrite (see
[`H024_PERFORMANCE_PLAN.md`](./H024_PERFORMANCE_PLAN.md) §4.5,
§9.B).

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

1. PR-002 lands using exactly the additive changes above. ✅ (merged
   in PR #4)
2. Branch protection on `main` still requires the same 14 jobs (no
   gate added without a §11 amendment). ✅
3. The "Tracked, not yet wired" list is updated as each phase lands,
   with a row removed and a "Today" line added.

# Anchorix v0.1 Implementation Roadmap

This roadmap defines the order in which v0.1 will be built. Phases are
intentionally small. Anything outside this roadmap is explicitly deferred.

> Reminder: every phase must respect [`CLAUDE.md`](./CLAUDE.md). If a step
> below conflicts with CLAUDE.md, CLAUDE.md wins and the roadmap is updated.

## Phase 0 — Foundations (this PR)

**Goal:** establish architecture, governance, and skeleton structure.

- [x] `CLAUDE.md` engineering constitution
- [x] `ARCHITECTURE.md` with topology and module boundaries
- [x] `DEVELOPMENT.md` with local setup
- [x] `ROADMAP.md` (this file)
- [x] Repository structure (backend/frontend/agent/docs/deploy)
- [x] Docker Compose skeleton
- [x] Go module skeleton with `cmd/anchorix` and `internal/*` stubs
- [x] React + Tailwind skeleton
- [x] Windows agent skeleton (`agent/windows`)
- [x] PostgreSQL schema proposal (`backend/migrations/0001_init.sql`)
- [x] REST API structure proposal (`docs/api/REST_API.md`)
- [x] Security docs scaffolding (`docs/security/`)

**Exit criteria:** repo builds, lints, and `docker compose up` reaches a
healthy state with placeholder endpoints.

## Phase 1 — Control Plane Walking Skeleton ✅ shipped

**Goal:** smallest end-to-end flow that proves the architecture.

- [x] Configuration loader with required-secret validation
- [x] Structured logger with redaction allow-list
- [x] HTTP server with `/healthz` (process-only) and `/readyz` (probe-based)
- [x] Database connection pool (pgx)
- [x] Migration runner wired into `cmd/anchorix migrate up`
- [x] Postgres ping registered as a `/readyz` probe (fails closed when DB down)
- [x] `anchorix admin create` implementation (no default admin / password)
- [x] `/api/v1/auth/login` (local password, bcrypt) + DB-backed sliding sessions
- [x] `/api/v1/auth/me`, `/api/v1/auth/logout`
- [x] Audit event recording for login / logout / admin_created
- [x] React login page hitting the API
- [x] AuthGate session-aware routing (anonymous → LoginPage, authenticated → AppShell)
- [x] Global 401 session-expiry handling (any non-/me request flips the gate)
- [x] Cross-tab session sync (BroadcastChannel)
- [x] Deterministic logout in the logging-out tab
- [x] Full-flow log-redaction integration test
- [x] `/readyz` negative-path smoke (asserts 503 when postgres is stopped)
- [x] CI: lint, vet, unit tests, integration tests against postgres, container build, CodeQL, govulncheck, npm audit, trivy, gitleaks, dependency obituary

**Deferred from Phase 1** (defense-in-depth, not blocking the exit criterion):

- CSRF middleware for state-changing endpoints. The session cookie is
  `HttpOnly` + `SameSite=Lax` (in every TLS posture other than the
  local-dev one), so cross-origin POSTs cannot replay the session. An
  explicit CSRF token is sensible defense-in-depth and will land
  alongside the first form-driven mutation outside of `/auth/login`
  (which is anonymous and idempotent in terms of impact).

**Exit criteria:** an operator can log in to the UI in dev. ✅ Met by
PR #4 (backend) + PR #8 (frontend); PRs #5–#11 hardened the
foundation (atomic auth, redaction sweep, fail-closed readyz,
session expiry + cross-tab).

The end-to-end shape and security properties of the auth foundation
are documented in
[`docs/engineering/AUTH_FOUNDATION.md`](./docs/engineering/AUTH_FOUNDATION.md).

## Phase 2 — Agent Enrollment (in progress)

**Goal:** a Windows agent can register and prove identity. PR #13
shipped the **backend / API / domain foundation** as a Deployment
Package model designed for SCCM-style bulk rollouts; subsequent PRs
add the agent-side wiring and the operator UI.

Foundation (PR #13, shipped):

- [x] `POST /api/v1/deployment-packages` (admin only); bootstrap
      secret returned once, stored as `sha256(secret)`
- [x] `POST /api/v1/agents/enroll`; bootstrap-secret-based, generic
      rejection envelope, organization-scoped
- [x] Persistent `agents` table extended with deployment_package_id,
      machine_fingerprint_hash, install_id, group_name, labels,
      credential_hash
- [x] Agent identity material as bearer credential (mTLS deferred to
      Phase 6)
- [x] Atomic `max_uses` / `expires_at` / `revoked_at` enforcement
      via conditional UPDATE; tested under concurrency
- [x] Audit events for `deployment_package.created`,
      `agent.enrolled`, `agent.enrollment_rejected`
      (severity:"security")
- [x] `GET /api/v1/agents` (operator-only, org-scoped) with
      group/labels in the response
- [x] Design + contract documented in
      [`docs/engineering/AGENT_ENROLLMENT.md`](./docs/engineering/AGENT_ENROLLMENT.md)

Still to come in Phase 2:

- [ ] Agent skeleton: config, logging, transport, single enrollment
      call
- [ ] Installer / MSI / .intunewin generator that bakes the bootstrap
      metadata
- [ ] Operator UI: deployment-package list + create dialog; agents
      list view
- [ ] Package revocation API + UI
- [ ] Agent revocation API + UI

**Exit criteria:** an admin can create a deployment package in the
UI, deploy the resulting installer artifact, and watch agents appear
in the UI as they enroll.

## Phase 3 — Inventory & Heartbeat

**Goal:** agents continuously upload certificate inventory.

- [ ] Heartbeat endpoint (`POST /agents/{id}/heartbeat`)
- [ ] Inventory endpoint (`POST /agents/{id}/inventory`)
- [ ] Windows discovery: enumerate `LocalMachine\My`, `WebHosting`, etc.
- [ ] Public-cert metadata only — explicit check that no private key
      material is included in payloads
- [ ] Upsert by `(fingerprint_sha256, source_host, source_store)`
- [ ] UI: certificates list, certificate detail page

**Exit criteria:** UI shows certificates discovered from a real Windows host.

## Phase 4 — Risk Findings

**Goal:** turn inventory into actionable findings.

- [ ] Built-in rules: expiring soon, expired, weak key, weak signature
- [ ] Deterministic recompute on each ingestion
- [ ] `findings` table with severity + status lifecycle
  (`open`, `acknowledged`, `suppressed`)
- [ ] Operator actions: acknowledge / suppress with required reason
- [ ] UI: findings list with filtering by severity/status

**Exit criteria:** operators see and triage real findings.

## Phase 5 — Provider Abstraction Stubs

**Goal:** prove the provider model without committing to specific vendors.

- [ ] `internal/providers/pki/Provider` interface
- [ ] No-op / introspection-only provider
- [ ] Skeleton for ADCS and Vault providers (no live calls in v0.1)
- [ ] `/api/v1/providers` read-only endpoints
- [ ] UI: providers list (read-only)

**Exit criteria:** a new provider can be added by implementing the
interface and registering it, with no changes to core domain code.

## Phase 6 — Hardening, Audit, Operations

**Goal:** make v0.1 enterprise-friendly.

- [ ] mTLS between agent and control plane
- [ ] Pinned control-plane cert in agent config
- [ ] Audit log UI with filtering
- [ ] Backup guidance for PostgreSQL
- [ ] Reverse-proxy + TLS sample compose overlay
- [ ] Container image SBOM and CVE scan in CI
- [ ] Documentation pass: deploy guide, runbook, troubleshooting

**Exit criteria:** v0.1 release candidate.

## See Also

Engineering plans referenced by phases above:

- [`docs/engineering/PR_002_PLAN.md`](./docs/engineering/PR_002_PLAN.md)
  — concrete plan for the next implementation PR (DB + migrations +
  auth + sessions, no UI).
- [`docs/engineering/CI_PLAN.md`](./docs/engineering/CI_PLAN.md) — how
  CI grows phase by phase, including Windows CI activation.
- [`docs/engineering/WINDOWS_CI.md`](./docs/engineering/WINDOWS_CI.md)
  — detailed design for the Phase 6 `windows-latest` job.
- [`docs/engineering/TESTING_STRATEGY.md`](./docs/engineering/TESTING_STRATEGY.md)
  — unit / integration / smoke / Windows tier model.
- [`docs/engineering/AGENT_HARDENING.md`](./docs/engineering/AGENT_HARDENING.md)
  — sequenced agent hardening items (H1–H7).
- [`docs/engineering/AGENT_ENROLLMENT.md`](./docs/engineering/AGENT_ENROLLMENT.md)
  — Phase 2 deployment-package + enrollment foundation contract.
- [`docs/architecture/PACKAGE_BOUNDARIES.md`](./docs/architecture/PACKAGE_BOUNDARIES.md)
  — per-package responsibility and forbidden imports.
- [`docs/architecture/EVOLUTION.md`](./docs/architecture/EVOLUTION.md)
  — sketches for v0.2 and v0.3 (directional, not commitments).

## Out of Scope (Tracked, Not Built)

Captured here so they aren't lost, but **not** part of v0.1:

- automated renewal / revocation / rotation
- built-in CA
- Kubernetes operator / Helm chart
- Linux & macOS agents
- SSH key inventory
- multi-tenant org isolation
- AI / ML risk classification
- SSO (SAML / OIDC)
- HA / multi-region
- SaaS billing

These will be opened in a future roadmap revision **after** v0.1 ships and
[`CLAUDE.md`](./CLAUDE.md) §4 is amended.

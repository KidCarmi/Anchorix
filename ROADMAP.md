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

## Phase 1 — Control Plane Walking Skeleton

**Goal:** smallest end-to-end flow that proves the architecture.

- [x] Configuration loader with required-secret validation
- [x] Structured logger with redaction allow-list
- [x] HTTP server with `/healthz` (process-only) and `/readyz` (probe-based)
- [ ] Database connection pool (pgx)
- [ ] Migration runner wired into `cmd/anchorix migrate up`
- [ ] Postgres ping registered as a `/readyz` probe (fails closed when DB down)
- [ ] `anchorix admin create` implementation (no default admin / password)
- [ ] `/api/v1/auth/login` (local password, bcrypt) + session cookies
- [ ] `/api/v1/auth/me`, `/api/v1/auth/logout`
- [ ] CSRF protection for state-changing endpoints
- [ ] Audit event recording for login / logout / admin_created
- [ ] React login page hitting the API
- [ ] CI: lint, vet, unit tests, container build, gitleaks

**Exit criteria:** an operator can log in to the UI in dev.

## Phase 2 — Agent Enrollment

**Goal:** a Windows agent can register and prove identity.

- [ ] Enrollment token issuance API + UI
- [ ] `POST /api/v1/agents/enroll` (token + agent pubkey)
- [ ] Persistent `agents` table with status lifecycle
- [ ] Agent identity material (initially HMAC bearer; mTLS in Phase 4)
- [ ] Agent skeleton: config, logging, transport, single enrollment call
- [ ] Audit events for enrollment, revocation, deletion
- [ ] UI: agents list + enrollment token modal

**Exit criteria:** an agent can enroll and appear in the UI.

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

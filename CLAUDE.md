# CLAUDE.md — Anchorix Engineering Constitution

> This document is the authoritative engineering, security, and architecture
> rulebook for Anchorix. It is binding on every contributor — human or AI.
>
> **If implementation conflicts with CLAUDE.md, CLAUDE.md wins.**
>
> CLAUDE.md is permanent. It evolves through deliberate review, not through
> the convenience of any single change.

---

## 1. What Anchorix Is

Anchorix is a **Machine Identity & Certificate Operations Platform**.

Anchorix exists to give organizations:

- certificate **discovery**
- certificate **inventory**
- certificate **risk identification**
- certificate **visibility**
- **integration** with existing PKI environments
- a foundation for **safe, future automation** of certificate lifecycle

Anchorix is a **control plane** above existing trust infrastructure:

- Microsoft ADCS
- HashiCorp Vault PKI
- Smallstep
- EJBCA
- Manual CSR workflows

## 2. What Anchorix Is NOT

- **Not** a replacement for enterprise PKI.
- **Not** a Certificate Authority.
- **Not** a key escrow service.
- **Not** a private-key custodian.
- **Not** a multi-tenant SaaS in v0.1.
- **Not** a Kubernetes-native platform in v0.1.
- **Not** an AI assistant for certificates in v0.1.

## 3. Core Philosophy

> **Visibility before automation.**

You cannot safely automate what you cannot see, classify, or explain.
Every feature must serve transparency, operator control, and auditability
**before** it serves convenience.

## 4. v0.1 Scope (Authoritative)

In scope:

- Windows discovery agent
- certificate inventory
- risk findings
- central control plane
- PostgreSQL backend
- basic web UI (React + Tailwind)
- Docker Compose deployment
- structured logging
- basic audit events

**Explicitly out of scope for v0.1:**

- automated renewal
- automated revocation
- built-in CA
- Kubernetes operators / Helm charts
- Linux discovery agent
- macOS agent
- SSH key management
- multi-tenancy
- AI / ML features
- HA clustering / multi-region failover
- SAML / OIDC SSO (basic auth in v0.1, SSO is v0.x)

A change that adds anything from the "out of scope" list to v0.1
**must be rejected** unless this document is amended first.

## 5. Architecture Constraints (Hard Rules)

1. **Modular monolith.** One deployable control-plane binary.
   No microservices in v0.1. No service mesh. No internal RPC bus.
2. **Provider-based design.** All PKI, secret, storage, and transport
   integrations live behind Go interfaces in `internal/providers/`.
   No PKI-specific code may leak into core domain logic.
3. **Stateless control plane** where possible. State lives in PostgreSQL.
   Control-plane processes must be safely restartable at any time.
4. **No microservices, no event bus, no Kubernetes** in v0.1.
5. **Linux-only control plane.** Containerized via Docker Compose.
6. **Windows-only agent** in v0.1, shipped as a Windows service.
7. **Go backend, React + Tailwind frontend, PostgreSQL only.**
   No alternate databases, no ORMs that hide SQL behavior.
8. **No microservice-style polyrepos.** One repo, clear module boundaries.
9. **Database migrations are append-only** and version-tracked.
   No destructive migrations without an explicit migration plan.
10. **Backward-compatible API evolution.** REST endpoints under
    `/api/v1/...` may not break existing agents or clients without a new
    version prefix.

## 6. Security Rules (Non-Negotiable)

1. **No plaintext secrets** anywhere — not in code, not in logs, not in
   env files committed to the repo, not in DB columns. Secrets live in
   environment variables, mounted secrets, or a secret provider.
2. **No private key exfiltration.** The agent **must never** transmit
   private key material to the control plane. Public certificates only.
3. **Least privilege everywhere.** Agents read certificate stores; they
   do not need administrative APIs they will not use.
4. **TLS for all agent ↔ control-plane traffic.** mTLS by default once
   an agent is enrolled. Plain HTTP is only allowed for `/healthz` /
   `/readyz` on a private interface.
5. **Authenticated agent enrollment** via single-use enrollment tokens
   with short TTL. Enrollment tokens are never logged.
6. **Audit everything that changes state.** Logins, agent enrollments,
   provider configuration changes, role changes, and finding overrides
   produce immutable audit events.
7. **No direct SQL string concatenation.** All queries use parameter
   binding. SQL builders are allowed; raw concatenation is not.
8. **Default deny.** Unknown agents are rejected. Unknown providers
   are rejected. Unknown API routes return 404, not stack traces.
9. **No secrets in logs.** Structured logging must redact known
   sensitive fields (`password`, `token`, `secret`, `private_key`,
   `enrollment_token`, `authorization`). Redaction is centralized.
10. **Threat model before major features.** Any feature that touches
    keys, identity, network trust, or provider integration requires a
    short threat model under `docs/security/` before merge.
11. **Signed artifacts later, but build for it now.** Releases will be
    signed; the build pipeline must be reproducible and traceable.
12. **Fail closed.** When in doubt, deny the operation, log it, and
    surface it to operators.

## 7. Operational Principles

1. **Operator-controlled.** Anchorix proposes, the operator decides.
   No "magic" automation that bypasses operator review in v0.1.
2. **Explainable.** Every finding, every classification, every state
   transition must be traceable to a rule, a source, and a timestamp.
3. **Transparent.** Operators can read every config value, every
   provider state, every job status. No hidden global state.
4. **Ops freedom.** No hardcoded PKI assumptions. The platform must
   accommodate future providers (Vault, ADCS, EJBCA, Smallstep, custom)
   without architectural rewrites.
5. **Graceful shutdown.** All long-running components honor `context`
   cancellation and drain in-flight work before exit.
6. **Deterministic behavior.** Given the same inputs and DB state,
   the same outputs. No nondeterministic side effects in core logic.
7. **Operational simplicity beats feature quantity.** A boring,
   debuggable system is the goal.

## 8. Coding Standards

### 8.1 General

- Small, focused packages. **No god packages.**
- Interface-driven design at module boundaries.
- High cohesion, low coupling. A package should have one reason to change.
- Explicit over implicit. No global mutable state. No init-time side effects.
- Centralized configuration via `internal/config`. No `os.Getenv` calls
  scattered across packages.
- Structured errors. Wrap with `fmt.Errorf("...: %w", err)`. Sentinel
  errors live next to the package that defines them.
- Context-aware. Every blocking call accepts a `context.Context`.
- Retry safety. Idempotent operations must be safe to retry; non-idempotent
  ones must be clearly named and gated.

### 8.2 Go

- `go fmt`, `go vet`, `staticcheck`, `golangci-lint` are required to pass.
- Public symbols are documented. Package docs live in `doc.go`.
- No `panic` in request paths. Reserve panics for truly unrecoverable
  programmer errors at startup.
- No `interface{}` / `any` in domain models. Use concrete types or
  defined sum types.
- No `time.Now()` directly inside business logic — inject a clock for
  testability.
- Tests live next to code (`_test.go`). Integration tests under
  `backend/test/integration/`.

### 8.3 TypeScript / React

- Strict TypeScript. `noImplicitAny`, `strictNullChecks`, `noUnused*` on.
- Functional components, hooks, no class components.
- API client is a single typed module. UI never crafts URLs by hand.
- Tailwind for styling. No CSS-in-JS frameworks.
- No global state libraries beyond what's needed (start with React Query
  for server state, Context for auth). Add Redux only with strong cause.

### 8.4 Naming Rule

Do not create variables, functions, files, packages, or types with vague,
generic, or AI-generated names. Names must clearly express domain purpose
and ownership.

**Forbidden examples:**

- `data`
- `payload`
- `temp`
- `misc`
- `helper`
- `util`
- `thing`
- `manager`
- `processor`
- `handler2`, `ctx2`, etc.
- `claude*` (anything that names the assistant or session)
- generic dumping-ground "service" abstractions

**Use explicit domain-oriented names instead:**

- `certificateInventory`
- `enrollmentToken`
- `certificateObservation`
- `riskFinding`
- `inventoryBatch`
- `heartbeatRequest`
- `providerConfig`
- `auditEvent`
- `agentIdentity`

**Accepted short Go conventions** (do **not** rename these):

- `ctx` (context.Context)
- `err` (error)
- `cfg` (config)
- `tx` (transaction)
- `id` (identifier)
- `srv` (server)
- `req` / `resp` (request/response)

If a name feels generic, AI-generated, or unclear: rename it. A name that
needs a comment to explain its purpose is the wrong name.

This rule is binding on contributors and on AI assistants. If a PR
introduces names that violate this rule, the names — not the rule — are
what get revised.

### 8.5 Anti-patterns (Forbidden)

- Giant files (>500 LOC by default — split or justify in PR).
- God objects, "manager" classes that own everything.
- Hidden side effects in constructors / `init()`.
- Tightly coupled packages (cyclic deps, leaky internals).
- Unclear abstractions invented before they are needed.
- Premature optimization without a benchmark or profile.
- Copy-paste implementations instead of small shared helpers.
- Hardcoded PKI vendor logic in core domain code.
- Catch-all `try { } catch (_) {}` style error swallowing.

### 8.6 Strict Decoupling Rules

The forbidden import edges are restated here so violations surface at
code review even if the per-package boundary doc isn't open:

- `domain → httpapi` is forbidden (reverse layering).
- `agent/windows/* → backend/*` is forbidden (split-binary leak).
- `httpapi/handlers → storage/postgres` is forbidden — handlers must
  go through the domain interface, never SQL directly.
- `internal/* → cmd/*` is forbidden — composition flows the other way.
- HTTP handlers MUST NOT contain business logic. They translate HTTP
  into domain calls and back.
- HTTP handlers MUST NOT access SQL directly. The storage layer owns
  database access.
- Frontend components MUST NOT build URLs by hand. Every API call
  goes through the single typed API client.
- No hidden global mutable state. No init-time side effects.

### 8.7 File Structure Discipline

- Soft caps: **500 LOC per file**, **80 LOC per function**. Anything
  over splits or carries an explicit justification in the PR body.
- If a file is becoming a dumping ground, refactor immediately — do
  not postpone cleanup.
- No commented-out code. No TODO-driven architecture (a TODO without a
  tracking issue is a defect).
- No giant switch statements; prefer table-driven dispatch or
  polymorphism.
- One responsibility per package; the package name reflects the
  responsibility.
- `cmd/anchorix/main.go` (and any other `main.go`) is the composition
  root only. No business logic lives there.

### 8.8 Dependency Injection Rules

The dependency graph must be explicit and auditable. Reflection-based
DI containers are deliberately rejected.

- **Constructor-based DI only.** `NewX(deps...)` style; dependencies
  are arguments.
- No service-locator patterns.
- No runtime dependency discovery (no reflection-based DI containers,
  no autowiring).
- No hidden dependency wiring (no global registries that callers
  mutate after process start).
- Dependencies must be explicit in constructors — no zero-value
  fields silently filled later.
- Interfaces are owned by the **consumer**, not the provider.
  Dependency-inversion direction is enforced at code review.
- DI containers / frameworks are not used. Plain Go composition in
  `cmd/anchorix/main.go` is the canonical wiring point.

### 8.9 Configuration Discipline

Prevent configuration drift and hidden runtime behavior.

- Configuration is **immutable after startup.** No hot-reload, no
  live config swap.
- All environment parsing is centralized in `internal/config`. No
  direct `os.Getenv` outside that package — restated as a hard rule
  on top of §8.1.
- Startup must fail explicitly on invalid configuration. No silent
  fallback for security-sensitive settings (TLS termination, DB SSL
  mode, session-key length, enrollment-token TTL bounds).
- Configuration validation is deterministic — same env in, same
  `*Config` (or same explicit error) out.
- Secrets are loaded only through explicit providers
  (`internal/providers/secrets`); a feature handler never reads a
  secret inline from environment.
- Config structs are typed and validated at construction. No
  `map[string]any`-style config shapes inside the application.

### 8.10 Concurrency Discipline

Prevent invisible runtime instability. Goroutine ownership is
non-negotiable.

- Every goroutine has a documented owner (a type or function), a
  cancellation path (typically `context.Context`), and a bounded
  lifetime.
- No orphan goroutines. No fire-and-forget. No unbounded worker
  spawning.
- Goroutine leaks are treated as defects.
- Shared mutable state requires explicit synchronization ownership —
  one type owns the mutex; callers go through methods.
- Background loops (heartbeats, scheduled scans, cache refresh) must:
  - honor context cancellation,
  - set explicit per-iteration timeouts,
  - use a deterministic retry policy with a documented cap.

### 8.11 Outbound Client Rules

External dependency behavior must be predictable and auditable.

- All outbound HTTP / gRPC clients accept `context.Context`.
- Explicit per-call timeouts. `http.Client{}` defaults are not
  acceptable — construct named clients with explicit configuration.
- Bounded retries with explicit policy ownership. No implicit retry
  libraries without a named owner.
- Structured error wrapping (`fmt.Errorf("...: %w", err)`) so
  callers can `errors.Is` / `errors.As`.
- TLS validated properly: pinned where the trust boundary requires
  pinning (agent → control plane, post-enrollment), CA-validated
  otherwise. `InsecureSkipVerify` is forbidden in production code.
- `http.DefaultClient` is **forbidden** in feature code.
- Outbound authentication is deterministic — same identity in, same
  authentication header out. No non-deterministic signing helpers.
- External provider failures surface operationally: audit event +
  structured log + observable failure mode. Never silent.

## 9. Logging & Audit

- **Structured logs only** (JSON). No `fmt.Println`, no plain `log.Print`.
- Required log fields: `timestamp`, `level`, `event`, `request_id`,
  `actor` (when applicable), `component`.
- **Audit events are not logs.** Audit events are persisted in
  PostgreSQL, signed by event type, and never deleted within retention.
  The `audit_events` table is append-only at the database level
  (enforced by the trigger introduced in `migrations/0001_init.sql`);
  this is a binding rule, not an implementation detail.
- Log levels: `debug`, `info`, `warn`, `error`. `error` requires a
  remediation hint or a linked playbook.
- Correlation IDs propagate across HTTP boundaries via
  `X-Request-Id`, **and across agent ↔ control-plane boundaries via
  the same header**. An agent call that does not carry a correlation
  ID still receives one server-side; logs and audit events on both
  sides reference the same ID.
- One canonical logger per process; one audit recorder per
  organization scope. Duplicate logging layers are forbidden.
- Security events MUST be explicit, structured, and labelled
  `severity: "security"` so downstream alerting can filter on them.
  This applies to (at minimum): auth failures, session revocation,
  enrollment-token issuance and consumption, finding overrides,
  provider configuration changes, admin-account creation.
- Errors must be diagnosable from the structured fields alone — no
  debug-only conditionals in production code paths, no `panic` for
  business flow.
- No tokens, credentials, certificate private material, or session
  identifiers in logs (cross-link: §6.9 redaction allow-list).

## 10. Provider Abstraction (Ops Freedom Rule)

- Every external integration is a Go interface in
  `internal/providers/<domain>/provider.go`.
- Provider implementations are isolated in subpackages
  (`internal/providers/pki/vault/`, `internal/providers/pki/adcs/`, etc).
- Core domain logic depends only on the interface.
- Adding a new provider must not require changes to `internal/inventory`,
  `internal/risks`, or `internal/httpapi` beyond DI wiring.
- Providers must be registerable at startup; no hard imports of specific
  vendor packages in core code paths.

## 11. CI/CD Security Requirements

Every merge into `main` is gated by automated CI. The following checks
are **mandatory and blocking** — a PR cannot be merged while any of them
is failing:

**Code quality**

- `gofmt` (no unformatted files) — backend and `agent/windows`
- `go vet ./...` — backend and `agent/windows`
- `go test ./...` — backend and `agent/windows`
- `go build ./...` — backend and `agent/windows` (the agent additionally
  cross-compiles for `GOOS=windows GOARCH=amd64`)
- `npm run lint` — frontend
- `npm run typecheck` — frontend
- `npm test` — frontend
- `npm run build` — frontend

**Static analysis**

- CodeQL (Go)
- CodeQL (JavaScript/TypeScript)

**Vulnerability scanning**

- `govulncheck` — backend Go module
- `govulncheck` — `agent/windows` Go module
- `npm audit --audit-level=high` — frontend
- Trivy filesystem scan — fails on HIGH/CRITICAL

**Secrets and dependency health**

- Gitleaks — secret scan over the diff and history
- Dependency Obituary — fails when **direct** dependency health drops
  below the configured threshold (currently 60). Scope is intentionally
  narrow: the action runs on `frontend/package.json`, not on the
  lockfile, so the gate covers direct dependencies only. Complements
  CVE scanners by catching abandoned, archived, or deprecated upstream
  packages we have chosen to depend on directly.
  Transitive dependency CVE risk is covered by `npm audit
  --audit-level=high` and the Trivy filesystem scan; transitive
  dependency *health* is intentionally not gated by Dependency Obituary
  for v0.1, because gating on the full npm long tail produces too much
  noise on healthy direct deps.

  **Exclusions (binding):**

  Exclusions are managed in a single file at the repo root:
  [`.depobituaryignore`](./.depobituaryignore). It is gitignore-style
  (one exact package name per line, `#` comments). The action loads
  it via `bin/check.js`'s `loadAllowlist()`. Excluded packages are
  still scored and tagged `IGNORED` in the report so they remain
  visible — they simply do not count toward the threshold-fail
  decision.

  The current allowed exclusion list is exactly **one** entry:

  - `eslint-plugin-react` — current obituary score 45 (below 60). The
    plugin is the de-facto React linting plugin in the ecosystem and is
    useful for future frontend maturity, but its current health score
    should not block the v0.1 foundation phase. The exclusion is
    explicit, single-package, and **reversible**: delete the
    `eslint-plugin-react` line in `.depobituaryignore` to re-arm the
    gate for this package.

  Wildcard / pattern entries (e.g. `@types/*`) are forbidden in
  `.depobituaryignore` regardless of whether the action accepts them.
  Every entry must be an exact package name with a comment immediately
  above it explaining why and how to remove it.

  Adding additional exclusions, switching to wildcard patterns, lowering
  the threshold, or wrapping the job in `continue-on-error` are all
  forbidden — they require a CLAUDE.md amendment, not a convenience
  tweak. The current exclusion is the only sanctioned one for v0.1.

**Build and runtime smoke**

- `docker compose config -q` — compose configuration validates
- `docker compose build` — backend and frontend images build cleanly
- Runtime smoke — the stack starts and `/healthz` and `/readyz` return
  the expected envelopes

**Release-time additions (not blocking on every PR)**

- SBOM generated for every release artifact
- Release artifacts will be signed (cosign or equivalent) by v1.0
- Dependency updates are reviewed; no auto-merge of dependency PRs

**Planned: Windows CI (lands in Phase 6)**

The current required-checks list does not include a Windows runner.
By Phase 6 the blocking set will gain a `windows-latest` job that:

- Builds the agent natively (a check the existing Linux
  `GOOS=windows` cross-compile is necessary but not sufficient for).
- Smoke-tests the Windows service install / uninstall flow.
- Runs an end-to-end agent-to-control-plane integration over real
  HTTPS: enrollment, heartbeat, inventory upload, TLS fingerprint
  pinning. Critical security flows MUST run end-to-end, not mocked.

Source of truth for the design: `docs/engineering/WINDOWS_CI.md`
(forward reference — created in the deliverables PR that follows
the rule-updates PR introducing this section).

The blocking set above is required to be **deterministic, reliable, and
reproducible**. Flaky or environment-dependent checks are not added to
the blocking set; if a blocking check becomes flaky, the right answer is
to fix the check, not to relax the gate.

The exact wiring lives in `.github/workflows/`:

- `ci.yml` — quality + Docker + smoke
- `codeql.yml` — CodeQL (Go + JS/TS)
- `security.yml` — govulncheck, npm audit, Trivy, Gitleaks
- `dependency-obituary.yml` — Dependency Obituary

Branch protection on `main` enforces the above. See
[`docs/BRANCHING.md`](./docs/BRANCHING.md) for the full PR policy.

## 12. Trust Model Assumptions (v0.1)

- The control plane is deployed in an environment the operator trusts.
- The PostgreSQL database is on a trusted network.
- Operators access the UI from authenticated sessions over TLS.
- Agents are installed by the operator on Windows endpoints they own.
- Agents trust the control plane's TLS identity (pinned at enrollment).
- The control plane does **not** trust agents to assert their own
  identity beyond the cryptographic material established at enrollment.

Anything outside these assumptions (hostile network between agent and
control plane, untrusted DB host, shared multi-tenant deployment) is
**out of scope for v0.1** and must be re-evaluated before being supported.

## 13. Non-Goals for v0.1

- Lifecycle automation (renewal, revocation, rotation).
- Built-in CA functionality.
- Kubernetes-native deployment.
- Linux/macOS discovery agents.
- SSH key inventory.
- Multi-tenant org isolation beyond a single `organizations` row.
- AI-assisted findings.
- HA clustering.
- SaaS billing / quotas.

## 14. Decision Process

When uncertain, choose:

- **simpler** over clever
- **explicit** over implicit
- **operator-controlled** over magical
- **secure-by-default** over convenient
- **modular monolith** over distributed
- **interface boundary** over direct coupling

Every major feature proposal is validated against:

- security impact
- ops freedom
- attack surface
- maintainability
- deployment simplicity
- long-term extensibility

A feature that fails any of these is rejected or redesigned.

## 15. Amending This Document

CLAUDE.md may only be amended by:

1. A pull request that explicitly modifies this file.
2. A short rationale in the PR description.
3. Explicit acknowledgement that the change is a constitutional change,
   not an implementation detail.

Implementation changes that conflict with CLAUDE.md must be reverted
or must update CLAUDE.md first — not silently work around it.

## 16. Database Rules

The storage layer owns the database. The rest of the system consumes
repository interfaces and never reaches around them.

- Every schema change goes through an explicit, numbered, append-only
  migration under `backend/migrations/NNNN_*.sql`. No exceptions.
- No auto-create / auto-mutate at runtime in production. The control
  plane refuses to start against a database whose `schema_migrations`
  table does not match the binary's expected version.
- Destructive migrations (column drop, type narrowing, NOT NULL on an
  existing column) require the documented two-phase pattern: ship code
  that handles both shapes, deploy, then drop in a follow-up migration
  once the old shape is no longer reachable.
- Storage / repository layer is the **only** place that knows SQL.
  Domain modules consume repository interfaces; HTTP handlers do not
  touch SQL; migrations contain DDL only, not business logic.
- No business logic inside migrations. Migrations move schema, not
  data semantics.
- Indexes are intentional and documented in the migration that
  introduces them — comment beside the `CREATE INDEX` explains the
  query pattern it serves.
- DB-engine-specific features (PostgreSQL extensions, JSONB-only
  operators, partial indexes) require explicit rationale in the
  migration. Default to portable SQL.
- Migrations are deterministic and repeatable across fresh installs
  and existing-database upgrades. A `migrate up` against a clean DB
  must produce the same schema as `migrate up` against an
  already-migrated DB.

## 17. API Evolution Rules

The HTTP surface is part of the product contract.

- `/api/v1` is stable. Field semantics, names, and the canonical
  error envelope shape `{ "error": { "code", "message" } }` (owned by
  `internal/httpapi/envelope`) do not change without a new prefix.
- Additive changes inside `/api/v1` are allowed: new endpoints, new
  optional fields, new error codes. Each addition is documented in
  `docs/api/REST_API.md` in the same PR that ships it.
- Breaking changes require `/api/v2`. Both prefixes coexist for at
  least one minor release before `/api/v1` is retired.
- Deprecation markers go in `docs/api/REST_API.md` before any removal.
  An endpoint cannot be removed in the same release it is deprecated.
- No transport-specific business logic in handlers. Handlers translate
  HTTP into domain calls and back; if a behavior changes, it changes
  in the domain module, not in `httpapi`.
- JSON shape is stable per resource. Field renames within `/api/v1`
  are forbidden; add a new field and deprecate the old.

## 18. Robustness Requirements

The system behaves predictably or fails closed. There is no third
state.

- Every blocking call accepts `context.Context`. Functions that
  cannot be cancelled are a defect.
- Graceful shutdown drains in-flight work before exit, with an
  explicit deadline. The control plane already does this in
  `httpapi.Server.Run`; this is the binding rule, not just the
  implementation.
- Bounded retries with explicit caps. No fire-and-forget loops, no
  hidden retries inside libraries (see §8.11).
- Idempotency keys are required on inventory uploads and on any
  non-idempotent agent → control-plane operation. The server treats
  duplicate keys as no-ops, never as conflicts.
- Readiness (`/readyz`) checks real dependencies (DB, registered
  probes). Liveness (`/healthz`) stays process-only — it answers
  "is the binary running?" with no external lookups.
- State transitions on agents, findings, sessions, and enrollment
  tokens are explicit enumerated state machines. No implicit string
  comparison; no skipping intermediate states.
- Forbidden patterns: panic-driven business flow; hidden retries;
  hidden async; fire-and-forget goroutines; silent / swallowed
  errors; unbounded goroutines; non-deterministic timing assertions
  in business code.

## 19. Engineering Discipline

Engineering discipline is a product feature in a cybersecurity
platform. The rules below are enforced at PR review.

**Package-level discipline (`doc.go` rule):**

Every package **exposing domain behavior** must contain a `doc.go`
defining:

- ownership boundaries (what this package owns, what it does not),
- responsibilities (the single reason this package exists),
- forbidden dependencies (which other packages this one must not
  import — a per-package narrowing of §8.6),
- architectural role (the layer this package sits in: `httpapi`,
  domain, storage, provider, agent component).

Trivial / internal utility packages (e.g. `clock`, `ids`) do not
need a separate `doc.go` if their primary file's package comment is
sufficient and their boundaries are unambiguous. The goal is
architecture clarity where it matters, not boilerplate everywhere.

**Per-feature discipline:**

- Every retry, every async operation, every external dependency has
  documented justification in the PR (and in the package's `doc.go`
  where it is structural).
- Every security-sensitive flow (auth, enrollment, token issuance,
  finding state changes, provider config) has an explicit threat
  model entry under `docs/security/` **before** merge — see §6.10.
- Every new module requires unit tests at merge time. Integration
  tests for behaviors that cross a process boundary (DB, agent,
  provider) live under `backend/test/integration/`.
- "When uncertain: simpler / explicit / lower coupling /
  operationally clear" wins over cleverness. Reaffirms §14 at the
  discipline level.

**Forbidden behaviors (PRs introducing them are rejected):**

- TODO-driven architecture (a TODO without a tracking issue).
- Dead commented-out code.
- Silent fallbacks (a code path that masks an upstream failure).
- Temporary hacks without a tracking issue.
- Hidden feature flags (env-driven behavior changes that are not
  documented in `internal/config`).
- Copy-paste implementations.
- Unbounded goroutines (see §8.10).
- Implicit retries.
- Panic-driven business flow.
- Hidden global state.
- Speculative abstractions ("we might need this later").
- Architecture-by-convenience that conflicts with CLAUDE.md.

This section references §8.5 (Anti-patterns), §8.8–§8.11 (DI,
Configuration, Concurrency, Outbound), §16 (Database), §17 (API
Evolution), and §18 (Robustness) rather than duplicating their
lists. A violation of any of those is also a violation of §19.

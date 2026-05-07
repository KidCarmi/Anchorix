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

## 9. Logging & Audit

- **Structured logs only** (JSON). No `fmt.Println`, no plain `log.Print`.
- Required log fields: `timestamp`, `level`, `event`, `request_id`,
  `actor` (when applicable), `component`.
- **Audit events are not logs.** Audit events are persisted in
  PostgreSQL, signed by event type, and never deleted within retention.
- Log levels: `debug`, `info`, `warn`, `error`. `error` requires a
  remediation hint or a linked playbook.
- Correlation IDs propagate across HTTP boundaries via
  `X-Request-Id`, and across agent calls via the same header.

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

- All merges to `main` require:
  - `go vet`, `golangci-lint`, `go test ./...` passing
  - `npm run lint`, `npm run typecheck`, `npm test` passing
  - SBOM generated for every release artifact
  - Container images scanned for CVEs (`trivy` or equivalent)
- Secret scanning runs on every PR (e.g., `gitleaks`).
- Dependency updates are reviewed; no auto-merge of dependency PRs.
- Release artifacts will be signed (cosign or equivalent) by v1.0.

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

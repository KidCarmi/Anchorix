# Anchorix — Architecture (v0.1)

This document describes the architecture of Anchorix v0.1. It is binding
guidance for design and implementation, but the engineering rules in
[`CLAUDE.md`](./CLAUDE.md) take precedence wherever the two overlap.

## 1. Goals

- Give operators **visibility** into certificates across their estate.
- Provide a **stable, extensible foundation** for future automation.
- Avoid **vendor lock-in** to any specific PKI.
- Be **operationally simple** to deploy, observe, and reason about.
- Be **secure by default** even before any automation features land.

## 2. Non-Goals (v0.1)

- Acting as a Certificate Authority.
- Storing or transmitting private keys.
- Automating renewal, revocation, or rotation.
- Linux / macOS / Kubernetes agent support.
- Multi-tenancy beyond a single organization row.
- HA / multi-region clustering.

## 3. High-Level Topology

```
+----------------------------+        HTTPS (mTLS after enrollment)
|  Windows endpoint(s)       |  ───────────────────────────────────┐
|                            |                                      │
|  anchorix-agent (service)  |                                      │
|  - cert store discovery    |                                      │
|  - inventory uploader      |                                      │
|  - heartbeat               |                                      │
+----------------------------+                                      │
                                                                    ▼
                                                   +-----------------------------+
                                                   |  Anchorix Control Plane     |
                                                   |  (single Go binary)         |
                                                   |                             |
                                                   |  +-----------------------+  |
                                                   |  | HTTP API (REST)       |  |
                                                   |  +-----------------------+  |
                                                   |  | Domain modules        |  |
                                                   |  |  inventory / risks /  |  |
                                                   |  |  agents / audit / ... |  |
                                                   |  +-----------------------+  |
                                                   |  | Provider abstractions |  |
                                                   |  +-----------------------+  |
                                                   |  | Storage (PostgreSQL)  |  |
                                                   |  +-----------------------+  |
                                                   +-----------------------------+
                                                              │
                                                              ▼
                                                      +---------------+
                                                      |  PostgreSQL   |
                                                      +---------------+

                                                              ▲
                                                              │ HTTPS
                                                  +---------------------+
                                                  | React + Tailwind UI |
                                                  +---------------------+
```

## 4. Components

### 4.1 Control Plane (Go modular monolith)

A single Go binary, deployed as one container. Internally organized into
small, cohesive packages with explicit interface boundaries.

Responsibilities:

- expose REST API for UI and agents
- enroll and authenticate agents
- ingest certificate inventory from agents
- evaluate risk findings
- persist audit events
- present provider abstractions to future integrations

The control plane is **stateless** at the process level. All durable state
lives in PostgreSQL. Restarting a control-plane process is always safe.

### 4.2 Windows Agent

A Go binary, packaged and run as a Windows service. Responsibilities:

- enumerate certificates from Windows certificate stores
  (LocalMachine\My, LocalMachine\WebHosting, CurrentUser\My, etc.)
- collect non-secret metadata (subject, issuer, SANs, validity, fingerprint,
  key usage, store location, friendly name, signature algorithm)
- send inventory to control plane via authenticated HTTPS
- send periodic heartbeats
- never read or transmit private key material
- run as `LocalSystem` only when needed; otherwise least-privilege user

### 4.3 Frontend (React + Tailwind)

A static SPA served by the control plane (or a separate lightweight static
server). Responsibilities:

- operator authentication
- views: dashboard, certificates, findings, agents, audit log, providers
- read-only in v0.1 with the exception of operator account actions and
  agent enrollment token issuance

### 4.4 PostgreSQL

The single source of truth for all durable data: organizations, users,
agents, certificates, findings, providers, audit events, migrations.

## 5. Internal Module Map (Backend)

```
backend/
  cmd/anchorix/          # main() — composition root, DI wiring
  internal/
    config/              # centralized configuration loader
    logger/              # structured logging (slog) + redaction
    httpapi/             # chi/echo router, middleware, handlers
    auth/                # session/token auth, RBAC stubs
    agents/              # enrollment, heartbeat, identity
    inventory/           # certificate domain logic
    risks/               # risk rule evaluation
    audit/               # audit event recording
    providers/
      pki/               # PKI provider interface + impls (stubs)
      secrets/           # secret backend interface (env, vault later)
      transport/         # agent transport interface
    storage/
      postgres/          # pgx-based repositories
      migrations/        # migration runner glue
    clock/               # time abstraction for testability
    ids/                 # ULID/UUID generation
  pkg/                   # public, stable helpers (kept tiny)
  migrations/            # raw .sql migrations (numbered, append-only)
  test/integration/      # integration test suites
```

### Boundaries (binding)

- `httpapi` → depends on domain modules via interfaces.
- Domain modules (`inventory`, `risks`, `agents`, `audit`) → depend on
  storage interfaces and provider interfaces. **Not** on `httpapi`.
- `storage/postgres` → implements storage interfaces, owns SQL.
- `providers/*` → never imported by core domain except via interfaces.

Cyclic imports are forbidden. PRs introducing them must be rejected.

## 6. Data Flow

### 6.1 Agent Enrollment

1. Operator generates a single-use enrollment token via the UI.
2. Operator installs the agent on a Windows host with the token.
3. Agent calls `POST /api/v1/agents/enroll` with token + a freshly
   generated key pair.
4. Control plane verifies token, issues an agent identity (cert or signed
   token), records the agent, and invalidates the enrollment token.
5. Subsequent calls use mTLS or HMAC-signed bearer tokens.

### 6.2 Certificate Inventory

1. Agent enumerates certificate stores on a configurable schedule.
2. Agent uploads `POST /api/v1/agents/{id}/inventory` with a list of
   non-secret certificate descriptors and a content hash.
3. Control plane upserts certificates keyed by `(fingerprint_sha256,
   source_host, source_store)`.
4. Inventory ingestion triggers risk evaluation.

### 6.3 Risk Evaluation

- Pluggable rules (initially built-in) compute findings:
  - expiring soon (< 30 days)
  - already expired
  - weak key (RSA < 2048, MD5/SHA1 signatures)
  - self-signed in production stores
  - duplicate identities across hosts
  - missing SANs
- Each finding has: rule_id, severity, evidence JSON, status
  (`open`, `acknowledged`, `suppressed`).
- Findings are recomputed deterministically on each ingestion.

### 6.4 Audit

State-changing operations record an `audit_event` row with:
`actor`, `action`, `target_type`, `target_id`, `metadata`, `request_id`,
`occurred_at`. Audit events are **insert-only**.

## 7. Security Architecture

- TLS terminates at the control plane (or at a reverse proxy in
  production). Agents pin the control plane's certificate at enrollment.
- Agent private keys are generated **on the agent host** and never leave it.
- Control plane has no key escrow features.
- Sessions are short-lived; cookies are `Secure`, `HttpOnly`, `SameSite=Lax`.
- All write paths require CSRF protection (token + same-site).
- Logs are redacted via a single allow-list of safe field names.

For the full threat model, see [`docs/security/THREAT_MODEL.md`](./docs/security/THREAT_MODEL.md).

## 8. Deployment

v0.1 ships as Docker Compose:

- `postgres` (official image)
- `anchorix-api` (Go binary container)
- `anchorix-web` (static React build served by Nginx or the API itself)

Operators are expected to front the stack with a reverse proxy / TLS
terminator they already manage. We provide a sample `compose` overlay,
not an opinionated TLS solution.

The Windows agent is **not** part of Compose. It ships as an MSI or zipped
service binary in a later milestone.

## 9. Observability

- Structured JSON logs to stdout.
- `/healthz` (liveness) and `/readyz` (readiness, including DB ping).
- Per-request `X-Request-Id`, propagated to logs.
- Basic Prometheus-compatible metrics endpoint planned (`/metrics`),
  scoped to internal use.

## 10. Extensibility (Ops Freedom Rule)

- New PKI providers plug into `internal/providers/pki/`.
- New secret backends plug into `internal/providers/secrets/`.
- New agent transports plug into `internal/providers/transport/`.
- Adding a provider must not require touching `inventory`, `risks`,
  `agents`, or `httpapi` beyond DI wiring.

## 11. What v0.1 Deliberately Excludes

See [`CLAUDE.md` §13](./CLAUDE.md). Repeating the most important here:
no built-in CA, no automated renewal/revocation, no Kubernetes, no Linux
agent, no AI features, no SSO, no multi-tenancy, no HA. Those phases will
land only after v0.1 is operationally stable and CLAUDE.md is updated.

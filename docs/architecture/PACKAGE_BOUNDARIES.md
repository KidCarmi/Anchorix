# Package Boundaries — Ownership & Forbidden Dependencies

**Source of truth for binding rules:** [`CLAUDE.md`](../../CLAUDE.md)
§§5, 8.6, 8.7, 8.8, 10, 16, 19. This document is the per-package
narrowing of those rules — when a future PR review asks "is this
import OK?" the answer is here.

## Layering (top-down)

```
cmd/                              composition root only
  ↓ wires concrete deps into
httpapi/  (handlers, middleware, server, envelope, readiness)
  ↓ depends on (interfaces)
domain/   (auth, agents, inventory, risks, audit)
  ↓ depends on (interfaces)
storage/  (postgres concrete) ← swappable behind repo interfaces
providers/ (pki, secrets, transport) ← swappable behind interfaces
clock, ids, logger, config           shared low-level primitives
```

The arrows are the **only** allowed direction. Reverse imports are
forbidden. A handler reaching directly into `storage/postgres` is
forbidden. A domain package importing from `httpapi` is forbidden.
Composition root (`cmd/anchorix/main.go`) is the only place that
*both* knows about every layer and wires concrete instances.

## Per-Package Spec

Each entry below states:

- **Responsibility** — the one reason this package exists.
- **Allowed deps** — packages it MAY import.
- **Forbidden deps** — packages it MUST NOT import (illustrative;
  the layering above is the general rule).
- **Anti-patterns** — patterns that would make this package
  drift from its purpose.

### `backend/cmd/anchorix`

- **Responsibility:** composition root + CLI dispatch (`serve`,
  `migrate`, `admin`, `healthcheck`, `version`).
- **Allowed deps:** every `internal/*` package (this is the only
  place that's true).
- **Forbidden deps:** none in principle, but: business logic is
  forbidden inside `cmd/`. The contents are wiring + flag parsing
  + small subcommand bodies that delegate.
- **Anti-patterns:** large subcommand functions; secret loading
  inline; SQL inline; HTTP handler inline.

### `backend/internal/config`

- **Responsibility:** the **only** package that calls `os.Getenv`.
  Loads, validates, and returns an immutable `*Config` (CLAUDE.md
  §8.9).
- **Allowed deps:** stdlib only.
- **Forbidden deps:** any other `internal/*` package (config has no
  upstreams other than the OS environment).
- **Anti-patterns:** silent fallback for security-sensitive
  settings; mutable config; lookup via reflection; config-key
  literals scattered across other packages.

### `backend/internal/httpapi`

- **Responsibility:** the HTTP edge — server lifecycle, routing,
  middleware, readiness probe registry, the canonical response
  envelope.
- **Subpackages:**
  - `httpapi/handlers` — translates HTTP into domain calls; no
    business logic; no SQL.
  - `httpapi/envelope` — single canonical JSON shape for all API
    responses (CLAUDE.md §17).
  - `httpapi/middleware` — request-id, recovery, security headers,
    auth resolver (added in PR-002).
- **Allowed deps:** `internal/auth`, `internal/agents`,
  `internal/inventory`, `internal/risks`, `internal/audit`,
  `internal/providers/*` **interfaces only**, `internal/config`,
  `internal/logger`, `internal/clock`, `internal/ids`,
  `internal/httpapi/envelope`.
- **Forbidden deps:** `internal/storage/*` (must go through domain
  interfaces). `cmd/*`. The agent module.
- **Anti-patterns:** business logic in handlers; SQL in handlers;
  hand-built JSON outside the envelope helper; URL constants used
  in tests instead of constants colocated with the route.

### `backend/internal/auth`

- **Responsibility:** operator authentication + session lifecycle.
  Owns the `User`, `Session`, and `Role` types; the password
  hashing policy; the cookie sign/verify primitives.
- **Allowed deps:** `internal/clock`, `internal/ids`,
  `internal/logger`, the `auth.Repository` and `auth.SessionStore`
  interfaces it defines.
- **Forbidden deps:** `internal/httpapi/*`, `internal/storage/*`
  (uses repo interfaces, never the pgx implementation).
- **Anti-patterns:** writing audit events directly (must go
  through `audit.Recorder`); reading config directly from env;
  caching session data in package-level globals.

### `backend/internal/agents`

- **Responsibility:** registered agents and their lifecycle —
  enrollment tokens, agent identity, status transitions
  (`pending_enrollment` → `active` → `disabled` → `revoked`).
- **Allowed deps:** `internal/clock`, `internal/ids`,
  `internal/logger`, the `agents.Repository` interface it defines.
- **Forbidden deps:** `internal/httpapi/*`, `internal/storage/*`,
  `internal/providers/*` (the agents domain knows about agents,
  not about how they connect — transport details belong in
  `providers/transport`).
- **Anti-patterns:** smuggling enrollment-token plaintext into
  audit events; storing token raw; goroutine-based token expiry.

### `backend/internal/inventory`

- **Responsibility:** the certificate domain model + ingestion
  logic. Owns `Certificate`, `CertificateObservation`,
  `InventoryBatch`, `DiscoveredCertificate`, and the `Ingestor`.
  Enforces the no-private-key rule at the domain boundary.
- **Allowed deps:** `internal/clock`, `internal/ids`,
  `internal/logger`, the `inventory.Repository` interface.
- **Forbidden deps:** `internal/httpapi/*`, `internal/storage/*`,
  any concrete provider package.
- **Anti-patterns:** PEM parsing in handlers; private-key
  detection scattered across multiple packages (must stay
  centralized in `inventory.rejectPrivateKeyMaterial` per
  CLAUDE.md §6.2).

### `backend/internal/risks`

- **Responsibility:** risk-rule registry and finding generation.
  Rules are pure functions over `*inventory.Certificate` (and an
  optional clock).
- **Allowed deps:** `internal/clock`, `internal/inventory` (read
  types only), the `risks.Repository` interface.
- **Forbidden deps:** `internal/httpapi/*`, `internal/storage/*`,
  any concrete provider package.
- **Anti-patterns:** stateful rules; rules with side effects;
  rules that touch IO.

### `backend/internal/audit`

- **Responsibility:** owns the `Event` type and the `Recorder`
  interface. Insert-only at the database layer (CLAUDE.md §16).
- **Allowed deps:** `internal/clock`, `internal/ids`. That's it.
- **Forbidden deps:** any other domain (audit is consumed by
  domains, not the other way around).
- **Anti-patterns:** providing query helpers that bypass the
  Recorder interface; log-and-audit duplication; non-structured
  metadata.

### `backend/internal/storage`

- **Responsibility:** repository **interfaces** consumed by
  domains. Aggregates them via `storage.Repositories` for the
  composition root.
- **Allowed deps:** every domain package whose `Repository` it
  re-exports (`auth`, `agents`, `inventory`, `audit`).
- **Forbidden deps:** `internal/httpapi/*`. No SQL here — only
  type aliases / interface aggregation.
- **Anti-patterns:** placing a concrete implementation in this
  directory.

### `backend/internal/storage/postgres`

- **Responsibility:** **the only place that knows SQL**. Each
  repository implementation lives in its own file
  (`auth_repository.go`, `agents_repository.go`, etc.) per
  CLAUDE.md §8.7.
- **Allowed deps:** `internal/auth`, `internal/agents`,
  `internal/inventory`, `internal/audit` (for the **types**, not
  for behavior); `internal/clock`, `internal/ids`,
  `internal/logger`; the pgx driver.
- **Forbidden deps:** `internal/httpapi/*`. The composition root
  itself imports this package, but no domain imports it.
- **Anti-patterns:** SQL string concat (CLAUDE.md §6.7); domain
  rules in repositories; cross-aggregate queries; auto-running
  migrations from `Open` (the runner is a separate explicit
  command, CLAUDE.md §16).

### `backend/internal/providers/pki`

- **Responsibility:** the abstraction every PKI backend
  implements — `Provider`, `Descriptor`, `Capability`, `Registry`.
- **Allowed deps:** stdlib only (`context`, etc.).
- **Forbidden deps:** any concrete vendor package; any other
  `internal/*` package.
- **Anti-patterns:** vendor-specific logic in this top-level
  interface package; shared helpers that assume one vendor's
  semantics.

### `backend/internal/providers/pki/<vendor>`

- **Responsibility:** one concrete backend (e.g. `pki/none` today;
  `pki/adcs`, `pki/vault` later).
- **Allowed deps:** the parent `pki` package, the vendor SDK,
  stdlib.
- **Forbidden deps:** other vendor packages; any domain package
  beyond the necessary type imports.
- **Anti-patterns:** shared helpers across vendor packages
  (extract to `pki/internal` if truly shared); vendor-specific
  config that bypasses `internal/config`.

### `backend/internal/providers/secrets`

- **Responsibility:** the secret-retrieval abstraction.
- **Allowed deps:** stdlib only.
- **Forbidden deps:** as above.
- **Anti-patterns:** caching secrets longer than the caller
  requires; logging the secret key name at info level when the
  value is sensitive.

### `backend/internal/providers/transport`

- **Responsibility:** the agent-facing transport interface.
- **Allowed deps:** stdlib + `internal/clock`, `internal/logger`.
- **Forbidden deps:** any domain.
- **Anti-patterns:** per-agent authentication state in this
  package (lives in `internal/agents`).

### `backend/internal/logger`

- **Responsibility:** the canonical structured logger with the
  redaction allow-list. CLAUDE.md §9.
- **Allowed deps:** stdlib + `internal/config` (for env-derived
  format).
- **Forbidden deps:** every other `internal/*` package — the
  logger is upstream of everything.
- **Anti-patterns:** package-level mutable state for the logger
  (callers receive `*Logger` via constructor injection).

### `backend/internal/clock`

- **Responsibility:** time abstraction for testability
  (CLAUDE.md §8.2).
- **Allowed deps:** stdlib only.
- **Forbidden deps:** every other `internal/*` package.
- **Anti-patterns:** any time-related utility beyond `Now()`.
  If the project needs a tick stream, it lives in a different
  package.

### `backend/internal/ids`

- **Responsibility:** opaque identifier generation (CLAUDE.md
  §8.7 — one responsibility per package).
- **Allowed deps:** stdlib only.
- **Forbidden deps:** every other `internal/*` package.
- **Anti-patterns:** parsing or interpreting IDs anywhere.

### `agent/windows/cmd/anchorix-agent`

- **Responsibility:** agent composition root + CLI dispatch.
- **Allowed deps:** every `agent/windows/internal/*` package.
- **Forbidden deps:** **anything under `backend/`.** The agent
  is a separate Go module by design (CLAUDE.md §5).
- **Anti-patterns:** business logic in `main.go`.

### `agent/windows/internal/config`

- **Responsibility:** agent-side env loading + validation.
- **Allowed deps:** stdlib.
- **Forbidden deps:** anything outside `agent/windows/`.
- **Anti-patterns:** silent fallback on
  `ANCHORIX_AGENT_CONTROL_PLANE_URL` (already enforced — fails
  closed).

### `agent/windows/internal/logger`

- **Responsibility:** structured logger for the agent process.
- **Allowed deps:** stdlib.
- **Forbidden deps:** anything outside `agent/windows/`.
- **Anti-patterns:** writing PEM blocks or token plaintext to
  logs.

### `agent/windows/internal/discovery`

- **Responsibility:** enumerate certificate stores; return only
  public-cert metadata.
- **Allowed deps:** Windows syscall packages (build-tagged).
- **Forbidden deps:** any HTTP client, any control-plane
  type.
- **Anti-patterns:** **reading private-key material** (CLAUDE.md
  §6.2). The package's contract is "no private keys, ever."

### `agent/windows/internal/transport`

- **Responsibility:** HTTPS client to the control plane;
  bearer-token / mTLS handling; retry policy; SPKI pinning
  (H3 in `AGENT_HARDENING.md`).
- **Allowed deps:** stdlib `net/http`, `crypto/tls`,
  `agent/windows/internal/logger`.
- **Forbidden deps:** any package that mutates global HTTP
  client state.
- **Anti-patterns:** `http.DefaultClient` (CLAUDE.md §8.11);
  unbounded retries; silent fallback to plain HTTP.

### `agent/windows/internal/service`

- **Responsibility:** Windows service runtime loop —
  heartbeat ticker, inventory ticker, graceful shutdown via
  `context.Context`.
- **Allowed deps:** other `agent/windows/internal/*` packages.
- **Forbidden deps:** anything outside `agent/windows/`.
- **Anti-patterns:** unbounded goroutine spawning per tick
  (CLAUDE.md §8.10); ignoring `ctx.Done()`.

### `frontend/src`

- **Responsibility:** operator UI.
- **Subdivision:**
  - `lib/api.ts` — the **single** typed API client. All HTTP
    goes through here.
  - `pages/` — top-level routed pages.
  - `components/` — reusable presentational pieces.
- **Allowed deps:** standard React ecosystem; React Query;
  React Router; Tailwind utility classes.
- **Forbidden deps:** anything that crafts API URLs by hand
  outside `lib/api.ts` (CLAUDE.md §8.6); CSS-in-JS frameworks;
  state libraries beyond what's needed.
- **Anti-patterns:** ad-hoc `fetch` calls in components; URL
  constants in pages; Tailwind class duplication that should
  be a component.

## Forbidden Cross-Cutting Edges (recap)

- `domain → httpapi` — reverse layering. **Forbidden.**
- `agent/windows/* → backend/*` — split-binary leak.
  **Forbidden.**
- `httpapi/handlers → storage/postgres` — must go through
  domain interface. **Forbidden.**
- `internal/* → cmd/*` — composition flows the other way.
  **Forbidden.**
- Two concrete provider packages importing each other —
  cross-vendor leak. **Forbidden.**

## Enforcement

Today these rules are enforced at code review. CLAUDE.md §19
makes a violation a rejected PR. A future small `go vet`-style
helper that walks the import graph and asserts the matrix above
is a possible PR-005-or-later addition; until then, this
document is the human-readable contract.

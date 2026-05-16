# Anchorix REST API — v0.1 (Proposal)

This document is the contract for the Anchorix HTTP API in v0.1. Handlers
live in [`backend/internal/httpapi`](../../backend/internal/httpapi). Routes
mounted under `/api/v1` are versioned and backward-compatible per CLAUDE.md
§5.10. Breaking changes require `/api/v2`.

## Conventions

- **Base URL:** `/api/v1`
- **Content type:** `application/json; charset=utf-8`
- **Auth:** session cookie for UI clients, HMAC-signed bearer token for
  agent clients (mTLS in Phase 6).
- **Correlation:** every request returns an `X-Request-Id` header.
- **Errors:** consistent envelope:

```json
{
  "error": {
    "code": "snake_case_code",
    "message": "human readable message"
  }
}
```

- **Pagination:** cursor-based for list endpoints:

```
GET /certificates?limit=50&cursor=eyJ...
```

Response includes `next_cursor` (or null) at the top level.

- **Time:** RFC 3339 UTC strings.

## Health (unauthenticated)

| Method | Path       | Purpose                  |
| ------ | ---------- | ------------------------ |
| GET    | `/healthz` | Liveness                 |
| GET    | `/readyz`  | Readiness (incl. DB ping) |

These are NOT under `/api/v1`. They must remain unauthenticated and stable.

## Auth

| Method | Path                | Auth | Purpose                              |
| ------ | ------------------- | ---- | ------------------------------------ |
| POST   | `/auth/login`       | none | Exchange email/password for session  |
| POST   | `/auth/logout`      | user | Terminate the current session        |
| GET    | `/auth/me`          | user | Return current operator profile      |

### `POST /auth/login`

Request body:

```json
{ "email": "alice@example.com", "password": "..." }
```

Successful response — `200 OK`, sets the session cookie, body is the
user profile:

```json
{
  "id": "...",
  "organization_id": "anchorix",
  "email": "alice@example.com",
  "display_name": "Alice",
  "role": "admin",
  "disabled": false,
  "created_at": "2026-05-09T10:00:00Z",
  "last_login_at": "2026-05-09T10:05:42Z"
}
```

The cookie:

- name: `anchorix_session` (overridable via `ANCHORIX_SESSION_COOKIE_NAME`)
- attributes: `HttpOnly; SameSite=Lax`. `Secure` is emitted whenever
  `ANCHORIX_TLS_TERMINATION` is anything other than `disabled_dev`
  — so production, staging, and reverse-proxy postures all get
  Secure cookies (CLAUDE.md §6.4). The only mode that emits a
  non-Secure cookie is the local dev mode over plain HTTP.
- value: signed; carries an opaque session id whose server-side row
  is the source of truth (CLAUDE.md §17 — envelope is stable, the
  cookie shape is implementation detail of the auth domain)

Sessions slide on each authenticated request: `expires_at` is
extended to `min(now + idle, created + absolute)`. Defaults are
8h idle / 24h absolute, both configurable via
`ANCHORIX_SESSION_IDLE_LIFETIME` and `ANCHORIX_SESSION_ABSOLUTE_LIFETIME`.

Failure responses (canonical envelope):

| Status | `code`                | When                                                |
| ------ | --------------------- | --------------------------------------------------- |
| 400    | `bad_request`         | Body is missing, malformed, or empty fields         |
| 401    | `invalid_credentials` | No matching user, wrong password, or disabled user  |

The server never distinguishes between "no user" and "wrong password"
externally (CLAUDE.md §6: deterministic auth behavior).

### `POST /auth/logout`

Requires authentication. Revokes the current session and clears the
cookie. `204 No Content` on success. `401 unauthorized` if no session
is present.

### `GET /auth/me`

Requires authentication. Returns the same user profile shape as
`POST /auth/login`.

Failure responses:

| Status | `code`            | When                                                       |
| ------ | ----------------- | ---------------------------------------------------------- |
| 401    | `unauthorized`    | No session cookie, or session is unknown                   |
| 401    | `session_expired` | Cookie validates but the session is revoked or expired     |

## Deployment Packages

An admin creates a **deployment package** that a fleet-management
tool (SCCM, Intune, GPO, etc.) deploys silently to Windows endpoints.
Each package carries a single bootstrap secret used by every agent
the package enrolls. Lifecycle is bounded by `max_uses`,
`expires_at`, and operator revocation; all three are checked
atomically on every enrollment.

End-to-end design lives in
[`docs/engineering/AGENT_ENROLLMENT.md`](../engineering/AGENT_ENROLLMENT.md).

| Method | Path                                          | Auth   | Purpose                                                 |
| ------ | --------------------------------------------- | ------ | ------------------------------------------------------- |
| POST   | `/deployment-packages`                        | admin  | Create a deployment package; bootstrap secret shown once |
| POST   | `/deployment-packages/{id}/revoke`            | admin  | Revoke a deployment package; no future enrollments      |

### `POST /deployment-packages`

Request body:

```json
{
  "name": "Baseline Windows 0.1.0",
  "description": "Approved baseline build",
  "package_type": "baseline",
  "agent_version": "0.1.0",
  "ttl_seconds": 604800,
  "max_uses": 500,
  "default_group_name": "Default",
  "default_labels": ["baseline", "win"]
}
```

`package_type` is one of `baseline`, `bulk_sccm`, `technician`,
`vip`, `lab`. `ttl_seconds` and `max_uses` must both be positive.

Successful response — `201 Created`:

```json
{
  "id": "...",
  "organization_id": "anchorix",
  "name": "Baseline Windows 0.1.0",
  "package_type": "baseline",
  "agent_version": "0.1.0",
  "max_uses": 500,
  "uses_count": 0,
  "expires_at": "2026-06-08T12:00:00Z",
  "created_at": "2026-06-01T12:00:00Z",
  "default_group_name": "Default",
  "default_labels": ["baseline", "win"],
  "bootstrap_secret": "<base64-url, shown exactly once>",
  "bootstrap_metadata": {
    "control_plane_url": "https://anchorix.example.com",
    "organization_id": "anchorix",
    "package_id": "...",
    "expires_at": "2026-06-08T12:00:00Z",
    "max_uses": 500
  }
}
```

The `bootstrap_secret` field appears in this response **once**. It
is never echoed by any other endpoint; the server stores only
`sha256(bootstrap_secret)`. The `bootstrap_metadata` block carries
the minimum installer-side configuration so a future installer
generator (MSI / Intune profile / GPO) can pre-bake the values.

Failure responses:

| Status | `code`         | When                                                            |
| ------ | -------------- | --------------------------------------------------------------- |
| 400    | `bad_request`  | Body is malformed; `package_type` invalid; `ttl_seconds` or `max_uses` non-positive |
| 401    | `unauthorized` | No session                                                      |
| 403    | `forbidden`    | Authenticated user does not have the `admin` role               |

### `POST /deployment-packages/{id}/revoke`

Admin-only. Marks the deployment package as revoked: future
enrollments through its bootstrap secret are rejected with the
generic `enrollment_rejected` envelope. **Already enrolled agents
are unaffected** — agent revocation is a separate action (Phase 3+).

Organization-scoped: a package belonging to a different
organization returns `404 not_found`, the same envelope a
truly-missing id would produce, so admins cannot enumerate
packages in neighboring tenants.

Request body (all fields optional; an empty body is valid):

```json
{ "reason": "version superseded by 0.1.1" }
```

Successful response — `200 OK`:

```json
{
  "id": "...",
  "organization_id": "anchorix",
  "name": "Baseline Windows 0.1.0",
  "package_type": "baseline",
  "revoked_at": "2026-06-01T12:00:00Z",
  "revoked_by_user_id": "...",
  "revoked_reason": "version superseded by 0.1.1",
  "already_revoked": false
}
```

The response **never** includes `bootstrap_secret`; the plaintext
secret only ever appears in the original create call.

**Idempotency.** Re-revoking an already-revoked package returns
`200 OK` with `already_revoked: true` and the **existing** revoked
metadata (the original revoker's `revoked_by_user_id`,
`revoked_at`, and `revoked_reason` — the second call does NOT
overwrite them). The server does NOT emit a duplicate
`deployment_package.revoked` audit row in that case — the
original revoke's audit row is the source of truth.

Audit: a single `deployment_package.revoked` event is written
in the same transaction as the row UPDATE. Metadata carries
`package_type`, `agent_version`, `uses_count`, `max_uses`,
`has_reason`, and `reason_length` — never the plaintext
bootstrap secret or its hash.

Failure responses:

| Status | `code`           | When                                                            |
| ------ | ---------------- | --------------------------------------------------------------- |
| 400    | `bad_request`    | URL has no id, body is malformed JSON, or service input invalid |
| 401    | `unauthorized`   | No session                                                      |
| 403    | `forbidden`      | Authenticated user does not have the `admin` role               |
| 404    | `not_found`      | No package with this id exists in the caller's organization     |

## Agents

Two separate identity surfaces share the `/agents` / `/agent`
prefixes:

- **Operator** (session cookie) — uses `/agents/*` to list and
  manage agents from the admin UI.
- **Agent bearer** (Authorization: Bearer) — uses `/agent/*`
  (singular) to authenticate the agent itself. The bearer is the
  `agent_credential` returned exactly once by
  `POST /agents/enroll`. Cookies are NOT consulted by these
  endpoints; operator and agent identity are independent axes
  (CLAUDE.md §8.6).

mTLS replaces the bearer credential in Phase 6 (CLAUDE.md §6.4);
until then, the bearer credential is the v0.1 agent identity
primitive.

| Method | Path                                  | Auth     | Purpose                                                |
| ------ | ------------------------------------- | -------- | ------------------------------------------------------ |
| GET    | `/agents`                             | user     | List registered agents (org-scoped)                    |
| GET    | `/agents/{id}`                        | user     | Get a single agent *(stub — Phase 2 continuation)*     |
| GET    | `/agents/{id}/inventory`              | user     | Read the agent's current machine-inventory snapshot    |
| GET    | `/agent-inventory`                    | user     | List slim machine-inventory summaries across the fleet |
| POST   | `/agents/enroll`                      | bootstrap| Agent enrollment (consumes bootstrap secret)           |
| GET    | `/agent/me`                           | agent    | Authenticated agent identity (bearer credential)       |
| POST   | `/agent/heartbeat`                    | agent    | Liveness heartbeat (bumps `last_seen_at`)              |
| POST   | `/agent/inventory`                    | agent    | Submit / replace the agent's machine-inventory snapshot |

The original v0.1 schema proposal included a
`POST /agents/enrollment-tokens` endpoint for issuing single-use
enrollment tokens. PR-013 supersedes that concept with deployment
packages; the path is no longer routed and returns `404 not_found`.

### `POST /agents/enroll`

Anonymous endpoint. The bootstrap secret **is** the authentication;
SCCM-style fleet rollouts call this endpoint silently on first boot
of the agent service.

Request body:

```json
{
  "bootstrap_secret": "<from deployment package>",
  "hostname": "ws-001.corp.example",
  "agent_version": "0.1.0",
  "machine_fingerprint": "<optional, hashed before storage>",
  "install_id": "<optional, idempotent installer id>"
}
```

`machine_fingerprint` and `install_id` are both optional but
recommended for v0.1. `install_id` is unique per organization; a
second enrollment with the same `install_id` is rejected (fail
closed — re-issuing a credential without an explicit reinstall
flow is out of scope for v0.1).

Successful response — `201 Created`:

```json
{
  "agent_id": "...",
  "organization_id": "anchorix",
  "status": "active",
  "agent_credential": "<bearer credential, shown exactly once>",
  "enrolled_at": "2026-06-01T12:00:00Z"
}
```

`agent_credential` is the v0.1 bearer identity. mTLS replacement is
deferred to Phase 6 (CLAUDE.md §6.4).

Failure responses use a single deterministic envelope so the caller
cannot enumerate package state:

| Status | `code`                  | When                                                                    |
| ------ | ----------------------- | ----------------------------------------------------------------------- |
| 401    | `enrollment_rejected`   | Bootstrap secret unknown / expired package / revoked package / exhausted package / duplicate `install_id` / malformed body |

The specific internal reason is recorded as an
`agent.enrollment_rejected` audit event with `severity: "security"`
so operators can diagnose rejections without leaking package state
to the caller.

### `GET /agents`

Operator-only, organization-scoped. Returns the most-recently-enrolled
agents first.

```json
{
  "items": [
    {
      "id": "...",
      "organization_id": "anchorix",
      "hostname": "ws-001.corp.example",
      "status": "active",
      "agent_version": "0.1.0",
      "enrolled_at": "2026-06-01T12:00:00Z",
      "last_seen_at": "2026-06-01T12:00:00Z",
      "deployment_package_id": "...",
      "group_name": "Default",
      "labels": ["baseline", "win"]
    }
  ],
  "next_cursor": null
}
```

`next_cursor` is always `null` in v0.1; pagination lands when
fleets grow large enough to need it.

### `GET /agent/me`

**Agent-authenticated** endpoint. The request MUST carry the
`Authorization: Bearer <agent_credential>` header. Operator session
cookies are NOT honored on this path; an operator wishing to view
their own user profile uses `GET /auth/me`.

Purpose: prove the agent-auth model works end-to-end so a freshly
enrolled agent can sanity-check its own identity before any
state-changing call.

Successful response — `200 OK`:

```json
{
  "agent_id": "...",
  "organization_id": "anchorix",
  "status": "active",
  "deployment_package_id": "...",
  "agent_version": "0.1.0",
  "group_name": "Finance",
  "labels": ["sccm", "finance"]
}
```

The response **never** echoes the bearer credential, the
credential hash, or the machine fingerprint.

Failure responses collapse to a single deterministic envelope so
the caller cannot enumerate identity state:

| Status | `code`                | When                                                                  |
| ------ | --------------------- | --------------------------------------------------------------------- |
| 401    | `agent_unauthorized`  | Missing `Authorization` header, scheme is not `Bearer`, token is empty, credential unknown, or agent status is not `active` |

The internal reason is recorded in an `agent.authentication_failed`
audit event tagged `severity: "security"` so operators can diagnose
attempts without surfacing the reason on the wire.

### `POST /agent/heartbeat`

**Agent-authenticated** endpoint. The agent reports liveness on a
fixed cadence. The handler bumps `last_seen_at` and (optionally)
refreshes `version` and `hostname` if the body supplies non-empty
values.

Heartbeat is **operational telemetry, not an audit event stream**.
No `audit_events` row is written for a successful heartbeat
regardless of whether `agent_version` or `hostname` drifted —
operators who want drift visibility query the `agents` table
directly. Failed authentication is already audited by the H-007
`agent.authentication_failed` path.

Request body (all fields optional; empty body is valid):

```json
{
  "agent_version": "0.1.0",
  "hostname": "HOST-01"
}
```

The agent id is taken from the authenticated context (never from
the request body) — an agent cannot heartbeat as another agent.

Successful response — `200 OK`:

```json
{
  "status": "ok",
  "server_time": "2026-06-01T12:00:00Z",
  "next_heartbeat_seconds": 300
}
```

`next_heartbeat_seconds` is a cadence hint (5 minutes in v0.1).
Future revisions may compute it dynamically; clients should treat
the field as authoritative for their next scheduled heartbeat.

The endpoint is **idempotent** — multiple heartbeats from the same
agent simply bump `last_seen_at` repeatedly. No row is ever
created by heartbeat. An agent that does not yet exist (deleted
between auth and update) gets the same `401 agent_unauthorized`
envelope as any other rejected auth.

Failure responses:

| Status | `code`               | When                                                        |
| ------ | -------------------- | ----------------------------------------------------------- |
| 400    | `bad_request`        | Body is malformed JSON                                      |
| 401    | `agent_unauthorized` | Bearer missing, malformed, unknown, or agent revoked/disabled |

Offline state is derived externally: an agent is "offline" if
`now() - last_seen_at` exceeds a deployment-specific threshold.
v0.1 does NOT ship a stale-agent sweeper, automatic state
transitions, or alerting — those are future work.

### `POST /agent/inventory`

**Agent-authenticated** endpoint. The agent reports its current
machine-inventory snapshot (host facts: OS, version, architecture,
local IPs). The handler UPSERTs a single row keyed by
`(organization_id, agent_id)`; there is **no history table** in v0.1
and repeated identical submissions are naturally idempotent at the
row level. Certificate inventory and risk findings are separate
domains; this endpoint does NOT accept certificate material.

The agent id and organization id come from the authenticated agent
principal — body-supplied `agent_id` / `organization_id` are
ignored. An agent cannot submit inventory on behalf of another
agent.

**Audit policy: this endpoint is operational state sync.** No
`audit_events` row is written for a successful submission, matching
the heartbeat cost model documented in
[`docs/engineering/AGENT_ENROLLMENT.md`](../engineering/AGENT_ENROLLMENT.md)
"Heartbeat". Failed authentication is still audited by the
`agent.authentication_failed` path (H-007).

Request body (every field optional; an empty `{}` is valid):

```json
{
  "hostname": "ws-001.corp.example",
  "os_name": "Windows 11",
  "os_version": "10.0.22631",
  "agent_version": "0.1.0",
  "machine_arch": "amd64",
  "local_ips": ["10.0.0.5", "fe80::1%eth0"],
  "installed_at": "2026-04-01T00:00:00Z"
}
```

`installed_at` may be omitted or `null` when the installer does not
record it. All string fields are trimmed; per-field byte caps
(non-negotiable, oversize input is rejected — no silent truncation):

| Field           | Max bytes |
| --------------- | --------- |
| `hostname`      | 255       |
| `os_name`       | 100       |
| `os_version`    | 100       |
| `agent_version` | 64        |
| `machine_arch`  | 64        |

`local_ips` is capped at 32 entries, each ≤ 64 bytes. Empty list
(or omitted field) is valid.

Successful response — `200 OK`:

```json
{
  "status": "ok",
  "received_at": "2026-06-01T12:00:00Z"
}
```

The response is intentionally minimal — there is no
`next_inventory_seconds` cadence hint in v0.1; inventory cadence is
operator-controlled. Adding a cadence hint later is an additive
change under CLAUDE.md §17.

Failure responses:

| Status | `code`               | When                                                        |
| ------ | -------------------- | ----------------------------------------------------------- |
| 400    | `bad_request`        | Body is malformed JSON, has trailing JSON / garbage after the first object, exceeds the per-field byte caps, has more than 32 `local_ips` entries, has a `local_ips` entry longer than 64 bytes, or has a `local_ips` entry that is empty after whitespace trimming |
| 401    | `agent_unauthorized` | Bearer missing, malformed, unknown, or agent revoked/disabled |

### `GET /agents/{id}/inventory`

Operator-only, organization-scoped. Returns the current machine-
inventory snapshot for an agent enrolled in the operator's
organization. A snapshot belonging to a different organization
surfaces as `404 not_found` (same envelope a truly-missing id
produces) so operators cannot enumerate snapshots in neighboring
tenants.

Successful response — `200 OK`:

```json
{
  "agent_id": "...",
  "organization_id": "anchorix",
  "hostname": "ws-001.corp.example",
  "os_name": "Windows 11",
  "os_version": "10.0.22631",
  "agent_version": "0.1.0",
  "machine_arch": "amd64",
  "local_ips": ["10.0.0.5", "fe80::1%eth0"],
  "installed_at": "2026-04-01T00:00:00Z",
  "received_at": "2026-06-01T12:00:00Z",
  "updated_at": "2026-06-01T12:00:00Z"
}
```

Failure responses:

| Status | `code`         | When                                                                |
| ------ | -------------- | ------------------------------------------------------------------- |
| 400    | `bad_request`  | URL has no id                                                       |
| 401    | `unauthorized` | No session                                                          |
| 404    | `not_found`    | No snapshot exists for this agent in the caller's organization      |

### `GET /agent-inventory`

Operator-only, organization-scoped. Returns a paginated list of
slim machine-inventory summaries for every agent in the operator's
organization. Designed for fleet-overview screens — operators
wanting the full snapshot for one agent still use
`GET /agents/{id}/inventory`.

The endpoint is mounted on the `/agent-inventory` (no trailing
`s`) resource so it does not collide with `/agents/{id}/...`
path-parameter routes. Agent bearer credentials are NOT honored;
operator and agent identity are independent axes (CLAUDE.md §8.6).

Query parameters:

| Param    | Default | Max | Notes                                                                     |
| -------- | ------- | --- | ------------------------------------------------------------------------- |
| `limit`  | 50      | 200 | Positive integer. Non-numeric, zero (treated as default), negative, or above-max values return `400 bad_request`. |
| `cursor` | —       | —   | Opaque pagination token from a prior response's `next_cursor`. Malformed cursor returns `400 bad_request`. |

Ordering is **`received_at DESC, agent_id ASC`** — newest snapshot
first, with a stable tie-break on `agent_id`. The
`(received_at, agent_id)` tuple is the cursor.

Successful response — `200 OK`:

```json
{
  "items": [
    {
      "agent_id": "...",
      "hostname": "ws-001.corp.example",
      "os_name": "Windows 11",
      "os_version": "10.0.22631",
      "agent_version": "0.1.0",
      "machine_arch": "amd64",
      "local_ips_count": 2,
      "installed_at": "2026-04-01T00:00:00Z",
      "received_at": "2026-06-01T12:00:00Z",
      "updated_at": "2026-06-01T12:00:00Z"
    }
  ],
  "next_cursor": "MjAyNi0wNi0wMVQxMjowMDowMC4xMjM0NTY3ODlafGFnZW50LTAwMQ"
}
```

`next_cursor` is `null` when no further pages remain.

`local_ips` is intentionally **not** returned in the list payload —
only `local_ips_count`. The list endpoint is the fleet-overview
surface; the per-agent endpoint
(`GET /agents/{id}/inventory`) remains the single source for the
full IP list and any other field the summary omits.

Failure responses:

| Status | `code`         | When                                                                |
| ------ | -------------- | ------------------------------------------------------------------- |
| 400    | `bad_request`  | `limit` non-numeric / non-positive / above 200, or `cursor` malformed |
| 401    | `unauthorized` | No operator session (agent bearer credentials are not honored)      |

Audit policy: read-only. No `audit_events` row is emitted
(CLAUDE.md §9 — audits record state changes).

### Certificate inventory (deferred)

Certificate inventory (PEM-bearing observation upload, deduplication
by fingerprint, observations table) is intentionally NOT part of
v0.1 PR-018; it ships in a later phase under a separate endpoint
contract. The original v0.1 schema proposal hinted at a
certificate-shaped `POST /agents/{id}/inventory` payload; that
shape is **not** the contract for `POST /agent/inventory` above.

## Certificates

| Method | Path                  | Auth | Purpose                                |
| ------ | --------------------- | ---- | -------------------------------------- |
| GET    | `/certificates`       | user | Paginated list with filters            |
| GET    | `/certificates/{id}`  | user | Single certificate + observations list |

Supported filters on list:

- `q` — substring match against subject / SANs / issuer
- `expiring_before` — RFC3339; returns certs with `not_after < value`
- `is_ca` — boolean
- `agent_id` — filter to a specific agent
- `cursor`, `limit`

## Findings

| Method | Path                                | Auth | Purpose                            |
| ------ | ----------------------------------- | ---- | ---------------------------------- |
| GET    | `/findings`                         | user | Paginated, filterable list         |
| GET    | `/findings/{id}`                    | user | Single finding with evidence       |
| POST   | `/findings/{id}/acknowledge`        | user | Acknowledge with required reason   |
| POST   | `/findings/{id}/suppress`           | user | Suppress with reason + expiry      |

Acknowledge / suppress bodies require a non-empty `reason`. Both actions
emit `audit_events`.

## Audit

| Method | Path             | Auth | Purpose                   |
| ------ | ---------------- | ---- | ------------------------- |
| GET    | `/audit/events`  | user | Paginated list with filters |

Filters: `actor`, `action`, `target_type`, `target_id`, `since`, `cursor`,
`limit`.

## Providers

| Method | Path                    | Auth  | Purpose                                  |
| ------ | ----------------------- | ----- | ---------------------------------------- |
| GET    | `/providers`            | user  | List registered providers                |
| GET    | `/providers/{id}`       | user  | Provider descriptor + last health check  |

Provider write APIs are deferred until specific provider implementations
land in later phases.

## Error Codes (initial)

| Code                     | HTTP | Meaning                                                |
| ------------------------ | ---- | ------------------------------------------------------ |
| `bad_request`            | 400  | Malformed input                                        |
| `unauthorized`           | 401  | No session, unknown session, or session resolution failed |
| `invalid_credentials`    | 401  | Login failed (no matching user, wrong password, or disabled user) |
| `session_expired`        | 401  | Session is revoked or past its idle/absolute deadline  |
| `forbidden`              | 403  | Authenticated but not allowed                          |
| `not_found`              | 404  | Resource does not exist                                |
| `conflict`               | 409  | Idempotency / state conflict                           |
| `rate_limited`           | 429  | Rate limit hit                                         |
| `private_key_rejected`   | 400  | Inventory upload contained private key material        |
| `enrollment_invalid`     | 400  | Token expired, consumed, or hostname mismatch          |
| `enrollment_rejected`    | 401  | Agent enrollment failed for any reason (generic; see audit) |
| `agent_unauthorized`     | 401  | Agent-credential auth missing, malformed, unknown, or revoked |
| `not_implemented`        | 501  | Endpoint exists in contract but not in this build      |
| `internal_error`         | 500  | Unhandled server error                                 |

Per CLAUDE.md §17, this table is **additive only**. A code's
meaning never changes within `/api/v1`; new codes may be added.

## Versioning

The `/api/v1` prefix is permanent. Breaking changes require `/api/v2`,
both routes coexist for at least one minor release, and CLAUDE.md is
updated to record the transition.

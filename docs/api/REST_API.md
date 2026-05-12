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

| Method | Path                                  | Auth   | Purpose                                                 |
| ------ | ------------------------------------- | ------ | ------------------------------------------------------- |
| POST   | `/deployment-packages`                | admin  | Create a deployment package; bootstrap secret shown once |

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

## Agents

| Method | Path                                  | Auth     | Purpose                                                |
| ------ | ------------------------------------- | -------- | ------------------------------------------------------ |
| GET    | `/agents`                             | user     | List registered agents (org-scoped)                    |
| GET    | `/agents/{id}`                        | user     | Get a single agent *(stub — Phase 2 continuation)*     |
| POST   | `/agents/enroll`                      | bootstrap| Agent enrollment (consumes bootstrap secret)           |
| POST   | `/agents/{id}/heartbeat`              | agent    | *Stub — Phase 3.*                                      |
| POST   | `/agents/{id}/inventory`              | agent    | *Stub — Phase 3.*                                      |
| POST   | `/agents/enrollment-tokens`           | n/a      | *Deprecated stub — superseded by `POST /deployment-packages`.* |

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

### Inventory upload

```json
{
  "agent_id": "...",
  "hostname": "ws-001.corp.example",
  "collected_at": "2026-05-07T13:24:00Z",
  "certificates": [
    {
      "store_location": "LocalMachine\\My",
      "fingerprint_sha256": "ab12...",
      "subject": "CN=ws-001.corp.example",
      "issuer": "CN=Internal Issuing CA",
      "serial_number_hex": "01ab...",
      "signature_algorithm": "SHA256-RSA",
      "public_key_algorithm": "RSA",
      "public_key_bits": 2048,
      "not_before": "2025-05-07T00:00:00Z",
      "not_after": "2026-05-07T00:00:00Z",
      "sans": ["ws-001.corp.example"],
      "key_usages": ["DigitalSignature","KeyEncipherment"],
      "ext_key_usages": ["ServerAuth"],
      "is_self_signed": false,
      "is_ca": false,
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
    }
  ]
}
```

**Server-side hard rejections (HTTP 400):**

- payload contains any `BEGIN ... PRIVATE KEY` block
- `certificate_pem` does not parse
- `agent_id` does not match the authenticated agent
- `collected_at` is more than 24h in the future

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
| `not_implemented`        | 501  | Endpoint exists in contract but not in this build      |
| `internal_error`         | 500  | Unhandled server error                                 |

Per CLAUDE.md §17, this table is **additive only**. A code's
meaning never changes within `/api/v1`; new codes may be added.

## Versioning

The `/api/v1` prefix is permanent. Breaking changes require `/api/v2`,
both routes coexist for at least one minor release, and CLAUDE.md is
updated to record the transition.

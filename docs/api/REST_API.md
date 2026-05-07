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

Login body:

```json
{ "email": "alice@example.com", "password": "..." }
```

A successful login sets a `Secure; HttpOnly; SameSite=Lax` session cookie.
Body returns the user profile only — never the session id.

## Agents

| Method | Path                                  | Auth   | Purpose                                          |
| ------ | ------------------------------------- | ------ | ------------------------------------------------ |
| GET    | `/agents`                             | user   | List registered agents                           |
| GET    | `/agents/{id}`                        | user   | Get a single agent                               |
| POST   | `/agents/enrollment-tokens`           | user   | Issue a single-use enrollment token              |
| POST   | `/agents/enroll`                      | token  | Agent enrollment (consumes token + pubkey)       |
| POST   | `/agents/{id}/heartbeat`              | agent  | Liveness ping from the agent                     |
| POST   | `/agents/{id}/inventory`              | agent  | Upload a batch of certificate observations       |

### Enrollment

Enrollment tokens are returned **once** to the issuing operator. The server
stores only `sha256(token)`. Tokens have a TTL of `ANCHORIX_ENROLLMENT_TOKEN_TTL`
(default 15m).

`POST /agents/enroll` body:

```json
{
  "token": "<single-use enrollment token>",
  "hostname": "ws-001.corp.example",
  "agent_version": "0.1.0",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

Response:

```json
{
  "agent_id": "...",
  "agent_token": "<bearer token, shown once>",
  "control_plane_fingerprint_sha256": "..."
}
```

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
| `unauthorized`           | 401  | Missing or invalid credentials                         |
| `forbidden`              | 403  | Authenticated but not allowed                          |
| `not_found`              | 404  | Resource does not exist                                |
| `conflict`               | 409  | Idempotency / state conflict                           |
| `rate_limited`           | 429  | Rate limit hit                                         |
| `private_key_rejected`   | 400  | Inventory upload contained private key material        |
| `enrollment_invalid`     | 400  | Token expired, consumed, or hostname mismatch          |
| `not_implemented`        | 501  | Endpoint exists in contract but not in this build      |
| `internal_error`         | 500  | Unhandled server error                                 |

## Versioning

The `/api/v1` prefix is permanent. Breaking changes require `/api/v2`,
both routes coexist for at least one minor release, and CLAUDE.md is
updated to record the transition.

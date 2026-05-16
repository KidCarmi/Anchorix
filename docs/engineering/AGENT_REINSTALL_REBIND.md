# Agent Reinstall, Rebind, and Credential Rotation — Design

> **Status:** design only. Implementation lands in dedicated follow-up
> PRs (see "Recommended PR sequence" below). This document is the
> source of truth for those PRs' contracts.
>
> **Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
> this design and CLAUDE.md disagree, CLAUDE.md wins and this
> document is updated.

## Goal and motivation

Anchorix's agent identity model in v0.1 is **fail-closed by design**:
once an agent enrolls, its credential is the only proof of identity
the control plane will accept, and the control plane never re-issues
a credential through the normal enrollment path. That posture is the
right default, but it leaves operators with no in-product flow for
the very real cases below — they currently have to drop to direct
SQL or revoke+re-deploy with a fresh `install_id`:

- A workstation is reinstalled (same hardware, fresh OS).
- An OS rebuild wipes the agent's local credential file.
- A VM is cloned and one of the two copies needs to be re-enrolled
  as a distinct agent identity.
- An operator detects credential exposure and needs to rotate.
- An agent crashes between receiving and persisting a new
  credential (loses access without explicit revocation).

Heartbeat (`PR-017`) and machine-inventory snapshot (`PR-018` /
`H-010`) are already in tree. Certificate-inventory observations
(`H-011`) are the next data domain to land. **Observations are
attached to `agent_id`**: if a rebind creates a new `agent_id`,
historical correlation fragments. If a rebind reuses the same
`agent_id`, observations stay continuous across reinstalls. This
design commits to the second model — and therefore must land before
certificate inventory ships.

## 1. Current v0.1 behavior

The following are the contracts in production today, owned by
[`PR-013`](../../backend/internal/enrollment/) +
[`AGENT_ENROLLMENT.md`](./AGENT_ENROLLMENT.md):

- **`install_id` is single-use per organization.** A second
  `POST /api/v1/agents/enroll` with the same `install_id` is
  rejected with the generic `enrollment_rejected` envelope and an
  `agent.enrollment_rejected` audit row tagged
  `reason: "install_id_already_enrolled"`.
- **Existing agent credentials are never re-issued.** The plaintext
  `agent_credential` appears in exactly one place in the
  application (the `EnrollAgentOutput` struct) and is GC'd as soon
  as the enrollment response is written. No endpoint reads it back.
- **Rebind / recovery are not implemented.** Operators who need to
  reinstall today must:
  1. Revoke the existing agent row (direct SQL UPDATE today; agent
     revocation API lands in a later phase).
  2. Re-deploy the installer with a **fresh** `install_id`.
  The new installer enrolls cleanly via the standard
  `POST /agents/enroll` flow but appears in the system as a
  **distinct** agent — its observations, heartbeat history, and
  inventory snapshots are NOT correlated with the old agent.
- **Credential rotation is not implemented.** There is no
  agent-initiated or admin-forced rotation path. The bearer
  credential issued at enrollment is a long-lived shared secret for
  the agent's lifetime in v0.1.
- **Composite FK enforces `(snapshot.org, snapshot.agent) ==
  (agent.org, agent.id)`.** Any rebind design must not produce a
  state where these disagree (`PR-019` hardening).

## 2. Reinstall scenarios

This table is the authoritative list of scenarios any rebind /
rotation flow must serve. The "v0.1 today" column is the current
fail-closed behavior; the "post-design" column is what the rebind /
rotation endpoints land.

| #  | Scenario                                                        | v0.1 today                                                                 | Post-design behavior                                                                                  |
| -- | --------------------------------------------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| 1  | Same machine reinstall, same `install_id`                       | `enrollment_rejected` (`install_id_already_enrolled`)                      | Operator issues a rebind token for the existing agent; new agent presents the token, gets new credential. Same `agent_id` preserved. |
| 2  | Same machine reinstall, fresh `install_id`                      | Enrolls successfully as a **new** agent (history orphaned)                 | Same as #1 if operator wants continuity; or fresh enrollment if operator wants a clean break.         |
| 3  | OS rebuild, fresh `install_id`, fresh credential                | New agent (history orphaned)                                               | Operator's call: rebind to the prior `agent_id` (continuity) or accept fresh enrollment.              |
| 4  | VM clone, both copies still running                             | Both enroll with their own `install_id` and appear as two distinct agents  | Same — clones are legitimately distinct. The control plane cannot reliably distinguish a clone from a reinstall without operator input. |
| 5  | VM clone with copied credential                                 | Both copies present the same credential → control plane cannot distinguish them; last write wins on every endpoint | v0.1 (bearer) cannot defend against this. Detection only: audit `agent.suspicious_duplicate` when `machine_fingerprint_hash` drifts between heartbeats from the same `agent_id`. Phase 6 mTLS is the real fix. |
| 6  | Hostname change                                                 | Drift is silently absorbed by heartbeat / inventory                        | Same — `hostname` is descriptive, not identity. No rebind needed.                                     |
| 7  | `machine_fingerprint` change (mainboard replacement)            | Drift surfaces in audit metadata only                                      | Same — descriptive only. No rebind needed unless the credential was also lost.                        |
| 8  | Lost local credential (crashed before persisting after rotate)  | Agent is bricked; operator workaround is revoke + redeploy                 | Operator issues a rebind token. Agent recovers without losing history.                                |
| 9  | Stolen credential (operator suspects exposure)                  | No in-product remediation                                                  | Admin-forced rotation: operator issues a rebind token AND revokes the current credential immediately. Old credential rejected on next call; agent must redeem the token to recover. |
| 10 | Deployment package reused after reinstall                       | Works — the package's `bootstrap_secret` is what authenticates enrollment  | Same. Bootstrap is enrollment-level identity; rebind is agent-level identity. They do not interact.   |

The scenarios that **need** a rebind flow are 1, 2, 3, 8, 9. Scenarios
4, 5, 6, 7, 10 are not rebind targets — clones are distinct identities
by definition (5 is a known v0.1 gap, mitigated only by audit and
Phase 6 mTLS).

## 3. Agent identity model

Identity is split into **stable** and **descriptive** axes. Stable
axes are what the control plane trusts; descriptive axes are
operator-visible metadata that may drift without breaking trust.

| Field                       | Role            | Mutable?        | Authoritative for                                                          |
| --------------------------- | --------------- | --------------- | -------------------------------------------------------------------------- |
| `agent_id`                  | **stable**      | never           | The thing observations / heartbeats / inventory attach to. Lifelong.       |
| `organization_id`           | **stable**      | never           | Org scoping. Bound at enrollment; rebind preserves it.                     |
| `agent.credential_hash`     | **stable axis** | rotates         | The wire-auth proof. Replaced atomically on rebind or rotation.            |
| `deployment_package_id`     | provenance      | never           | Which bootstrap minted the agent. Survives rebind unchanged.               |
| `install_id`                | descriptive     | replaced on rebind | Helps operators recognize an installer at a glance. NOT proof of identity. |
| `machine_fingerprint_hash`  | descriptive     | drifts          | Diagnostic / suspicious-clone signal. NOT proof of identity.               |
| `hostname`                  | descriptive     | drifts          | Display only. NOT proof of identity.                                       |
| `agent_version`             | descriptive     | drifts          | Display / version-drift visibility.                                        |

**The control plane trusts `credential_hash` and nothing else.**
That is the single bearer of identity proof in v0.1. Every other
field is either an immutable bookkeeping anchor (`agent_id`,
`organization_id`) or operator-visible metadata.

Implication: a rebind is an **atomic swap of `credential_hash`** on
an existing `agent_id` row. The agent stays the same agent; only
its proof of identity changes. This is the design's central
commitment.

## 4. Rebind model

Rebind is **admin-mediated** (CLAUDE.md §7.1 operator-controlled
posture). An agent cannot rebind itself without operator
participation, because rebind is precisely the recovery primitive
for the case where the agent's existing credential is missing,
suspect, or unrecognized.

### Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Admin (operator UI / API)                                           │
│    POST /api/v1/agents/{id}/rebind-token                               │
│       {ttl_seconds?, reason?}                                          │
│    ←  201 + {rebind_token, expires_at, agent_id}     (shown ONCE)      │
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. Operator delivers the token out-of-band to the recovering          │
│    agent (manual install, SCCM redeploy, etc.).                        │
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. Recovering agent on first run:                                      │
│    POST /api/v1/agents/rebind                                          │
│       {rebind_token, hostname, agent_version,                          │
│        machine_fingerprint?, install_id?}                              │
│    ←  201 + {agent_id, agent_credential, rebound_at}   (credential     │
│                                                          shown ONCE)   │
│                                                                        │
│    Control plane transaction (atomic):                                 │
│      a) verify token (single-use, not expired, target = $id)           │
│      b) mint new credential, hash with SHA-256                         │
│      c) UPDATE agents SET credential_hash = $new                       │
│         WHERE id = $target AND organization_id = $tokenOrg             │
│      d) consume token (mark consumed_at)                               │
│      e) write audit_events row agent.rebound                           │
│         (severity:"security", actor=admin or agent, target=agent_id)   │
│                                                                        │
│    The old credential_hash is OVERWRITTEN in step (c). The old         │
│    plaintext (if it still exists on a crashed-host disk) no longer     │
│    matches anything. No overlap window.                                │
└────────────────────────────────────────────────────────────────────────┘
```

### Properties

- **Token is scoped to one `agent_id`.** A token issued for agent X
  cannot rebind agent Y. The target `agent_id` is hashed into the
  token row at issuance and checked at redemption.
- **Token is one-time use.** `max_uses = 1`, enforced by the same
  atomic conditional UPDATE pattern used for deployment-package
  `uses_count` (`PR-013` precedent: zero-row UPDATE → reject).
- **Short TTL.** Default 1 hour, configurable by the issuing admin
  via `ttl_seconds` (bounded by config — e.g. min 60s, max 24h).
  Past `expires_at`: rejected with the generic rebind-rejected
  envelope; audit-recorded as `token_expired`.
- **Token plaintext appears exactly once.** Server stores only
  `sha256(token)`. Same model as deployment-package bootstrap
  secrets and agent credentials.
- **Same `agent_id` survives the rebind.** Heartbeat history,
  machine-inventory snapshot (one row per agent, UPSERTed in
  place), and future certificate observations remain attached to
  the agent_id throughout. The operator-visible row in
  `GET /agents` looks unchanged except for `updated_at` and a new
  `last_credential_rotated_at` field (see §10).
- **Old credential is invalidated atomically.** The UPDATE in step
  (c) overwrites `credential_hash`. A request carrying the old
  plaintext credential will fail `FindByCredentialHash` and surface
  the standard generic `agent_unauthorized` envelope.
- **Optional descriptive refresh.** The rebind request body may
  carry fresh `hostname` / `machine_fingerprint` / `install_id` /
  `agent_version` to update the agent's descriptive fields in the
  same transaction. None of these are trusted as identity — the
  token is the authentication.
- **Default-deny on classification ambiguity.** Any failure mode
  (token unknown, expired, exhausted, target-mismatch, agent
  already revoked, agent disabled) collapses to a single wire
  envelope (`401 rebind_rejected` or similar). The specific reason
  is recorded in the audit row only.

### Token lifecycle

A rebind token is **active** when all three conditions hold:

1. `consumed_at IS NULL` (not yet redeemed)
2. `revoked_at IS NULL` (operator can revoke a leaked token)
3. `expires_at > now()` (within TTL)

The same conditional-UPDATE pattern as deployment packages
guarantees atomic redemption under concurrent attempts.

## 5. Credential rotation model

Credential rotation is **agent-initiated** — the agent presents its
current valid credential and asks the control plane for a new one.
Admin-forced rotation does NOT use this endpoint; it uses the
rebind flow above with the operator's revoke-current-credential
intent recorded in the audit row.

### Flow

```
Agent (with valid current credential)         Control plane
  │                                              │
  │  POST /api/v1/agent/credential/rotate ──────►│
  │  Authorization: Bearer <current_credential>  │
  │  Body: {} (empty)                            │
  │                                              │
  │                                              │  Transaction:
  │                                              │    1) auth via current credential
  │                                              │    2) mint new credential
  │                                              │    3) UPDATE agents SET
  │                                              │       credential_hash = sha256(new)
  │                                              │    4) audit: agent.credential_rotated
  │                                              │
  │ ◄─── 200 + {agent_credential, rotated_at} ───│
  │       (plaintext shown ONCE)                 │
  │                                              │
  │  Agent persists new credential locally,      │
  │  discards old.                               │
```

### Properties

- **No overlap window.** The new credential is valid immediately;
  the old credential is invalidated immediately (the same row's
  `credential_hash` is replaced atomically). Reasoning: overlap
  windows complicate the schema (`previous_credential_hash`,
  `previous_credential_expires_at`), the audit trail, and the
  failure modes. An agent that crashes between receiving the
  response and persisting it locally needs a rebind token from an
  operator — that's a real failure mode the rebind primitive is
  already designed to solve. Adding overlap to rescue this case
  trades a sharp design for a fuzzy one.
  - **Alternative considered:** 5-minute overlap with
    `previous_credential_hash` and `previous_credential_expires_at`
    columns. Rejected for v0.1 — design simplicity wins. Revisit if
    operator data shows real failure-rate problems.
- **Idempotency.** Rotation is NOT idempotent — every successful
  call mints a new credential. A retry by the agent (e.g. network
  failure on response delivery) would result in TWO new credentials,
  the second of which is the only valid one. The agent SDK must
  treat rotation as a non-retryable operation; a network-level
  retry leaves the agent with a credential the server already
  invalidated. Failure mode: agent loses connectivity → admin must
  issue a rebind token.
- **Audit always.** `agent.credential_rotated` audit row written in
  the same transaction as the credential swap. Failure to audit
  rolls the swap back (CLAUDE.md §9; same posture as deployment
  package create / revoke). Metadata: `agent_id`, optionally
  `reason: "scheduled" | "self_initiated"`. NEVER the plaintext or
  hash of either credential.
- **Old credential never returned again.** Plaintext appears in the
  response struct exactly once.

### Failure modes

| Failure                                | Wire envelope          | Audit reason                |
| -------------------------------------- | ---------------------- | --------------------------- |
| Current credential invalid             | `401 agent_unauthorized` (via existing agent-auth middleware) | `agent.authentication_failed` |
| Agent status != active                 | `401 agent_unauthorized`                                       | `agent.authentication_failed` (already audited)  |
| Audit write fails after credential mint| `500 internal_error`, transaction rolled back                  | n/a                            |
| Body not empty (extra fields)          | `200` — silently ignored (rotation takes no input)             | n/a                            |

## 6. Duplicate / clone handling

Distinct from rebind / rotation — these are detection / rejection
behaviors during normal operation.

| Pattern                                                     | Detection                                                                         | v0.1 response                                                                                                  |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Duplicate `install_id` within an org                        | Unique index on `agents(organization_id, install_id) WHERE install_id IS NOT NULL`| Fail closed at enrollment (current v0.1).                                                                      |
| Same `machine_fingerprint_hash`, different `install_id`     | Heartbeat / inventory drift check (post-implementation)                            | Audit `agent.suspicious_duplicate` (severity:"security") — operator decides whether to revoke. NOT auto-rejected.  |
| Same hostname from multiple agents                          | Hostname is descriptive — not a uniqueness signal.                                | Allowed.                                                                                                       |
| Cloned VM with copied credential (both copies running)      | `machine_fingerprint_hash` drift between heartbeats from the same `agent_id`      | Audit `agent.suspicious_duplicate`. v0.1 cannot reliably prevent the clone with bearer auth alone — Phase 6 mTLS is the real defense. |
| Cloned VM with copied `install_id`, no credential           | Enrollment-time unique constraint                                                  | Fail closed at enrollment.                                                                                     |
| Rebind token reused (replay)                                | `consumed_at` is non-NULL on token row                                            | Fail closed; audit `agent.rebind_rejected` with `reason: "token_consumed"`.                                    |

**Known v0.1 limitation explicitly accepted by this design:** a
clone that copies the credential AND the local installation state
cannot be distinguished from the legitimate original at the
control-plane wire boundary. The bearer credential is the entire
proof. Detection is operational (audit signals), not enforced. This
is exactly what CLAUDE.md §6.4 commits to fixing in Phase 6 via
mTLS — each agent's identity becomes its private key, which is
stored in CNG/DPAPI and resists copy.

## 7. Security invariants

These are binding on every PR that touches this design's
implementation surface.

1. **Existing credentials are never returned again.** Plaintext
   appears exactly once per credential — at issuance — and is GC'd
   when the response is written. No endpoint reads back stored
   credentials.
2. **No silent duplicate identities.** Two agents cannot share an
   `agent_id` (PRIMARY KEY) and cannot share a `credential_hash`
   (partial unique index, see migration 0003). The composite FK
   from `agent_inventory_snapshots(organization_id, agent_id)`
   guarantees observations stay attached to a real agent within
   the right org.
3. **Operator-approved recovery.** Rebind requires a token an
   admin issues; the recovering agent cannot self-promote. The
   token is admin-scoped to one `agent_id`.
4. **Audit every rebind / rotation / suspicious event.** Every
   state change (rebind, rotation) and every detection signal
   (suspicious duplicate) writes an `audit_events` row in the same
   transaction (CLAUDE.md §9). An audit-write failure rolls the
   state change back. Suspicious detection signals are
   best-effort writes (same posture as `agent.enrollment_rejected`
   for unknown-bootstrap-secret).
5. **Generic external errors.** Every rebind / rotation failure
   collapses to a single wire envelope (`rebind_rejected` /
   `agent_unauthorized`). The specific reason lives in the audit
   row only — no enumeration via error code (CLAUDE.md §6).
6. **No credentials in logs or audit metadata.** Plaintext rebind
   tokens, plaintext credentials, and credential hashes never
   appear in `audit_events.metadata`. Enforced by:
   - the centralized logger redaction allow-list
   (`internal/logger/redact.go`),
   - explicit audit-metadata builders that whitelist only
     non-sensitive fields,
   - the `TestNoPlaintextSecretsInLogs` integration sweep
     (extended to cover rebind / rotation routes when those PRs
     ship).
7. **No trust in hostname / fingerprint / install_id.** These are
   descriptive. A request that "looks like" agent X (same hostname,
   same fingerprint) but does not present a valid credential or
   rebind token IS NOT agent X.
8. **Fail closed on ambiguous identity.** Token validation,
   rebind execution, and rotation all use the conditional-UPDATE
   pattern (zero-row UPDATE → reject) the deployment-package
   `IncrementUses` flow established (`PR-013`). No "best guess"
   resolutions — if the SQL doesn't match exactly one row, the
   request is rejected.
9. **Composite FK invariants preserved.** Rebind reuses
   `agent_id`, so `agent_inventory_snapshots(organization_id,
   agent_id) → agents(organization_id, id)` continues to hold.
   Rotation never changes `organization_id` or `agent_id` (it
   only swaps `credential_hash`).
10. **Cross-org rebind is impossible at the schema level.** The
    rebind token's stored org id MUST match the target agent's
    org id. The redemption SQL filters on both — a cross-org
    token (even one whose hash collides) cannot mint a credential
    for a foreign agent.

## 8. Audit policy

Adding the following action vocabulary. All carry the
`severity: "security"` tag where indicated.

| Action                            | Actor    | Target              | Severity | Metadata fields                                                          |
| --------------------------------- | -------- | ------------------- | -------- | ------------------------------------------------------------------------ |
| `agent.rebind_token_issued`       | `user` (admin) | `agent`             | security | `agent_id`, `expires_at`, `has_reason`, `reason_length` (NEVER `reason` plaintext) |
| `agent.rebind_token_revoked`      | `user` (admin) | `agent`             | security | `agent_id`, `revoked_by_user_id`, optional `reason_length`               |
| `agent.rebound`                   | `agent`  | `agent`             | security | `agent_id`, `previous_credential_rotated`, `hostname`, `agent_version`   |
| `agent.rebind_rejected`           | `agent`  | `agent` or `(none)` | security | `reason ∈ {token_unknown, token_expired, token_consumed, token_revoked, target_mismatch, agent_disabled, agent_revoked}`, `has_install_id`, `has_machine_fp` |
| `agent.credential_rotated`        | `agent`  | `agent`             | security | `agent_id`                                                               |
| `agent.suspicious_duplicate`      | `system` | `agent`             | security | `agent_id`, `signal ∈ {machine_fp_drift, parallel_heartbeat_from_distinct_ips, ...}` — additive |

**Metadata rules (binding):**

- **No plaintext rebind tokens, ever.** Audit rows about token
  issuance carry the token's row id only — the plaintext lives in
  the issuance response and is GC'd.
- **No plaintext credentials, ever.** Same rule.
- **`reason` strings are operator-visible operator-supplied text.**
  The audit row records the *length* and a *boolean* "has_reason",
  not the text itself, to avoid an operator typing a credential or
  internal note into the reason field and unintentionally
  persisting it. The pattern matches what
  `deployment_package.revoked` already does (PR-015).
- **`severity: "security"`** is required on every action above so
  downstream alerting can filter on it (CLAUDE.md §9).

## 9. API sketch

Endpoint shapes for the implementation follow-ups. **No
implementation in this PR.** These are reference contracts for
H-012 / H-013 to validate against.

### `POST /api/v1/agents/{id}/rebind-token`

Admin-only. Issues a single-use rebind token scoped to the target
`agent_id`. The plaintext token appears in the response exactly
once.

```http
POST /api/v1/agents/agent-abc123/rebind-token
Cookie: anchorix_session=...

{ "ttl_seconds": 3600, "reason": "OS rebuild" }
```

Response — `201 Created`:

```json
{
  "rebind_token": "<base64-url, shown exactly once>",
  "expires_at": "2026-06-01T12:00:00Z",
  "agent_id": "agent-abc123"
}
```

Failure responses:

| Status | `code`               | When                                                                           |
| ------ | -------------------- | ------------------------------------------------------------------------------ |
| 400    | `bad_request`        | Body malformed; `ttl_seconds` out of bounds; URL missing id                    |
| 401    | `unauthorized`       | No operator session                                                            |
| 403    | `forbidden`          | Authenticated user is not an admin                                             |
| 404    | `not_found`          | No agent with this id in the operator's organization (cross-org indistinguishable from missing — CLAUDE.md §6) |

Audit: `agent.rebind_token_issued` written in the same transaction
as the token row INSERT.

### `POST /api/v1/agents/rebind`

Anonymous endpoint (the token IS the authentication, mirroring the
enrollment endpoint's posture with bootstrap secrets). Consumes
the token, mints a new credential, atomically swaps the agent's
`credential_hash`.

```http
POST /api/v1/agents/rebind

{
  "rebind_token": "<from operator>",
  "hostname": "ws-001.corp.example",
  "agent_version": "0.1.0",
  "machine_fingerprint": "<optional>",
  "install_id": "<optional, fresh installer id>"
}
```

Response — `201 Created`:

```json
{
  "agent_id": "agent-abc123",
  "organization_id": "anchorix",
  "agent_credential": "<bearer, shown exactly once>",
  "rebound_at": "2026-06-01T12:00:00Z"
}
```

Failure responses use a single deterministic envelope so the caller
cannot enumerate token state:

| Status | `code`             | When                                                                            |
| ------ | ------------------ | ------------------------------------------------------------------------------- |
| 401    | `rebind_rejected`  | Token unknown / expired / consumed / revoked; target agent disabled or revoked; cross-org collision; malformed body |

Audit: `agent.rebind_rejected` (severity:"security") on every
failure; `agent.rebound` (severity:"security") on success.

### `POST /api/v1/agent/credential/rotate`

Agent-bearer-authenticated. Mints a new credential, swaps
`credential_hash` atomically, returns the new plaintext exactly
once. Singular `/agent/*` prefix matches the established convention
for agent-bearer-keyed routes (`/agent/me`, `/agent/heartbeat`,
`/agent/inventory`).

```http
POST /api/v1/agent/credential/rotate
Authorization: Bearer <current_credential>

{}
```

Response — `200 OK`:

```json
{
  "agent_credential": "<new bearer, shown exactly once>",
  "rotated_at": "2026-06-01T12:00:00Z"
}
```

Failure responses:

| Status | `code`               | When                                                                       |
| ------ | -------------------- | -------------------------------------------------------------------------- |
| 401    | `agent_unauthorized` | Bearer missing / malformed / unknown / agent disabled or revoked (handled by the existing agent-auth middleware; no rotation-specific failure code) |
| 500    | `internal_error`     | Audit write failed; transaction rolled back; client should retry once      |

Audit: `agent.credential_rotated` (severity:"security") in the same
transaction.

## 10. Data model sketch

Schema-level shapes the implementation PRs will introduce. **No
migration in this PR.** Numbering is illustrative — actual
migration numbers will be assigned at implementation time per
CLAUDE.md §16.

### New table: `agent_rebind_tokens`

Mirrors the deployment-package model in spirit — admin-issued,
hashed at rest, atomic lifecycle bounds.

```sql
CREATE TABLE agent_rebind_tokens (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL,
    agent_id        TEXT        NOT NULL,
    -- SHA-256 of plaintext token; plaintext never stored.
    token_hash      BYTEA       NOT NULL UNIQUE,
    issued_by_user_id TEXT      NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by_user_id TEXT     REFERENCES users(id) ON DELETE RESTRICT,
    -- has_reason / reason_length style — see audit metadata rules.
    reason_length   INTEGER     NOT NULL DEFAULT 0,
    -- Composite FK matches the AGENT_INVENTORY_SNAPSHOTS pattern
    -- (PR-019 H-009 follow-up): the token row's (org, agent) MUST
    -- match the agents table, enforced at the DB level.
    FOREIGN KEY (organization_id, agent_id)
        REFERENCES agents(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX agent_rebind_tokens_org_idx     ON agent_rebind_tokens(organization_id);
CREATE INDEX agent_rebind_tokens_expires_idx ON agent_rebind_tokens(expires_at);
```

### `agents` column additions

Two columns track rotation history without storing previous
credentials.

```sql
ALTER TABLE agents ADD COLUMN last_credential_rotated_at TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 1;
```

`last_credential_rotated_at` is `NULL` for agents that have not
rotated since enrollment; otherwise carries the last rotation's
timestamp.

`credential_version` is an increasing counter the operator UI can
display. Rebind and rotation both increment it. There is **no**
`previous_credential_hash` column — overlap is explicitly out of
scope (see §5).

### What we are NOT adding

- No `previous_credential_hash` or any "old credential still valid
  for N seconds" column. See §5 rationale.
- No separate `agent_credential_rotations` table. Rotation events
  live in `audit_events` only — the audit table is the authoritative
  history (CLAUDE.md §9 append-only invariant).
- No "rebind history" table. Rebind audit rows in `audit_events`
  are the source of truth.

## 11. Impact on future certificate inventory

Certificate observations (`H-011`) will attach to `agent_id`. The
design decision in this document — **rebind reuses the same
`agent_id`** — directly enables three properties certificate
inventory needs:

1. **Observation continuity across reinstalls.** A workstation
   that's reinstalled and rebound keeps the same `agent_id`, so
   its certificate observations carry forward. An operator
   investigating "which certificates were ever on this host" sees
   the full history regardless of how many times the agent was
   reinstalled.
2. **Stable correlation key.** Risk findings (Phase 4) will join
   `certificates ↔ certificate_observations ↔ agents`. The join on
   `agent_id` remains valid forever — rebind does not invalidate
   any FK or join.
3. **Single-snapshot model holds.** Machine inventory snapshot
   (`PR-018`) is one row per `(org, agent_id)`. Rebind does not
   create a second row; it reuses the same one. Certificate
   observations follow the same model (one row per
   (`certificate`, `agent`, `store`) — see ROADMAP.md Phase 3) and
   benefit identically.

If rebind had instead created a fresh `agent_id`, every reinstall
would orphan history and the operator would have to manually merge
agents — an ops burden Anchorix exists to *eliminate*, not create.

The H-011 design PR (separate from this one) will pick up these
properties as preconditions.

## 12. Non-goals

Explicitly **NOT** in scope for this design or the implementation
PRs it spawns:

- **Rebind endpoint implementation.** Lands in H-012 (see below).
- **Credential rotation endpoint implementation.** Lands in H-013.
- **DPAPI / CNG-protected local credential storage on the agent.**
  Phase 6 hardening.
- **mTLS between agent and control plane.** Phase 6 (CLAUDE.md
  §6.4 commits this; H-008 tracks it).
- **Certificate inventory.** H-011, separate design.
- **Risk findings / Phase 4 work.**
- **Operator UI for issuing rebind tokens.** Lands after the
  endpoint PR.
- **Background workers** (e.g. token expiry sweeper). Tokens
  expire by predicate at redemption time; no sweeper needed for
  v0.1.
- **Overlap-window rotation.** Considered and rejected; see §5.
- **Cross-org rebind / migration.** Out of scope for v0.1
  (multi-tenant isolation is explicitly deferred per CLAUDE.md §4).

## Recommended PR sequence after this design

1. **This PR (H-006 design)** — docs only. No code.
2. **H-012 — `feat(enrollment): admin rebind-token issuance + agent rebind execution`.**
   Implements both rebind endpoints (token issuance and rebind
   execution) in a single PR — the two endpoints share the
   `agent_rebind_tokens` schema and atomicity model, and shipping
   them separately would leave issuance live with no consumer.
   Includes the new table migration, repository, service,
   handlers, audit events, and full unit + integration test
   coverage following the deployment-package precedent.
3. **H-013 — `feat(enrollment): agent-initiated credential rotation`.**
   Implements `POST /agent/credential/rotate`. Adds
   `last_credential_rotated_at` + `credential_version` columns to
   `agents`. Independent of H-012 (rotation requires a valid
   current credential; rebind requires no credential at all).
4. **(Phase 6) mTLS migration** — see H-008. Supersedes the
   bearer-credential model entirely; this design's
   `agent.credential_rotated` audit shape and the
   `credential_version` column carry forward (the "credential" just
   becomes a client cert).

H-012 and H-013 can ship in either order; this design is the
shared source of truth for both.

## Unresolved questions

The following are real design questions whose answers are flagged
for the implementation PRs to confirm or revisit. They do not block
this design from landing — each has a reasonable default in the
text above — but the implementer should verify with operators
before locking the wire.

1. **Default rebind-token TTL.** This design proposes 1 hour
   default, configurable via `ttl_seconds` (range to be set in
   `internal/config`). Operators rebuilding a fleet via SCCM may
   want longer windows (e.g. 24h) so a single rolling wave of
   reinstalls can complete before tokens expire. Counterargument:
   long-lived rebind tokens are more dangerous if leaked.
2. **Rebind-token format vs deployment-package bootstrap secret.**
   Both are hashed at rest with the same scheme. Should the
   plaintext format / length be identical (operational
   familiarity) or deliberately different (so a leaked token
   string can be identified by shape)? Recommend identical for
   simplicity; operators distinguish by source (which endpoint
   issued it).
3. **Should rebind invalidate any in-flight inventory / heartbeat
   the old credential might be writing concurrently?** The new
   `credential_hash` is the only valid one immediately after the
   UPDATE — so a concurrent heartbeat from the old credential will
   fail authentication at the next request. No special handling
   needed. Flagging in case operators want a "pause heartbeat
   processing for N seconds during rebind" mode for paranoid
   ops.
4. **Rotation rate-limit.** Should an agent be able to rotate its
   credential N times per hour, or are rotations rare enough that
   no limit is needed? Recommend no rate limit in v0.1 (each
   rotation is audited; suspicious volume surfaces operationally),
   revisit if abuse appears.
5. **Phase 6 mTLS handoff.** When mTLS lands, do rebind tokens
   become CSR-issuance tokens (sign the agent's client-cert CSR
   in place of minting a bearer)? Likely yes — the design carries
   forward; the credential becomes a key pair instead of a shared
   secret. The audit shape, token lifecycle, and `agent_id`
   continuity all survive.

## References

- [`CLAUDE.md`](../../CLAUDE.md) §6, §8.4, §9, §16, §18 —
  enrollment / audit / migration / robustness rules.
- [`docs/engineering/AGENT_ENROLLMENT.md`](./AGENT_ENROLLMENT.md)
  — current deployment-package + agent-credential identity model.
- [`docs/engineering/AUTH_FOUNDATION.md`](./AUTH_FOUNDATION.md) —
  operator session model used by the rebind-token issuance
  endpoint.
- [`docs/engineering/HARDENING_BACKLOG.md`](./HARDENING_BACKLOG.md)
  — H-006 (this design), H-008 (Phase 6 mTLS), H-011 (certificate
  inventory).
- [`backend/migrations/0001_init.sql`](../../backend/migrations/0001_init.sql),
  [`0002_deployment_packages.sql`](../../backend/migrations/0002_deployment_packages.sql),
  [`0003_agents_credential_hash_index.sql`](../../backend/migrations/0003_agents_credential_hash_index.sql),
  [`0004_agent_inventory_snapshots.sql`](../../backend/migrations/0004_agent_inventory_snapshots.sql)
  — schema this design extends.
- [`docs/api/REST_API.md`](../api/REST_API.md) — envelope and
  pagination conventions the implementation PRs will conform to.

# Agent ↔ Control Plane Protocol — v0.1

This document defines the wire protocol between `anchorix-agent` and the
control plane. The HTTP surface is documented in
[`docs/api/REST_API.md`](../api/REST_API.md); this file focuses on the
state machine, security, and lifecycle.

## States

```
   +---------------------+
   | un-installed        |
   +----------+----------+
              | install + token
              v
   +---------------------+
   | pending_enrollment  |
   +----------+----------+
              | POST /agents/enroll succeeds
              v
   +---------------------+
   | active              |  <----+
   +----------+----------+        |
              | operator action    | (re-enable)
              v                   |
   +---------------------+        |
   | disabled            | -------+
   +----------+----------+
              | operator action
              v
   +---------------------+
   | revoked             |  (terminal)
   +---------------------+
```

## Identity

- The agent generates an Ed25519 (preferred) or P-256 key pair locally on
  first start. The private key never leaves the host (CLAUDE.md §6.2).
- The public key is sent at enrollment.
- The control plane stores `sha256(public_key)` as the agent's stable
  identifier alongside the assigned `agent_id`.
- After enrollment, the agent receives an HMAC-style bearer token whose
  validation key is the agent's public key fingerprint plus a
  control-plane-side secret. (Phase 6 upgrades this to mTLS using a
  short-lived agent certificate issued by an internal Anchorix CA.)

## Enrollment

1. Operator issues an enrollment token via the UI.
   - Token is shown **once**; only `sha256(token)` is stored.
   - Token TTL: `ANCHORIX_ENROLLMENT_TOKEN_TTL` (default 15m).
2. Operator installs the agent on a Windows host with the token.
3. Agent generates a local key pair and calls `POST /agents/enroll`.
4. Control plane verifies the token, stores the agent record, marks the
   token consumed, and emits `audit_events.action = "agent_enrolled"`.

If anything fails (token unknown, expired, hostname mismatch, replay) the
control plane returns 400 `enrollment_invalid` and audits the failure.

## Heartbeat

- Default interval: `ANCHORIX_AGENT_HEARTBEAT_INTERVAL` (60s).
- Body is intentionally tiny — `{ "agent_version": "...", "ts": "..." }`.
- Server updates `agents.last_seen_at`. No audit event is emitted for
  heartbeats; presence/absence is observable via inventory and audit logs.

## Inventory

- Default interval: `ANCHORIX_AGENT_INVENTORY_INTERVAL` (15m).
- Agent enumerates configured certificate stores (default:
  `LocalMachine\My`, `LocalMachine\WebHosting`, `CurrentUser\My`).
- Agent uploads a list of `IngestedCertificate` objects via
  `POST /agents/{id}/inventory`.
- Agent must collect **only public certificate metadata + PEM**. Reading
  private key material is explicitly forbidden by the agent's design.
- Server validates, parses, dedupes by fingerprint, and records
  observations. Risk evaluation runs synchronously (or via an async queue
  in later phases).

## Backoff & Retry

- Network failures: exponential backoff starting at 5s, capped at 5m.
- HTTP 5xx: same backoff.
- HTTP 401/403: agent stops; this is a server-side trust decision.
- HTTP 429: respect `Retry-After`; otherwise back off as for 5xx.

## TLS

- Agent pins the control plane's certificate **fingerprint** at
  enrollment. Subsequent calls validate the fingerprint, not just the
  hostname. This protects against TLS termination changes that an
  operator did not authorize.
- Plain HTTP is allowed only for development. Production deployments
  must terminate TLS in front of the control plane.

## Privacy

- The agent never transmits private key material.
- The agent never transmits user files, registry contents, or other
  data outside the certificate stores it is configured to read.
- The agent's logs are local and do not include certificate PEMs by
  default; only metadata for troubleshooting.

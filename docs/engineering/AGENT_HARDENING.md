# Windows Agent — Hardening Roadmap

**Source of truth for binding rules:** [`CLAUDE.md`](../../CLAUDE.md).
This document is a sequenced plan. Each item lands as its own PR with
its own threat model under
[`docs/security/`](../security/) (CLAUDE.md §6.10, §19).

The order below is the order of expected delivery; later items
depend on earlier ones. Each item is **not implemented yet** — this
file is the contract that future PRs must satisfy.

## H0 — Foundation (already in place)

These are the invariants the v0.1 foundation already enforces. They
are listed here so subsequent items don't accidentally weaken them.

- **No private-key extraction.** The agent code path that enumerates
  certificate stores reads only public-key metadata + the public
  certificate PEM. The control plane rejects any inbound payload
  containing a `BEGIN ... PRIVATE KEY` block at the API boundary
  (`internal/inventory.rejectPrivateKeyMaterial`). Both sides are
  required by CLAUDE.md §6.2.
- **TLS verification by default.** No `InsecureSkipVerify` in the
  agent's transport client (CLAUDE.md §8.11).
- **Single-use enrollment tokens.** The control plane stores only
  `sha256(token)`; tokens have a short TTL; consumed tokens are
  marked at the database level (CLAUDE.md §6.5).
- **Audit on enrollment.** Every successful and failed enrollment
  emits an `audit_events` row (CLAUDE.md §6.6, §9).
- **Bounded retries.** The agent's transport layer is constructed to
  carry an explicit retry policy (CLAUDE.md §8.11, §18). Today the
  policy is a stub; H4 makes it real.
- **No unbounded goroutines.** The agent's `service.Run` loop is a
  single ticker per concern (heartbeat, inventory). No fanout
  spawning (CLAUDE.md §8.10).

## H1 — Local Identity Storage (PR-002 / PR-003 territory)

**Goal:** the agent's enrollment private key is stored on disk in a
file that no other local process (other than `LocalSystem` /
administrators on Windows) can read or modify.

**Concrete:**

- File: `%ProgramData%\Anchorix\agent\identity.json`.
- ACL: owner `LocalSystem`, full control; `Administrators`, full
  control; explicit deny-everyone-else. Set by the agent on first
  write; verified on every start.
- File contents schema documented in
  [`AGENT_PROTOCOL.md`](../architecture/AGENT_PROTOCOL.md).
- Refusal to start if ACLs are weaker than expected (fail closed,
  CLAUDE.md §6.12).
- The token used to enroll is **never** persisted; only the
  resulting agent identity material is.

**Threat model entry:** `docs/security/agent_identity_storage.md`
(created in the PR that lands H1).

## H2 — Enrollment Token Hardening

**Goal:** narrow the window in which a leaked enrollment token can
do harm, and make leakage observable.

**Concrete:**

- Tokens default to 15 minutes TTL with a configurable lower bound
  (CLAUDE.md §8.9 — config validation enforces sensible bounds).
- Rate limit on `POST /agents/enroll` per source IP and per token
  hash (the same hash used for storage). Exceeded → 429 + audit
  event `enrollment_rate_limited`.
- Failed enrollments are audited with reason codes
  (`token_unknown`, `token_expired`, `token_consumed`,
  `hostname_mismatch`).
- Tokens are bound at issuance to an optional **expected hostname**;
  enrollments from a different hostname fail with
  `hostname_mismatch` and emit an audit event flagged
  `severity:"security"` (CLAUDE.md §9).

**Threat model entry:**
`docs/security/enrollment_token_hardening.md`.

## H3 — TLS Pinning Beyond Hostname

**Goal:** the agent does not trust DNS or the system trust store
after enrollment. It pins on the control plane's certificate
fingerprint captured at enrollment and refuses to talk to a
different fingerprint.

**Concrete:**

- During enrollment, the agent computes
  `sha256(server_subject_public_key_info)` from the server's TLS
  cert and stores it alongside its identity (`identity.json`).
- On every subsequent request, the agent's `*tls.Config` uses
  `VerifyPeerCertificate` to compare the SPKI hash before
  proceeding.
- Rotation: the control plane can announce a planned rotation by
  publishing the new SPKI hash through an authenticated endpoint
  the agent polls; the agent accepts the second hash for a
  documented overlap window. Outside that window, only the pinned
  hash is accepted.
- A change to the server's cert without a published rotation causes
  the agent to fail closed and log a `severity:"security"` event
  on its side (the control plane learns about it next time the
  agent reaches a different endpoint, or via missing heartbeats).

**Threat model entry:** `docs/security/agent_tls_pinning.md`.

## H4 — Retry, Backoff, and Offline Queue

**Goal:** agent communication is deterministic, predictable, and
bounded under partial outage.

**Concrete (binding by CLAUDE.md §8.11 / §18):**

- Heartbeats and inventory uploads use exponential backoff with
  jitter, starting at 5s, capped at 5 minutes, with a configurable
  cap.
- Retries are bounded; after an absolute upper limit (configurable,
  default 24h cumulative), the agent stops retrying and logs a
  `severity:"security"` event.
- Inventory uploads carry an `Idempotency-Key` derived from
  `(agent_id, inventory_run_id)`. The control plane treats duplicate
  keys as no-ops (200 OK with the original observation set), never
  as conflicts.
- An offline queue persists at most N inventory batches locally
  (configurable, default 5) when the control plane is unreachable;
  oldest batches are dropped first. The drop emits a local audit
  log entry.
- HTTP 401/403 from the control plane is **terminal** for the
  current identity — the agent stops, logs, and waits for operator
  re-enrollment. No silent re-attempt.

**Threat model entry:** `docs/security/agent_retry_offline.md`.

## H5 — Hardware-Backed Identity (TPM / Windows KSP)

**Goal:** the agent's enrollment private key is non-exportable from
the host. Even an attacker with `LocalSystem` cannot copy the key
to another host.

**Concrete:**

- Agent identity key is generated and stored in a Windows
  Cryptography Next Generation (CNG) Key Storage Provider — Platform
  Crypto Provider (TPM-backed) where TPM 2.0 is available, otherwise
  Microsoft Software Key Storage Provider as a fallback (with a
  capability bit recorded at the control plane for risk
  reporting).
- Identity-key operations (signing the bearer token) happen via
  CNG, not via Go-managed memory.
- `identity.json` becomes a key-handle reference, not raw key bytes.
- An H5-aware agent can still operate against an H1-only control
  plane (forward compat is required by CLAUDE.md §17).

**Threat model entry:**
`docs/security/agent_hardware_identity.md`.

## H6 — Service Lifecycle Hardening

**Goal:** the Windows service runs under the **least** privilege
that lets it do its job, with explicit recovery and tamper
visibility.

**Concrete:**

- Service installed as `LocalSystem` initially (needed to read
  machine certificate stores) but reduced to a least-privilege
  account where the operator's policy permits — TBD per `services.msc`
  docs and per Windows version constraints. Documented before
  shipping.
- Service recovery options set: restart on first/second failure with
  bounded delay; do nothing on third (operator must intervene).
- Service description, display name, and start type set explicitly
  by the installer — no ambiguity.
- Tamper detection: on start, the agent checks the SHA-256 of its
  own binary against a baseline recorded at install time. A
  mismatch is logged with `severity:"security"` and the service
  refuses to start (CLAUDE.md §6.12 — fail closed).

**Threat model entry:** `docs/security/agent_service_lifecycle.md`.

## H7 — Signed Updates / Signed Installers

**Goal:** the agent only runs binaries the operator authorized.

**Concrete:**

- The release pipeline signs `anchorix-agent.exe` and the MSI with
  a cosign- or Authenticode-issued signature.
- The installer rejects an unsigned binary at install time.
- The running service rejects an unsigned binary on the disk
  (re-checks signature on start; H6 tamper-check is the same flow
  with a different verifier).
- Signing keys live in the release infrastructure, never in the
  developer environment. No agent ever signs anything itself.

**Threat model entry:** `docs/security/agent_signed_updates.md`.

## What This Roadmap Does NOT Include

These items are **explicitly out of scope** for v0.1 hardening
(per CLAUDE.md §13). Adding them requires amending CLAUDE.md
first.

- Auto-renewal or auto-rotation of certificates the agent discovers.
- Built-in CA in the control plane.
- Linux agent.
- macOS agent.
- SSH key inventory.
- Network-level segmentation tooling.
- AI / ML anomaly detection on inventory.
- Multi-tenant agent identity binding beyond a single
  `organizations` row.

## Sequencing & PR Mapping

| Item | Likely PR window | Lands together with                                    |
| ---- | ---------------- | ------------------------------------------------------ |
| H0   | already in place | foundation                                              |
| H1   | PR-004 (agents)  | enrollment domain implementation                       |
| H2   | PR-004 / PR-005  | enrollment + heartbeat                                 |
| H3   | PR-006 (Win CI)  | Windows CI activates with TLS-pinning negative test    |
| H4   | PR-005 / PR-007  | inventory + risk pipeline                              |
| H5   | post-v0.1        | hardware-backed identity follows operator demand       |
| H6   | Phase 6          | service installer + release plumbing                   |
| H7   | Phase 6          | release pipeline maturity                              |

Each row's PR carries the corresponding threat-model entry.

# Hardening Backlog

This file tracks **real** follow-up engineering items surfaced during
the post-PR-002 hardening pass (PR-005). Each entry is small enough
to land in a focused PR but was deferred from PR-005 to keep that PR
documentation-only.

**This is not a TODO list.** Per CLAUDE.md §19, TODO-driven
architecture is forbidden. Each entry below has a clear scope, a
recommended PR title, and a rationale for why it wasn't fixed in
PR-005. New items get added only when the work is real, scoped, and
justifiable.

**Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
this file and CLAUDE.md disagree, CLAUDE.md wins.

## Open Items

### H-014 — Certificate inventory: storage layer

- **Title:** `feat(inventory): certificate + observations storage layer`
- **Risk:** medium (schema introduction, no-private-key
  invariant, ingestion atomicity). H-011's design landed (see
  References); this implementation PR is the schema half.
- **Scope:** migration introducing `certificates` and
  `certificate_observations` with the composite FK pattern
  established in PR-019 H-009
  (`(organization_id, agent_id) → agents(organization_id, id)`
  and `(organization_id, certificate_id) → certificates(organization_id, id)`);
  internal/inventory repository implementation (deduplication
  by `(organization_id, fingerprint_sha256)`, reconciliation
  with `removed_at` for store_coverage); indexes per
  CERTIFICATE_INVENTORY.md §10. No HTTP surface yet.
- **Recommended PR:** `feat(inventory): certificate + observations storage layer`.
- **Reason not fixed now:** spawned by the H-011 design PR.
  Land schema first so H-015 (the ingestion endpoint) has a
  storage layer to wire against.
- **References:**
  [`docs/engineering/CERTIFICATE_INVENTORY.md`](./CERTIFICATE_INVENTORY.md)
  §1, §8, §10; CLAUDE.md §6.2, §16; PR-019 H-009 composite-FK
  precedent.

### H-015 — Certificate inventory: agent ingestion endpoint

- **Title:** `feat(inventory): agent certificate ingestion endpoint`
- **Risk:** medium-high (real product wire, no-private-key
  invariant on hot path). Implements
  `POST /api/v1/agent/certificates` behind the existing
  `RequireAuthenticatedAgent` middleware. Uses the H-014
  storage layer plus the shared
  `envelope.DecodeStrictOptionalJSON` helper (H-009).
- **Scope:** handler, ingestion service, set-reconciliation
  logic (per CERTIFICATE_INVENTORY.md §3), private-key
  rejection (entire-batch fail closed per §7), server-side
  PEM parsing + canonical fingerprint computation (§4),
  audit events `agent.certificate_batch_rejected` /
  `agent.certificate_batch_invalid` with
  `severity: "security"` and no cert content in metadata
  (§6, §7). Size / count caps per §4. Full unit + integration
  test coverage including private-key rejection, batch
  reconciliation, out-of-order arrival handling, and the
  cross-org defense.
- **Recommended PR:** `feat(inventory): agent certificate ingestion endpoint`.
- **Reason not fixed now:** depends on H-014 landing first
  (needs the storage layer).
- **References:**
  [`docs/engineering/CERTIFICATE_INVENTORY.md`](./CERTIFICATE_INVENTORY.md)
  §4, §5, §6, §7; CLAUDE.md §6.2, §6.9, §9, §18; H-009
  (DecodeStrictOptionalJSON); H-007 (agent-auth middleware).

### H-016 — Certificate inventory: operator read API

- **Title:** `feat(inventory): operator certificate read endpoints`
- **Risk:** low-medium (read-only operator surface; org-scoping
  is the only security concern, and the H-010 pattern already
  has the recipe).
- **Scope:** four operator-side endpoints —
  `GET /api/v1/certificates`,
  `GET /api/v1/certificates/{id}`,
  `GET /api/v1/certificates/{id}/observations`,
  `GET /api/v1/agents/{id}/certificates`. Cursor pagination
  matching the H-010 pattern; slim summary rows for list
  endpoints, full detail (including PEM) for the single-cert
  endpoint. Filters per CERTIFICATE_INVENTORY.md §12.
  Cross-org → 404 not_found.
- **Recommended PR:** `feat(inventory): operator certificate read endpoints`.
- **Reason not fixed now:** depends on H-014. Can ship before
  or after H-015 — without H-015 the read endpoints return
  empty pages, but they still build the operator-facing query
  surface.
- **References:**
  [`docs/engineering/CERTIFICATE_INVENTORY.md`](./CERTIFICATE_INVENTORY.md)
  §11, §12; H-010 (operator-side list pattern).

### H-012 — Agent rebind: admin token issuance + redemption

- **Title:** `feat(enrollment): admin rebind-token issuance + agent rebind execution`
- **Risk:** medium (operational + security). The bearer-credential
  identity model has no in-product recovery path today; operators
  reinstalling a workstation orphan its observation history or
  drop to direct SQL. The design landed (see References) commits
  to **rebind reuses the same `agent_id`**, which keeps heartbeat,
  inventory, and future certificate observations continuous
  across reinstalls.
- **Scope:** ship both endpoints in one PR — they share the
  `agent_rebind_tokens` table and atomicity model, and shipping
  issuance without a consumer would leak admin tokens with no way
  to redeem them. Concretely: new migration for
  `agent_rebind_tokens` (composite FK to `agents(organization_id,
  id)`, hashed token, single-use lifecycle bounds);
  `internal/enrollment` service additions for issuance + atomic
  redemption (conditional UPDATE pattern); two handlers
  (`POST /agents/{id}/rebind-token` admin, `POST /agents/rebind`
  anonymous); audit actions `agent.rebind_token_issued`,
  `agent.rebound`, `agent.rebind_rejected` (all
  severity:"security"); full unit + integration test coverage
  following the deployment-package precedent (concurrency,
  cross-org, idempotency-like behavior, generic-rejection
  envelope).
- **Recommended PR:** `feat(enrollment): admin rebind-token
  issuance + agent rebind execution`.
- **Reason not fixed now:** spawned by the H-006 design PR
  ([`AGENT_REINSTALL_REBIND.md`](./AGENT_REINSTALL_REBIND.md)).
  Land design first so the implementation can lock the wire
  shape; H-012 then implements against the agreed contract.
- **References:** CLAUDE.md §6, §9, §16, §18;
  [`docs/engineering/AGENT_REINSTALL_REBIND.md`](./AGENT_REINSTALL_REBIND.md)
  §4, §8, §9, §10; H-008 (Phase 6 mTLS carries the design forward).

### H-013 — Agent-initiated credential rotation

- **Title:** `feat(enrollment): agent-initiated credential rotation`
- **Risk:** low-medium. Independent of H-012 — rotation requires a
  valid current credential and so does not need the rebind token
  primitive. The endpoint is small but security-significant: every
  rotation atomically invalidates the previous credential.
- **Scope:** `POST /api/v1/agent/credential/rotate` behind the
  existing agent-bearer middleware (`/agent/*` singular-prefix
  convention). Mints new credential, swaps `agents.credential_hash`
  atomically, returns plaintext exactly once. Adds
  `last_credential_rotated_at` and `credential_version` columns to
  `agents` (small migration). Audit action
  `agent.credential_rotated` (severity:"security") in the same
  transaction as the swap. No overlap window — see the design's §5
  rationale. Full unit + integration test coverage including the
  old-credential-immediately-invalid assertion.
- **Recommended PR:** `feat(enrollment): agent-initiated
  credential rotation`.
- **Reason not fixed now:** spawned by the H-006 design PR. Can
  ship before or after H-012; the two are independent (rebind
  recovers from a LOST credential, rotation requires a VALID one).
- **References:** CLAUDE.md §6, §9, §18;
  [`docs/engineering/AGENT_REINSTALL_REBIND.md`](./AGENT_REINSTALL_REBIND.md)
  §5, §8, §9, §10.

### H-008 — Future mTLS / device crypto identity hardening

- **Title:** `design(security): Phase 6 mTLS migration for agent identity`
- **Risk:** high (security; Phase 6, not v0.1). The v0.1
  identity is a bearer credential. CLAUDE.md §6.4 commits to
  mTLS in Phase 6: each agent presents a client certificate, the
  control plane pins it at enrollment, and the agent's identity
  becomes its key pair rather than a long-lived shared secret.
  Migration 0002 already relaxed
  `agents.public_key_fingerprint` to NULL specifically so a
  future mTLS migration can populate it for every agent without a
  schema reshape. The design + migration are deferred but should
  be tracked formally.
- **Scope:** **design first**. Enrollment flow needs a key-pair
  generation step on the agent, a CSR to the control plane, an
  issuance flow (a built-in CA? a delegated PKI provider?), and
  a pinning model. The `internal/providers/pki/` package already
  exists for the provider abstraction. The agent side requires
  Windows-native key storage (CNG / DPAPI). The transition story
  matters: a fleet enrolled on bearer must be able to upgrade
  in-place without re-deploying installers.
- **Recommended PR:** First a design doc
  (`docs/security/AGENT_MTLS.md`); then a migration that
  populates `public_key_fingerprint`; then the issuance flow.
- **Reason not fixed now:** Phase 6 boundary; the bearer
  credential is the documented v0.1 primitive and the migration
  preserves the schema for the upgrade.
- **References:** CLAUDE.md §6.4 (mTLS by Phase 6); §10 (provider
  abstraction); `docs/engineering/AGENT_ENROLLMENT.md` Schema
  notes section.

## How items get added or removed

- **Added** when a deferred follow-up has clear scope, a real risk,
  and a recommended PR shape. "We might want to look at X someday"
  is not an entry; design speculation lives in
  `docs/architecture/EVOLUTION.md`.
- **Removed** when the recommended PR has merged. Crossing the entry
  out is not enough — delete it. The merge commit + this file's git
  history are the audit trail.
- **Promoted** to a CLAUDE.md amendment if the item turns out to
  encode a binding rule. CLAUDE.md is the constitution; this file is
  the punch list.
